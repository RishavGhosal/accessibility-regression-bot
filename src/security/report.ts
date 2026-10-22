import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { SecurityCheck, SecurityFinding } from './types.js';

export interface SecurityReport {
  schemaVersion: 1;
  status: 'complete' | 'incomplete';
  summary: { findings: number; gatedSecrets: number; incompleteChecks: number };
  checks: { name: SecurityCheck['name']; status: SecurityCheck['status']; count: number; error?: string }[];
  findings: SecurityFinding[];
}

const categories = new Set(['secrets', 'dependencies', 'code', 'http']);
const severities = new Set(['critical', 'high', 'medium', 'low', 'review']);
const safePath = /^[a-zA-Z0-9._/\\-]{1,200}$/;
const gatedSecretIds = new Set([
  'gitleaks:aws-access-token', 'gitleaks:aws-secret-access-key',
  'gitleaks:github-pat', 'gitleaks:github-fine-grained-pat',
  'gitleaks:private-key', 'gitleaks:stripe-access-token',
  'gitleaks:slack-access-token',
]);
const codeIds = new Set([
  'app-safety.dynamic-evaluation', 'app-safety.shell-command-concatenation',
  'app-safety.sql-string-concatenation', 'app-safety.unsafe-html-insertion',
  'app-safety.sensitive-data-in-logs', 'app-safety.sensitive-data-in-analytics',
  'app-safety.sensitive-data-in-http-errors',
  'app-safety.exposed-debug-route', 'app-safety.csrf-disabled-or-bypassed',
]);
const httpIds = new Set([
  'http.hsts.missing', 'http.csp.missing', 'http.content-type-options.missing',
  'http.cookie.secure.missing', 'http.cookie.httponly.missing',
  'http.cookie.samesite.missing', 'http.cookie.samesite.none',
  'http.cors.wildcard-credentials', 'http.cors.wildcard', 'http.cors.null-origin',
]);

function safeFindingId(value: SecurityFinding): string {
  if (value.category === 'secrets') return gatedSecretIds.has(value.id) ? value.id : 'gitleaks:possible-secret';
  if (value.category === 'dependencies') {
    return /^osv:(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\d{4}-\d{4,})$/i.test(value.id)
      ? value.id : 'osv:advisory';
  }
  if (value.category === 'code') return codeIds.has(value.id) ? value.id : 'app-safety:code-pattern';
  return httpIds.has(value.id) ? value.id : 'http:configuration';
}

const titles: Record<SecurityFinding['category'], string> = {
  secrets: 'Possible exposed credential',
  dependencies: 'Dependency advisory',
  code: 'Potential unsafe code pattern',
  http: 'HTTP configuration review',
};
const guidance: Record<SecurityFinding['category'], string> = {
  secrets: 'Remove the credential from source, rotate it if real, and use a secret store.',
  dependencies: 'Review the advisory and upgrade to a fixed version where available.',
  code: 'Review the input trust boundary and use a safer API or validation.',
  http: 'Review the response policy and configure the relevant header or cookie option.',
};

// Review pointers to OWASP ASVS 5.0.0. A finding does not establish conformance.
const review: Record<string, { asvs: string; guidance: string }> = {
  'app-safety.dynamic-evaluation': { asvs: 'v5.0.0-1.3.2', guidance: 'Replace dynamic code execution with explicit operations. Review any user-controlled input that reaches the interpreter.' },
  'app-safety.shell-command-concatenation': { asvs: 'v5.0.0-1.2.5', guidance: 'Use an argument-array process API without a shell and allowlist any user-controlled arguments.' },
  'app-safety.sql-string-concatenation': { asvs: 'v5.0.0-1.2.4', guidance: 'Use parameterized queries or safe ORM bindings instead of assembling query text.' },
  'app-safety.unsafe-html-insertion': { asvs: 'v5.0.0-3.2.2', guidance: 'Use textContent for plain text or sanitize intentionally supported HTML with a vetted library.' },
  'app-safety.sensitive-data-in-logs': { asvs: 'v5.0.0-14.2.4', guidance: 'Remove or redact the sensitive field before logging; review log access and retention.' },
  'app-safety.sensitive-data-in-analytics': { asvs: 'v5.0.0-14.2.3', guidance: 'Omit sensitive fields from analytics events and review the destination and data policy.' },
  'app-safety.sensitive-data-in-http-errors': { asvs: 'v5.0.0-16.5.1', guidance: 'Return a generic client error and keep sensitive diagnostic details out of the response.' },
  'app-safety.exposed-debug-route': { asvs: 'v5.0.0-13.4.2', guidance: 'Remove debug functionality from production or restrict it with server-side authorization and deployment controls.' },
  'app-safety.csrf-disabled-or-bypassed': { asvs: 'v5.0.0-3.5.1', guidance: 'Review the exception and require a CSRF defense for credentialed state-changing requests.' },
  'http.hsts.missing': { asvs: 'v5.0.0-3.4.1', guidance: 'Set an appropriate Strict-Transport-Security policy on HTTPS responses.' },
  'http.csp.missing': { asvs: 'v5.0.0-3.4.3', guidance: 'Define a Content-Security-Policy for trusted resources and review its directives.' },
  'http.content-type-options.missing': { asvs: 'v5.0.0-3.4.4', guidance: 'Set X-Content-Type-Options: nosniff on responses.' },
  'http.cookie.secure.missing': { asvs: 'v5.0.0-3.3.1', guidance: 'Set Secure on cookies sent over HTTPS.' },
  'http.cookie.httponly.missing': { asvs: 'v5.0.0-3.3.4', guidance: 'Set HttpOnly when client-side scripts do not need access to the cookie.' },
  'http.cookie.samesite.missing': { asvs: 'v5.0.0-3.3.2', guidance: 'Choose a SameSite policy based on the cookie purpose and cross-site flows.' },
  'http.cookie.samesite.none': { asvs: 'v5.0.0-3.3.2', guidance: 'Set Secure for a SameSite=None cookie and review whether cross-site access is required.' },
  'http.cors.wildcard-credentials': { asvs: 'v5.0.0-3.4.2', guidance: 'Use a trusted-origin allowlist and review credentialed cross-origin responses.' },
  'http.cors.wildcard': { asvs: 'v5.0.0-3.4.2', guidance: 'Confirm wildcard origin access is intended and responses contain no sensitive data.' },
  'http.cors.null-origin': { asvs: 'v5.0.0-3.4.2', guidance: 'Review whether null-origin clients should be allowed and use a trusted-origin allowlist.' },
};

function safeFinding(value: SecurityFinding): SecurityFinding {
  const category = categories.has(value.category) ? value.category : 'code';
  const severity = severities.has(value.severity) ? value.severity : 'review';
  const id = safeFindingId(value);
  const area = review[id];
  const asvs = area?.asvs ?? (category === 'secrets' ? 'v5.0.0-13.3.1' : category === 'dependencies' ? 'v5.0.0-15.2.1' : undefined);
  const location: SecurityFinding['location'] = {};
  const line = value.location?.line;
  if (typeof line === 'number' && Number.isInteger(line) && line > 0 && line < 1_000_000) {
    location.line = line;
  }
  if (category !== 'secrets' && value.location?.path && safePath.test(value.location.path)
      && !path.isAbsolute(value.location.path) && !value.location.path.split(/[\\/]/).includes('..')) {
    location.path = value.location.path.replaceAll('\\', '/');
  }
  if (category === 'http' && value.location?.url) {
    try {
      const url = new URL(value.location.url);
      if (url.protocol === 'http:' || url.protocol === 'https:') location.url = url.origin;
    } catch { /* Drop untrusted locations. */ }
  }
  return {
    id,
    category,
    severity,
    title: titles[category],
    ...(Object.keys(location).length ? { location } : {}),
    guidance: area?.guidance ?? guidance[category],
    ...(asvs ? { asvs } : {}),
    ...(value.gate === true && category === 'secrets' && gatedSecretIds.has(value.id) ? { gate: true } : {}),
  };
}

export function buildSecurityReport(checks: SecurityCheck[]): SecurityReport {
  const findings = checks.flatMap(check => check.findings.map(safeFinding));
  const incompleteChecks = checks.filter(check => check.status === 'incomplete').length;
  return {
    schemaVersion: 1,
    status: incompleteChecks ? 'incomplete' : 'complete',
    summary: {
      findings: findings.length,
      gatedSecrets: findings.filter(finding => finding.gate === true).length,
      incompleteChecks,
    },
    checks: checks.map(check => ({
      name: check.name,
      status: check.status,
      count: check.findings.length,
      ...(check.status === 'incomplete' ? { error: 'Check could not complete; review the local scanner setup.' } : {}),
    })),
    findings,
  };
}

export function securityGateExit(report: SecurityReport): number {
  const secret = report.checks.find(check => check.name === 'secrets');
  if (!secret || secret.status !== 'complete') return 2;
  return report.summary.gatedSecrets > 0 ? 1 : 0;
}

export async function writeSecurityReport(report: SecurityReport, outputDir: string): Promise<void> {
  await mkdir(outputDir, { recursive: true });
  await writeFile(path.join(outputDir, 'security-report.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  const lines = [
    '# App safety check', '',
    `Status: **${report.status}**`, '',
    `Findings: ${report.summary.findings} · Gated secrets: ${report.summary.gatedSecrets} · Incomplete checks: ${report.summary.incompleteChecks}`, '',
    ...report.checks.map(check => `- ${check.name}: ${check.status} (${check.count} findings)`),
    '', 'Security findings are pattern-based review leads; this check cannot establish that an app is secure.',
  ];
  if (report.findings.length) {
    lines.push('', '## Findings', '');
    for (const finding of report.findings) {
      const where = finding.location?.path
        ? ` in \`${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}\``
        : finding.location?.url ? ` at ${finding.location.url}` : finding.location?.line ? ` at line ${finding.location.line}` : '';
      lines.push(`- ${finding.category} / ${finding.severity} / ${finding.id}${where}: ${finding.guidance}${finding.asvs ? ` Review: OWASP ASVS ${finding.asvs}.` : ''}`);
    }
  }
  await writeFile(path.join(outputDir, 'security-summary.md'), `${lines.join('\n')}\n`, 'utf8');
}
