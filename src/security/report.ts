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

function safeFinding(value: SecurityFinding): SecurityFinding {
  const category = categories.has(value.category) ? value.category : 'code';
  const severity = severities.has(value.severity) ? value.severity : 'review';
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
    id: safeFindingId(value),
    category,
    severity,
    title: titles[category],
    ...(Object.keys(location).length ? { location } : {}),
    guidance: guidance[category],
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
      lines.push(`- ${finding.category} / ${finding.severity} / ${finding.id}${where}: ${finding.guidance}`);
    }
  }
  await writeFile(path.join(outputDir, 'security-summary.md'), `${lines.join('\n')}\n`, 'utf8');
}
