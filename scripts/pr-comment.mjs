#!/usr/bin/env node

import { readFile, stat, writeFile } from 'node:fs/promises';

const escapeMarkdown = (value) => {
  let text = String(value).replaceAll('\r', ' ').replaceAll('\n', ' ');
  for (const character of ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '.', '!', '|', '>', '~', '-']) {
    text = text.replaceAll(character, `\\${character}`);
  }
  return text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
};

function safeText(value, fallback = 'Unspecified') {
  if (typeof value !== 'string') return fallback;
  return escapeMarkdown(value.slice(0, 500));
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function renderSecuritySection(report, expected) {
  if (!report) return expected ? ['', '## App safety check', '', '**Security report unavailable:** The scan did not produce a reviewable result. Inspect the scan workflow.'] : [];
  const valid = isRecord(report)
    && report.schemaVersion === 1
    && ['complete', 'incomplete'].includes(report.status)
    && isRecord(report.summary)
    && Array.isArray(report.checks) && report.checks.length <= 4
    && report.checks.every((check) => isRecord(check)
      && ['secrets', 'dependencies', 'code', 'http'].includes(check.name)
      && ['complete', 'incomplete', 'skipped'].includes(check.status)
      && Number.isInteger(check.count) && check.count >= 0)
    && Array.isArray(report.findings) && report.findings.length <= 2000
    && report.findings.every((finding) => isRecord(finding)
      && ['secrets', 'dependencies', 'code', 'http'].includes(finding.category)
      && ['critical', 'high', 'medium', 'low', 'review'].includes(finding.severity));
  if (!valid) throw new Error('Unsupported or invalid security report');
  const lines = ['', '## App safety check', '', 'Security findings are redacted review leads. No matched values or source excerpts are shown. Automated checks cannot establish that an app is secure.', ''];
  const findings = report.findings.slice(0, 30);
  if (!findings.length) lines.push('No security findings were reported.');
  else {
    lines.push(`Found **${report.findings.length}** finding${report.findings.length === 1 ? '' : 's'} (showing at most 30):`, '');
    for (const finding of findings) {
      const category = {
        secrets: 'Possible credential', dependencies: 'Dependency advisory',
        code: 'Code pattern', http: 'HTTP configuration',
      }[finding.category];
      lines.push(`- **${category}** (${finding.severity}): review the corresponding redacted report entry and affected code or configuration.`);
    }
  }
  const incomplete = report.checks.filter(check => check.status === 'incomplete').map(check => check.name);
  if (incomplete.length) lines.push('', `**Incomplete checks:** ${incomplete.join(', ')}. These checks provide no clean result.`);
  if (report.checks.some(check => check.name === 'http' && check.status === 'skipped')) {
    lines.push('', 'HTTP checks were skipped because no URL was supplied.');
  }
  return lines;
}

export function renderComment(report, securityReport, securityExpected = false) {
  const validSummary = isRecord(report?.summary)
    && ['new', 'existing', 'resolved', 'uncertain'].every((key) => Number.isInteger(report.summary[key]) && report.summary[key] >= 0);
  const validFindings = Array.isArray(report?.findings) && report.findings.every((finding) => isRecord(finding)
    && ['new', 'existing', 'resolved', 'uncertain'].includes(finding.classification)
    && ['ruleId', 'page', 'target', 'description', 'rationale'].every((key) => typeof finding[key] === 'string'));
  const validFailures = Array.isArray(report?.failures) && report.failures.every((failure) => isRecord(failure)
    && ['revision', 'page', 'message'].every((key) => typeof failure[key] === 'string'));
  const validMeta = isRecord(report?.meta) && typeof report.meta.baseRef === 'string' && typeof report.meta.headRef === 'string'
    && isRecord(report.meta.viewport) && Number.isInteger(report.meta.viewport.width) && Number.isInteger(report.meta.viewport.height)
    && isRecord(report.meta.tool) && ['name', 'version', 'axeVersion'].every((key) => typeof report.meta.tool[key] === 'string');
  if (!isRecord(report) || report.schemaVersion !== 1 || !['complete', 'incomplete'].includes(report.status) || !validSummary || !validFindings || !validFailures || !validMeta) {
    throw new Error('Unsupported or invalid accessibility report');
  }
  const findings = report.findings.filter((finding) => finding && typeof finding === 'object' && finding.classification === 'new').slice(0, 50);
  const lines = [
    '<!-- a11y-regression-report -->',
    '## Accessibility regression scan',
    '',
    'This report highlights newly detected accessibility findings. Automated checks are incomplete and can produce false positives; review the evidence manually. A scan error or missing evidence does not mean a page is accessible.',
    '',
  ];
  if (!findings.length) {
    lines.push('No new findings were reported. This does not establish that the pages are fully accessible.');
  } else {
    lines.push(`Found **${findings.length}** new finding${findings.length === 1 ? '' : 's'} (showing at most 50):`, '');
    for (const finding of findings) {
      if (!finding || typeof finding !== 'object' || Array.isArray(finding)) continue;
      const title = safeText(finding.ruleId, 'Accessibility finding');
      const page = safeText(finding.page, 'Page unavailable');
      const target = safeText(finding.target, 'Target unavailable');
      const description = safeText(finding.description, 'Description unavailable.');
      const rationale = safeText(finding.rationale, 'Classification rationale unavailable.');
      const impact = safeText(finding.impact, 'unknown');
      const htmlEvidence = safeText(finding.html, '');
      const screenshot = safeText(finding.screenshot, '');
      lines.push(`- **${title}** (${impact}) on ${page}, target ${target}: ${description} _${rationale}_`);
      if (htmlEvidence) lines.push(`  DOM evidence: ${htmlEvidence}`);
      if (screenshot) lines.push(`  Screenshot artifact: ${screenshot}`);
    }
  }
  if (report.status === 'incomplete') lines.push('', '**Scan caveat:** The comparison is incomplete; some pages or revisions could not be scanned. Review the report failures and uncertain findings.');
  const failures = Array.isArray(report.failures) ? report.failures.slice(0, 20) : [];
  if (failures.length) {
    lines.push('', '**Scan failures:**');
    for (const failure of failures) {
      if (!failure || typeof failure !== 'object') continue;
      lines.push(`- ${safeText(failure.revision)} · ${safeText(failure.page)}: ${safeText(failure.message)}`);
    }
  }
  const uncertain = report.summary && Number.isFinite(report.summary.uncertain) ? report.summary.uncertain : 0;
  if (uncertain > 0) lines.push('', `**Uncertain classifications:** ${Math.min(uncertain, 100000)}. These need manual review.`);
  lines.push(...renderSecuritySection(securityReport, securityExpected));
  lines.push('', 'The redacted security report and accessibility artifacts are attached to the scan workflow run.');
  return lines.join('\n');
}

if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const [input, output, securityInput] = process.argv.slice(2);
  if (!input || !output) {
    console.error('Usage: node scripts/pr-comment.mjs <report.json> <comment.md>');
    process.exit(2);
  }
  try {
    if ((await stat(input)).size > 5_000_000) throw new Error('Accessibility report exceeds size limit');
    const report = JSON.parse(await readFile(input, 'utf8'));
    let security;
    if (securityInput) {
      try {
        if ((await stat(securityInput)).size > 5_000_000) throw new Error('Security report exceeds size limit');
        security = JSON.parse(await readFile(securityInput, 'utf8'));
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
    await writeFile(output, renderComment(report, security, Boolean(securityInput)), { encoding: 'utf8', flag: 'w' });
  } catch (error) {
    console.error(`Cannot create PR comment: ${error.message}`);
    process.exit(1);
  }
}
