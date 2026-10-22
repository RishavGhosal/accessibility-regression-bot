#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';

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

export function renderComment(report) {
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
  lines.push('', 'The complete JSON, HTML, Markdown summary, and screenshots are attached to the scan workflow run.');
  return lines.join('\n');
}

if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) {
    console.error('Usage: node scripts/pr-comment.mjs <report.json> <comment.md>');
    process.exit(2);
  }
  try {
    const report = JSON.parse(await readFile(input, 'utf8'));
    await writeFile(output, renderComment(report), { encoding: 'utf8', flag: 'w' });
  } catch (error) {
    console.error(`Cannot create PR comment: ${error.message}`);
    process.exit(1);
  }
}
