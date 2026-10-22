import type { Report } from './types.js';

export function escapeHtml(value: unknown): string {
  const entities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return String(value ?? '').replace(/[&<>"']/g, c => entities[c]!);
}

function safeHelpUrl(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null;
  } catch { return null; }
}

function safeScreenshotPath(value: string | undefined): string | null {
  return value && /^screenshots\/(?:base|head)-[a-z0-9-]+-[a-f0-9]{12}\.png$/.test(value) ? value : null;
}

function escapeMarkdown(value: unknown): string {
  return String(value ?? '').replace(/[\r\n]+/g, ' ').replace(/[\\`*_{}\[\]()#+.!|>]/g, '\\$&').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function renderHtml(report: Report): string {
  const rows = report.findings.map(f => {
    const helpUrl = safeHelpUrl(f.helpUrl);
    const screenshot = safeScreenshotPath(f.screenshot);
    return `<tr><td>${escapeHtml(f.classification)}</td><td>${escapeHtml(f.impact ?? 'unknown')}</td><td>${escapeHtml(f.ruleId)}</td><td>${escapeHtml(f.page)}</td><td><code>${escapeHtml(f.target)}</code></td><td>${escapeHtml(f.description)}${helpUrl ? ` <a href="${escapeHtml(helpUrl)}" rel="noreferrer">Help</a>` : ''}${screenshot ? `<br><a href="${screenshot}">Screenshot</a>` : ''}${f.html ? `<details><summary>HTML evidence</summary><pre>${escapeHtml(f.html)}</pre></details>` : ''}<p>${escapeHtml(f.rationale)}</p></td></tr>`;
  }).join('\n');
  const failures = report.failures.map(f => `<li>${escapeHtml(f.revision)} — ${escapeHtml(f.page)}: ${escapeHtml(f.message)}</li>`).join('');
  const s = report.summary;
  const tool = report.meta.tool;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Accessibility comparison</title><style>body{font:15px system-ui,sans-serif;max-width:1400px;margin:2rem auto;padding:0 1rem;color:#182230}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.65rem;border-bottom:1px solid #ccd3dc;vertical-align:top}code,pre{white-space:pre-wrap;overflow-wrap:anywhere}p{max-width:60rem}.status{font-weight:bold}</style></head><body><h1>Accessibility comparison</h1><p class="status">${escapeHtml(report.status)}</p><p>New: ${s.new} · Existing: ${s.existing} · Resolved: ${s.resolved} · Uncertain: ${s.uncertain}</p><h2>Run metadata</h2><ul><li>Base revision: ${escapeHtml(report.meta.baseRef)}</li><li>Head revision: ${escapeHtml(report.meta.headRef)}</li><li>Viewport: ${report.meta.viewport.width} × ${report.meta.viewport.height}</li><li>Tool: ${escapeHtml(tool.name)} ${escapeHtml(tool.version)}</li><li>axe-core: ${escapeHtml(tool.axeVersion)}</li></ul><p>Automated accessibility testing covers only the checks implemented by axe-core and cannot establish that a page is fully accessible. Manual review and assistive technology testing are still needed.</p>${failures ? `<h2>Scan failures</h2><ul>${failures}</ul>` : ''}<table><thead><tr><th>Status</th><th>Impact</th><th>Rule</th><th>Page</th><th>Target</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}

export function renderSummary(report: Report): string {
  const s = report.summary;
  const lines = [`# Accessibility comparison`, '', `Status: **${report.status}**`, '', `New: ${s.new} · Existing: ${s.existing} · Resolved: ${s.resolved} · Uncertain: ${s.uncertain}`, '', `Base revision: ${escapeMarkdown(report.meta.baseRef)}  `, `Head revision: ${escapeMarkdown(report.meta.headRef)}  `, `Viewport: ${report.meta.viewport.width} × ${report.meta.viewport.height}  `, `Tool: ${escapeMarkdown(report.meta.tool.name)} ${escapeMarkdown(report.meta.tool.version)}  `, `axe-core: ${escapeMarkdown(report.meta.tool.axeVersion)}`, '', '> Automated accessibility testing covers only the checks implemented by axe-core and cannot establish that a page is fully accessible. Manual review and assistive technology testing are still needed.', ''];
  if (report.failures.length) {
    lines.push('## Scan failures', '');
    for (const f of report.failures) lines.push(`- ${escapeMarkdown(f.revision)} · ${escapeMarkdown(f.page)}: ${escapeMarkdown(f.message)}`);
    lines.push('');
  }
  if (report.findings.length) {
    lines.push('## Findings', '');
    for (const f of report.findings) {
      const helpUrl = safeHelpUrl(f.helpUrl);
      const screenshot = safeScreenshotPath(f.screenshot);
      const rule = helpUrl ? `[${escapeMarkdown(f.ruleId)}](<${helpUrl}>)` : escapeMarkdown(f.ruleId);
      lines.push(`- **${f.classification}** (${escapeMarkdown(f.impact ?? 'unknown')}) ${rule} on page ${escapeMarkdown(f.page)}, target ${escapeMarkdown(f.target)}: ${escapeMarkdown(f.description)} _${escapeMarkdown(f.rationale)}_`);
      if (screenshot) lines.push(`  - [Screenshot evidence](${screenshot})`);
      if (f.html) lines.push(`  - <details><summary>HTML element context</summary><pre>${escapeHtml(f.html)}</pre></details>`);
    }
  } else lines.push('No accessibility violations found.');
  return lines.join('\n') + '\n';
}
