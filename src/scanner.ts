import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import axe from 'axe-core';
import { findingContext, matchFindings } from './matching.js';
import { renderHtml, renderSummary } from './report.js';
import type { RawFinding, Report, Revision, ScanFailure, Viewport } from './types.js';

type ScanOptions = {
  baseUrl: string; prUrl: string; pages: string[]; viewport: Viewport; outputDir: string;
  metadata: { baseRef: string; headRef: string };
  redactEvidence?: boolean;
};

function pageUrl(origin: string, page: string): string {
  return new URL(page, origin.endsWith('/') ? origin : `${origin}/`).toString();
}

function safeSlug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 45) || 'finding';
}

async function scanRevision(revision: Revision, origin: string, pages: string[], viewport: Viewport, outputDir: string, redactEvidence = false): Promise<{ findings: RawFinding[]; failures: ScanFailure[]; screenshots: Map<string, string>; browserVersion: string }> {
  const findings: RawFinding[] = [];
  const failures: ScanFailure[] = [];
  const screenshots = new Map<string, string>();
  let browser: Browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    for (const page of pages) failures.push({ revision, page, message: `Could not launch Chromium: ${message}` });
    return { findings, failures, screenshots, browserVersion: 'unavailable' };
  }
  let ctx: BrowserContext;
  try {
    ctx = await browser.newContext({ viewport });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    for (const page of pages) failures.push({ revision, page, message: `Could not create browser context: ${message}` });
    await browser.close().catch(() => undefined);
    return { findings, failures, screenshots, browserVersion: browser.version() };
  }
  try {
    for (const pagePath of pages) {
      const page = await ctx.newPage();
      try {
        await page.goto(pageUrl(origin, pagePath), { waitUntil: 'networkidle', timeout: 30_000 });
        await page.addScriptTag({ content: axe.source });
        const results = await page.evaluate(async () => {
          const axeApi = (window as unknown as Window & { axe: typeof axe }).axe;
          return axeApi.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'] } });
        });
        for (const violation of results.violations) {
          for (const node of violation.nodes) {
            const target = Array.isArray(node.target) ? node.target.join(' | ') : String(node.target ?? '');
            let contextData = ['', ''];
            try {
              contextData = await page.locator(String(node.target?.[0] ?? '')).first().evaluate((el: Element) => {
                const role = el.getAttribute('role') || el.tagName.toLowerCase();
                const labelledBy = el.getAttribute('aria-labelledby');
                const labelledText = labelledBy ? labelledBy.split(/\s+/).map(id => document.getElementById(id)?.textContent ?? '').join(' ') : '';
                const name = el.getAttribute('aria-label') || labelledText || (el as HTMLImageElement).alt || el.getAttribute('title') || el.textContent || '';
                return [role, name.replace(/\s+/g, ' ').trim()] as [string, string];
              });
            } catch { /* The target may be an axe shadow-DOM path; keep empty context conservatively. */ }
            const context = findingContext(contextData[0], contextData[1]);
            const finding: RawFinding = {
              ruleId: violation.id, impact: node.impact ?? violation.impact ?? null, page: pagePath,
              target, description: node.failureSummary || violation.description || violation.help,
              helpUrl: violation.helpUrl ?? null, ...(!redactEvidence && node.html ? { html: node.html } : {}), context,
            };
            findings.push(finding);
            if (!redactEvidence) {
              const fingerprint = createHash('sha256').update(`${revision}\0${pagePath}\0${violation.id}\0${target}\0${context}`).digest('hex').slice(0, 12);
              const relative = `screenshots/${revision}-${safeSlug(pagePath)}-${safeSlug(violation.id)}-${fingerprint}.png`;
              try {
                await page.screenshot({ path: join(outputDir, relative), fullPage: true, animations: 'disabled' });
                screenshots.set(JSON.stringify([finding.ruleId, finding.page, finding.target, finding.context, revision]), relative);
              } catch (error) {
                failures.push({ revision, page: pagePath, message: `Could not capture screenshot for ${violation.id}: ${error instanceof Error ? error.message : String(error)}` });
              }
            }
          }
        }
      } catch (error) {
        failures.push({ revision, page: pagePath, message: error instanceof Error ? error.message : String(error) });
      } finally {
        await page.close().catch(() => undefined);
      }
    }
  } finally {
    await ctx.close();
    await browser.close();
  }
  return { findings, failures, screenshots, browserVersion: browser.version() };
}

export async function scanPair(options: ScanOptions): Promise<Report> {
  await mkdir(join(options.outputDir, 'screenshots'), { recursive: true });
  const failedScan = (revision: Revision, error: unknown) => ({
    findings: [] as RawFinding[], screenshots: new Map<string, string>(), browserVersion: 'unavailable',
    failures: options.pages.map(page => ({ revision, page, message: error instanceof Error ? error.message : String(error) })),
  });
  let base: Awaited<ReturnType<typeof scanRevision>>;
  let head: Awaited<ReturnType<typeof scanRevision>>;
  try { base = await scanRevision('base', options.baseUrl, options.pages, options.viewport, options.outputDir, options.redactEvidence); }
  catch (error) { base = failedScan('base', error); }
  try { head = await scanRevision('head', options.prUrl, options.pages, options.viewport, options.outputDir, options.redactEvidence); }
  catch (error) { head = failedScan('head', error); }
  const failures = [...base.failures, ...head.failures].sort((a, b) => a.revision.localeCompare(b.revision) || a.page.localeCompare(b.page) || a.message.localeCompare(b.message));
  const findings = matchFindings(base.findings, head.findings, failures).map(f => {
    const isHead = head.findings.some(raw => raw.ruleId === f.ruleId && raw.page === f.page && raw.target === f.target && raw.html === f.html);
    const source = isHead ? head : base;
    const raw = source.findings.find(raw => raw.ruleId === f.ruleId && raw.page === f.page && raw.target === f.target && raw.html === f.html);
    const screenshot = raw ? source.screenshots.get(JSON.stringify([raw.ruleId, raw.page, raw.target, raw.context, isHead ? 'head' : 'base'])) : undefined;
    return screenshot ? { ...f, screenshot } : f;
  });
  const summary = { new: 0, existing: 0, resolved: 0, uncertain: 0 };
  for (const finding of findings) summary[finding.classification]++;
  const report: Report = {
    schemaVersion: 1, status: failures.length ? 'incomplete' : 'complete', summary, findings, failures,
    meta: { baseRef: options.metadata.baseRef, headRef: options.metadata.headRef, viewport: options.viewport,
      tool: { name: 'Playwright Chromium', version: base.browserVersion === 'unavailable' ? head.browserVersion : base.browserVersion, axeVersion: axe.version } },
  };
  await writeFile(join(options.outputDir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  await writeFile(join(options.outputDir, 'report.html'), renderHtml(report), 'utf8');
  await writeFile(join(options.outputDir, 'summary.md'), renderSummary(report), 'utf8');
  return report;
}
