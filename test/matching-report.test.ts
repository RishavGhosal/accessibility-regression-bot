import { describe, expect, it } from 'vitest';
import { findingContext, matchFindings } from '../src/matching.js';
import { escapeHtml, renderHtml, renderSummary } from '../src/report.js';
import type { RawFinding, Report } from '../src/types.js';

function finding(page: string, target: string, ruleId = 'button-name', context = findingContext('button', 'Save')): RawFinding {
  return { ruleId, page, target, context, impact: 'critical', description: 'Button needs a name', helpUrl: 'https://example.test/help' };
}

describe('finding matching', () => {
  it('classifies added, persistent, and resolved findings and sorts deterministically', () => {
    const base = [finding('/b', '#save'), finding('/c', '#old')];
    const head = [finding('/a', '#new'), finding('/b', '#save')];
    const first = matchFindings(base, head);
    expect(first.map(f => [f.page, f.classification])).toEqual([
      ['/a', 'new'], ['/b', 'existing'], ['/c', 'resolved'],
    ]);
    expect(matchFindings(base, head)).toEqual(first);
  });

  it('marks unmatched findings uncertain when their page scan failed', () => {
    const results = matchFindings([], [finding('/')], [{ revision: 'base', page: '/', message: 'Navigation failed' }]);
    expect(results[0]).toMatchObject({ classification: 'uncertain' });
  });

  it('uses role and accessible name context to avoid false exact matches', () => {
    const result = matchFindings([finding('/', '#save')], [finding('/', '#save', 'button-name', findingContext('button', 'Submit'))]);
    expect(result).toHaveLength(2);
    expect(result.every(item => item.classification === 'uncertain')).toBe(true);
  });

  it('does not treat screenshot failures as scan failures', () => {
    const result = matchFindings([], [finding('/')], [{ revision: 'base', page: '/', message: 'Could not capture screenshot: disk full' }]);
    expect(result[0]?.classification).toBe('new');
  });
});

it('escapes HTML evidence and labels before rendering', () => {
  expect(escapeHtml(`<img src=x onerror="x"> & 'test'`)).toBe('&lt;img src=x onerror=&quot;x&quot;&gt; &amp; &#39;test&#39;');
});

it('escapes untrusted report fields and rejects unsafe help links in both rendered reports', () => {
  const report: Report = {
    schemaVersion: 1, status: 'complete', summary: { new: 1, existing: 0, resolved: 0, uncertain: 0 },
    findings: [{ ...finding('/', '#x'), classification: 'new', page: '</td><script>alert(1)</script>', target: '`[x](javascript:alert(1))`', description: '<img src=x onerror=alert(1)>', helpUrl: 'javascript:alert(1)', rationale: '**unsafe**', html: '<button onfocus="x">', screenshot: 'screenshots/head-home-button-name-0123456789ab.png' }],
    failures: [{ revision: 'head', page: '<svg onload=alert(1)>', message: '<script>failure</script>' }],
    meta: { baseRef: '<b>base</b>', headRef: 'head', viewport: { width: 1280, height: 800 }, tool: { name: 'scanner', version: '1', axeVersion: '4' } },
  };
  const html = renderHtml(report);
  const markdown = renderSummary(report);
  expect(html).not.toContain('<script>');
  expect(html).not.toContain('href="javascript:');
  expect(markdown).not.toContain('<script>');
  expect(markdown).not.toContain('](javascript:');
  expect(markdown).toContain('Viewport: 1280 × 800');
  expect(markdown).toContain('Manual review');
  expect(markdown).toContain('[Screenshot evidence](screenshots/head-home-button-name-0123456789ab.png)');
  expect(markdown).toContain('HTML element context');
  expect(markdown).not.toContain('<button onfocus=');
  report.findings[0]!.screenshot = 'javascript:alert(1)';
  expect(renderHtml(report)).not.toContain('href="javascript:');
  expect(renderSummary(report)).not.toContain('Screenshot evidence');
});
