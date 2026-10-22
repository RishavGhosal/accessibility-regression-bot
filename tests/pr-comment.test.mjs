import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { renderComment } from '../scripts/pr-comment.mjs';

const report = (overrides = {}) => ({
  schemaVersion: 1,
  status: 'complete',
  summary: { new: 1, existing: 0, resolved: 0, uncertain: 0 },
  findings: [{ classification: 'new', ruleId: 'color-contrast', impact: 'serious', page: '/home', target: 'main > h1', description: 'Text contrast is too low', rationale: 'The rule was absent in the base scan.' }],
  failures: [],
  meta: { baseRef: 'base', headRef: 'head', viewport: { width: 1280, height: 800 }, tool: { name: 'axe-core', version: '1', axeVersion: '1' } },
  ...overrides,
});

describe('PR comment rendering', () => {
  it('includes only new findings and safe review caveats', () => {
    const body = renderComment(report({
      status: 'incomplete',
      summary: { new: 1, existing: 1, resolved: 0, uncertain: 1 },
      findings: [...report().findings, { classification: 'existing', ruleId: 'old-finding', page: '/', target: 'body', description: 'old', rationale: 'same' }],
      failures: [{ revision: 'head', page: '/account', message: 'navigation timed out' }],
    }));
    expect(body).toContain('color\\-contrast');
    expect(body).not.toContain('old-finding');
    expect(body).toContain('comparison is incomplete');
    expect(body).toContain('navigation timed out');
    expect(body).toContain('Uncertain classifications');
  });

  it('escapes hostile Markdown and HTML fields and bounds field length', () => {
    const body = renderComment(report({ findings: [{
      classification: 'new', ruleId: '](owned) `@everyone` <script>alert(1)</script>',
      impact: 'serious|critical', page: '[click](https://attacker.invalid)', target: '`\n> injected list',
      description: '![x](javascript:alert(1)) **pwned**', rationale: 'x'.repeat(1000),
    }] }));
    expect(body).not.toContain('<script>');
    expect(body).not.toContain('\n> injected list');
    expect(body).not.toContain('**pwned**');
    expect(body.length).toBeLessThan(3000);
  });

  it('rejects unsupported report schemas and omits comments when there are no new findings', () => {
    expect(() => renderComment(report({ schemaVersion: 2 }))).toThrow(/invalid accessibility report/i);
    expect(renderComment(report({ findings: [] })).toLowerCase()).toContain('no new findings');
  });
  it('renders bounded security findings without copying secrets or source fields', () => {
    const secret = 'ghp_FAKE_SECRET_FOR_TEST_123456789';
    const security = {
      schemaVersion: 1, status: 'complete',
      summary: { findings: 1, gatedSecrets: 1, incompleteChecks: 0 },
      checks: [{ name: 'secrets', status: 'complete', count: 1 }],
      findings: [{ category: 'secrets', severity: 'high', id: secret, title: secret,
        guidance: secret, location: { path: secret, url: `https://example.test/${secret}` } }],
    };
    const body = renderComment(report(), security, true);
    expect(body).toContain('Possible credential');
    expect(body).not.toContain(secret);
    expect(body).not.toContain('https://example.test');
    expect(() => renderComment(report(), { ...security, checks: [{ name: 'secrets', status: 'unsafe', count: 1 }] }, true)).toThrow(/invalid security report/i);
  });
  it('flags an expected but missing security artifact', () => {
    expect(renderComment(report(), undefined, true)).toContain('Security report unavailable');
  });
});

describe('workflow privilege boundaries', () => {
  it('runs pull request code with read-only permissions and no pull_request_target trigger', async () => {
    const yaml = await readFile(new URL('../.github/workflows/accessibility-regression.yml', import.meta.url), 'utf8');
    expect(yaml).toContain('pull_request:');
    expect(yaml).toContain('contents: read');
    expect(yaml).not.toContain('pull_request_target');
    expect(yaml).toContain('uses: ./');
    expect(yaml).toContain("security-check: 'true'");
  });

  it('uses workflow_run only for trusted comment tooling and downloads the exact run artifact', async () => {
    const yaml = await readFile(new URL('../.github/workflows/accessibility-regression-comment.yml', import.meta.url), 'utf8');
    expect(yaml).toContain('workflow_run:');
    expect(yaml).toContain('actions/download-artifact@v4');
    expect(yaml).toContain('run-id: ${{ github.event.workflow_run.id }}');
    expect(yaml).toContain('ref: ${{ github.event.repository.default_branch }}');
    expect(yaml).toContain('RUN_HEAD_SHA');
    expect(yaml).toContain("pr.head?.sha !== process.env.RUN_HEAD_SHA");
    expect(yaml).not.toContain('ref: ${{ github.event.workflow_run.head_sha }}');
    expect(yaml).toContain("if: steps.artifact.outcome == 'success'");
    expect(yaml).toContain("if: steps.prepare.outcome == 'success'");
    expect(yaml).toContain('report-download/security-report.json');
  });
  it('keeps security checks optional for existing Action consumers', async () => {
    const yaml = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
    expect(yaml).toContain('security-check:');
    expect(yaml).toContain("default: 'false'");
    expect(yaml).toContain('A11Y_SECURITY_CHECK');
  });
});
