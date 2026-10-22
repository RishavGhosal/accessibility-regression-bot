import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const rulesPath = path.resolve('skills/app-safety/rules/sensitive-data-exposure.yml');
const roots: string[] = [];
afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));

const fixture = `
const token = req.headers.authorization;
const email = req.user.email;
console.info('request', token);
analytics.track('account-view', { email });
res.status(401).json({ error: token });
const statusCode = err.status;
res.status(statusCode).json({ profile: email });
res.status(error.status).json({ profile: email });
res.status(err.status).json({ profile: email });
res.status(200).json({ profile: email });
console.info('request accepted');
analytics.track('account-view', { page: 'settings' });
res.status(401).json({ error: 'Unauthorized' });
`;

describe('sensitive-data Semgrep rules', () => {
  it('defines review-only taint rules for each requested sink class', async () => {
    const yamlText = await readFile(rulesPath, 'utf8');
    expect([...yamlText.matchAll(/^  - id: (app-safety\.[a-z-]+)$/gm)].map((match) => match[1])).toEqual([
      'app-safety.sensitive-data-in-logs',
      'app-safety.sensitive-data-in-analytics',
      'app-safety.sensitive-data-in-http-errors',
    ]);
    expect([...yamlText.matchAll(/^    mode: taint$/gm)]).toHaveLength(3);
    expect([...yamlText.matchAll(/^    severity: WARNING$/gm)]).toHaveLength(3);
    for (const source of ['headers.authorization', 'headers.cookie', 'body.password', 'body.email', 'body.phone', 'user.email']) {
      expect(yamlText).toContain(source);
    }
    for (const sink of ['console.info', '$LOGGER.error', 'analytics.track', '$ANALYTICS.identify', '.status($STATUS).json', '.status($STATUS).send']) {
      expect(yamlText).toContain(sink);
    }
    expect(yamlText).toContain("regex: '(?i)^(?:[45][0-9]{2}|statusCode|(?:error|err)\\.status)$'");
    expect(yamlText).toContain('Status expressions are a heuristic');
    expect(fixture).toContain("console.info('request', token)");
    expect(fixture).toContain("console.info('request accepted')");
    expect(fixture).toContain('res.status(200).json({ profile: email })');
    expect(fixture).toContain('res.status(statusCode).json({ profile: email })');
  });

  it('reports seeded sensitive flows while leaving unrelated values clean when Semgrep is installed', async (context) => {
    try {
      await execFileAsync('semgrep', ['--version'], { windowsHide: true });
    } catch {
      context.skip();
      return;
    }

    const root = await mkdtemp(path.join(tmpdir(), 'privacy-security-'));
    roots.push(root);
    const sourcePath = path.join(root, 'fixture.js');
    await writeFile(sourcePath, fixture);
    const { stdout } = await execFileAsync('semgrep', [
      'scan', '--config', rulesPath, '--json', '--quiet', '--metrics=off', sourcePath,
    ], { windowsHide: true, maxBuffer: 2_000_000 });
    const report = JSON.parse(stdout) as { results: Array<{ check_id: string; start: { line: number } }> };
    expect(report.results.filter((result) => result.check_id === 'app-safety.sensitive-data-in-http-errors')).toHaveLength(4);
    expect(report.results.filter((result) => result.check_id === 'app-safety.sensitive-data-in-http-errors').map((result) => result.start.line)).not.toContain(11);
    expect([...new Set(report.results.map((result) => result.check_id))].sort()).toEqual([
      'app-safety.sensitive-data-in-analytics',
      'app-safety.sensitive-data-in-http-errors',
      'app-safety.sensitive-data-in-logs',
    ]);
  });
});
