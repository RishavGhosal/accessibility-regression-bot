import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const rulesPath = path.resolve('skills/app-safety/rules/browser-boundaries.yml');
const roots: string[] = [];
afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));

const fixture = `
import express from 'express';
const app = express();
app.get('/debug', (req, res) => res.send(process.env));
app.post('/_debug/config', (req, res) => res.json(config));
app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/api/users/:id', authenticate, (req, res) => res.json({ id: req.params.id }));
app.post('/checkout', csrfProtection, checkout);
app.use(csrf({ enabled: false }));
app.use(csrf({ ignoreMethods: ['GET', 'HEAD', 'OPTIONS'] }));
app.use(csrf({ ignoreMethods: ['GET', 'POST'] }));
app.use(csrfProtection);
feature({ enabled: false });
worker.disable();
`;

describe('browser boundary Semgrep rules', () => {
  it('defines narrow review rules for exposed debug routes and explicit CSRF bypasses', async () => {
    const yamlText = await readFile(rulesPath, 'utf8');
    expect([...yamlText.matchAll(/^  - id: (app-safety\.[a-z-]+)$/gm)].map((match) => match[1])).toEqual([
      'app-safety.exposed-debug-route',
      'app-safety.csrf-disabled-or-bypassed',
    ]);
    expect(yamlText).toContain('languages: [javascript, typescript]');
    expect(yamlText).toContain('severity: WARNING');
    expect(yamlText).toContain('explicitly disables or bypasses CSRF');
    expect(yamlText).toContain('metavariable: $CSRF');
    expect(yamlText).toContain("regex: '(?i)csrf'");
    expect(fixture).toContain("app.get('/debug'");
    expect(fixture).toContain("app.use(csrf({ enabled: false }))");
    expect(fixture).toContain('feature({ enabled: false })');
    expect(fixture).toContain('worker.disable()');
  });

  it('finds seeded risky patterns and keeps ordinary routes and CSRF configuration clean when Semgrep is installed', async (context) => {
    try {
      await execFileAsync('semgrep', ['--version'], { windowsHide: true });
    } catch {
      context.skip('Semgrep CLI is not installed; seeded rule execution was not verified.');
      return;
    }

    const root = await mkdtemp(path.join(tmpdir(), 'boundary-security-'));
    roots.push(root);
    const sourcePath = path.join(root, 'fixture.js');
    await writeFile(sourcePath, fixture);
    const { stdout } = await execFileAsync('semgrep', [
      'scan', '--config', rulesPath, '--json', '--quiet', '--metrics=off', sourcePath,
    ], { windowsHide: true, maxBuffer: 2_000_000 });
    const report = JSON.parse(stdout) as { results: Array<{ check_id: string; start: { line: number } }> };
    expect(report.results.map((result) => `${result.check_id}:${result.start.line}`).sort()).toEqual([
      'app-safety.csrf-disabled-or-bypassed:8',
      'app-safety.csrf-disabled-or-bypassed:10',
      'app-safety.exposed-debug-route:4',
      'app-safety.exposed-debug-route:5',
    ]);
  });
});
