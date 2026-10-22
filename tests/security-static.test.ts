import { access, mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runStaticChecks } from '../src/security/static.js';

const roots: string[] = [];
afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));

async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'static-security-'));
  roots.push(root);
  return root;
}

describe('runStaticChecks', () => {
  it('returns bounded safe findings from all three scanners', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'package-lock.json'), '{}');
    await mkdir(path.join(root, 'skills/app-safety/rules'), { recursive: true });
    let reportPath = '';
    const runner = async (command: string, args: string[]) => {
      if (command === 'gitleaks') {
        reportPath = args[args.indexOf('--report-path') + 1]!;
        expect(args).toContain('--redact');
        await writeFile(reportPath, JSON.stringify([{ RuleID: 'github-pat', File: 'src/a.ts', StartLine: 3, Secret: 'DO_NOT_LEAK_TOKEN' }]));
        return { code: 1, stdout: '', stderr: 'DO_NOT_LEAK_STDERR' };
      }
      if (command === 'osv-scanner') return { code: 0, stdout: JSON.stringify({ results: [{ source: { path: 'package-lock.json' }, packages: [{ package: { name: 'sample', version: '1.2.3' }, vulnerabilities: [{ id: 'GHSA-abcd-efgh-ijkl', summary: 'safe advisory' }] }] }] }), stderr: '' };
      return { code: 0, stdout: JSON.stringify({ results: [{ check_id: 'app-safety.dynamic-evaluation', path: 'src/a.ts', start: { line: 9 }, extra: { message: 'unsafe eval', severity: 'ERROR' } }] }), stderr: '' };
    };
    const checks = await runStaticChecks(root, { runner });
    expect(checks.map(({ name, status }) => [name, status])).toEqual([['secrets', 'complete'], ['dependencies', 'complete'], ['code', 'complete']]);
    expect(checks.flatMap((check) => check.findings).map((f) => [f.category, f.location?.path, f.location?.line])).toEqual([
      ['secrets', 'src/a.ts', 3], ['dependencies', 'package-lock.json', undefined], ['code', 'src/a.ts', 9],
    ]);
    expect(checks[0]?.findings[0]?.gate).toBe(true);
    expect(JSON.stringify(checks)).not.toContain('DO_NOT_LEAK');
    expect(JSON.stringify(checks)).not.toContain('unsafe eval');
    await expect(access(reportPath)).rejects.toThrow();
  });

  it('marks missing tools incomplete with generic errors and no stderr', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'package-lock.json'), '{}');
    const checks = await runStaticChecks(root, { runner: async () => ({ code: 127, stdout: '', stderr: 'private path /secret/value' }) });
    expect(checks).toHaveLength(3);
    expect(checks.every((check) => check.status === 'incomplete' && check.error === 'Scanner unavailable or failed.')).toBe(true);
    expect(JSON.stringify(checks)).not.toContain('/secret/value');
  });

  it('marks non-empty oversized scanner output incomplete without preserving it', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'package-lock.json'), '{}');
    const checks = await runStaticChecks(root, { maxOutputBytes: 20, runner: async () => ({ code: 0, stdout: 'x'.repeat(500), stderr: '' }) });
    expect(checks.every((check) => check.status === 'incomplete' && check.findings.length === 0)).toBe(true);
  });

  it('accepts OSV exit code 1 when the JSON report contains advisories', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'bun.lock'), '{}');
    const runner = async (command: string, args: string[]) => command === 'osv-scanner'
      ? (expect(args).toContain(`--lockfile=:${path.join(root, 'bun.lock')}`), { code: 1, stdout: JSON.stringify({ results: [{ source: { path: 'bun.lock' }, packages: [{ package: { name: 'private-package', version: '3.4.5' }, vulnerabilities: [{ id: 'GHSA-abcd-efgh-ijkl' }] }] }] }), stderr: '' })
      : command === 'gitleaks'
        ? { code: 0, stdout: '', stderr: '' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' };
    const checks = await runStaticChecks(root, { runner });
    expect(checks[1]?.status).toBe('complete');
    expect(checks[1]?.findings).toHaveLength(1);
    expect(checks[1]?.findings[0]?.id).toBe('osv:GHSA-abcd-efgh-ijkl');
    expect(JSON.stringify(checks[1])).not.toContain('private-package');
  });

  it('skips OSV when no supported JavaScript lockfile is present', async () => {
    const root = await fixture();
    await writeFile(path.join(root, 'Cargo.lock'), 'not a JavaScript lockfile');
    const commands: string[] = [];
    const runner = async (command: string) => {
      commands.push(command);
      return command === 'gitleaks'
        ? { code: 0, stdout: '', stderr: '' }
        : { code: 0, stdout: JSON.stringify({ results: [] }), stderr: '' };
    };
    const checks = await runStaticChecks(root, { runner });
    expect(checks[1]).toEqual({ name: 'dependencies', status: 'skipped', findings: [] });
    expect(commands).not.toContain('osv-scanner');
  });

  it('keeps bundled privacy rule IDs while discarding matched data from Semgrep output', async () => {
    const root = await fixture();
    const runner = async (command: string) => command === 'gitleaks'
      ? { code: 0, stdout: '', stderr: '' }
      : { code: 0, stdout: JSON.stringify({ results: [{
        check_id: 'app-safety.sensitive-data-in-logs', path: 'src/server.ts',
        start: { line: 4 }, extra: { severity: 'WARNING', message: 'PRIVATE_PERSONAL_VALUE' },
      }] }), stderr: '' };
    const checks = await runStaticChecks(root, { runner });
    expect(checks[2]?.findings[0]?.id).toBe('app-safety.sensitive-data-in-logs');
    expect(JSON.stringify(checks)).not.toContain('PRIVATE_PERSONAL_VALUE');
  });

  it('accepts bundled browser-boundary IDs as review findings', async () => {
    const root = await fixture();
    const runner = async (command: string) => command === 'gitleaks'
      ? { code: 0, stdout: '', stderr: '' }
      : { code: 0, stdout: JSON.stringify({ results: [
        { check_id: 'app-safety.exposed-debug-route', path: 'src/server.ts', start: { line: 9 }, extra: { severity: 'WARNING' } },
        { check_id: 'app-safety.csrf-disabled-or-bypassed', path: 'src/server.ts', start: { line: 11 }, extra: { severity: 'WARNING' } },
      ] }), stderr: '' };
    const checks = await runStaticChecks(root, { runner });
    expect(checks[2]?.findings.map((finding) => finding.id)).toEqual([
      'app-safety.exposed-debug-route', 'app-safety.csrf-disabled-or-bypassed',
    ]);
  });
});
