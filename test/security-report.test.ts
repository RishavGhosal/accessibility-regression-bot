import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildSecurityReport, securityGateExit, writeSecurityReport } from '../src/security/report.js';
import type { SecurityCheck } from '../src/security/types.js';

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

describe('security report sanitization and gate', () => {
  it('never persists a matched secret or source excerpt', async () => {
    const secret = 'ghp_FAKE_SECRET_FOR_TEST_123456789';
    const checks: SecurityCheck[] = [{
      name: 'secrets', status: 'complete', findings: [{
        id: 'gitleaks:github-pat', category: 'secrets', severity: 'high',
        title: secret, location: { path: `src/${secret}.ts`, line: 9 },
        guidance: `Remove ${secret}`, reference: `https://example.test/${secret}`, gate: true,
      }],
    }];
    const report = buildSecurityReport(checks);
    const directory = await mkdtemp(path.join(process.cwd(), '.security-report-test-'));
    directories.push(directory);
    await writeSecurityReport(report, directory);
    const json = await readFile(path.join(directory, 'security-report.json'), 'utf8');
    const markdown = await readFile(path.join(directory, 'security-summary.md'), 'utf8');
    expect(json + markdown).not.toContain(secret);
    expect(json).not.toContain('src/');
    expect(securityGateExit(report)).toBe(1);
  });

  it('fails closed when the secret scanner did not complete', () => {
    const report = buildSecurityReport([
      { name: 'secrets', status: 'incomplete', findings: [], error: 'raw error with token' },
      { name: 'dependencies', status: 'skipped', findings: [] },
    ]);
    expect(report.status).toBe('incomplete');
    expect(JSON.stringify(report)).not.toContain('raw error with token');
    expect(securityGateExit(report)).toBe(2);
  });
  it('drops scanner-controlled identifiers and guidance from persisted findings', () => {
    const secret = 'ghp_FAKE_SECRET_FOR_TEST_123456789';
    const report = buildSecurityReport([{
      name: 'code', status: 'complete', findings: [{
        id: secret, category: 'code', severity: 'medium', title: secret,
        guidance: secret, location: { path: 'src/example.ts', line: 12 },
      }],
    }]);
    expect(JSON.stringify(report)).not.toContain(secret);
    expect(report.findings[0]?.id).toBe('app-safety:code-pattern');
    expect(report.findings[0]?.location?.path).toBe('src/example.ts');
  });
});
