import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const scanPairMock = vi.hoisted(() => vi.fn());
const startBuildPairMock = vi.hoisted(() => vi.fn());
const runSecurityReviewMock = vi.hoisted(() => vi.fn());
const writeSecurityReportMock = vi.hoisted(() => vi.fn());
vi.mock('../src/scanner.js', () => ({ scanPair: scanPairMock }));
vi.mock('../src/builds.js', () => ({ startBuildPair: startBuildPairMock }));
vi.mock('../src/security/index.js', () => ({ runSecurityReview: runSecurityReviewMock }));
vi.mock('../src/security/report.js', () => ({
  writeSecurityReport: writeSecurityReportMock,
  securityGateExit: (value: { summary: { gatedSecrets: number }; checks: { name: string; status: string }[] }) =>
    value.checks.some(check => check.name === 'secrets' && check.status !== 'complete') ? 2 : value.summary.gatedSecrets ? 1 : 0,
}));
import { main } from '../src/cli.js';

const roots: string[] = [];
const originalCwd = process.cwd();
afterEach(async () => {
  process.chdir(originalCwd);
  scanPairMock.mockReset();
  startBuildPairMock.mockReset();
  runSecurityReviewMock.mockReset();
  writeSecurityReportMock.mockReset();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function workspace(config: object): Promise<string> {
  const directory = await mkdtemp(path.join(process.cwd(), '.cli-test-'));
  roots.push(directory);
  await writeFile(path.join(directory, 'config.json'), JSON.stringify(config));
  return directory;
}
const report = { status: 'complete', summary: { new: 0 } };

describe('CLI modes', () => {
  it('runs previews mode with the supplied URLs and scanner options', async () => {
    const original = process.cwd();
    const directory = await workspace({ mode: 'previews', pages: ['/'] });
    process.chdir(directory);
    scanPairMock.mockResolvedValue(report);
    expect(await main(['scan', '--config', 'config.json', '--base-url', 'https://example.test/base/', '--pr-url', 'https://example.test/pr', '--output', 'report'])).toBe(0);
    expect(scanPairMock).toHaveBeenCalledWith(expect.objectContaining({
      baseUrl: 'https://example.test/base', prUrl: 'https://example.test/pr', pages: ['/'],
      metadata: { baseRef: 'base preview', headRef: 'PR preview' },
    }));
    process.chdir(original);
  });
  it('rejects missing mode arguments before scanning', async () => {
    const original = process.cwd();
    const directory = await workspace({ mode: 'previews', pages: ['/'] });
    process.chdir(directory);
    expect(await main(['scan', '--config', 'config.json', '--base-url', 'https://example.test'])).toBe(2);
    expect(scanPairMock).not.toHaveBeenCalled();
    process.chdir(original);
  });
  it('runs a local security check without accessibility config and fails on gated secrets', async () => {
    const directory = await workspace({ mode: 'previews', pages: ['/'] });
    process.chdir(directory);
    runSecurityReviewMock.mockResolvedValue({
      summary: { gatedSecrets: 1 }, checks: [{ name: 'secrets', status: 'complete' }],
    });
    expect(await main(['check', '--output', 'safety'])).toBe(1);
    expect(runSecurityReviewMock).toHaveBeenCalledWith(directory, undefined);
    expect(writeSecurityReportMock).toHaveBeenCalled();
    expect(scanPairMock).not.toHaveBeenCalled();
  });
  it('never echoes a malformed URL containing credentials', async () => {
    const value = 'https://user:fake-secret@';
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      expect(await main(['check', '--url', value])).toBe(2);
      expect(errors.mock.calls.flat().join(' ')).not.toContain('fake-secret');
      expect(runSecurityReviewMock).not.toHaveBeenCalled();
    } finally { errors.mockRestore(); }
  });
  it('runs security alongside the head preview and suppresses raw accessibility evidence', async () => {
    const directory = await workspace({ mode: 'previews', pages: ['/'] });
    process.chdir(directory);
    scanPairMock.mockResolvedValue(report);
    runSecurityReviewMock.mockResolvedValue({
      summary: { gatedSecrets: 0 }, checks: [{ name: 'secrets', status: 'complete' }],
    });
    expect(await main(['scan', '--config', 'config.json', '--base-url', 'https://base.test', '--pr-url', 'https://head.test', '--security-check'])).toBe(0);
    expect(scanPairMock).toHaveBeenCalledWith(expect.objectContaining({ redactEvidence: true }));
    expect(runSecurityReviewMock).toHaveBeenCalledWith(directory, 'https://head.test/');
  });
  it('scans the selected head build worktree rather than the caller checkout', async () => {
    const directory = await workspace({ mode: 'builds', pages: ['/'], builds: {
      install: ['npm', 'ci'], build: ['npm', 'run', 'build'], start: ['npm', 'start'], readyPath: '/',
    } });
    process.chdir(directory);
    const cleanup = vi.fn().mockResolvedValue(undefined);
    startBuildPairMock.mockResolvedValue({
      baseUrl: 'http://127.0.0.1:3001', prUrl: 'http://127.0.0.1:3002',
      headDirectory: path.join(directory, 'selected-head'), cleanup,
    });
    scanPairMock.mockResolvedValue(report);
    runSecurityReviewMock.mockResolvedValue({
      summary: { gatedSecrets: 0 }, checks: [{ name: 'secrets', status: 'complete' }],
    });
    expect(await main(['scan', '--config', 'config.json', '--base-ref', 'main', '--head-ref', 'feature', '--security-check'])).toBe(0);
    expect(runSecurityReviewMock).toHaveBeenCalledWith(path.join(directory, 'selected-head'), 'http://127.0.0.1:3002/');
    expect(cleanup).toHaveBeenCalled();
  });
});
