import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { startBuildPair } from '../src/builds.js';
import type { RegressionConfig } from '../src/config.js';

const roots: string[] = [];
async function repoFixture(): Promise<string> {
  const root = await mkdtemp(path.join(process.cwd(), '.test-git-'));
  roots.push(root);
  const git = (args: string[]) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' });
    if (result.status !== 0) throw new Error(result.stderr);
  };
  git(['init', '-q']);
  git(['config', 'user.email', 'test@example.invalid']);
  git(['config', 'user.name', 'Test']);
  await writeFile(path.join(root, 'version.txt'), 'one');
  git(['add', '.']); git(['commit', '-qm', 'first']);
  git(['branch', 'second']);
  return root;
}
afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 })));
});

const config: RegressionConfig = {
  mode: 'builds', pages: ['/'], viewport: { width: 1280, height: 800 }, builds: {
    install: ['node', '-e', ''], build: ['node', '-e', ''],
    start: ['node', '-e', 'setInterval(() => {}, 1000)'], readyPath: '/health',
  },
};

describe('startBuildPair', () => {
  it('starts both worktrees on distinct ports and removes worktrees on cleanup', async () => {
    const requestedUrls: string[] = [];
    vi.stubGlobal('fetch', async (input: string | URL | Request) => {
      requestedUrls.push(String(input));
      return new Response('ok', { status: 200 });
    });
    const root = await repoFixture();
    const pair = await startBuildPair({ cwd: root, baseRef: 'HEAD', headRef: 'second', config, readinessTimeoutMs: 5000 });
    try {
      expect(pair.baseUrl).not.toBe(pair.prUrl);
      expect(new Set(requestedUrls.map((url) => new URL(url).port)).size).toBe(2);
      expect(requestedUrls).toContain(`${pair.baseUrl}/health`);
      expect(requestedUrls).toContain(`${pair.prUrl}/health`);
    } finally { await pair.cleanup(); }
    const worktrees = spawnSync('git', ['worktree', 'list', '--porcelain'], { cwd: root, encoding: 'utf8' }).stdout;
    expect(worktrees.match(/^worktree /gm)).toHaveLength(1);
  }, 20_000);
  it('cleans worktrees when startup fails readiness', async () => {
    const root = await repoFixture();
    const broken = { ...config, builds: { ...config.builds!, start: ['node', '-e', 'process.exit(9)'] } };
    await expect(startBuildPair({ cwd: root, baseRef: 'HEAD', headRef: 'second', config: broken, readinessTimeoutMs: 2000 })).rejects.toThrow('exited before becoming ready');
    const entries = spawnSync('git', ['worktree', 'list', '--porcelain'], { cwd: root, encoding: 'utf8' }).stdout;
    expect(entries.match(/^worktree /gm)).toHaveLength(1);
  }, 20_000);
});
