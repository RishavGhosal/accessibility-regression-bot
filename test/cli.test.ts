import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

const scanPairMock = vi.hoisted(() => vi.fn());
vi.mock('../src/scanner.js', () => ({ scanPair: scanPairMock }));
import { main } from '../src/cli.js';

const roots: string[] = [];
const originalCwd = process.cwd();
afterEach(async () => {
  process.chdir(originalCwd);
  scanPairMock.mockReset();
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
});
