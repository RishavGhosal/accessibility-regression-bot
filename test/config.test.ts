import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig, validateBaseUrl } from '../src/config.js';

const directories: string[] = [];
async function fixture(value: unknown): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'a11y-config-test-'));
  directories.push(dir);
  const file = path.join(dir, 'config.json');
  await writeFile(file, JSON.stringify(value));
  return file;
}
afterEach(async () => { await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

describe('loadConfig', () => {
  it('defaults viewport and accepts a minimal previews config', async () => {
    await expect(loadConfig(await fixture({ mode: 'previews', pages: ['/'] }))).resolves.toMatchObject({ viewport: { width: 1280, height: 800 } });
  });
  it('rejects unknown keys and unsafe page paths', async () => {
    await expect(loadConfig(await fixture({ mode: 'previews', pages: ['/'], typo: true }))).rejects.toThrow('Unknown config field');
    await expect(loadConfig(await fixture({ mode: 'previews', pages: ['/../private'] }))).rejects.toThrow('Dot segments');
  });
  it('requires all build lifecycle fields', async () => {
    await expect(loadConfig(await fixture({ mode: 'builds', pages: ['/'] }))).rejects.toThrow('requires a "builds" object');
    await expect(loadConfig(await fixture({ mode: 'builds', pages: ['/'], builds: {
      install: [], build: ['npm', 'run', 'build'], start: ['node', 'site.mjs'], readyPath: '/',
    } }))).rejects.toThrow('builds.install');
  });
});

it('validates preview URL protocol and credentials', () => {
  expect(validateBaseUrl('https://example.com/')).toBe('https://example.com');
  expect(() => validateBaseUrl('javascript:alert(1)')).toThrow('HTTP(S)');
  expect(() => validateBaseUrl('https://user:pass@example.com')).toThrow('credentials');
});
