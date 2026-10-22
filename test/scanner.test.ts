import { createServer, type Server } from 'node:http';
import { mkdtemp, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright';
import { scanPair } from '../src/scanner.js';

const roots: string[] = [];
const servers: Server[] = [];
async function fixtureServer(html: string): Promise<string> {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html lang="en"><head><title>Fixture</title></head><body>${html}</body></html>`);
  });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fixture server did not bind a TCP port');
  return `http://localhost:${address.port}`;
}
async function outputDirectory(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), 'a11y-scanner-test-'));
  roots.push(dir);
  return dir;
}
afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

describe('scanPair browser comparison', () => {
  it('captures added, persistent, and resolved findings with deterministic report paths', async (ctx) => {
    const baseUrl = await fixtureServer('<button></button><img src="/x">');
    const prUrl = await fixtureServer('<button></button><a href="/next"></a>');
    let browser: Browser;
    try { browser = await chromium.launch({ headless: true }); }
    catch { ctx.skip(); return; }
    try {
      const probe = await browser.newPage();
      await probe.goto(baseUrl, { timeout: 3000 });
      await probe.close();
    } catch (error) {
      await browser.close();
      if (String(error).includes('ERR_NETWORK_ACCESS_DENIED')) { ctx.skip(); return; }
      throw error;
    }
    await browser.close();

    const outputDir = await outputDirectory();
    const options = { baseUrl, prUrl, pages: ['/'], viewport: { width: 900, height: 700 }, outputDir, metadata: { baseRef: 'base', headRef: 'head' } };
    const report = await scanPair(options);
    expect(report.status, JSON.stringify(report.failures)).toBe('complete');
    expect(report.summary).toMatchObject({ new: expect.any(Number), existing: expect.any(Number), resolved: expect.any(Number) });
    expect(report.summary.new).toBeGreaterThan(0);
    expect(report.summary.existing).toBeGreaterThan(0);
    expect(report.summary.resolved).toBeGreaterThan(0);
    expect(report.findings.every(f => !f.screenshot || f.screenshot.startsWith('screenshots/'))).toBe(true);
    const files = await readdir(path.join(outputDir, 'screenshots'));
    expect(files.length).toBeGreaterThan(0);
    const first = await readFile(path.join(outputDir, 'report.json'), 'utf8');
    await scanPair(options);
    expect(await readFile(path.join(outputDir, 'report.json'), 'utf8')).toBe(first);
  }, 60_000);
});
