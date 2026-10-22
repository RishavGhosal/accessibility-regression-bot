#!/usr/bin/env node
// End-to-end local verification. Uses a disposable Git repository and loopback servers.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = resolve(fileURLToPath(new URL('..', import.meta.url)));
const cli = join(project, 'dist', 'cli.js');
const temporaryRoot = await mkdtemp(join(process.cwd(), '.smoke-'));
const servers = [];

async function run(command, args, cwd = project) {
  await new Promise((resolveRun, reject) => {
    const child = spawn(command, args, { cwd, env: process.env, stdio: 'inherit', windowsHide: true });
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolveRun() : reject(new Error(`${command} exited ${code}`)));
  });
}

async function serve(body) {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><html lang="en"><title>Fixture</title><body>${body}</body>`);
  });
  servers.push(server);
  await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
  return `http://127.0.0.1:${server.address().port}`;
}

async function checkReport(directory, label) {
  const report = JSON.parse(await readFile(join(directory, 'report.json'), 'utf8'));
  if (report.status !== 'complete' || report.summary.new < 1 || report.summary.existing < 1 || report.summary.resolved < 1) {
    throw new Error(`${label} did not classify new, existing, and resolved findings: ${JSON.stringify(report.summary)} ${JSON.stringify(report.failures)}`);
  }
  console.log(`${label}: ${JSON.stringify(report.summary)}`);
}

try {
  const baseUrl = await serve('<button></button><img src="/missing.png">');
  const prUrl = await serve('<button></button><a href="/next"></a>');
  const previewConfig = join(temporaryRoot, 'previews.json');
  await writeFile(previewConfig, JSON.stringify({ mode: 'previews', pages: ['/'] }));
  const previewOutput = join(temporaryRoot, 'preview-report');
  await run(process.execPath, [cli, 'scan', '--config', previewConfig, '--base-url', baseUrl, '--pr-url', prUrl, '--output', previewOutput]);
  await checkReport(previewOutput, 'previews mode');

  const repository = join(temporaryRoot, 'fixture-repo');
  await mkdir(repository);
  await run('git', ['init', '-q'], repository);
  await run('git', ['config', 'user.name', 'Smoke Test'], repository);
  await run('git', ['config', 'user.email', 'smoke@example.invalid'], repository);
  const site = join(repository, 'site.mjs');
  const siteSource = body => `import { createServer } from 'node:http';\ncreateServer((_q,r)=>{r.writeHead(200,{'content-type':'text/html'});r.end(${JSON.stringify(`<!doctype html><html lang="en"><title>Fixture</title><body>${body}</body>`)});}).listen(Number(process.env.PORT),'127.0.0.1');\n`;
  await writeFile(site, siteSource('<button></button><img src="/missing.png">'));
  await writeFile(join(repository, '.a11y-regression.json'), JSON.stringify({ mode: 'builds', pages: ['/'], builds: { install: ['node', '-e', 'void 0'], build: ['node', '-e', 'void 0'], start: ['node', 'site.mjs'], readyPath: '/' } }));
  await run('git', ['add', '.'], repository);
  await run('git', ['commit', '-qm', 'base fixture'], repository);
  await writeFile(site, siteSource('<button></button><a href="/next"></a>'));
  await run('git', ['add', '.'], repository);
  await run('git', ['commit', '-qm', 'head fixture'], repository);
  const buildOutput = join(repository, 'report');
  await run(process.execPath, [cli, 'scan', '--config', '.a11y-regression.json', '--base-ref', 'HEAD~1', '--head-ref', 'HEAD', '--output', buildOutput], repository);
  await checkReport(buildOutput, 'builds mode');
  const worktrees = await new Promise((resolveList, reject) => {
    let output = '';
    const child = spawn('git', ['worktree', 'list', '--porcelain'], { cwd: repository });
    child.stdout.on('data', chunk => { output += chunk; });
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolveList(output) : reject(new Error('git worktree list failed')));
  });
  if ((worktrees.match(/^worktree /gm) ?? []).length !== 1) throw new Error('Build-mode worktrees were not cleaned up');
  console.log('Both modes passed; temporary worktrees were cleaned up.');
} finally {
  await Promise.all(servers.map(server => new Promise(resolveClose => server.close(resolveClose))));
  await rm(temporaryRoot, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
}
