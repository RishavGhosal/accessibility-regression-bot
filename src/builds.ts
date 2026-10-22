import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:net';
import type { RegressionConfig } from './config.js';

export interface BuildPair { baseUrl: string; prUrl: string; cleanup: () => Promise<void> }
export interface BuildOptions {
  cwd: string;
  baseRef: string;
  headRef: string;
  config: RegressionConfig;
  readinessTimeoutMs?: number;
}

function run(command: string, args: string[], cwd: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, stdio: 'inherit', shell: false, windowsHide: true });
    child.once('error', (error) => reject(new Error(`Could not run ${command}: ${error.message}`)));
    child.once('close', (code, signal) => code === 0 ? resolve() : reject(new Error(`${command} ${args.join(' ')} failed${signal ? ` (${signal})` : ` with exit code ${code}`}.`)));
  });
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') { server.close(); reject(new Error('Could not reserve a local port.')); return; }
      const port = address.port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function start(args: string[], cwd: string, port: number): ChildProcess {
  if (!args.length) throw new Error('startArgs must not be empty.');
  const [command, ...commandArgs] = args;
  const child = spawn(command!, commandArgs, {
    cwd, env: { ...process.env, PORT: String(port) }, stdio: 'ignore', shell: false, windowsHide: true,
    detached: process.platform !== 'win32',
  });
  child.on('error', () => { /* readiness reports failed launches with the associated process context */ });
  return child;
}

function stop(child: ChildProcess): Promise<void> {
  if (!child.pid) return Promise.resolve();
  if (process.platform === 'win32') {
    return new Promise((resolve) => {
      const killer = spawn('taskkill', ['/pid', String(child.pid), '/t', '/f'], { stdio: 'ignore', windowsHide: true });
      killer.once('close', () => resolve());
      killer.once('error', () => resolve());
    });
  }
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      try { process.kill(-child.pid!, 'SIGKILL'); } catch { /* process group already exited */ }
      resolve();
    }, 1500);
    child.once('close', () => { clearTimeout(timeout); resolve(); });
    try { process.kill(-child.pid!, 'SIGTERM'); } catch { clearTimeout(timeout); resolve(); }
  });
}

async function waitReady(url: string, child: ChildProcess, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'no response';
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) throw new Error(`Preview process exited before becoming ready (code ${child.exitCode ?? child.signalCode ?? 'launch failure'}).`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) { lastError = error instanceof Error ? error.message : String(error); }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Preview did not become ready at ${url} within ${timeoutMs} ms (${lastError}).`);
}

export async function startBuildPair(options: BuildOptions): Promise<BuildPair> {
  const { cwd, config, baseRef, headRef } = options;
  if (config.mode !== 'builds' || !config.builds) {
    throw new Error('Build lifecycle requires a complete builds-mode config.');
  }
  const buildConfig = config.builds;
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'a11y-regression-'));
  const baseDir = path.join(temporaryRoot, 'base');
  const headDir = path.join(temporaryRoot, 'head');
  const worktrees: string[] = [];
  const processes: ChildProcess[] = [];
  let cleaned = false;
  const cleanup = async (): Promise<void> => {
    if (cleaned) return;
    cleaned = true;
    await Promise.all(processes.map(stop));
    for (const worktree of worktrees.reverse()) {
      try { await run('git', ['worktree', 'remove', '--force', worktree], cwd); } catch { /* best-effort; fallback removes the temp tree */ }
    }
    await rm(temporaryRoot, { recursive: true, force: true });
  };
  try {
    await run('git', ['worktree', 'add', '--detach', baseDir, baseRef], cwd);
    worktrees.push(baseDir);
    await run('git', ['worktree', 'add', '--detach', headDir, headRef], cwd);
    worktrees.push(headDir);
    for (const dir of [baseDir, headDir]) {
      await run(buildConfig.install[0]!, buildConfig.install.slice(1), dir);
      await run(buildConfig.build[0]!, buildConfig.build.slice(1), dir);
    }
    const ports = await Promise.all([freePort(), freePort()]);
    if (ports[0] === ports[1]) ports[1] = await freePort();
    const baseProcess = start(buildConfig.start, baseDir, ports[0]!);
    processes.push(baseProcess);
    const headProcess = start(buildConfig.start, headDir, ports[1]!);
    processes.push(headProcess);
    const baseUrl = `http://127.0.0.1:${ports[0]}`;
    const prUrl = `http://127.0.0.1:${ports[1]}`;
    await Promise.all([
      waitReady(`${baseUrl}${buildConfig.readyPath}`, baseProcess, options.readinessTimeoutMs ?? 60_000),
      waitReady(`${prUrl}${buildConfig.readyPath}`, headProcess, options.readinessTimeoutMs ?? 60_000),
    ]);
    return { baseUrl, prUrl, cleanup };
  } catch (error) {
    await cleanup();
    throw error;
  }
}
