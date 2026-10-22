import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SecurityCheck, SecurityFinding } from './types.js';

const OUTPUT_LIMIT = 2 * 1024 * 1024;
const TIMEOUT_MS = 120_000;
const SAFE_ERROR = 'Scanner unavailable or failed.';
const RULES_DIR = fileURLToPath(new URL('../../skills/app-safety/rules', import.meta.url));
const JS_LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock']);
const SEMGREP_RULE_IDS = new Set([
  'app-safety.dynamic-evaluation',
  'app-safety.shell-command-concatenation',
  'app-safety.sql-string-concatenation',
  'app-safety.unsafe-html-insertion',
]);

type CommandResult = { code: number | null; stdout: string; stderr: string };
type Runner = (command: string, args: string[], cwd: string, limit: number, timeout: number) => Promise<CommandResult>;
type StaticOptions = { runner?: Runner; maxOutputBytes?: number; timeoutMs?: number };

const runProcess: Runner = (command, args, cwd, limit, timeout) => new Promise((resolve, reject) => {
  let child;
  try {
    child = spawn(command, args, { cwd, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    reject(new Error(SAFE_ERROR));
    return;
  }
  let stdout = '';
  let stderr = '';
  let size = 0;
  let overflow = false;
  let timedOut = false;
  const collect = (target: 'stdout' | 'stderr') => (chunk: Buffer) => {
    size += chunk.length;
    if (size > limit) {
      overflow = true;
      child.kill();
      return;
    }
    if (target === 'stdout') stdout += chunk.toString('utf8');
    else stderr += chunk.toString('utf8');
  };
  child.stdout.on('data', collect('stdout'));
  child.stderr.on('data', collect('stderr'));
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeout);
  child.once('error', () => { clearTimeout(timer); reject(new Error(SAFE_ERROR)); });
  child.once('close', (code: number | null) => {
    clearTimeout(timer);
    if (overflow || timedOut) reject(new Error(SAFE_ERROR));
    else resolve({ code, stdout, stderr });
  });
});

function check(name: SecurityCheck['name'], findings: SecurityFinding[] = [], status: SecurityCheck['status'] = 'complete'): SecurityCheck {
  return { name, status, findings };
}

function relativeLocation(root: string, candidate: unknown): string | undefined {
  if (typeof candidate !== 'string' || candidate.length === 0) return undefined;
  const resolved = path.resolve(root, candidate);
  const relative = path.relative(root, resolved);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) return undefined;
  return relative.split(path.sep).join('/').slice(0, 500);
}

function positiveLine(value: unknown): number | undefined {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : undefined;
}

function safeId(value: unknown, fallback: string): string {
  return typeof value === 'string' && /^[A-Za-z0-9._:-]{1,120}$/.test(value) ? value : fallback;
}

function parseJson(output: string): unknown {
  try { return JSON.parse(output); } catch { throw new Error(SAFE_ERROR); }
}

function secretFindings(report: unknown, root: string): SecurityFinding[] {
  if (!Array.isArray(report)) throw new Error(SAFE_ERROR);
  const gatedRules = new Set(['aws-access-token', 'aws-secret-access-key', 'github-pat', 'github-fine-grained-pat', 'private-key', 'stripe-access-token', 'slack-access-token']);
  return report.slice(0, 1000).flatMap((entry: Record<string, unknown>) => {
    if (!entry || typeof entry !== 'object') return [];
    const rule = safeId(entry.RuleID, 'unclassified-secret');
    const gated = gatedRules.has(rule.toLowerCase());
    const location = relativeLocation(root, entry.File);
    const line = positiveLine(entry.StartLine);
    return [{
      id: `gitleaks:${rule}`, category: 'secrets', severity: gated ? 'high' : 'review',
      title: gated ? 'Potential provider credential' : 'Potential secret pattern',
      ...(location || line ? { location: { ...(location ? { path: location } : {}), ...(line ? { line } : {}) } } : {}),
      guidance: 'Review locally. Remove exposed credentials and rotate provider tokens or private keys; this check never validates credentials.',
      ...(gated ? { gate: true } : {}),
    } satisfies SecurityFinding];
  });
}

function dependencyFindings(data: unknown, root: string): SecurityFinding[] {
  if (!data || typeof data !== 'object') throw new Error(SAFE_ERROR);
  const results = (data as { results?: unknown }).results;
  if (!Array.isArray(results)) throw new Error(SAFE_ERROR);
  const findings: SecurityFinding[] = [];
  for (const result of results.slice(0, 1000)) {
    if (!result || typeof result !== 'object') continue;
    const row = result as Record<string, unknown>;
    const src = row.source as Record<string, unknown> | undefined;
    const sourcePath = typeof src?.path === 'string' ? src.path.replaceAll('\\', '/') : '';
    if (!JS_LOCKFILES.has(sourcePath.slice(sourcePath.lastIndexOf('/') + 1).toLowerCase())) continue;
    const file = relativeLocation(root, src?.path);
    const packages = row.packages;
    if (!Array.isArray(packages)) continue;
    for (const packageRow of packages.slice(0, 1000)) {
      if (!packageRow || typeof packageRow !== 'object') continue;
      const pkg = packageRow as Record<string, unknown>;
      if (!Array.isArray(pkg.vulnerabilities)) continue;
      for (const advisory of pkg.vulnerabilities.slice(0, 100)) {
        if (!advisory || typeof advisory !== 'object') continue;
        const vuln = advisory as Record<string, unknown>;
        const id = safeId(vuln.id, 'OSV-UNKNOWN');
        findings.push({
          id: `osv:${id}`, category: 'dependencies', severity: 'high',
          title: 'Vulnerable JavaScript dependency',
          ...(file ? { location: { path: file } } : {}),
          guidance: 'Upgrade to a fixed version identified by the advisory and regenerate the lockfile.',
          ...(id.startsWith('GHSA-') ? { reference: `https://github.com/advisories/${id}` } : { reference: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` }),
        });
      }
    }
  }
  return findings.slice(0, 2000);
}

async function discoverJsLockfiles(root: string): Promise<string[]> {
  const found: string[] = [];
  const pending = [root];
  let visited = 0;
  while (pending.length > 0) {
    const directory = pending.pop()!;
    visited += 1;
    if (visited > 10_000) throw new Error(SAFE_ERROR);
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!['.git', 'node_modules'].includes(entry.name.toLowerCase())) pending.push(entryPath);
      } else if (entry.isFile() && JS_LOCKFILES.has(entry.name.toLowerCase())) {
        found.push(entryPath);
        if (found.length > 100) throw new Error(SAFE_ERROR);
      }
    }
  }
  return found.sort();
}

function semgrepFindings(data: unknown, root: string): SecurityFinding[] {
  if (!data || typeof data !== 'object' || !Array.isArray((data as { results?: unknown }).results)) throw new Error(SAFE_ERROR);
  return ((data as { results: Record<string, unknown>[] }).results).slice(0, 1000).flatMap((result) => {
    if (!result || typeof result !== 'object') return [];
    const extra = result.extra as Record<string, unknown> | undefined;
    const start = result.start as Record<string, unknown> | undefined;
    const location = relativeLocation(root, result.path);
    const id = safeId(result.check_id, 'semgrep:local-rule');
    if (!SEMGREP_RULE_IDS.has(id)) return [];
    const line = positiveLine(start?.line);
    const severity = extra?.severity === 'ERROR' ? 'high' : extra?.severity === 'WARNING' ? 'medium' : 'review';
    return [{
      id, category: 'code', severity, title: 'Potentially unsafe code pattern',
      ...(location || line ? { location: { ...(location ? { path: location } : {}), ...(line ? { line } : {}) } } : {}),
      guidance: 'Review the flagged operation and use a safe API that avoids evaluating untrusted input or assembling executable commands, SQL, or HTML.',
    } satisfies SecurityFinding];
  });
}

async function runCheck(name: SecurityCheck['name'], action: () => Promise<SecurityFinding[]>): Promise<SecurityCheck> {
  try { return check(name, await action()); }
  catch { return { ...check(name, [], 'incomplete'), error: SAFE_ERROR }; }
}

export async function runStaticChecks(root: string, options: StaticOptions = {}): Promise<SecurityCheck[]> {
  const sourceRoot = path.resolve(root);
  const runner = options.runner ?? runProcess;
  const limit = options.maxOutputBytes ?? OUTPUT_LIMIT;
  const timeout = options.timeoutMs ?? TIMEOUT_MS;
  const invoke = async (command: string, args: string[]) => {
    const result = await runner(command, args, sourceRoot, limit, timeout);
    if (Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) > limit) throw new Error(SAFE_ERROR);
    return result;
  };

  const secrets = await runCheck('secrets', async () => {
    const temp = await mkdtemp(path.join(tmpdir(), 'security-gitleaks-'));
    const report = path.join(temp, 'report.json');
    try {
      const result = await invoke('gitleaks', ['dir', sourceRoot, '--report-format', 'json', '--report-path', report, '--redact', '--no-banner']);
      if (result.code !== 0 && result.code !== 1) throw new Error(SAFE_ERROR);
      let raw = '[]';
      const reportInfo = await stat(report).catch(() => undefined);
      if (reportInfo) {
        if (reportInfo.size > limit) throw new Error(SAFE_ERROR);
        raw = await readFile(report, 'utf8');
      } else if (result.code === 1) throw new Error(SAFE_ERROR);
      return secretFindings(parseJson(raw), sourceRoot);
    } finally { await rm(temp, { recursive: true, force: true }); }
  });

  let noLockfiles = false;
  const dependencyCheck = await runCheck('dependencies', async () => {
    const lockfiles = await discoverJsLockfiles(sourceRoot);
    if (lockfiles.length === 0) { noLockfiles = true; return []; }
    const args = ['scan', 'source', '--format', 'json', ...lockfiles.map((file) => `--lockfile=:${file}`)];
    const result = await invoke('osv-scanner', args);
    if (result.code !== 0 && result.code !== 1) throw new Error(SAFE_ERROR);
    return dependencyFindings(parseJson(result.stdout), sourceRoot);
  });
  const dependencies = noLockfiles ? check('dependencies', [], 'skipped') : dependencyCheck;

  const code = await runCheck('code', async () => {
    const result = await invoke('semgrep', ['scan', '--config', RULES_DIR, '--json', '--quiet', '--metrics=off', sourceRoot]);
    if (result.code !== 0) throw new Error(SAFE_ERROR);
    return semgrepFindings(parseJson(result.stdout), sourceRoot);
  });
  return [secrets, dependencies, code];
}
