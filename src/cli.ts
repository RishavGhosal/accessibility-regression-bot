#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, validateBaseUrl } from './config.js';
import { startBuildPair } from './builds.js';
import { scanPair } from './scanner.js';
import { runSecurityReview } from './security/index.js';
import { securityGateExit, writeSecurityReport } from './security/report.js';

interface Arguments {
  command: 'scan' | 'check';
  config: string;
  baseUrl?: string;
  prUrl?: string;
  baseRef?: string;
  headRef?: string;
  output: string;
  failOnNew: boolean;
  securityCheck: boolean;
  url?: string;
}

function parseArgs(argv: string[]): Arguments {
  if (argv[0] !== 'scan' && argv[0] !== 'check') {
    throw new Error('Usage: accessibility-regression scan [--config FILE] [--base-url URL --pr-url URL | --base-ref REF --head-ref REF] [--output DIR] [--fail-on-new] [--security-check] | check [--url URL] [--output DIR].');
  }
  const command = argv[0];
  const result: Arguments = {
    command, config: '.a11y-regression.json',
    output: command === 'check' ? 'app-safety-report' : 'a11y-regression-report',
    failOnNew: false, securityCheck: false,
  };
  const values: Record<string, keyof Arguments> = {
    '--config': 'config', '--base-url': 'baseUrl', '--pr-url': 'prUrl', '--base-ref': 'baseRef', '--head-ref': 'headRef', '--output': 'output', '--url': 'url',
  };
  for (let index = 1; index < argv.length; index += 1) {
    const flag = argv[index]!;
    if (flag === '--fail-on-new' && command === 'scan') { result.failOnNew = true; continue; }
    if (flag === '--security-check' && command === 'scan') { result.securityCheck = true; continue; }
    const key = values[flag];
    if (!key || (command === 'check' && key !== 'url' && key !== 'output')
      || (command === 'scan' && key === 'url')) throw new Error(`Unknown option: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Option ${flag} requires a value.`);
    (result as unknown as Record<string, string>)[key] = value;
    index += 1;
  }
  return result;
}

function outputDirectory(value: string): string {
  const resolved = path.resolve(value);
  const relative = path.relative(process.cwd(), resolved);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('--output must be a directory inside the current working directory and cannot be the working directory itself.');
  }
  return resolved;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  let pair: Awaited<ReturnType<typeof startBuildPair>> | undefined;
  try {
    const args = parseArgs(argv);
    const reportDir = outputDirectory(args.output);
    if (args.command === 'check') {
      const url = args.url === undefined ? undefined : validateBaseUrl(args.url);
      const report = await runSecurityReview(process.cwd(), url);
      await writeSecurityReport(report, reportDir);
      console.log(`App safety report written to ${reportDir}.`);
      return securityGateExit(report);
    }
    const config = await loadConfig(args.config);
    let baseUrl: string;
    let prUrl: string;
    let baseRef: string;
    let headRef: string;
    if (config.mode === 'previews') {
      if (!args.baseUrl || !args.prUrl || args.baseRef || args.headRef) throw new Error('Previews mode requires --base-url and --pr-url, and does not accept build refs.');
      baseUrl = validateBaseUrl(args.baseUrl);
      prUrl = validateBaseUrl(args.prUrl);
      baseRef = 'base preview';
      headRef = 'PR preview';
    } else {
      if (!args.baseRef || !args.headRef || args.baseUrl || args.prUrl) throw new Error('Builds mode requires --base-ref and --head-ref, and does not accept preview URLs.');
      baseRef = args.baseRef;
      headRef = args.headRef;
      pair = await startBuildPair({ cwd: process.cwd(), baseRef, headRef, config });
      ({ baseUrl, prUrl } = pair);
    }
    const report = await scanPair({
      baseUrl, prUrl, pages: config.pages, viewport: config.viewport, outputDir: reportDir,
      metadata: { baseRef, headRef },
      redactEvidence: args.securityCheck,
    });
    console.log(`Accessibility report written to ${reportDir}.`);
    let exitCode = report.status === 'incomplete' ? 2 : args.failOnNew && report.summary.new > 0 ? 1 : 0;
    if (args.securityCheck) {
      const headPageUrl = new URL(config.pages[0]!, prUrl.endsWith('/') ? prUrl : `${prUrl}/`).toString();
      const security = await runSecurityReview(pair?.headDirectory ?? process.cwd(), headPageUrl);
      await writeSecurityReport(security, reportDir);
      console.log(`App safety report written to ${reportDir}.`);
      exitCode = Math.max(exitCode, securityGateExit(security));
    }
    return exitCode;
  } catch (error) {
    console.error(`Accessibility regression scan failed: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  } finally {
    await pair?.cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  process.exitCode = await main();
}
