import { readFile } from 'node:fs/promises';
import path from 'node:path';

export interface Viewport { width: number; height: number }
export interface RegressionConfig {
  mode: 'previews' | 'builds';
  pages: string[];
  viewport: Viewport;
  builds?: { install: string[]; build: string[]; start: string[]; readyPath: string };
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function stringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new Error(`Config field "${name}" must be a non-empty array of non-empty strings.`);
  }
  return value as string[];
}

function validatePage(page: string): void {
  if (!page.startsWith('/') || page.startsWith('//') || page.includes('\\') || /[\u0000-\u001f]/.test(page)) {
    throw new Error(`Invalid page path "${page}". Pages must be safe root-relative paths.`);
  }
  const pathname = page.split(/[?#]/, 1)[0] ?? '';
  if (pathname.split('/').some((part) => part === '.' || part === '..')) {
    throw new Error(`Invalid page path "${page}". Dot segments are not allowed.`);
  }
}

export async function loadConfig(file: string): Promise<RegressionConfig> {
  const fullPath = path.resolve(file);
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(fullPath, 'utf8')) as unknown;
  } catch (error) {
    throw new Error(`Could not read config ${fullPath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isRecord(parsed)) throw new Error('Config must be a JSON object.');
  const allowed = new Set(['mode', 'pages', 'viewport', 'builds']);
  const unknown = Object.keys(parsed).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`Unknown config field(s): ${unknown.join(', ')}.`);
  if (parsed.mode !== 'previews' && parsed.mode !== 'builds') throw new Error('Config field "mode" must be "previews" or "builds".');
  const pages = stringArray(parsed.pages, 'pages');
  if (pages.length === 0) throw new Error('Config field "pages" must contain at least one page.');
  pages.forEach(validatePage);
  const viewportRaw = parsed.viewport === undefined ? { width: 1280, height: 800 } : parsed.viewport;
  if (!isRecord(viewportRaw) || !Number.isInteger(viewportRaw.width) || !Number.isInteger(viewportRaw.height)
      || (viewportRaw.width as number) < 1 || (viewportRaw.height as number) < 1
      || Object.keys(viewportRaw).some((key) => !['width', 'height'].includes(key))) {
    throw new Error('Config field "viewport" must contain positive integer width and height values.');
  }
  const config: RegressionConfig = {
    mode: parsed.mode,
    pages,
    viewport: { width: viewportRaw.width as number, height: viewportRaw.height as number },
  };
  if (parsed.builds !== undefined) {
    if (!isRecord(parsed.builds) || Object.keys(parsed.builds).some((key) => !['install', 'build', 'start', 'readyPath'].includes(key))) {
      throw new Error('Config field "builds" must contain install, build, start, and readyPath only.');
    }
    if (typeof parsed.builds.readyPath !== 'string' || !parsed.builds.readyPath.startsWith('/') || parsed.builds.readyPath.startsWith('//')) {
      throw new Error('Config field "builds.readyPath" must be a root-relative HTTP path.');
    }
    config.builds = {
      install: stringArray(parsed.builds.install, 'builds.install'),
      build: stringArray(parsed.builds.build, 'builds.build'),
      start: stringArray(parsed.builds.start, 'builds.start'),
      readyPath: parsed.builds.readyPath,
    };
  }
  if (config.mode === 'builds' && !config.builds) {
    throw new Error('Builds mode requires a "builds" object with install, build, start, and readyPath.');
  }
  if (config.mode === 'previews' && config.builds) {
    throw new Error('Config field "builds" is only valid in builds mode.');
  }
  return config;
}

export function validateBaseUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`Invalid URL: ${value}`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Preview URLs must use HTTP(S) and must not include credentials.');
  }
  return url.toString().replace(/\/$/, '');
}
