import { runHttpCheck } from './http.js';
import { runStaticChecks } from './static.js';
import { buildSecurityReport, type SecurityReport } from './report.js';
import type { SecurityCheck } from './types.js';

export async function runSecurityReview(root: string, url?: string): Promise<SecurityReport> {
  let staticChecks: SecurityCheck[];
  try {
    staticChecks = await runStaticChecks(root);
  } catch {
    staticChecks = (['secrets', 'dependencies', 'code'] as const).map(name => ({
      name, status: 'incomplete' as const, findings: [], error: 'Scanner could not complete.',
    }));
  }
  let httpCheck: SecurityCheck;
  if (!url) {
    httpCheck = { name: 'http', status: 'skipped', findings: [] };
  } else {
    try {
      httpCheck = await runHttpCheck(url);
    } catch {
      httpCheck = { name: 'http', status: 'incomplete', findings: [], error: 'HTTP check could not complete.' };
    }
  }
  return buildSecurityReport([...staticChecks, httpCheck]);
}
