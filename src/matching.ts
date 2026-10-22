import type { Finding, RawFinding, ScanFailure } from './types.js';

function key(f: RawFinding): string {
  return JSON.stringify([f.ruleId, f.page, f.target, f.context]);
}

/** Match reports conservatively: exact target plus role/name context is required. */
export function matchFindings(base: RawFinding[], head: RawFinding[], failures: ScanFailure[] = []): Finding[] {
  const baseMap = new Map<string, RawFinding[]>();
  const headMap = new Map<string, RawFinding[]>();
  for (const f of base) baseMap.set(key(f), [...(baseMap.get(key(f)) ?? []), f]);
  for (const f of head) headMap.set(key(f), [...(headMap.get(key(f)) ?? []), f]);
  const keys = new Set([...baseMap.keys(), ...headMap.keys()]);
  const failedPages = new Set(failures.filter(f => !f.message.startsWith('Could not capture screenshot')).map(f => f.page));
  const results: Finding[] = [];
  const targetKey = (f: RawFinding) => JSON.stringify([f.ruleId, f.page, f.target]);
  const baseByTarget = new Map<string, RawFinding[]>();
  const headByTarget = new Map<string, RawFinding[]>();
  for (const f of base) baseByTarget.set(targetKey(f), [...(baseByTarget.get(targetKey(f)) ?? []), f]);
  for (const f of head) headByTarget.set(targetKey(f), [...(headByTarget.get(targetKey(f)) ?? []), f]);
  for (const k of keys) {
    const bs = baseMap.get(k) ?? [];
    const hs = headMap.get(k) ?? [];
    const representative = hs[0] ?? bs[0];
    if (!representative) continue;
    const relatedBase = baseByTarget.get(targetKey(representative)) ?? [];
    const relatedHead = headByTarget.get(targetKey(representative)) ?? [];
    const contextChanged = (bs.length > 0 && hs.length === 0 && relatedHead.length > 0) || (hs.length > 0 && bs.length === 0 && relatedBase.length > 0);
    const failed = failedPages.has(representative.page) && (bs.length === 0 || hs.length === 0);
    const uncertain = (failed || contextChanged) && (bs.length !== hs.length || bs.length === 0 || hs.length === 0);
    const classification = uncertain ? 'uncertain' : bs.length && hs.length ? 'existing' : hs.length ? 'new' : 'resolved';
    const rationale = uncertain
      ? failed ? 'A scan failed for this page, so the missing side may be incomplete; change status cannot be determined.'
        : 'The rule and target occur on both sides, but role or accessible-name context changed; exact matching is uncertain.'
      : bs.length && hs.length ? 'The same rule, page, target, role, and accessible-name context appears in both revisions.'
        : hs.length ? 'This finding appears in the head revision and has no exact contextual match in the base revision.'
          : 'This finding appears in the base revision and has no exact contextual match in the head revision.';
    for (const f of (hs.length ? hs : bs)) {
      results.push({
        classification, ruleId: f.ruleId, impact: f.impact, page: f.page, target: f.target,
        description: f.description, helpUrl: f.helpUrl, ...(f.html ? { html: f.html } : {}), rationale,
      });
    }
  }
  const rank = { new: 0, uncertain: 1, existing: 2, resolved: 3 } as const;
  return results.sort((a, b) => rank[a.classification] - rank[b.classification] || a.page.localeCompare(b.page) || a.ruleId.localeCompare(b.ruleId) || a.target.localeCompare(b.target) || a.description.localeCompare(b.description));
}

export function findingContext(role?: string | null, accessibleName?: string | null): string {
  return JSON.stringify([role?.trim().toLowerCase() ?? '', accessibleName?.trim().replace(/\s+/g, ' ') ?? '']);
}
