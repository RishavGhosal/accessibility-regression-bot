export type Classification = 'new' | 'existing' | 'resolved' | 'uncertain';
export type Revision = 'base' | 'head';

export interface Viewport { width: number; height: number }
export interface Finding {
  classification: Classification;
  ruleId: string;
  impact: string | null;
  page: string;
  target: string;
  description: string;
  helpUrl: string | null;
  html?: string;
  screenshot?: string;
  rationale: string;
}
export interface ScanFailure { revision: Revision; page: string; message: string }
export interface Report {
  schemaVersion: 1;
  status: 'complete' | 'incomplete';
  summary: { new: number; existing: number; resolved: number; uncertain: number };
  findings: Finding[];
  failures: ScanFailure[];
  meta: {
    baseRef: string;
    headRef: string;
    viewport: Viewport;
    tool: { name: string; version: string; axeVersion: string };
  };
}

export interface RawFinding {
  ruleId: string;
  impact: string | null;
  page: string;
  target: string;
  description: string;
  helpUrl: string | null;
  html?: string;
  context: string;
}
