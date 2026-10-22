export type SecurityFinding = {
  id: string;
  category: 'secrets' | 'dependencies' | 'code' | 'http';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'review';
  title: string;
  location?: { path?: string; line?: number; url?: string };
  guidance: string;
  asvs?: string;
  reference?: string;
  gate?: boolean;
};

export type SecurityCheck = {
  name: SecurityFinding['category'];
  status: 'complete' | 'incomplete' | 'skipped';
  findings: SecurityFinding[];
  error?: string;
};
