declare module '@scabase/data' {
  export interface ManifestFile {
    path: string;
    sha256: string;
    size: number;
  }

  export interface ManifestDataset extends ManifestFile {
    entries: number | null;
    vuln_count?: number;
    cve_count?: number;
    usable_entries?: number;
    grade_counts?: Record<string, number>;
    generated_at?: string | null;
    component_count?: number | null;
  }

  export interface Manifest {
    schema: string;
    version: string;
    generated_at: string;
    source: Record<string, unknown>;
    content_digest: string;
    file_count: number;
    total_size: number;
    files: ManifestFile[];
    datasets: Record<'vulns' | 'health' | 'community', ManifestDataset>;
    facts: Record<string, unknown>;
    signature?: { algo: string; keyid: string; value: string };
  }

  export interface CveHit {
    component: string;
    osvId: string | null;
    aliases: string[];
    cves: string[];
    severity: string | null;
    published: string | null;
    modified: string | null;
    source: string;
  }

  export interface VerifyResult {
    ok: boolean;
    checked: number;
    failures: Array<{ path: string; reason: string }>;
  }

  export function root(): string;
  export function manifest(): Manifest;
  export function version(): string;
  export function contentDigest(): string;
  export function datasetPath(name: string): string | null;
  export function read(name: string): unknown | null;
  export function vulns(): Record<string, unknown> | null;
  export function health(): Record<string, unknown> | null;
  export function community(): unknown | null;
  export function factsDir(): string | null;
  export function findByCve(cveId: string): CveHit[];
  export function componentsByGrade(grade: string): unknown[];
  export function verify(): VerifyResult;
}
