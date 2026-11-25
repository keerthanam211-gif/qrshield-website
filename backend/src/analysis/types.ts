export type Verdict = "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "UNVERIFIED";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** One reason that contributed to (or explains) a verdict. */
export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** Points added to the 0-100 risk score. Info findings use 0. */
  weight: number;
}

/** Result of asking one threat-intelligence source about the URLs. */
export interface SourceCheck {
  source: string;
  status: "clean" | "match" | "error" | "not_configured";
  detail: string;
  matches?: { url: string; threat: string }[];
}

export interface AnalysisResult {
  contentType: string;
  target: string | null;
  finalUrl: string | null;
  verdict: Verdict;
  riskScore: number;
  summary: string;
  reasons: Finding[];
  details: Record<string, unknown>;
}

/** Score at or above which a result is SUSPICIOUS (when no intel source confirmed it malicious). */
export const SUSPICIOUS_THRESHOLD = 30;

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.weight - a.weight);
}

/** De-duplicate by id, keeping the heaviest instance. */
export function dedupeFindings(list: Finding[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const f of list) {
    const prev = map.get(f.id);
    if (!prev || f.weight > prev.weight) map.set(f.id, f);
  }
  return sortFindings([...map.values()]);
}

export function scoreOf(findings: Finding[]): number {
  return Math.max(0, Math.min(100, findings.reduce((s, f) => s + f.weight, 0)));
}

/**
 * Turns findings into a verdict. There is no default SAFE:
 *  - DANGEROUS  only when a threat-intel source matched, or content is inherently malicious (e.g. javascript: payload)
 *  - SUSPICIOUS when heuristic risk >= threshold
 *  - SAFE       only when verification actually succeeded and risk is low
 *  - UNVERIFIED otherwise (sources unreachable, backend failure, unsupported content)
 */
export function decideVerdict(opts: {
  findings: Finding[];
  confirmedMalicious: boolean;
  verified: boolean;
}): { verdict: Verdict; riskScore: number } {
  const score = scoreOf(opts.findings);
  if (opts.confirmedMalicious) return { verdict: "DANGEROUS", riskScore: Math.max(score, 90) };
  if (score >= SUSPICIOUS_THRESHOLD) return { verdict: "SUSPICIOUS", riskScore: score };
  if (opts.verified) return { verdict: "SAFE", riskScore: score };
  return { verdict: "UNVERIFIED", riskScore: score };
}

export function finding(id: string, severity: Severity, weight: number, title: string, detail: string): Finding {
  return { id, severity, weight, title, detail };
}
