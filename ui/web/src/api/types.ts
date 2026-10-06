// Mirrors dashboard/queries.py and dashboard/api.py responses.
export type Severity = "Critical" | "High" | "Medium" | "Low";
export type Route = "fix" | "review" | "reject";
export type RunStatus = "Passed" | "Fix PR open" | "Blocked" | "Checked";

export interface RunSummary {
  id: string; repository: string; base_branch: string; fix_branch: string | null;
  commit: string | null; trigger: string | null; mode: string; url: string | null;
  started_at: string | null; finished_at: string | null; duration_s: number | null;
  scanned: number; confirmed: number; fixed: number; review: number; rejected: number;
  residual: number; blocking: number; gate_passed: boolean | null; status: RunStatus;
  pr_number: number | null; pr_url: string | null; fix_branch_state: string | null;
}
export interface Paged<T> { total: number; items: T[] }

export interface FindingSummary {
  id: number; run_id: string; fingerprint: string; severity: Severity; title: string; cwe: string;
  rule_id: string; repository: string; branch: string; file: string; line: number;
  verdict: string; route: Route; confidence: number; fix_status: string; outcome: string;
  detected_at: string | null;
}

export interface Provenance {
  tool_version?: string; triage_model?: string; fix_models?: string[]; laya_model?: string;
  laya_version?: string | null; semgrep_version?: string | null;
  generation?: { temperature?: number; seed?: number; num_predict?: number; repeat_penalty?: number };
  thresholds?: { fix: number; review: number }; triage_max_rounds?: number;
  max_fix_retries?: number; fix_review?: boolean; rulesets?: string[];
}

export interface FixRecord {
  validated: boolean; scanner_clean: boolean; attempts: number; failure: string | null;
  note: string | null; diff: string | null; created_files: string[];
  check_output: string | null; last_proposal: string | null;
}

export interface FindingDetail extends FindingSummary {
  message: string; owasp: string[]; end_line: number | null; snippet: string;
  code: { n: number; text: string; flagged: boolean }[];
  commit: string | null; run_url: string | null; pr_number: number | null; pr_url: string | null;
  first_detected: string | null; last_detected: string | null; times_detected: number;
  investigation: {
    llm_label: "tp" | "fp" | null; laya_score: number; rounds: number; max_rounds: number | null;
    initial: string | null; questions: { key: string | null; question: string; answer: string }[];
  };
  fix: FixRecord | null; provenance: Provenance;
}

export interface Stage { key: string; name: string; seconds: number | null; text: string }
export interface Patch {
  finding_id: number; title: string; cwe: string; file: string; line: number;
  diff: string | null; attempts: number | null; created_files: string[]; note: string | null;
}
export interface RunDetail extends RunSummary {
  stages: Stage[]; provenance: Provenance; fix_branch_description: string | null;
  patches: Patch[]; findings: FindingSummary[];
}

export interface Overview {
  window_days: number;
  kpis: {
    open_findings: number; open_findings_prev: number; critical: number; high: number;
    critical_prev: number; high_prev: number; autofix_success: number | null;
    autofix_success_prev: number | null; fixed: number; fixed_prev: number;
    avg_run_seconds: number | null; blocked_branches: number; runs: number;
  };
  posture: { severity: Severity; count: number; prev: number }[];
  activity: { finding_id: number; at: string | null; title: string; status: string; where: string;
              pr_number: number | null; repository: string }[];
  repositories: { repository: string; open_findings: number; critical: number; branches: number;
                  last_scan: string | null; status: "Healthy" | "Blocked" }[];
  recent_runs: RunSummary[];
}

export interface PrSummary {
  number: number; url: string | null; repository: string; head: string | null; base: string;
  run_id: string; findings: number; fixes: number; validation: string | null;
  gate_passed: boolean | null; updated_at: string | null;
}
export interface PrLive {
  available: boolean; error?: string; state?: string; title?: string; author?: string;
  reviewers?: string[]; additions?: number; deletions?: number; changed_files?: number;
  checks?: { context: string; state: string; description: string | null }[];
}
export interface PrDetail {
  number: number; url: string | null; repository: string; head: string | null; base: string;
  run: RunSummary;
  summary: { scanned: number; confirmed: number; fixed: number; review: number; rejected: number };
  validation: { state: string | null; description: string | null };
  gate: { passed: boolean | null; blocking: number | null; run_id: string | null };
  findings: FindingSummary[]; live: PrLive;
}

export interface ModelsInfo {
  ollama: { online: boolean; error?: string; version?: string; api_latency_ms?: number;
            models: { name: string; parameter_size: string | null; quantization: string | null;
                      family: string | null; size_bytes: number | null; loaded: boolean }[] };
  provenance: Provenance | null;
}

export interface Health {
  cpu_percent: number; memory_percent: number; memory_total_gb: number; disk_percent: number;
  load_avg: number[];
  gpus: { name: string; utilization: number | null; memory_used_mb: number | null;
          memory_total_mb: number | null; temperature_c: number | null }[];
  services: Record<string, { ok: boolean; unit?: string | null }>;
  runs_24h: number; blocked_24h: number;
}

export interface Bar { label: string; value: number }
export interface Report {
  window_days: number;
  kpis: { runs: number; findings: number; autofix_success: number | null;
          false_positive_rate: number | null; fix_attempt_failure_rate: number | null;
          avg_run_seconds: number | null; blocked_runs: number };
  charts: { by_cwe: Bar[]; by_repository: Bar[]; confidence: Bar[]; by_severity: Bar[] };
}

export interface Meta { version: string; repositories: string[] }
