import type { FindingDetail, Overview, RunSummary } from "../api/types";

export const run: RunSummary = {
  id: "101", repository: "o/r", base_branch: "SV", fix_branch: "SV-fix", commit: "abc1234def",
  trigger: "push", mode: "fix", url: "https://github.com/o/r/actions/runs/101",
  started_at: "2026-10-06T10:00:00+00:00", finished_at: "2026-10-06T10:07:00+00:00", duration_s: 420,
  scanned: 6, confirmed: 6, fixed: 2, review: 0, rejected: 0, residual: 2, blocking: 6, gate_passed: false,
  status: "Fix PR open", pr_number: 7, pr_url: "https://github.com/o/r/pull/7", fix_branch_state: "failure",
};

export const overview: Overview = {
  window_days: 7,
  kpis: { open_findings: 6, open_findings_prev: 2, critical: 1, high: 2, critical_prev: 0, high_prev: 1,
          autofix_success: 0.3333, autofix_success_prev: null, fixed: 2, fixed_prev: 0,
          avg_run_seconds: 420, blocked_branches: 1, runs: 3 },
  posture: [{ severity: "Critical", count: 1, prev: 0 }, { severity: "High", count: 2, prev: 1 },
            { severity: "Medium", count: 3, prev: 1 }, { severity: "Low", count: 0, prev: 0 }],
  activity: [{ finding_id: 5, at: "2026-10-06T10:07:00+00:00", title: "Open Redirect", status: "Fixed",
               where: "app.py:117", pr_number: 7, repository: "o/r" }],
  repositories: [{ repository: "o/r", open_findings: 6, critical: 1, branches: 2, last_scan: "2026-10-06T10:00:00+00:00", status: "Blocked" }],
  recent_runs: [run],
};

export const finding: FindingDetail = {
  id: 5, run_id: "101", fingerprint: "abc", severity: "High", title: "Open Redirect", cwe: "CWE-601",
  rule_id: "python.flask.security.open-redirect.open-redirect", repository: "o/r", branch: "SV",
  file: "app.py", line: 117, verdict: "True positive", route: "fix", confidence: 0.89, fix_status: "Fixed",
  cvss: null, risk: 4.5, advisory_url: null,
  outcome: "fixed and validated", detected_at: "2026-10-06T10:00:00+00:00",
  message: "Untrusted redirect target", owasp: ["A01:2021"], end_line: 117, snippet: "return redirect(next)",
  code: [{ n: 116, text: "    abort(401)", flagged: false }, { n: 117, text: "    return redirect(next)", flagged: true }],
  commit: "abc1234def", run_url: null, pr_number: 7, pr_url: null,
  first_detected: "2026-10-05T10:00:00+00:00", last_detected: "2026-10-06T10:00:00+00:00", times_detected: 2,
  investigation: {
    llm_label: "tp", laya_score: 0.89, rounds: 1, max_rounds: 3,
    initial: "The next parameter flows to redirect.\nVERDICT: TRUE POSITIVE — attacker controls the target",
    questions: [{ key: "sanitization", question: "Is the input validated?", answer: "No validation.\nVERDICT: nothing restricts the host" }],
  },
  fix: { validated: true, scanner_clean: true, attempts: 1, failure: null, note: null,
         diff: "--- a/app.py\n+++ b/app.py\n@@ -117 +117,3 @@\n-    return redirect(next)\n+    if urlparse(next).netloc: abort(403)\n+    return redirect(next)\n",
         created_files: [], check_output: "9 passed", last_proposal: null },
  provenance: { triage_model: "qwen3.5:35b-a3b", generation: { temperature: 0.2, seed: 42 }, tool_version: "abc123" },
};
