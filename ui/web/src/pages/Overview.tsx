import { Link } from "react-router-dom";
import { qs } from "../api/client";
import type { Overview as OverviewData, RunSummary } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { AiTag, Async, B, Bar, Card, DataTable, Empty, FixStatusPill, Kpis, M, N, PageHead, Pill, RunStatusPill } from "../components/ui";
import { carry, useFilters } from "../lib/filters";
import { ago, delta, duration, pct } from "../lib/format";

const LIFECYCLE = ["Push", "Scan", "Triage (LLM)", "Laya decision", "Autofix", "Validate", "Fix PR", "Human review", "Merge gate", "Merge"];
const SEV_TONE = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" } as const;

export function Overview() {
  const { repo, days, search } = useFilters();
  const state = useApi<OverviewData>(`/overview${qs({ repository: repo, days })}`, 60000);
  const link = carry(search);

  return (
    <Shell crumb="Overview">
      <PageHead title="SAST Autofix" large sub="Local AI-powered security remediation"
        actions={<Link className="btn" to={`/runs${link}`}>All runs</Link>} />
      <div className="card" style={{ padding: "14px 16px" }}>
        <div className="lifecycle" aria-label="Remediation lifecycle">
          {LIFECYCLE.map((t, i) => (
            <span key={t} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span className={`step ${t === "Autofix" ? "on" : ""}`}><span className="n">{String(i + 1).padStart(2, "0")}</span>{t}</span>
              {i < LIFECYCLE.length - 1 && <span className="mute" aria-hidden="true">→</span>}
            </span>
          ))}
        </div>
      </div>
      <Async state={state}>
        {(d) => {
          const k = d.kpis;
          const maxSev = Math.max(1, ...d.posture.map((p) => p.count));
          const open = delta(k.open_findings, k.open_findings_prev);
          const crit = delta(k.critical + k.high, k.critical_prev + k.high_prev);
          const fixed = delta(k.fixed, k.fixed_prev, false);
          return (
            <>
              <Kpis items={[
                { label: "Open findings", value: k.open_findings, detail: open.text, tone: open.tone },
                { label: "Critical / High", value: `${k.critical} / ${k.high}`, detail: crit.text, tone: crit.tone },
                { label: "Autofix success", value: pct(k.autofix_success),
                  detail: k.autofix_success_prev !== null ? `${pct(k.autofix_success_prev)} previous period` : "no previous data" },
                { label: `Fixed (${d.window_days}d)`, value: k.fixed, detail: fixed.text, tone: fixed.tone },
                { label: "Avg run time", value: duration(k.avg_run_seconds), detail: `${k.runs} run(s) in window` },
                { label: "Blocked branches", value: k.blocked_branches, valueTone: k.blocked_branches ? "red" : undefined,
                  detail: "merge gate red" },
              ]} />
              <div className="grid-2">
                <Card title="Security posture" aside={<small>open now vs start of window</small>}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                    {d.posture.map((p) => {
                      const dd = delta(p.count, p.prev);
                      return (
                        <div className="posture-row" key={p.severity}>
                          <span style={{ fontWeight: 500 }}>{p.severity}</span>
                          <Bar value={p.count} max={maxSev} tone={SEV_TONE[p.severity]} />
                          <span className="mono" style={{ textAlign: "right", fontSize: 15 }}>{p.count}</span>
                          <span className={`mono ${dd.tone}`} style={{ fontSize: 12 }}>{dd.text.replace(" vs previous", "")}</span>
                        </div>
                      );
                    })}
                  </div>
                </Card>
                <Card title="Autofix activity" aside={<AiTag />}>
                  {d.activity.length === 0 ? <Empty>No autofix activity in this window.</Empty> : (
                    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                      {d.activity.map((a) => (
                        <Link key={`${a.finding_id}`} to={`/findings/${a.finding_id}${link}`} style={{ color: "inherit", display: "grid", gridTemplateColumns: "64px 1fr", gap: 12 }}>
                          <span className="mono mute" style={{ fontSize: 12 }}>{ago(a.at)}</span>
                          <div>
                            <div style={{ fontWeight: 500, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>{a.title}<FixStatusPill status={a.status} /></div>
                            <div className="mono mute" style={{ fontSize: 12, marginTop: 3 }}>{a.where}{a.pr_number ? ` · PR #${a.pr_number}` : ""}</div>
                          </div>
                        </Link>
                      ))}
                    </div>
                  )}
                </Card>
              </div>
              <Card title="Repository health" flush>
                <DataTable rowKey={(r) => r.repository} rows={d.repositories}
                  to={(r) => `/runs?repo=${encodeURIComponent(r.repository)}&days=${days}`}
                  empty={<Empty>No repositories scanned yet. Push a branch to start the first scan.</Empty>}
                  columns={[
                    { header: "Repository", width: "1.6fr", cell: (r) => <B>{r.repository}</B> },
                    { header: "Open findings", width: ".8fr", cell: (r) => <N>{r.open_findings}</N> },
                    { header: "Critical", width: ".7fr", cell: (r) => <N tone={r.critical ? "red" : undefined}>{r.critical}</N> },
                    { header: "Branches", width: ".7fr", cell: (r) => <N>{r.branches}</N> },
                    { header: "Last scan", width: ".9fr", cell: (r) => <M>{ago(r.last_scan)}</M> },
                    { header: "Status", width: "1fr", cell: (r) => <Pill tone={r.status === "Healthy" ? "green" : "red"}>{r.status}</Pill> },
                  ]} />
              </Card>
              <Card title="Recent runs" flush>
                <RunsTable runs={d.recent_runs} link={link} />
              </Card>
            </>
          );
        }}
      </Async>
    </Shell>
  );
}

export function RunsTable({ runs, link }: { runs: RunSummary[]; link: string }) {
  return (
    <DataTable rowKey={(r) => r.id} rows={runs} to={(r) => `/runs/${encodeURIComponent(r.id)}${link}`}
      empty={<Empty>No runs yet. Runs appear here after the CI workflow scans a branch.</Empty>}
      columns={[
        { header: "Run", width: ".9fr", cell: (r) => <M>{r.id}</M> },
        { header: "Repository", width: "1.4fr", cell: (r) => <B>{r.repository}</B> },
        { header: "Branch", width: ".9fr", cell: (r) => <M>{r.base_branch}</M> },
        { header: "Findings", width: ".7fr", cell: (r) => <N>{r.scanned}</N> },
        { header: "Fixed", width: ".6fr", cell: (r) => <N tone="green">{r.fixed}</N> },
        { header: "Review", width: ".6fr", cell: (r) => <N tone="amber">{r.review}</N> },
        { header: "Rejected", width: ".7fr", cell: (r) => <N tone="red">{r.rejected}</N> },
        { header: "Duration", width: ".8fr", cell: (r) => <M>{duration(r.duration_s)}</M> },
        { header: "Status", width: "1fr", cell: (r) => <RunStatusPill status={r.status} /> },
      ]} />
  );
}
