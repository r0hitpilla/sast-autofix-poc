import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { qs } from "../api/client";
import type { FindingSummary, Paged } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, B, Card, DataTable, Empty, FixStatusPill, M, N, PageHead, SeverityPill } from "../components/ui";
import { carry, useFilters } from "../lib/filters";
import { dateTime, pct } from "../lib/format";

const SEVERITIES = ["Critical", "High", "Medium", "Low"];
const ROUTES = [["fix", "True positive"], ["review", "Uncertain"], ["reject", "False positive"]];

export function Findings() {
  const { repo, days, q, search } = useFilters();
  const [params, setParams] = useSearchParams();
  const view = params.get("view") === "all" ? "all" : "open";
  const severity = params.get("severity") ?? "";
  const route = params.get("route") ?? "";
  const state = useApi<Paged<FindingSummary>>(`/findings${qs({
    state: view, repository: repo, severity, route, days: view === "all" ? days : undefined, limit: 500,
  })}`, 60000);
  const setParam = (k: string, v: string) => setParams((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); return n; }, { replace: true });

  const filter = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (f: FindingSummary) => !needle || [f.title, f.cwe, f.file, f.rule_id, f.repository, f.branch]
      .some((s) => s.toLowerCase().includes(needle));
  }, [q]);

  return (
    <Shell crumb="Findings">
      <PageHead title="Findings" sub="Found by Semgrep, investigated by the LLM, decided by Laya" />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }} role="group" aria-label="Filters">
        <select className="select" aria-label="Scope" value={view} onChange={(e) => setParam("view", e.target.value === "all" ? "all" : "")}>
          <option value="open">Open (latest run per branch)</option>
          <option value="all">All occurrences in window</option>
        </select>
        <select className="select" aria-label="Severity" value={severity} onChange={(e) => setParam("severity", e.target.value)}>
          <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="select" aria-label="AI verdict" value={route} onChange={(e) => setParam("route", e.target.value)}>
          <option value="">All verdicts</option>{ROUTES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        {q && <button className="btn sm" onClick={() => setParam("q", "")}>Search: “{q}” ✕</button>}
      </div>
      <Async state={state}>
        {(d) => {
          const rows = d.items.filter(filter);
          return (
            <Card flush>
              <div style={{ paddingTop: 4 }} />
              <DataTable rowKey={(f) => f.id} rows={rows} to={(f) => `/findings/${f.id}${carry(search)}`}
                empty={<Empty>{view === "open" ? "No open findings. Every scanned branch is clean." : "No findings match these filters."}</Empty>}
                columns={[
                  { header: "Severity", width: ".8fr", cell: (f) => <SeverityPill severity={f.severity} /> },
                  { header: "Finding", width: "1.3fr", cell: (f) => <B>{f.title}</B> },
                  { header: "Repository", width: "1.1fr", cell: (f) => <span>{f.repository}</span> },
                  { header: "Branch", width: ".7fr", cell: (f) => <M>{f.branch}</M> },
                  { header: "File", width: "1.4fr", cell: (f) => <M>{f.file}</M> },
                  { header: "Line", width: ".5fr", cell: (f) => <M>{f.line}</M> },
                  { header: "AI verdict", width: "1fr", cell: (f) => f.verdict },
                  { header: "Confidence", width: ".8fr", cell: (f) => <N>{pct(f.confidence, 0)}</N> },
                  { header: "Seen", width: "1fr", cell: (f) => f.occurrences == null ? "—" :
                      <span title={`first ${dateTime(f.first_seen)} · last ${dateTime(f.last_seen)}`}>
                        <N>{f.occurrences}×</N> <span className="mute">{dateTime(f.last_seen)}</span></span> },
                  { header: "Risk", width: ".5fr", cell: (f) => <N>{f.risk == null ? "—" : f.risk.toFixed(1)}</N> },
                  { header: "CVSS", width: ".5fr", cell: (f) => <N>{f.cvss == null ? "—" : f.cvss.toFixed(1)}</N> },
                  { header: "Fix status", width: "1fr", cell: (f) => <FixStatusPill status={f.fix_status} /> },
                ]} />
              <div className="table-foot"><span>Showing {rows.length} of {d.total}</span></div>
            </Card>
          );
        }}
      </Async>
    </Shell>
  );
}
