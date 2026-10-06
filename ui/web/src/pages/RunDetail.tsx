import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import type { Provenance, RunDetail as RunDetailData } from "../api/types";
import { useApi } from "../api/useApi";
import { DiffView } from "../components/code";
import { Shell } from "../components/Shell";
import { AiTag, Async, B, Card, DataTable, Empty, FixStatusPill, M, N, PageHead, Pill, RunStatusPill, SeverityPill } from "../components/ui";
import { carry, useFilters } from "../lib/filters";
import { dateTime, duration, pct, shortSha } from "../lib/format";

export const CHECKS = [
  "Semgrep rescan clean",
  "No new findings introduced",
  "No new undefined names or syntax errors (pyflakes)",
  "Project test suite passes",
  "AI security review approved",
];

export function ProvenanceList({ p, runId, commit }: { p: Provenance; runId?: string; commit?: string | null }) {
  const g = p.generation ?? {};
  const rows: [string, string | undefined][] = [
    ["Triage model", p.triage_model],
    ["Fix models", p.fix_models?.join(", ")],
    ["Laya", [p.laya_model, p.laya_version && `v${p.laya_version}`].filter(Boolean).join(" ")],
    ["Temperature / seed", g.temperature !== undefined ? `${g.temperature} / ${g.seed ?? "—"}` : undefined],
    ["Thresholds (fix / review)", p.thresholds ? `${p.thresholds.fix} / ${p.thresholds.review}` : undefined],
    ["Triage rounds / fix retries", p.triage_max_rounds !== undefined ? `${p.triage_max_rounds} / ${p.max_fix_retries ?? "—"}` : undefined],
    ["Semgrep", p.semgrep_version ? `v${p.semgrep_version}` : undefined],
    ["Rule packs", p.rulesets?.join(", ")],
    ["Tool version", p.tool_version],
    ["Run ID", runId],
    ["Commit", commit ? shortSha(commit) : undefined],
  ];
  return (
    <div className="kv-list">
      {rows.filter(([, v]) => v).map(([k, v]) => <div key={k}><span className="mute">{k}</span><span>{v}</span></div>)}
    </div>
  );
}

export function RunDetail() {
  const { id = "" } = useParams();
  const { search } = useFilters();
  const link = carry(search);
  const state = useApi<RunDetailData>(`/runs/${encodeURIComponent(id)}`);
  const [stage, setStage] = useState(0);

  return (
    <Shell crumb={<><Link to={`/runs${link}`}>Autofix Runs</Link> / {id}</>}>
      <Async state={state}>
        {(r) => {
          const current = r.stages[Math.min(stage, r.stages.length - 1)];
          const added = r.patches.reduce((n, p) => n + (p.diff?.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++")).length ?? 0), 0);
          const removed = r.patches.reduce((n, p) => n + (p.diff?.split("\n").filter((l) => l.startsWith("-") && !l.startsWith("---")).length ?? 0), 0);
          return (
            <>
              <PageHead large subMono
                title={<><span className="mono">Run {r.id}</span><RunStatusPill status={r.status} /></>}
                sub={`${r.repository} · branch ${r.base_branch} · commit ${shortSha(r.commit)} · ${dateTime(r.started_at)} · ${r.trigger ?? "—"}`}
                actions={<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {r.url && <a className="btn" href={r.url} target="_blank" rel="noreferrer">CI log ↗</a>}
                  {r.pr_number && <Link className="btn primary" to={`/pulls/${r.repository}/${r.pr_number}${link}`}>Pull request #{r.pr_number}</Link>}
                </div>} />
              <Card title="Pipeline" aside={<small>select a stage</small>}>
                {r.stages.length === 0 ? <Empty>No stage timings recorded.</Empty> : (
                  <>
                    <div className="stages">
                      {r.stages.map((s, i) => (
                        <button key={s.key} className={`stage ${i === stage ? "on" : ""}`} onClick={() => setStage(i)} aria-pressed={i === stage}>
                          <span className="i">{String(i + 1).padStart(2, "0")}</span>
                          <span style={{ fontWeight: 600 }}>{s.name}</span>
                          <span className="dur">{duration(s.seconds)}</span>
                        </button>
                      ))}
                    </div>
                    {current && <div className="stage-info"><b>{current.name}.</b> {current.text}</div>}
                  </>
                )}
              </Card>
              <Card title="Proposed patches" aside={<AiTag />}>
                {r.patches.length === 0 ? <Empty>No fix was validated in this run.</Empty> : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
                    {r.patches.map((p) => (
                      <div key={p.finding_id} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <Link to={`/findings/${p.finding_id}${link}`} style={{ fontWeight: 600 }}>{p.title}</Link>
                          <span className="mono mute">{p.cwe} · {p.file}:{p.line} · {p.attempts} attempt(s)</span>
                          {p.created_files.length > 0 && <Pill tone="blue">creates {p.created_files.join(", ")}</Pill>}
                        </div>
                        {p.note && <div className="pill tone-amber" style={{ whiteSpace: "normal" }}>⚠ {p.note}</div>}
                        {p.diff ? <DiffView diff={p.diff} /> : <Empty>Diff not recorded.</Empty>}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
              <div className="grid-2">
                <Card title="Validation" aside={r.fix_branch_state && <Pill tone={r.fix_branch_state === "success" ? "green" : "red"}>fix branch {r.fix_branch_state}</Pill>}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {CHECKS.map((c) => <div key={c} style={{ display: "flex", gap: 10 }}><span style={{ color: "var(--green)", fontWeight: 600 }}>✓</span>{c}</div>)}
                  </div>
                  <div className="mute" style={{ marginTop: 12, fontSize: 12, lineHeight: 1.5 }}>
                    Every accepted patch passed all five checks.
                    {r.fix_branch_description && <><br />Fix-branch rescan: {r.fix_branch_description}</>}
                  </div>
                  <div style={{ marginTop: 18, borderTop: "1px solid var(--line)", paddingTop: 14, display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8 }}>
                    <div><div className="mono" style={{ fontSize: 20 }}>{r.patches.length}</div><div className="mute" style={{ fontSize: 11 }}>Patches</div></div>
                    <div><div className="mono" style={{ fontSize: 20, color: "var(--green)" }}>+{added}</div><div className="mute" style={{ fontSize: 11 }}>Lines added</div></div>
                    <div><div className="mono" style={{ fontSize: 20, color: "var(--red)" }}>−{removed}</div><div className="mute" style={{ fontSize: 11 }}>Lines removed</div></div>
                  </div>
                </Card>
                <Card title="Provenance"><ProvenanceList p={r.provenance} runId={r.id} commit={r.commit} /></Card>
              </div>
              <Card title={`Findings (${r.findings.length})`} flush>
                <DataTable rowKey={(f) => f.id} rows={r.findings} to={(f) => `/findings/${f.id}${link}`}
                  columns={[
                    { header: "Severity", width: ".8fr", cell: (f) => <SeverityPill severity={f.severity} /> },
                    { header: "Finding", width: "1.4fr", cell: (f) => <B>{f.title}</B> },
                    { header: "Location", width: "1.4fr", cell: (f) => <M>{f.file}:{f.line}</M> },
                    { header: "Verdict", width: "1fr", cell: (f) => f.verdict },
                    { header: "Laya", width: ".6fr", cell: (f) => <N>{pct(f.confidence, 0)}</N> },
                    { header: "Outcome", width: "1fr", cell: (f) => <FixStatusPill status={f.fix_status} /> },
                  ]} />
              </Card>
            </>
          );
        }}
      </Async>
    </Shell>
  );
}
