import { Link, useParams } from "react-router-dom";
import { qs } from "../api/client";
import type { PrDetail, PrSummary } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, B, Card, DataTable, Empty, FixStatusPill, GatePill, Kpis, M, N, PageHead, Pill, SeverityPill } from "../components/ui";
import { carry, useFilters } from "../lib/filters";
import { ago, pct } from "../lib/format";

const validationPill = (state: string | null) =>
  state === "success" ? <Pill tone="green">Clean</Pill> : state === "failure" ? <Pill tone="red">Findings remain</Pill> : <Pill tone="grey">—</Pill>;

export function PullRequests() {
  const { repo, search } = useFilters();
  const state = useApi<{ items: PrSummary[] }>(`/prs${qs({ repository: repo })}`, 60000);
  return (
    <Shell crumb="Pull Requests">
      <PageHead title="Pull Requests" sub="Fix PRs opened by the pipeline (head: <branch>-fix → base: <branch>), with merge-gate status" />
      <Async state={state}>
        {(d) => (
          <Card flush>
            <div style={{ paddingTop: 4 }} />
            <DataTable rowKey={(p) => `${p.repository}#${p.number}`} rows={d.items}
              to={(p) => `/pulls/${p.repository}/${p.number}${carry(search)}`}
              empty={<Empty>No fix pull requests yet.</Empty>}
              columns={[
                { header: "PR", width: ".6fr", cell: (p) => <B>#{p.number}</B> },
                { header: "Repository", width: "1.3fr", cell: (p) => p.repository },
                { header: "Head → base", width: "1.3fr", cell: (p) => <M>{p.head} → {p.base}</M> },
                { header: "Findings", width: ".7fr", cell: (p) => <N>{p.findings}</N> },
                { header: "Fixes", width: ".6fr", cell: (p) => <N tone="green">{p.fixes}</N> },
                { header: "Fix-branch rescan", width: "1fr", cell: (p) => validationPill(p.validation) },
                { header: "Base gate", width: "1fr", cell: (p) => <GatePill passed={p.gate_passed} /> },
                { header: "Updated", width: ".8fr", cell: (p) => <M>{ago(p.updated_at)}</M> },
              ]} />
          </Card>
        )}
      </Async>
    </Shell>
  );
}

export function PullRequestDetail() {
  const { owner = "", name = "", number = "" } = useParams();
  const { search } = useFilters();
  const link = carry(search);
  const state = useApi<PrDetail>(`/prs/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/${encodeURIComponent(number)}`, 60000);
  return (
    <Shell crumb={<><Link to={`/pulls${link}`}>Pull Requests</Link> / #{number}</>}>
      <Async state={state}>
        {(p) => {
          const live = p.live;
          const title = live.available && live.title ? live.title : `Security fixes for ${p.base}`;
          return (
            <>
              <PageHead large subMono
                title={<>PR #{p.number} · {title}<GatePill passed={p.gate.passed} />
                  {live.available && live.state && <Pill tone={live.state === "merged" ? "grey" : live.state === "open" ? "blue" : "grey"}>{live.state}</Pill>}</>}
                sub={`${p.repository} · ${p.head} → ${p.base}${live.available && live.author ? ` · opened by ${live.author}` : ""}`}
                actions={<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <Link className="btn" to={`/runs/${encodeURIComponent(p.run.id)}${link}`}>Run {p.run.id}</Link>
                  {p.url && <a className="btn primary" href={p.url} target="_blank" rel="noreferrer">View on GitHub ↗</a>}
                </div>} />
              {!live.available && <div className="state" style={{ padding: 12 }}>Live GitHub state unavailable ({live.error ?? "not requested"}); showing what the pipeline recorded.</div>}
              <Kpis items={[
                { label: "Findings scanned", value: p.summary.scanned },
                { label: "Confirmed", value: p.summary.confirmed },
                { label: "Fixed in this PR", value: p.summary.fixed, valueTone: "green" },
                { label: "Needs review", value: p.summary.review, valueTone: p.summary.review ? "amber" : undefined },
                { label: "Rejected (false positive)", value: p.summary.rejected },
              ]} />
              <div className="grid-2">
                <Card title="Merge gate">
                  <div className="kv-list">
                    <div><span className="mute">Base branch ({p.base}) gate</span><span><GatePill passed={p.gate.passed} /></span></div>
                    <div><span className="mute">Blocking findings on {p.base}</span><span>{p.gate.blocking ?? "—"}</span></div>
                    <div><span className="mute">Fix-branch rescan</span><span>{validationPill(p.validation.state)}</span></div>
                  </div>
                  <p className="mute prose" style={{ marginBottom: 0 }}>{p.validation.description}. The gate on {p.base} turns green once this PR is merged and the rescan of {p.base} is clean.</p>
                </Card>
                <Card title="Checks on GitHub">
                  {live.available && live.checks?.length ? (
                    <div className="kv-list">{live.checks.map((c) => <div key={c.context}><span>{c.context}</span><span><Pill tone={c.state === "success" ? "green" : c.state === "pending" ? "amber" : "red"}>{c.state}</Pill></span></div>)}</div>
                  ) : <Empty>No commit statuses reported.</Empty>}
                  {live.available && live.changed_files !== undefined && (
                    <div className="mono" style={{ marginTop: 12, fontSize: 12 }}>{live.changed_files} file(s) · <span style={{ color: "var(--green)" }}>+{live.additions}</span> <span style={{ color: "var(--red)" }}>−{live.deletions}</span></div>
                  )}
                </Card>
              </div>
              <Card title="Findings in this run" flush>
                <DataTable rowKey={(f) => f.id} rows={p.findings} to={(f) => `/findings/${f.id}${link}`}
                  columns={[
                    { header: "Finding", width: "1.4fr", cell: (f) => <B>{f.title}</B> },
                    { header: "CWE", width: ".7fr", cell: (f) => <M>{f.cwe}</M> },
                    { header: "Severity", width: ".8fr", cell: (f) => <SeverityPill severity={f.severity} /> },
                    { header: "Location", width: "1.4fr", cell: (f) => <M>{f.file}:{f.line}</M> },
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
