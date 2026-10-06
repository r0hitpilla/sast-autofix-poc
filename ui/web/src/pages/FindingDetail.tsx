import { Link, useParams } from "react-router-dom";
import type { ReactNode } from "react";
import type { FindingDetail as FindingData } from "../api/types";
import { useApi } from "../api/useApi";
import { CodeView, DiffView } from "../components/code";
import { Shell } from "../components/Shell";
import { AiTag, Async, Card, Empty, FixStatusPill, PageHead, Pill, SeverityPill } from "../components/ui";
import { carry, useFilters } from "../lib/filters";
import { dateTime, pct, shortSha } from "../lib/format";

const QUESTION_LABEL: Record<string, string> = {
  input_source: "Input source", sanitization: "Sanitization", reachability: "Reachability",
  sink_safety: "Sink safety", exploit: "Exploit",
};

/** The LLM ends every answer with "VERDICT: …"; split it out for display. */
function splitVerdict(answer: string): { body: string; verdict: string | null } {
  const m = answer.match(/^[\s*_`#>-]*VERDICT[\s*_`]*:[\s*_`]*(.+)$/im);
  return m ? { body: answer.replace(m[0], "").trim(), verdict: m[1]!.trim() } : { body: answer.trim(), verdict: null };
}

export function FindingDetail() {
  const { id = "" } = useParams();
  const { search } = useFilters();
  const link = carry(search);
  const state = useApi<FindingData>(`/findings/${encodeURIComponent(id)}`);

  return (
    <Shell crumb={<><Link to={`/findings${link}`}>Findings</Link> / #{id}</>}>
      <Async state={state}>
        {(f) => {
          const inv = f.investigation;
          const initial = inv.initial ? splitVerdict(inv.initial) : null;
          const llm = inv.llm_label === "tp" ? ["TRUE POSITIVE", "red"] : inv.llm_label === "fp" ? ["FALSE POSITIVE", "green"] : ["NO VERDICT", "mute"];
          const g = f.provenance.generation ?? {};
          return (
            <>
              <PageHead large subMono
                title={<>{f.title}<span className="mono mute" style={{ fontSize: 14 }}>{f.cwe}</span><SeverityPill severity={f.severity} /><FixStatusPill status={f.fix_status} /></>}
                sub={`#${f.id} · ${f.repository} · ${f.file}:${f.line} · ${f.rule_id}`}
                actions={<div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <Link className="btn" to={`/runs/${encodeURIComponent(f.run_id)}${link}`}>Run {f.run_id}</Link>
                  {f.pr_number && <Link className="btn primary" to={`/pulls/${f.repository}/${f.pr_number}${link}`}>Fix PR #{f.pr_number}</Link>}
                </div>} />
              <div className="split">
                <div className="stack">
                  <Card title="Flagged code" aside={<span className="mono mute" style={{ fontSize: 12, fontWeight: 400 }}>{f.file}</span>}>
                    {f.code.length ? <CodeView lines={f.code} /> : <pre className="code" style={{ margin: 0, padding: 12 }}>{f.snippet}</pre>}
                    <p className="mute prose" style={{ marginBottom: 0 }}>{f.message}</p>
                  </Card>
                  {f.fix?.validated && f.fix.diff && (
                    <Card title="Applied fix" aside={<AiTag />}>
                      {f.fix.note && <div className="pill tone-amber" style={{ whiteSpace: "normal", marginBottom: 10 }}>⚠ {f.fix.note}</div>}
                      <DiffView diff={f.fix.diff} />
                      <div className="mute" style={{ fontSize: 12, marginTop: 8 }}>Validated after {f.fix.attempts} attempt(s): rescan, no new findings, broken-code check, tests and AI review.</div>
                    </Card>
                  )}
                  {f.fix && !f.fix.validated && (
                    <Card title="Not fixed automatically" aside={<Pill tone="amber">needs a developer</Pill>}>
                      <div className="prose" style={{ marginBottom: 10 }}>{f.fix.attempts} attempt(s) failed validation{f.fix.failure ? ` (${f.fix.failure})` : ""}. Last check output:</div>
                      {f.fix.check_output && <pre className="code" style={{ margin: 0, padding: 12, maxHeight: 220, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{f.fix.check_output}</pre>}
                      {f.fix.last_proposal && (
                        <details style={{ marginTop: 12 }}><summary>Last proposed change (unverified)</summary>
                          <pre className="code" style={{ margin: "8px 0 0", padding: 12 }}>{f.fix.last_proposal}</pre></details>
                      )}
                    </Card>
                  )}
                  <Card title="Context">
                    <div className="kv">
                      {([["Repository", f.repository], ["Branch", f.branch], ["File", `${f.file}:${f.line}${f.end_line && f.end_line !== f.line ? `–${f.end_line}` : ""}`],
                        ["Commit", shortSha(f.commit)],
                        ["Rule", f.advisory_url ? <a href={f.advisory_url} target="_blank" rel="noreferrer">{f.rule_id}</a> : f.rule_id],
                        ["CWE", f.cwe],
                        ["CVSS", f.cvss == null ? "—" : f.cvss.toFixed(1)],
                        ["Risk", f.risk == null ? "—" : f.risk.toFixed(1)],
                        ["OWASP", f.owasp.length ? f.owasp[f.owasp.length - 1] : "—"], ["First detected", dateTime(f.first_detected)],
                        ["Last detected", dateTime(f.last_detected)], ["Times detected", String(f.times_detected)]] as [string, ReactNode][])
                        .map(([k, v]) => <div key={k}><div className="k">{k}</div><div className="v">{v}</div></div>)}
                    </div>
                  </Card>
                </div>
                <Card title="AI investigation" aside={<AiTag />} className="sticky">
                  <div className="verdict-grid">
                    <div><div className="mute" style={{ fontSize: 11 }}>LLM verdict</div><div style={{ color: `var(--${llm[1]})`, fontWeight: 600, marginTop: 4, fontSize: 12.5 }}>{llm[0]}</div></div>
                    <div><div className="mute" style={{ fontSize: 11 }}>Laya confidence</div><div className="mono" style={{ fontSize: 20, marginTop: 2 }}>{pct(inv.laya_score, 0)}</div></div>
                    <div><div className="mute" style={{ fontSize: 11 }}>Rounds</div><div className="mono" style={{ fontSize: 20, marginTop: 2 }}>{inv.rounds}{inv.max_rounds ? ` / ${inv.max_rounds}` : ""}</div></div>
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                    {initial && (
                      <div className="qa">
                        <div className="qa-n">INITIAL ANALYSIS</div>
                        <div className="prose">{initial.body}</div>
                        {initial.verdict && <div className="assess"><span className="mute" style={{ fontSize: 11 }}>Verdict</span><div style={{ marginTop: 2 }}>{initial.verdict}</div></div>}
                      </div>
                    )}
                    {inv.questions.length === 0 && <div className="mute" style={{ fontSize: 12 }}>Laya was confident after the initial analysis and asked no follow-up questions.</div>}
                    {inv.questions.map((q, i) => {
                      const a = splitVerdict(q.answer);
                      return (
                        <div className="qa" key={i}>
                          <div className="qa-n">QUESTION {i + 1}{q.key && QUESTION_LABEL[q.key] ? ` · ${QUESTION_LABEL[q.key]}` : ""} · asked by Laya</div>
                          <div style={{ fontWeight: 500 }}>{q.question}</div>
                          <div><div className="mute" style={{ fontSize: 11, marginBottom: 2 }}>Answer</div><div className="prose">{a.body}</div></div>
                          {a.verdict && <div className="assess"><span className="mute" style={{ fontSize: 11 }}>Conclusion</span><div style={{ marginTop: 2 }}>{a.verdict}</div></div>}
                        </div>
                      );
                    })}
                  </div>
                  <div className="mono mute" style={{ marginTop: 14, borderTop: "1px solid var(--line)", paddingTop: 12, fontSize: 11, lineHeight: 1.6 }}>
                    {[f.provenance.triage_model, g.temperature !== undefined && `temp ${g.temperature}`,
                      g.seed !== undefined && `seed ${g.seed}`, f.provenance.laya_version && `laya ${f.provenance.laya_version}`,
                      f.provenance.tool_version && `tool ${f.provenance.tool_version}`].filter(Boolean).join(" · ")}
                  </div>
                  {inv.questions.length === 0 && !initial && <Empty>No investigation recorded.</Empty>}
                </Card>
              </div>
            </>
          );
        }}
      </Async>
    </Shell>
  );
}
