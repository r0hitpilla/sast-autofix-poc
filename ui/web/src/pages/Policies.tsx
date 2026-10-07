import { useEffect, useState } from "react";
import { ApiError, sendJson } from "../api/client";
import type { GateAction, PolicyContent, PolicyData, Severity } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Card, PageHead, Pill, type Tone } from "../components/ui";
import { dateTime } from "../lib/format";
import { can, useSession } from "../lib/session";

const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];
const ACTION: Record<GateAction, [string, Tone]> = {
  block: ["Block merge", "red"], review: ["Review required", "amber"], allow: ["Allow", "green"],
};
const list = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

export function Policies() {
  const me = useSession();
  const editable = can(me, "policy:manage");
  const state = useApi<PolicyData>("/policy");
  const [draft, setDraft] = useState<PolicyContent | null>(null);
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    if (state.data) setDraft(structuredClone(state.data.active?.content ?? state.data.default));
  }, [state.data]);

  const publish = async () => {
    if (!draft) return;
    setMsg(null);
    try {
      const v = await sendJson<{ version: number }>("POST", "/policy", { content: draft, note });
      setNote("");
      setMsg(`Published v${v.version}. It applies from the next pipeline run.`);
      state.reload();
    } catch (err) {
      setMsg(err instanceof ApiError ? err.message : "Could not publish.");
    }
  };

  return (
    <Shell crumb="Policies">
      <Async state={state} skeleton={320}>
        {(d) => {
          const active = d.active;
          const next = (active?.version ?? 0) + 1;
          const shown = draft ?? active?.content ?? d.default;
          const changed = JSON.stringify(shown) !== JSON.stringify(active?.content ?? d.default);
          const set = (patch: Partial<PolicyContent>) => setDraft({ ...shown, ...patch });
          return (
            <>
              <PageHead title={d.name}
                sub={active
                  ? `Version ${active.version} · active · repositories ${active.content.repositories.join(", ")} · branches ${active.content.branches.join(", ")}`
                  : "Nothing published yet: the strict default applies (every confirmed finding blocks the merge)"}
                actions={<div style={{ display: "flex", gap: 8 }}>
                  <button className="btn" onClick={() => setShowHistory((v) => !v)}>Version history</button>
                  <button className="btn primary" disabled={!editable || !changed || note.trim().length < 3} onClick={publish}>Publish v{next}</button>
                </div>} />
              {editable && (
                <div className="policy-note">
                  <input className="input" style={{ width: "100%" }} placeholder={`What changes in v${next}? (required, recorded in the audit log)`}
                         value={note} onChange={(e) => setNote(e.target.value)} aria-label="Change note" />
                </div>
              )}
              {msg && <div className="pill tone-blue" role="status" style={{ whiteSpace: "normal", margin: "10px 0" }}>{msg}</div>}
              <div className="policy-grid">
                <Card title={<>Rules <span className="mute" style={{ fontWeight: 400, fontSize: 12 }}>applied to every confirmed finding</span></>}>
                  {SEVERITIES.map((s) => (
                    <div className="policy-row" key={s}>
                      <span>{s} findings</span>
                      {editable ? (
                        <select className="select" aria-label={`${s} findings`} value={shown.severity_actions[s]}
                                onChange={(e) => set({ severity_actions: { ...shown.severity_actions, [s]: e.target.value as GateAction } })}>
                          {(Object.keys(ACTION) as GateAction[]).map((a) => <option key={a} value={a}>{ACTION[a][0]}</option>)}
                        </select>
                      ) : <Pill tone={ACTION[shown.severity_actions[s]][1]}>→ {ACTION[shown.severity_actions[s]][0]}</Pill>}
                    </div>
                  ))}
                  <div className="policy-row">
                    <span>A person's decision (false positive, suppressed)</span>
                    {editable ? (
                      <select className="select" aria-label="Decisions" value={shown.decisions_clear_blocks ? "yes" : "no"}
                              onChange={(e) => set({ decisions_clear_blocks: e.target.value === "yes" })}>
                        <option value="no">Clears "review" only</option>
                        <option value="yes">Clears "review" and "block"</option>
                      </select>
                    ) : <Pill tone="blue">→ {shown.decisions_clear_blocks ? "Clears review and block" : "Clears review only"}</Pill>}
                  </div>
                  <div className="policy-row">
                    <span>Autofix</span>
                    {editable ? (
                      <select className="select" aria-label="Autofix" value={shown.autofix ? "on" : "off"}
                              onChange={(e) => set({ autofix: e.target.value === "on" })}>
                        <option value="on">Allowed, except the paths below</option>
                        <option value="off">Never (report only)</option>
                      </select>
                    ) : <Pill tone="blue">→ {shown.autofix ? "Allowed, except paths below" : "Never"}</Pill>}
                  </div>
                  <div className="policy-row">
                    <span>Never autofix these paths<br /><span className="mute" style={{ fontSize: 12 }}>Always included: {d.always_never_autofix.join(", ")} (CI/CD changes)</span></span>
                    {editable ? (
                      <input className="input" aria-label="Never autofix paths" placeholder="infra/**, auth/**"
                             value={shown.never_autofix.join(", ")} onChange={(e) => set({ never_autofix: list(e.target.value) })} />
                    ) : <span className="mono">{shown.never_autofix.join(", ") || "—"}</span>}
                  </div>
                </Card>
                <div className="stack">
                  <Card title="Scope">
                    {editable ? (
                      <>
                        <label className="field"><span>Repositories (patterns, comma-separated)</span>
                          <input className="input" style={{ width: "100%" }} value={shown.repositories.join(", ")}
                                 onChange={(e) => set({ repositories: list(e.target.value) })} /></label>
                        <label className="field" style={{ marginTop: 10 }}><span>Branches</span>
                          <input className="input" style={{ width: "100%" }} value={shown.branches.join(", ")}
                                 onChange={(e) => set({ branches: list(e.target.value) })} /></label>
                        <div className="mute" style={{ fontSize: 12, marginTop: 8 }}>Outside this scope the strict default applies.</div>
                      </>
                    ) : (
                      <div className="scope-chips">
                        {shown.repositories.map((r) => <span key={`r${r}`} className="scope-chip"><span className="mute">repo</span> <span className="mono">{r}</span></span>)}
                        {shown.branches.map((b) => <span key={`b${b}`} className="scope-chip"><span className="mute">branch</span> <span className="mono">{b}</span></span>)}
                      </div>
                    )}
                  </Card>
                  <Card title="Versions">
                    {d.versions.length === 0 ? <div className="mute">No versions yet.</div> :
                      (showHistory ? d.versions : d.versions.slice(0, 4)).map((v) => (
                        <div className="version-row" key={v.version}>
                          <span className="mono">v{v.version}</span>
                          <div><div>{v.note}</div><div className="mute mono" style={{ fontSize: 12 }}>{v.published_by} · {dateTime(v.published_at)}</div></div>
                        </div>
                      ))}
                  </Card>
                </div>
              </div>
            </>
          );
        }}
      </Async>
    </Shell>
  );
}
