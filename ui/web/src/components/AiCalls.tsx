import { useState } from "react";
import type { AiCall, AiContent, RunAi } from "../api/types";
import { getJson } from "../api/client";
import { useApi } from "../api/useApi";
import { compact, duration } from "../lib/format";
import { purposeLabel } from "./AiUsage";
import { Card, Empty, M, N } from "./ui";

/** The prompt and reply of one call, fetched only when asked for: they contain source code. */
function Content({ id }: { id: number }) {
  const [state, setState] = useState<{ data?: AiContent; error?: string; loading?: boolean } | null>(null);
  const load = () => {
    setState({ loading: true });
    getJson<AiContent>(`/ai-calls/${id}/content`)
      .then((data) => setState({ data }))
      .catch((e: Error) => setState({ error: e.message }));
  };
  if (!state) return <button className="btn" onClick={load}>Show prompt and reply</button>;
  if (state.loading) return <span className="mute">Loading…</span>;
  if (state.error) return <span className="mute">Could not load: {state.error}</span>;
  const d = state.data!;
  if (!d.available) return <span className="mute">{d.reason}</span>;
  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div><div className="mute" style={{ fontSize: 11 }}>Prompt</div><pre className="code-block">{d.input}</pre></div>
      <div><div className="mute" style={{ fontSize: 11 }}>Reply</div><pre className="code-block">{d.output}</pre></div>
      {d.truncated && <small className="mute">Shortened for display; the full text is in Langfuse.</small>}
    </div>
  );
}

function Row({ c, total, canRead }: { c: AiCall; total: number; canRead: boolean }) {
  const [open, setOpen] = useState(false);
  const left = total ? (c.offset_s / total) * 100 : 0;
  const width = total ? Math.max(0.8, (c.duration_ms / 1000 / total) * 100) : 100;
  return (
    <div style={{ borderTop: "1px solid var(--line)", padding: "8px 0" }}>
      <div style={{ display: "grid", gridTemplateColumns: "1.5fr 2fr .9fr .9fr", gap: 12, alignItems: "center" }}>
        <div>
          <button className="linklike" onClick={() => setOpen(!open)} aria-expanded={open}>{purposeLabel(c.purpose)}</button>
          {c.ref && <div className="mute mono" style={{ fontSize: 11 }}>{c.ref}</div>}
        </div>
        <div style={{ position: "relative", height: 8, background: "var(--line)", borderRadius: 4 }} aria-hidden>
          <div style={{ position: "absolute", left: `${Math.min(left, 99)}%`, width: `${Math.min(width, 100 - left)}%`, height: 8,
                        borderRadius: 4, background: c.ok ? "var(--blue, #4c8dff)" : "var(--red, #e5484d)" }} />
        </div>
        <N>{duration(c.duration_ms / 1000)}</N>
        <N>{c.prompt_tokens === null ? "—" : `${compact(c.prompt_tokens)} → ${compact(c.completion_tokens ?? 0)}`}</N>
      </div>
      {open && (
        <div style={{ padding: "8px 0 4px", display: "grid", gap: 8 }}>
          <div className="mute" style={{ fontSize: 12 }}>
            <M>{c.model}</M> via {c.provider}{c.truncated ? " · reply hit the output limit" : ""}{c.error ? ` · failed: ${c.error}` : ""}
          </div>
          {!c.traced && <small className="mute">Not traced, so no prompt or reply was kept.</small>}
          {c.traced && canRead && <Content id={c.id} />}
          {c.traced && !canRead && <small className="mute">Prompts contain source code; your role cannot read them.</small>}
          {c.link && <a href={c.link} target="_blank" rel="noreferrer noopener">Open in Langfuse ↗</a>}
        </div>
      )}
    </div>
  );
}

/** Every AI call of one run as a timeline, with the Langfuse trace one click away. */
export function RunAiCalls({ runId }: { runId: string }) {
  const state = useApi<RunAi>(`/runs/${encodeURIComponent(runId)}/ai`);
  const data = state.data;
  if (!data || !data.calls.length) return null;
  const total = Math.max(...data.calls.map((c) => c.offset_s + c.duration_ms / 1000), 0.001);
  const lf = data.langfuse;
  return (
    <Card title="AI calls" aside={lf.trace_url
      ? <a href={lf.trace_url} target="_blank" rel="noreferrer noopener">Open trace in Langfuse ↗</a>
      : <small>{lf.connected ? "not traced" : "Langfuse not connected"}</small>}>
      {data.calls.length === 0 ? <Empty>No AI calls.</Empty> : data.calls.map((c) => (
        <Row key={c.id} c={c} total={total} canRead={lf.can_read_content} />
      ))}
    </Card>
  );
}
