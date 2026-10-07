import type { ModelsInfo, UsageOverview } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { AiUsage } from "../components/AiUsage";
import { Async, B, Card, DataTable, M, PageHead, Pill } from "../components/ui";
import { ProvenanceList } from "./RunDetail";

const gb = (b: number | null) => (b ? `${(b / 2 ** 30).toFixed(1)} GB` : "—");

const USAGE_DAYS = 30;

export function Models() {
  const state = useApi<ModelsInfo>("/models", 30000);
  const usage = useApi<UsageOverview>(`/usage?days=${USAGE_DAYS}`, 60000);
  return (
    <Shell crumb="Models">
      <Async state={state}>
        {(d) => {
          const o = d.ollama;
          const inUse = new Set([d.provenance?.triage_model, ...(d.provenance?.fix_models ?? [])].filter(Boolean));
          return (
            <>
              <PageHead title="Models" sub="All inference runs locally on this machine. No prompts or code leave your network."
                actions={<Pill tone="green">100% local</Pill>} />
              <div className="grid-2">
                <Card title="Ollama" aside={o.online ? <Pill tone="green" icon={false}>● ONLINE</Pill> : <Pill tone="red">OFFLINE</Pill>}>
                  {o.online ? (
                    <div className="kv">
                      {[["Version", o.version], ["API latency", `${o.api_latency_ms} ms`], ["Models installed", String(o.models.length)],
                        ["Loaded now", o.models.filter((m) => m.loaded).map((m) => m.name).join(", ") || "none"]]
                        .map(([k, v]) => <div key={k}><div className="k">{k}</div><div className="v">{v}</div></div>)}
                    </div>
                  ) : <div className="state error">Ollama is unreachable: {o.error}</div>}
                </Card>
                <Card title="Pipeline configuration" aside={<small>from the latest run</small>}>
                  {d.provenance ? <ProvenanceList p={d.provenance} /> : <div className="mute">No runs recorded yet.</div>}
                </Card>
              </div>
              <Async state={usage}>{(u) => <AiUsage usage={u} days={USAGE_DAYS} />}</Async>
              <Card title="Installed models" flush>
                <DataTable rowKey={(m) => m.name} rows={o.models}
                  columns={[
                    { header: "Model", width: "2fr", cell: (m) => <B>{m.name}</B> },
                    { header: "Family", width: ".8fr", cell: (m) => <M>{m.family ?? "—"}</M> },
                    { header: "Parameters", width: ".8fr", cell: (m) => <M>{m.parameter_size ?? "—"}</M> },
                    { header: "Quantization", width: ".8fr", cell: (m) => <M>{m.quantization ?? "—"}</M> },
                    { header: "Size", width: ".7fr", cell: (m) => <M>{gb(m.size_bytes)}</M> },
                    { header: "Role", width: "1fr", cell: (m) => inUse.has(m.name) ? <Pill tone="blue">used by pipeline</Pill> : <span className="mute">—</span> },
                    { header: "State", width: ".7fr", cell: (m) => m.loaded ? <Pill tone="green">loaded</Pill> : <span className="mute">idle</span> },
                  ]} />
              </Card>
            </>
          );
        }}
      </Async>
    </Shell>
  );
}
