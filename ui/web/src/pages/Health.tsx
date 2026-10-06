import type { Health as HealthData } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Bar, Card, Kpis, PageHead, Pill } from "../components/ui";

const SERVICE_NAMES: Record<string, string> = {
  database: "Database", ollama: "Ollama", actions_runner: "GitHub Actions runner",
  semgrep: "Semgrep", pipeline_venv: "Pipeline environment",
};
const toneFor = (v: number) => (v >= 90 ? "red" : v >= 75 ? "amber" : "green");

export function Health() {
  const state = useApi<HealthData>("/health", 15000);
  return (
    <Shell crumb="System Health">
      <Async state={state}>
        {(h) => {
          const down = Object.values(h.services).filter((s) => !s.ok).length;
          const gpu = h.gpus[0];
          const resources: [string, number | null][] = [
            ["CPU", h.cpu_percent], ["Memory", h.memory_percent], ["Disk", h.disk_percent],
            ...(gpu ? [["GPU", gpu.utilization] as [string, number | null]] : []),
          ];
          return (
            <>
              <PageHead title="System health" sub={`Self-hosted${gpu ? ` · ${gpu.name}` : ""}`}
                actions={down ? <Pill tone="red">{down} service(s) down</Pill> : <Pill tone="green" icon={false}>● ALL ONLINE</Pill>} />
              <Kpis items={[
                { label: "Runs (24h)", value: h.runs_24h },
                { label: "Blocked runs (24h)", value: h.blocked_24h, valueTone: h.blocked_24h ? "red" : undefined },
                { label: "Load average", value: h.load_avg[0]?.toFixed(2) ?? "—", detail: h.load_avg.slice(1).map((x) => x.toFixed(2)).join(" · ") },
                { label: "Memory", value: `${h.memory_total_gb} GB` },
                { label: "GPU temp", value: gpu?.temperature_c != null ? `${gpu.temperature_c}°C` : "—" },
              ]} />
              <div className="grid-2">
                <Card title="Resources">
                  <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                    {resources.map(([l, v]) => (
                      <div key={l}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}><span>{l}</span><span className="mono">{v === null ? "n/a" : `${v.toFixed(0)}%`}</span></div>
                        <Bar value={v ?? 0} max={100} tone={toneFor(v ?? 0)} />
                      </div>
                    ))}
                  </div>
                </Card>
                <Card title="Services">
                  <div className="kv-list">
                    {Object.entries(h.services).map(([k, s]) => (
                      <div key={k}><span>{SERVICE_NAMES[k] ?? k}{s.unit ? <span className="mono mute" style={{ fontSize: 11 }}> {s.unit}</span> : null}</span>
                        <span>{s.ok ? <Pill tone="green">up</Pill> : <Pill tone="red">down</Pill>}</span></div>
                    ))}
                  </div>
                </Card>
              </div>
            </>
          );
        }}
      </Async>
    </Shell>
  );
}
