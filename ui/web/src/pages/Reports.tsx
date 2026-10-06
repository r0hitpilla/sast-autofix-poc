import { qs } from "../api/client";
import type { Bar as BarItem, Report } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Bar, Card, Empty, Kpis, PageHead } from "../components/ui";
import { useFilters } from "../lib/filters";
import { duration, pct } from "../lib/format";

function Chart({ title, bars, tone }: { title: string; bars: BarItem[]; tone: string }) {
  const max = Math.max(1, ...bars.map((b) => b.value));
  return (
    <Card title={title}>
      {bars.every((b) => !b.value) ? <Empty>No data in this window.</Empty> : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {bars.map((b) => (
            <div className="chart-row" key={b.label}>
              <span style={{ fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={b.label}>{b.label}</span>
              <Bar value={b.value} max={max} tone={tone} />
              <span className="mono" style={{ textAlign: "right", fontSize: 12 }}>{b.value}</span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

export function Reports() {
  const { repo, days } = useFilters();
  const query = qs({ repository: repo, days });
  const state = useApi<Report>(`/reports${query}`);
  return (
    <Shell crumb="Reports">
      <PageHead title="Reports" sub={`Last ${days} day(s) · ${repo ?? "all repositories"}`}
        actions={<div style={{ display: "flex", gap: 8 }}>
          <a className="btn" href={`/api/reports/export.csv${query}`} download>CSV</a>
          <a className="btn primary" href={`/api/reports/export.json${query}`} download>JSON</a>
        </div>} />
      <Async state={state}>
        {(r) => (
          <>
            <Kpis items={[
              { label: "Runs", value: r.kpis.runs },
              { label: "Findings", value: r.kpis.findings },
              { label: "Autofix success", value: pct(r.kpis.autofix_success) },
              { label: "False-positive rate", value: pct(r.kpis.false_positive_rate) },
              { label: "Failed fix attempts", value: pct(r.kpis.fix_attempt_failure_rate) },
              { label: "Avg run time", value: duration(r.kpis.avg_run_seconds) },
            ]} />
            <div className="grid-2">
              <Chart title="Findings by CWE" bars={r.charts.by_cwe} tone="blue" />
              <Chart title="Findings by severity" bars={r.charts.by_severity} tone="orange" />
              <Chart title="Findings by repository" bars={r.charts.by_repository} tone="blue" />
              <Chart title="Laya confidence distribution" bars={r.charts.confidence} tone="green" />
            </div>
          </>
        )}
      </Async>
    </Shell>
  );
}
