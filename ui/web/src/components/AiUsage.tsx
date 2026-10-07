import type { ByModel, ByPurpose, RunUsage, UsageOverview, UsageRow } from "../api/types";
import { compact, duration } from "../lib/format";
import { Bar, Card, DataTable, Empty, Kpis, M, N } from "./ui";

const PURPOSE: Record<string, string> = {
  triage: "Triage: first analysis", triage_followup: "Triage: follow-up questions", fix: "Fix writing",
  review: "Fix review", laya_triage: "Laya: finding score", laya_fix_trust: "Laya: fix trust", proof: "Proof-of-fix test writing",
};
export const purposeLabel = (p: string) => PURPOSE[p] ?? p;

const rows = (title: string, label: string, items: (ByModel | ByPurpose)[], name: (r: any) => string) => (
  <Card title={title} flush>
    <div style={{ paddingTop: 4 }} />
    <DataTable rowKey={(r: any) => name(r)} rows={items} empty={<Empty>No AI calls recorded yet.</Empty>}
      columns={[
        { header: label, width: "2fr", cell: (r: any) => <M>{name(r)}</M> },
        { header: "Calls", width: ".6fr", cell: (r: UsageRow) => <N>{r.calls}</N> },
        { header: "Prompt tokens", width: ".9fr", cell: (r: UsageRow) => <N>{compact(r.prompt_tokens)}</N> },
        { header: "Output tokens", width: ".9fr", cell: (r: UsageRow) => <N>{compact(r.completion_tokens)}</N> },
        { header: "Avg time", width: ".7fr", cell: (r: UsageRow) => <N>{duration(r.avg_ms / 1000)}</N> },
        { header: "Failed", width: ".5fr", cell: (r: UsageRow) => <N tone={r.errors ? "red" : undefined}>{r.errors}</N> },
      ]} />
  </Card>
);

function Totals({ t, runs }: { t: UsageRow; runs?: number }) {
  return (
    <Kpis items={[
      { label: "AI calls", value: t.calls, detail: runs !== undefined ? `across ${runs} run(s)` : undefined },
      { label: "Tokens", value: compact(t.total_tokens), detail: `${compact(t.prompt_tokens)} in · ${compact(t.completion_tokens)} out` },
      { label: "Model time", value: duration(t.duration_ms / 1000) },
      { label: "Failed calls", value: t.errors, valueTone: t.errors ? "red" : undefined },
    ]} />
  );
}

/** Usage over a window: the Models page. Laya reports no tokens, only calls and time. */
export function AiUsage({ usage, days }: { usage: UsageOverview; days: number }) {
  if (!usage.totals.calls) {
    return <Card title="AI usage"><Empty>No AI calls recorded in the last {days} days. Usage appears after the next scan.</Empty></Card>;
  }
  const maxDay = Math.max(1, ...usage.by_day.map((d) => d.total_tokens));
  return (
    <>
      <Card title={`AI usage, last ${days} days`} aside={<small>tokens as counted by the model server</small>}>
        <Totals t={usage.totals} runs={usage.runs} />
      </Card>
      <div className="grid-2">
        {rows("By model", "Model", usage.by_model, (r: ByModel) => r.model)}
        {rows("By purpose", "What it was for", usage.by_purpose, (r: ByPurpose) => purposeLabel(r.purpose))}
      </div>
      <div className="grid-2">
        <Card title="Tokens per day">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {usage.by_day.map((d) => (
              <div className="chart-row" key={d.day}>
                <span className="mono" style={{ fontSize: 12 }}>{d.day}</span>
                <Bar value={d.total_tokens} max={maxDay} tone="blue" />
                <span className="mono" style={{ textAlign: "right", fontSize: 12 }}>{compact(d.total_tokens)}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Heaviest runs" flush>
          <div style={{ paddingTop: 4 }} />
          <DataTable rowKey={(r) => r.run_id} rows={usage.top_runs} empty={<Empty>No runs.</Empty>}
            to={(r) => `/runs/${encodeURIComponent(r.run_id)}`}
            columns={[
              { header: "Run", width: "1.4fr", cell: (r) => <M>{r.repository.split("/").pop()} @ {r.branch}</M> },
              { header: "Tokens", width: ".7fr", cell: (r) => <N>{compact(r.total_tokens)}</N> },
              { header: "Calls", width: ".5fr", cell: (r) => <N>{r.calls}</N> },
            ]} />
        </Card>
      </div>
    </>
  );
}

/** One run's usage: the run page. */
export function RunAiUsage({ usage }: { usage: RunUsage }) {
  if (!usage.totals.calls) return null;
  return (
    <Card title="AI usage" aside={<small>this run</small>}>
      <Totals t={usage.totals} />
      <div style={{ height: 12 }} />
      {rows("By purpose", "What it was for", usage.by_purpose, (r: ByPurpose) => purposeLabel(r.purpose))}
    </Card>
  );
}
