import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { RunStatus, Severity } from "../api/types";

export type Tone = "red" | "amber" | "green" | "blue" | "orange" | "grey";
const ICON: Record<Tone, string> = { red: "✕", amber: "!", green: "✓", blue: "●", orange: "▲", grey: "–" };

export function Pill({ tone, children, icon = true }: { tone: Tone; children: ReactNode; icon?: boolean }) {
  return <span className={`pill tone-${tone}`}>{icon && <span aria-hidden="true">{ICON[tone]}</span>}{children}</span>;
}

const SEV_TONE: Record<Severity, Tone> = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
export const SeverityPill = ({ severity }: { severity: Severity }) => <Pill tone={SEV_TONE[severity] ?? "grey"}>{severity}</Pill>;

const STATUS_TONE: Record<RunStatus, Tone> = { Passed: "green", "Fix PR open": "amber", Blocked: "red", Checked: "blue" };
export const RunStatusPill = ({ status }: { status: RunStatus }) => <Pill tone={STATUS_TONE[status] ?? "grey"}>{status}</Pill>;

const FIX_TONE: Record<string, Tone> = { Fixed: "green", "Needs review": "amber", "Not fixed": "red", "False positive": "grey" };
export const FixStatusPill = ({ status }: { status: string }) => <Pill tone={FIX_TONE[status] ?? "grey"}>{status}</Pill>;

export function GatePill({ passed }: { passed: boolean | null | undefined }) {
  if (passed === null || passed === undefined) return <Pill tone="grey">Unknown</Pill>;
  return passed ? <Pill tone="green">Gate passed</Pill> : <Pill tone="red">Gate blocked</Pill>;
}

export const AiTag = () => <span className="ai-tag">AI GENERATED</span>;

export function Card({ title, aside, children, flush, className = "" }:
  { title?: ReactNode; aside?: ReactNode; children: ReactNode; flush?: boolean; className?: string }) {
  return (
    <section className={`card ${flush ? "flush" : ""} ${className}`}>
      {title && <h2 className="card-h" style={{ margin: 0, marginBottom: 14 }}><span>{title}</span>{aside}</h2>}
      {children}
    </section>
  );
}

export function PageHead({ title, sub, actions, large, subMono }:
  { title: ReactNode; sub?: ReactNode; actions?: ReactNode; large?: boolean; subMono?: boolean }) {
  return (
    <div className="page-head">
      <div>
        <h1 className={`page-title ${large ? "lg" : ""}`} style={{ margin: 0 }}>{title}</h1>
        {sub && <div className={`page-sub ${subMono ? "mono" : ""}`}>{sub}</div>}
      </div>
      {actions}
    </div>
  );
}

export function Kpis({ items }: { items: { label: string; value: ReactNode; detail?: ReactNode; tone?: string; valueTone?: string }[] }) {
  return (
    <div className="kpis">
      {items.map((k) => (
        <div className="kpi" key={k.label}>
          <div className="kpi-l">{k.label}</div>
          <div className="kpi-v" style={k.valueTone ? { color: `var(--${k.valueTone})` } : undefined}>{k.value}</div>
          {k.detail && <div className={`kpi-d ${k.tone ?? "mute"}`}>{k.detail}</div>}
        </div>
      ))}
    </div>
  );
}

export interface Column<T> { header: string; width: string; cell: (row: T) => ReactNode }

/** Grid table; rows become links when `to` is given. */
export function DataTable<T>({ columns, rows, to, rowKey, empty }:
  { columns: Column<T>[]; rows: T[]; to?: (row: T) => string; rowKey: (row: T) => string | number; empty?: ReactNode }) {
  const grid = { gridTemplateColumns: columns.map((c) => c.width).join(" ") };
  if (!rows.length) return <div style={{ padding: "16px 0" }}>{empty ?? <Empty>Nothing to show yet.</Empty>}</div>;
  // Rows that navigate are plain links (a role="row" would hide from screen
  // readers that they're clickable); only static tables get table semantics.
  const t = to ? {} : { table: { role: "table" }, row: { role: "row" }, head: { role: "columnheader" }, cell: { role: "cell" } };
  return (
    <div className="table-wrap" {...t.table}>
      <div className="trow head" style={grid} {...t.row} aria-hidden={to ? true : undefined}>
        {columns.map((c) => <span key={c.header} {...t.head}>{c.header}</span>)}
      </div>
      {rows.map((row) => {
        const cells = columns.map((c) => <span key={c.header} {...t.cell}>{c.cell(row)}</span>);
        return to
          ? <Link key={rowKey(row)} to={to(row)} className="trow link" style={grid}>{cells}</Link>
          : <div key={rowKey(row)} className="trow" style={grid} {...t.row}>{cells}</div>;
      })}
    </div>
  );
}

export const B = ({ children }: { children: ReactNode }) => <span className="cell-b">{children}</span>;
export const M = ({ children }: { children: ReactNode }) => <span className="cell-m">{children}</span>;
export const N = ({ children, tone }: { children: ReactNode; tone?: string }) =>
  <span className="cell-n" style={tone ? { color: `var(--${tone})` } : undefined}>{children}</span>;

export function Loading({ height = 120 }: { height?: number }) {
  return <div className="skeleton" style={{ height }} role="status" aria-label="Loading" />;
}
export const Empty = ({ children }: { children: ReactNode }) => <div className="state">{children}</div>;

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  return (
    <div className="state error" role="alert">
      <div>Couldn’t load this data: {error.message}</div>
      {retry && <button className="btn sm" style={{ marginTop: 12 }} onClick={retry}>Try again</button>}
    </div>
  );
}

/** Standard data-page wrapper: loading skeleton, error with retry, then content. */
export function Async<T>({ state, children, skeleton = 160 }:
  { state: { data: T | null; error: Error | null; loading: boolean; reload: () => void };
    children: (data: T) => ReactNode; skeleton?: number }) {
  if (state.error && !state.data) return <ErrorState error={state.error} retry={state.reload} />;
  if (!state.data) return <Loading height={skeleton} />;
  return <>{children(state.data)}</>;
}

export function Bar({ value, max, tone }: { value: number; max: number; tone: string }) {
  const w = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return <div className="bar-track"><div className={`bar bg-${tone}`} style={{ width: `${w}%` }} /></div>;
}
