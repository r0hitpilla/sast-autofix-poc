import { useState } from "react";
import { qs } from "../api/client";
import type { AuditEvent, Paged } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, B, Card, DataTable, Empty, M, PageHead, Pill } from "../components/ui";
import { dateTime } from "../lib/format";

const OUTCOME_TONE: Record<string, "green" | "red" | "amber"> = { success: "green", failure: "red", denied: "amber" };
const PAGE = 50;

export function Audit() {
  const [offset, setOffset] = useState(0);
  const [action, setAction] = useState("");
  const events = useApi<Paged<AuditEvent>>(`/audit${qs({ limit: PAGE, offset, action })}`);

  return (
    <Shell crumb="Audit log">
      <PageHead title="Audit log" sub="Every sign-in, sign-out, user change and refused request. Entries are never edited." />
      <Card>
        <label className="field" style={{ maxWidth: 260 }}>
          <span>Action</span>
          <select className="select" value={action} onChange={(e) => { setAction(e.target.value); setOffset(0); }}>
            <option value="">all actions</option>
            {["login", "login_failed", "logout", "user_created", "user_updated", "access_denied"].map((a) => (
              <option key={a} value={a}>{a.replace(/_/g, " ")}</option>
            ))}
          </select>
        </label>
      </Card>
      <div style={{ height: 12 }} />
      <Async state={events} skeleton={260}>
        {(d) => (
          <Card flush>
            <div style={{ paddingTop: 4 }} />
            <DataTable rowKey={(e) => e.id} rows={d.items} empty={<Empty>No events match.</Empty>}
              columns={[
                { header: "When", width: "1.1fr", cell: (e) => dateTime(e.at) },
                { header: "Who", width: "1.3fr", cell: (e) => <M>{e.actor_email ?? "—"}</M> },
                { header: "Action", width: "1.2fr", cell: (e) => <B>{e.action.replace(/_/g, " ")}</B> },
                { header: "Outcome", width: ".8fr", cell: (e) => <Pill tone={OUTCOME_TONE[e.outcome] ?? "grey"}>{e.outcome}</Pill> },
                { header: "Target", width: "1.4fr", cell: (e) => <M>{e.target ?? "—"}</M> },
                { header: "IP", width: ".8fr", cell: (e) => <M>{e.ip ?? "—"}</M> },
              ]} />
            <div className="table-foot" style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span>Showing {d.items.length ? offset + 1 : 0}–{offset + d.items.length} of {d.total}</span>
              <button className="btn sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Newer</button>
              <button className="btn sm" disabled={offset + PAGE >= d.total} onClick={() => setOffset(offset + PAGE)}>Older</button>
            </div>
          </Card>
        )}
      </Async>
    </Shell>
  );
}
