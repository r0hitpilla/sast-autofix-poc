import { useState } from "react";
import { ApiError, sendJson } from "../api/client";
import type { FindingSummary } from "../api/types";
import { dateTime } from "../lib/format";
import { can, useSession } from "../lib/session";
import { Card, Pill } from "./ui";

const LABEL = { false_positive: "False positive", suppressed: "Suppressed" } as const;

/** A person's decision about a finding: mark false positive, suppress, or reopen. */
export function Decision({ finding, onChange }: { finding: FindingSummary; onChange: () => void }) {
  const me = useSession();
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const allowed = can(me, "findings:act");

  const send = async (decision: "false_positive" | "suppressed" | "open") => {
    setBusy(true);
    setError(null);
    try {
      await sendJson("POST", `/findings/${finding.fingerprint}/decision`, { decision, reason });
      setReason("");
      onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save the decision.");
    } finally {
      setBusy(false);
    }
  };

  const createIssue = async () => {
    setBusy(true);
    setError(null);
    try {
      await sendJson("POST", `/findings/${finding.fingerprint}/issue`, {});
      onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the issue.");
    } finally {
      setBusy(false);
    }
  };

  const current = finding.decision;
  return (
    <Card title="Decision" aside={current ? <Pill tone={current === "false_positive" ? "grey" : "amber"}>{LABEL[current]}</Pill> : null}>
      {current ? (
        <div className="prose" style={{ marginBottom: allowed ? 12 : 0 }}>
          <b>{finding.decided_by}</b> marked this {LABEL[current].toLowerCase()} on {dateTime(finding.decided_at)}:
          <div className="mute" style={{ marginTop: 4 }}>{finding.decision_reason}</div>
        </div>
      ) : (
        <div className="mute" style={{ marginBottom: allowed ? 12 : 0 }}>No decision recorded. The pipeline treats this as open.</div>
      )}
      {allowed && (
        <>
          {!current && (
            <textarea className="input decision-reason" rows={2} maxLength={500} aria-label="Reason"
                      placeholder="Why? (recorded in the audit log)" value={reason}
                      onChange={(e) => setReason(e.target.value)} />
          )}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
            {finding.issue_key ? (
              <a className="btn sm" href={finding.issue_url ?? "#"} target="_blank" rel="noreferrer">Issue {finding.issue_key} ↗</a>
            ) : (
              <button className="btn sm" disabled={busy} onClick={createIssue}>Create issue</button>
            )}
            {current ? (
              <button className="btn sm" disabled={busy} onClick={() => send("open")}>Reopen</button>
            ) : (
              <>
                <button className="btn sm" disabled={busy || reason.trim().length < 3} onClick={() => send("false_positive")}>Mark false positive</button>
                <button className="btn sm" disabled={busy || reason.trim().length < 3} onClick={() => send("suppressed")}>Suppress</button>
              </>
            )}
          </div>
          {error && <div className="login-error" role="alert" style={{ marginTop: 8 }}>{error}</div>}
        </>
      )}
    </Card>
  );
}
