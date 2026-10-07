import type { RuleRow } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Card, DataTable, Empty, M, N, PageHead, Pill, SeverityPill } from "../components/ui";
import { dateTime } from "../lib/format";

const ACTION = { block: ["Block merge", "red"], review: ["Review required", "amber"], allow: ["Allow", "green"] } as const;

export function Rules() {
  const state = useApi<{ policy_version: number | null; total: number; items: RuleRow[] }>("/rules");
  return (
    <Shell crumb="Rules">
      <PageHead title="Rules" sub="Every rule that has produced a finding: Semgrep packs, custom rules, gitleaks and osv-scanner." />
      <Async state={state} skeleton={260}>
        {(d) => (
          <Card flush>
            <div style={{ paddingTop: 4 }} />
            <DataTable rowKey={(r) => r.rule_id} rows={d.items} empty={<Empty>No findings recorded yet.</Empty>}
              columns={[
                { header: "Rule ID", width: "2fr", cell: (r) => <M>{r.rule_id}</M> },
                { header: "CWE", width: ".7fr", cell: (r) => <M>{r.cwe}</M> },
                { header: "Severity", width: ".8fr", cell: (r) => <SeverityPill severity={r.severity} /> },
                { header: "Pack", width: "1.2fr", cell: (r) => r.pack },
                { header: "Findings", width: ".6fr", cell: (r) => <N>{r.findings}</N> },
                { header: "Last seen", width: "1fr", cell: (r) => dateTime(r.last_seen) },
                { header: `Policy ${d.policy_version ? `v${d.policy_version}` : "(strict default)"}`, width: "1.1fr",
                  cell: (r) => <Pill tone={ACTION[r.gate_action][1]}>{ACTION[r.gate_action][0]}</Pill> },
              ]} />
            <div className="table-foot"><span>{d.total} rule(s)</span></div>
          </Card>
        )}
      </Async>
    </Shell>
  );
}
