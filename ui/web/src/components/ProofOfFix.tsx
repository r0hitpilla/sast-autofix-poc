import type { ProofRecord } from "../api/types";
import { Card, Pill, type Tone } from "./ui";

const STATUS: Record<string, [string, Tone, string]> = {
  proven: ["Attack blocked", "green", "An exploit test attacked the original code and succeeded there; it no longer succeeds with this fix. It is part of the PR as a regression test. It shows this attack is blocked, not that every variant is."],
  refuted: ["Attack still works", "red", "The exploit test still succeeds against this fix. Review this fix with extra care."],
  unproven: ["Not shown", "amber", "No valid exploit test could be produced or run, so there is no claim either way. The other checks still apply."],
};

/** What an exploit test showed about a fix. Nothing is shown for findings the scanner proves alone. */
export function ProofOfFix({ proof }: { proof: ProofRecord | null | undefined }) {
  if (!proof || !STATUS[proof.status]) return null;
  const [label, tone, meaning] = STATUS[proof.status]!;
  return (
    <Card title="Proof of fix" aside={<Pill tone={tone}>{label}</Pill>}>
      <div className="prose">{meaning}</div>
      {proof.reason && proof.status !== "proven" && <div className="mute" style={{ marginTop: 6 }}>{proof.reason}</div>}
      {proof.test && (
        <div className="mute mono" style={{ fontSize: 12, marginTop: 8 }}>
          {proof.test}{proof.model ? ` · written by ${proof.model}` : ""}{proof.attempts ? ` · attempt ${proof.attempts}` : ""}
        </div>
      )}
      {proof.code && (
        <details style={{ marginTop: 10 }}><summary>The exploit test</summary>
          <pre className="code" style={{ margin: "8px 0 0", padding: 12, whiteSpace: "pre-wrap" }}>{proof.code}</pre></details>
      )}
      {proof.vulnerable_output && (
        <details style={{ marginTop: 8 }}><summary>Why it failed on the original code</summary>
          <pre className="code" style={{ margin: "8px 0 0", padding: 12, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{proof.vulnerable_output}</pre></details>
      )}
      {proof.status === "refuted" && proof.fixed_output && (
        <details open style={{ marginTop: 8 }}><summary>Why it still fails with the fix</summary>
          <pre className="code" style={{ margin: "8px 0 0", padding: 12, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{proof.fixed_output}</pre></details>
      )}
    </Card>
  );
}
