export function CodeView({ lines }: { lines: { n: number; text: string; flagged: boolean }[] }) {
  return (
    <div className="code" aria-label="Source code">
      {lines.map((l) => (
        <div key={l.n} className={`code-line ${l.flagged ? "flag" : ""}`}>
          <span className="ln">{l.n}</span><span className="tx">{l.text}</span>
          {l.flagged && <span className="tag">FLAGGED</span>}
        </div>
      ))}
    </div>
  );
}

/** Render a unified diff with per-line add/remove highlighting. */
export function DiffView({ diff }: { diff: string }) {
  const lines = diff.replace(/\n$/, "").split("\n");
  return (
    <div className="code" aria-label="Diff">
      {lines.map((l, i) => {
        if (l.startsWith("--- ") || l.startsWith("+++ ")) {
          return l.startsWith("+++ ") ? <div key={i} className="diff-file">{l.slice(4).replace(/^b\//, "")}</div> : null;
        }
        const cls = l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "";
        return <div key={i} className={`diff-line ${cls}`}>{l || " "}</div>;
      })}
    </div>
  );
}
