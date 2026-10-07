export function pct(v: number | null | undefined, digits = 1): string {
  return v === null || v === undefined ? "—" : `${(v * 100).toFixed(digits)}%`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

export function ago(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const secs = Math.max(0, (now.getTime() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 7) : "—";
}

/** "↑ 2 vs prev" with good/bad tone; lowerIsBetter for findings counts. */
export function delta(now: number, prev: number, lowerIsBetter = true): { text: string; tone: string } {
  const d = now - prev;
  if (d === 0) return { text: "no change vs previous", tone: "mute" };
  const up = d > 0;
  const good = lowerIsBetter ? !up : up;
  return { text: `${up ? "↑" : "↓"} ${Math.abs(d)} vs previous`, tone: good ? "down-good" : "up-bad" };
}

/** 1_234 -> "1.2k", 3_400_000 -> "3.4M": token counts are read, not computed with. */
export function compact(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
