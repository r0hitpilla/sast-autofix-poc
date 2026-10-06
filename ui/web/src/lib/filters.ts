import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

export const WINDOWS = [
  { days: 1, label: "Last 24 hours" },
  { days: 7, label: "Last 7 days" },
  { days: 30, label: "Last 30 days" },
  { days: 90, label: "Last 90 days" },
];

/** Global filters (repository, time window, search) live in the URL. */
export function useFilters() {
  const [params, setParams] = useSearchParams();
  const repo = params.get("repo") || null;
  const days = Number(params.get("days")) || 7;
  const q = params.get("q") || "";
  const set = useCallback((patch: Record<string, string | number | null>) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) {
        if (v === null || v === "") next.delete(k);
        else next.set(k, String(v));
      }
      return next;
    }, { replace: true });
  }, [setParams]);
  const search = params.toString() ? `?${params.toString()}` : "";
  return { repo, days, q, set, search };
}

/** Keep only the global filter params when linking between pages. */
export function carry(search: string): string {
  const p = new URLSearchParams(search);
  const keep = new URLSearchParams();
  for (const k of ["repo", "days"]) { const v = p.get(k); if (v) keep.set(k, v); }
  const s = keep.toString();
  return s ? `?${s}` : "";
}
