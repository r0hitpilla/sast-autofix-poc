import { useCallback, useEffect, useState } from "react";
import { ApiError, getJson } from "./client";

export interface ApiState<T> {
  data: T | null;
  error: ApiError | Error | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Fetch `path` (null = don't fetch). Re-fetches when the path changes,
 * cancels the in-flight request on change/unmount, and optionally polls.
 */
export function useApi<T>(path: string | null, pollMs?: number): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (path === null) return;
    const ctl = new AbortController();
    setLoading(true);
    getJson<T>(path, ctl.signal)
      .then((d) => { setData(d); setError(null); })
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return;
        setError(e instanceof Error ? e : new Error(String(e)));
      })
      .finally(() => { if (!ctl.signal.aborted) setLoading(false); });
    return () => ctl.abort();
  }, [path, tick]);

  useEffect(() => {
    if (!pollMs) return;
    const id = window.setInterval(reload, pollMs);
    return () => window.clearInterval(id);
  }, [pollMs, reload]);

  return { data, error, loading, reload };
}
