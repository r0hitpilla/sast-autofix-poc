export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** GET a JSON API path (relative to /api). Throws ApiError on non-2xx. */
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const resp = await fetch(`/api${path}`, { signal, headers: { Accept: "application/json" } });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = (await resp.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, detail || `HTTP ${resp.status}`);
  }
  return (await resp.json()) as T;
}

export function qs(params: Record<string, string | number | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}
