export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** Where a signed-out visitor is sent. */
export const LOGIN_PATH = "/login";

async function parse<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    if (resp.status === 401 && !window.location.pathname.startsWith(LOGIN_PATH)) {
      // The session ended (signed out elsewhere, expired, or disabled): sign in again.
      window.location.assign(LOGIN_PATH);
    }
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

/** Send a JSON body (POST, PATCH). The server refuses any other content type for changes. */
export async function sendJson<T>(method: "POST" | "PATCH" | "DELETE", path: string, body: unknown): Promise<T> {
  const resp = await fetch(`/api${path}`, {
    method, credentials: "same-origin",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return parse<T>(resp);
}

/** GET a JSON API path (relative to /api). Throws ApiError on non-2xx. */
export async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const resp = await fetch(`/api${path}`, { signal, credentials: "same-origin", headers: { Accept: "application/json" } });
  return parse<T>(resp);
}

export function qs(params: Record<string, string | number | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}
