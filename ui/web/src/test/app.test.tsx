import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { ago, delta, duration, pct } from "../lib/format";
import { finding, overview, run } from "./fixtures";

type Routes = Record<string, unknown | (() => Response)>;

/** Route /api/* fetches to fixtures; anything else 404s. */
function mockApi(routes: Routes) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = new URL(String(input), "http://x");
    const key = url.pathname.replace(/^\/api/, "");
    const hit = Object.entries(routes).find(([k]) => k === key || (k.endsWith("*") && key.startsWith(k.slice(0, -1))));
    if (!hit) return new Response(JSON.stringify({ detail: "not found" }), { status: 404 });
    const v = hit[1] as unknown;
    if (typeof v === "function") return (v as () => Response)();
    if (v && typeof v === "object" && "status" in v && "body" in v) {
      const { status, body } = v as { status: number; body: unknown };
      return new Response(JSON.stringify(body), { status });
    }
    return new Response(JSON.stringify(v), { status: 200 });
  });
}

const admin = {
  id: 1, email: "admin@example.com", name: "Admin", role: "admin", role_label: "Admin",
  permissions: ["dashboard:read", "findings:act", "users:manage", "audit:read", "integrations:read", "integrations:manage"],
};

const shellApi = {
  "/auth/me": admin,
  "/meta": { version: "1.0.0", repositories: ["o/r"] },
  "/findings": { total: 6, items: [] },
  "/prs": { items: [] },
  "/health": { services: { database: { ok: true } } },
};

const at = (path: string) => render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);

describe("format", () => {
  it("formats numbers for display", () => {
    expect(pct(0.3333)).toBe("33.3%");
    expect(pct(null)).toBe("—");
    expect(duration(420)).toBe("7m 00s");
    expect(duration(3.2)).toBe("3s");
    expect(ago("2026-10-06T10:00:00Z", new Date("2026-10-06T12:00:00Z"))).toBe("2h ago");
    expect(delta(6, 2)).toEqual({ text: "↑ 4 vs previous", tone: "up-bad" });
    expect(delta(1, 3, false).tone).toBe("up-bad");
  });
});

describe("pages", () => {
  it("overview shows KPIs, posture, activity and runs", async () => {
    mockApi({ ...shellApi, "/overview": overview });
    at("/");
    expect(await screen.findByText("Open findings", { selector: ".kpi-l" })).toBeInTheDocument();
    expect(screen.getByText("33.3%")).toBeInTheDocument();
    expect(screen.getByText("app.py:117 · PR #7")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /101/ })).toHaveAttribute("href", "/runs/101");
  });

  it("shows an error with a working retry", async () => {
    let calls = 0;
    mockApi({ ...shellApi, "/overview": () => {
      calls += 1;
      return calls === 1 ? new Response(JSON.stringify({ detail: "database down" }), { status: 500 })
                         : new Response(JSON.stringify(overview));
    } });
    at("/");
    expect(await screen.findByRole("alert")).toHaveTextContent("database down");
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Open findings", { selector: ".kpi-l" })).toBeInTheDocument();
  });

  it("finding detail renders code, Laya's questions and the applied fix", async () => {
    mockApi({ ...shellApi, "/findings/5": finding });
    at("/findings/5");
    expect(await screen.findByText("Is the input validated?")).toBeInTheDocument();
    expect(screen.getByText("TRUE POSITIVE")).toBeInTheDocument();
    expect(screen.getByText("89%")).toBeInTheDocument();
    expect(screen.getByText("nothing restricts the host")).toBeInTheDocument();  // verdict split out
    expect(screen.getByText("FLAGGED")).toBeInTheDocument();
    expect(screen.getByText(/if urlparse\(next\)\.netloc: abort\(403\)/)).toBeInTheDocument();
  });

  it("runs page paginates", async () => {
    const fetchSpy = mockApi({ ...shellApi, "/runs": { total: 30, items: Array.from({ length: 25 }, (_, i) => ({ ...run, id: String(i) })) } });
    at("/runs");
    expect(await screen.findByText("Showing 1–25 of 30")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Next ›" }));
    await waitFor(() => expect(fetchSpy.mock.calls.some(([u]) => String(u).includes("offset=25"))).toBe(true));
  });

  it("empty states explain what to do", async () => {
    mockApi({ ...shellApi, "/overview": { ...overview, repositories: [], recent_runs: [], activity: [] } });
    at("/");
    expect(await screen.findByText(/Push a branch to start the first scan/)).toBeInTheDocument();
  });

  it("unknown routes get a not-found page", async () => {
    mockApi(shellApi);
    at("/nope");
    expect(await screen.findByText(/This page doesn’t exist/)).toBeInTheDocument();
  });
});

describe("sign-in", () => {
  it("shows the sign-in page when there is no session", async () => {
    mockApi({ "/auth/me": { status: 401, body: { detail: "sign in required" } } });
    at("/");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("shows user administration and the audit log only to roles that have them", async () => {
    mockApi({ ...shellApi, "/auth/me": { ...admin, role: "developer", role_label: "Developer",
                                         permissions: ["dashboard:read"] } });
    at("/");
    await screen.findAllByText("Overview");
    expect(screen.queryByText("Users & roles")).not.toBeInTheDocument();
    expect(screen.queryByText("Audit Log")).not.toBeInTheDocument();
  });
});

describe("integrations", () => {
  const item = (key: string, name: string, status: string, extra = {}) => ({
    key, name, available: status !== "unavailable", builtin: false, auth: null, permissions: [], fields: [],
    events: [], status, meta: "", configured: status === "connected", ...extra,
  });

  it("lists providers by category with their real status", async () => {
    mockApi({ ...shellApi, "/integrations": {
      outbox_pending: 0, secrets_ready: true,
      categories: [
        { category: "Notifications", items: [item("slack", "Slack", "connected", { enabled: true })] },
        { category: "Source control", items: [item("gitlab", "GitLab", "unavailable")] },
      ],
    } });
    at("/integrations");
    expect(await screen.findByText("Slack")).toBeInTheDocument();
    expect(screen.getByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Not available yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Coming later" })).toBeDisabled();
  });
});

describe("policies", () => {
  it("explains the strict default and needs a note before publishing", async () => {
    const strict = { severity_actions: { Critical: "block", High: "block", Medium: "block", Low: "block" },
                     decisions_clear_blocks: false, autofix: true, never_autofix: [], repositories: ["*"], branches: ["*"] };
    mockApi({ ...shellApi, "/policy": { name: "Production Security Policy", active: null, default: strict,
                                         always_never_autofix: [".github/**"], versions: [], repositories: [] } });
    at("/policies");
    expect(await screen.findByText(/strict default applies/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Publish v1" })).toBeDisabled();
  });
});

describe("AI usage", () => {
  const row = (extra = {}) => ({ calls: 4, prompt_tokens: 12000, completion_tokens: 3400, total_tokens: 15400,
                                 duration_ms: 42000, errors: 0, avg_ms: 10500, ...extra });
  const models = { ollama: { online: true, version: "0.9", api_latency_ms: 4, models: [] }, provenance: null };

  it("shows tokens and time by model and purpose on the Models page", async () => {
    mockApi({ ...shellApi, "/models": models, "/usage": {
      runs: 3, totals: row(),
      by_model: [{ ...row(), model: "qwen3.5:35b-a3b", provider: "ollama" },
                 { ...row({ prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }), model: "laya", provider: "laya" }],
      by_purpose: [{ ...row(), purpose: "fix" }, { ...row(), purpose: "laya_triage" }],
      by_day: [{ ...row(), day: "2026-10-07" }],
      top_runs: [{ ...row(), run_id: "42", repository: "o/r", branch: "main", started_at: null }],
    } });
    at("/models");
    expect(await screen.findByText("AI usage, last 30 days")).toBeInTheDocument();
    expect(screen.getByText("qwen3.5:35b-a3b")).toBeInTheDocument();
    expect(screen.getByText("Fix writing")).toBeInTheDocument();
    expect(screen.getByText("Laya: finding score")).toBeInTheDocument();
    expect(screen.getAllByText("15k").length).toBeGreaterThan(0);        // 15,400 tokens, read not counted
  });

  it("says so when nothing has been recorded yet", async () => {
    mockApi({ ...shellApi, "/models": models, "/usage": {
      runs: 0, totals: row({ calls: 0, total_tokens: 0 }), by_model: [], by_purpose: [], by_day: [], top_runs: [] } });
    at("/models");
    expect(await screen.findByText(/No AI calls recorded in the last 30 days/)).toBeInTheDocument();
  });
});

describe("proof of fix", () => {
  const withProof = (proof: object) => ({
    ...finding, fix: { validated: true, scanner_clean: true, attempts: 1, failure: null, note: null,
                       diff: "+x\n", created_files: [], check_output: null, last_proposal: null, proof },
  });

  it("shows a proven fix with the test that proves it", async () => {
    mockApi({ ...shellApi, "/findings/5": withProof({ status: "proven", test: "tests/test_security_cwe601_app_117.py",
                                                        model: "qwen3-coder", attempts: 2, code: "def test_proof_redirect(): ..." }) });
    at("/findings/5");
    expect(await screen.findByText("Proof of fix")).toBeInTheDocument();
    expect(screen.getByText("Attack blocked")).toBeInTheDocument();
    expect(screen.getByText(/tests\/test_security_cwe601_app_117.py/)).toBeInTheDocument();
    expect(screen.getByText("The exploit test")).toBeInTheDocument();
  });

  it("flags a refuted fix and shows why the exploit still works", async () => {
    mockApi({ ...shellApi, "/findings/5": withProof({ status: "refuted", fixed_output: "assert 'evil.example' not in location" }) });
    at("/findings/5");
    expect(await screen.findByText("Attack still works")).toBeInTheDocument();
    expect(screen.getByText(/assert 'evil.example' not in location/)).toBeInTheDocument();
  });

  it("shows nothing for findings the scanner proves on its own", async () => {
    mockApi({ ...shellApi, "/findings/5": withProof({ status: "not_applicable", reason: "the scanner is the proof" }) });
    at("/findings/5");
    await screen.findByText("Applied fix");
    expect(screen.queryByText("Proof of fix")).not.toBeInTheDocument();
  });
});
