import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, sendJson } from "../api/client";
import type { IntegrationItem, IntegrationsData, TestResult } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Card, Empty, PageHead, Pill, type Tone } from "../components/ui";
import { can, useSession } from "../lib/session";

const STATUS: Record<IntegrationItem["status"], [string, Tone]> = {
  connected: ["Connected", "green"], failing: ["Failing", "red"], untested: ["Not tested", "amber"],
  not_configured: ["Not configured", "grey"], unavailable: ["Not available yet", "grey"], disabled: ["Disabled", "grey"],
};

export function Integrations() {
  const me = useSession();
  const admin = can(me, "integrations:manage");
  const state = useApi<IntegrationsData>("/integrations");
  const navigate = useNavigate();

  const toggle = async (item: IntegrationItem) => {
    await sendJson("PATCH", `/integrations/${item.key}`, { enabled: !item.enabled });
    state.reload();
  };

  return (
    <Shell crumb="Integrations">
      <PageHead title="Integrations" sub="Connect source control, CI/CD, notifications, ticketing and security tools"
        actions={<button className="btn primary" disabled={!admin} onClick={() => navigate("/integrations/new")}>Create integration</button>} />
      <Async state={state} skeleton={320}>
        {(d) => (
          <>
            {!d.secrets_ready && (
              <div className="pill tone-amber" style={{ whiteSpace: "normal", marginBottom: 12 }}>
                SAST_SECRET_KEY is not set on the server, so integrations can't be saved.
              </div>
            )}
            {d.outbox_pending > 0 && <div className="mute" style={{ marginBottom: 12 }}>{d.outbox_pending} notification(s) waiting to be delivered.</div>}
            {d.categories.map((cat) => (
              <div key={cat.category} style={{ marginBottom: 20 }}>
                <div className="integ-cat">{cat.category}</div>
                <div className="integ-grid">
                  {cat.items.map((i) => {
                    const [label, tone] = STATUS[i.status];
                    return (
                      <div className="card integ-card" key={i.key}>
                        <div className="integ-head"><b>{i.name}</b><Pill tone={tone}>{label}</Pill></div>
                        <div className="integ-meta">{i.last_error ? `Last error: ${i.last_error}` : (i.meta || " ")}</div>
                        {i.builtin ? (
                          <button className="btn sm" disabled>Built in</button>
                        ) : !i.available ? (
                          <button className="btn sm" disabled>Coming later</button>
                        ) : i.configured ? (
                          <div style={{ display: "flex", gap: 6 }}>
                            <button className="btn sm" disabled={!admin} onClick={() => navigate(`/integrations/new?provider=${i.key}`)}>Configure</button>
                            <button className="btn sm" disabled={!admin} onClick={() => toggle(i)}>{i.enabled ? "Disable" : "Enable"}</button>
                          </div>
                        ) : (
                          <button className="btn sm" disabled={!admin} onClick={() => navigate(`/integrations/new?provider=${i.key}`)}>Connect</button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </>
        )}
      </Async>
    </Shell>
  );
}

type Step = "provider" | "auth" | "permissions" | "repos" | "events" | "test" | "done";
const STEP_LABEL: Record<Step, string> = {
  provider: "Select provider", auth: "Authentication", permissions: "Permissions", repos: "Repository selection",
  events: "Events", test: "Test connection", done: "Complete",
};

function stepsFor(item: IntegrationItem | undefined): Step[] {
  if (!item) return ["provider"];
  const steps: Step[] = ["provider", "auth"];
  if (item.permissions.length) steps.push("permissions");
  if (item.fields.some((f) => f.key === "repositories")) steps.push("repos");
  if (item.events.length) steps.push("events");
  return [...steps, "test", "done"];
}

export function IntegrationWizard() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const state = useApi<IntegrationsData>("/integrations");
  const [provider, setProvider] = useState(params.get("provider") ?? "");
  const [values, setValues] = useState<Record<string, string>>({});
  const [events, setEvents] = useState<string[] | null>(null);
  const [step, setStep] = useState<Step>(params.get("provider") ? "auth" : "provider");
  const [results, setResults] = useState<TestResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const all = useMemo(() => state.data?.categories.flatMap((c) => c.items) ?? [], [state.data]);
  const choices = all.filter((i) => i.available && !i.builtin);
  const item = all.find((i) => i.key === provider);
  const steps = stepsFor(item);
  const at = steps.indexOf(step);
  const chosenEvents = events ?? item?.subscribed ?? item?.events.map((e) => e.key) ?? [];
  const value = (k: string) => values[k] ?? (item?.config?.[k] ?? "");

  const body = () => ({ provider, values: Object.fromEntries((item?.fields ?? []).map((f) => [f.key, value(f.key)])), events: chosenEvents });

  const runTest = async () => {
    setBusy(true); setError(null); setResults(null);
    try {
      const r = await sendJson<{ ok: boolean; results: TestResult[] }>("POST", "/integrations/test", body());
      setResults(r.results);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Test failed to run.");
    } finally { setBusy(false); }
  };

  const save = async () => {
    setBusy(true); setError(null);
    try {
      await sendJson("POST", "/integrations", body());
      setStep("done");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not save.");
    } finally { setBusy(false); }
  };

  const next = () => {
    setError(null);
    if (step === "test") return save();
    if (step === "done") return navigate("/integrations");
    const n = steps[at + 1];
    if (n) { setStep(n); if (n === "test") runTest(); }
  };
  const back = () => (at > 0 ? setStep(steps[at - 1]!) : navigate("/integrations"));

  return (
    <Shell crumb={<><Link to="/integrations">Integrations</Link> / Create integration</>}>
      <PageHead title="Create integration" />
      <Async state={state}>
        {() => (
          <>
            <div className="wiz-steps">
              {steps.map((s, i) => (
                <span key={s} className={`wiz-step ${i === at ? "now" : i < at ? "done" : ""}`}>{i + 1} {STEP_LABEL[s]}</span>
              ))}
            </div>
            <Card className="wiz-card">
              <div className="wiz-title">{STEP_LABEL[step]}</div>

              {step === "provider" && (
                <>
                  <div className="mute">Choose the system to connect.</div>
                  <div className="wiz-list">
                    {choices.map((c) => (
                      <label key={c.key} className="wiz-item">
                        <input type="radio" name="provider" checked={provider === c.key}
                               onChange={() => { setProvider(c.key); setValues({}); setEvents(null); setResults(null); }} />
                        {c.name}{c.configured ? <span className="mute"> · already connected</span> : null}
                      </label>
                    ))}
                  </div>
                </>
              )}

              {step === "auth" && item && (
                <>
                  <div className="mute">{item.auth}. Secrets are stored encrypted and masked after saving.</div>
                  {item.fields.filter((f) => f.key !== "repositories").map((f) => (
                    <label key={f.key} className="field">
                      <span>{f.label}{f.required ? "" : " (optional)"}</span>
                      <input className="input wiz-input" type={f.secret ? "password" : "text"} autoComplete="off"
                             placeholder={f.secret && item.secrets_set?.includes(f.key) ? "•••••••• saved (leave blank to keep)" : ""}
                             value={values[f.key] ?? (f.secret ? "" : item.config?.[f.key] ?? "")}
                             onChange={(e) => setValues({ ...values, [f.key]: e.target.value })} />
                    </label>
                  ))}
                </>
              )}

              {step === "permissions" && item && (
                <>
                  <div className="mute">SAST Autofix needs only these. Grant nothing more to the token.</div>
                  <div className="wiz-list">{item.permissions.map((p) => <div key={p} className="wiz-item">✓ <span className="mono">{p}</span></div>)}</div>
                </>
              )}

              {step === "repos" && item && (
                <label className="field">
                  <span>Repositories to check access to (owner/name, comma-separated). Blank checks the token only.</span>
                  <input className="input wiz-input" value={value("repositories")}
                         onChange={(e) => setValues({ ...values, repositories: e.target.value })} />
                </label>
              )}

              {step === "events" && item && (
                <>
                  <div className="mute">Which events send a message.</div>
                  <div className="wiz-list">
                    {item.events.map((e) => (
                      <label key={e.key} className="wiz-item">
                        <input type="checkbox" checked={chosenEvents.includes(e.key)}
                               onChange={(ev) => setEvents(ev.target.checked ? [...chosenEvents, e.key] : chosenEvents.filter((x) => x !== e.key))} />
                        {e.label}
                      </label>
                    ))}
                  </div>
                </>
              )}

              {step === "test" && (
                <>
                  <div className="mute">Checking the connection with the settings above. Saving stores them whatever the result, so a failing connection shows as failing.</div>
                  {busy && !results && <div className="mute">Testing…</div>}
                  {results && (
                    <div className="wiz-list">
                      {results.map((r) => (
                        <div key={r.check} className="wiz-item">
                          <Pill tone={r.ok ? "green" : "red"}>{r.ok ? "✓" : "✗"}</Pill> {r.check} <span className="mute">· {r.detail}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div><button className="btn sm" disabled={busy} onClick={runTest}>Test again</button></div>
                </>
              )}

              {step === "done" && item && <div>{item.name} is saved. Its status on the Integrations page shows whether the last test passed.</div>}
              {!item && step !== "provider" && <Empty>Unknown provider.</Empty>}

              {error && <div className="login-error" role="alert">{error}</div>}
              <div className="wiz-nav">
                <button className="btn" onClick={back} disabled={busy || step === "done"}>Back</button>
                <button className="btn primary" onClick={next} disabled={busy || (step === "provider" && !item)}>
                  {step === "done" ? "Go to integrations" : step === "test" ? "Save" : "Continue"}
                </button>
              </div>
            </Card>
          </>
        )}
      </Async>
    </Shell>
  );
}
