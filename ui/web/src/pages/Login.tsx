import { type FormEvent, useState } from "react";
import { ApiError, sendJson } from "../api/client";

const LIFECYCLE = [
  "Repository", "Scan", "Finding", "Evidence", "AI Investigation", "Laya Decision", "Policy",
  "Autofix", "Validation", "Pull Request", "Human Review", "Security Gate", "Merge",
];

export function Login() {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await sendJson("POST", "/auth/login", { name, password });
      window.location.assign("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach the dashboard. Try again.");
      setBusy(false);
    }
  };

  return (
    <div className="login-grid">
      <div className="login-main">
        <form className="login-form" onSubmit={submit} aria-labelledby="login-title">
          <div className="login-brand"><span className="logo">S</span>SAST Autofix</div>
          <div>
            <h1 id="login-title">Sign in</h1>
            <p className="login-sub">Local AI-powered security remediation</p>
          </div>

          <button type="button" className="login-sso" disabled title="SSO is not configured on this server">
            Continue with SSO (SAML)
          </button>
          <div className="login-or"><span /> or <span /></div>

          <label className="login-field">
            Name
            <input className="login-input" autoComplete="username" required value={name}
                   onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="login-field">
            Password
            <input className="login-input" type="password" autoComplete="current-password" required value={password}
                   onChange={(e) => setPassword(e.target.value)} />
          </label>

          {error && <div className="login-error" role="alert">{error}</div>}
          <button className="login-submit" type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="login-foot">
            Self-hosted. Models run locally on your infrastructure. All sign-ins are recorded in the audit log.
          </p>
        </form>
      </div>
      <aside className="login-side" aria-label="Remediation lifecycle">
        <div className="login-side-title">Remediation lifecycle</div>
        {LIFECYCLE.map((step, i) => (
          <div className="login-step" key={step}>
            <span className="login-step-n">{i + 1}</span>
            {step}
          </div>
        ))}
      </aside>
    </div>
  );
}
