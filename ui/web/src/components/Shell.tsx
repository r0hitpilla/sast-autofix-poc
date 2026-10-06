import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { qs, sendJson, LOGIN_PATH } from "../api/client";
import type { Health, Meta, Paged, FindingSummary, PrSummary } from "../api/types";
import { useApi } from "../api/useApi";
import { WINDOWS, carry, useFilters } from "../lib/filters";
import { ROLE_OPTIONS } from "../lib/roles";
import { can, useSession } from "../lib/session";
import { useTheme } from "../lib/theme";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/findings", label: "Findings", badge: "findings" },
  { to: "/runs", label: "Autofix Runs" },
  { to: "/pulls", label: "Pull Requests", badge: "prs" },
  { to: "/models", label: "Models" },
  { to: "/reports", label: "Reports" },
  { to: "/health", label: "System Health" },
  { to: "/users", label: "Users & roles", perm: "users:manage" },
  { to: "/audit", label: "Audit Log", perm: "audit:read" },
] as const;

export function Shell({ crumb, children }: { crumb: ReactNode; children: ReactNode }) {
  const { repo, days, q, set, search } = useFilters();
  const [theme, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const meta = useApi<Meta>("/meta");
  const findings = useApi<Paged<FindingSummary>>(`/findings${qs({ state: "open", repository: repo, limit: 1 })}`, 60000);
  const prs = useApi<{ items: PrSummary[] }>(`/prs${qs({ repository: repo })}`, 60000);
  const health = useApi<Health>("/health", 30000);
  const [query, setQuery] = useState(q);
  const me = useSession();
  const roleLabel = ROLE_OPTIONS.find((r) => r.value === me.role)?.label ?? me.role;
  const signOut = async () => {
    try {
      await sendJson("POST", "/auth/logout", {});
    } finally {
      window.location.assign(LOGIN_PATH);
    }
  };

  useEffect(() => setOpen(false), [location.pathname]);
  useEffect(() => setQuery(q), [q]);

  const badges: Record<string, string> = {
    findings: findings.data ? String(findings.data.total) : "",
    prs: prs.data ? String(prs.data.items.filter((p) => p.gate_passed === false).length || "") : "",
  };
  const down = health.data ? Object.entries(health.data.services).filter(([, s]) => !s.ok).map(([k]) => k) : [];
  const sysText = health.error ? "Status unavailable" : !health.data ? "Checking status…"
    : down.length ? `Degraded: ${down.join(", ").replace(/_/g, " ")}` : "All systems operational";

  const onSearch = (e: FormEvent) => {
    e.preventDefault();
    navigate(`/findings${carry(search)}${carry(search) ? "&" : "?"}q=${encodeURIComponent(query)}`);
  };

  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`} aria-label="Main navigation">
        <NavLink to={`/${carry(search)}`} className="brand"><span className="logo">S</span>SAST Autofix</NavLink>
        <nav className="nav">
          {NAV.filter((n) => !("perm" in n) || can(me, n.perm)).map((n) => (
            <NavLink key={n.to} to={`${n.to}${carry(search)}`} end={"end" in n ? n.end : false}
                     className={({ isActive }) => (isActive ? "active" : "")}>
              <span>{n.label}</span>
              {"badge" in n && <span className="badge">{badges[n.badge]}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="sys" role="status"><span className={`dot ${health.data ? (down.length ? "bad" : "ok") : ""}`} />{sysText}</div>
          <div className="who">
            <span className="avatar" aria-hidden="true">{(me.name || me.email).charAt(0).toUpperCase()}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={me.email}>{me.name || me.email}</div>
              <div className="mono mute" style={{ fontSize: 11 }}>{roleLabel}{meta.data ? ` · v${meta.data.version}` : ""}</div>
            </div>
            <button className="btn sm" onClick={toggleTheme} aria-label="Toggle dark mode">{theme === "dark" ? "Light" : "Dark"}</button>
            <button className="btn sm" onClick={signOut}>Sign out</button>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="btn sm menu-btn" onClick={() => setOpen((o) => !o)} aria-label="Open navigation" aria-expanded={open}>☰</button>
          <div className="crumbs"><span>SAST Autofix</span><span>/</span><b>{crumb}</b></div>
          <label className="sr-only" htmlFor="repo-filter">Repository</label>
          <select id="repo-filter" className="select mono" value={repo ?? ""} onChange={(e) => set({ repo: e.target.value || null })}>
            <option value="">all repositories</option>
            {meta.data?.repositories.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <label className="sr-only" htmlFor="window-filter">Time window</label>
          <select id="window-filter" className="select" value={days} onChange={(e) => set({ days: Number(e.target.value) })}>
            {WINDOWS.map((w) => <option key={w.days} value={w.days}>{w.label}</option>)}
          </select>
          <form onSubmit={onSearch} role="search">
            <label className="sr-only" htmlFor="search">Search findings</label>
            <input id="search" className="input" placeholder="Search findings: file, rule, CWE" value={query}
                   onChange={(e) => setQuery(e.target.value)} />
          </form>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
