import { type FormEvent, useState } from "react";
import { ApiError, sendJson } from "../api/client";
import type { UserRow } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Card, DataTable, Empty, PageHead, Pill } from "../components/ui";
import { dateTime } from "../lib/format";
import { ROLE_OPTIONS } from "../lib/roles";
import { useSession } from "../lib/session";

function AddUser({ onAdded }: { onAdded: () => void }) {
  const [form, setForm] = useState({ email: "", name: "", role: "developer", password: "" });
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await sendJson("POST", "/users", form);
      setForm({ email: "", name: "", role: "developer", password: "" });
      onAdded();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not add the user.");
    }
  };
  return (
    <Card title="Add a user">
      <form onSubmit={submit} className="user-form">
        <input className="input" type="email" required placeholder="work email" aria-label="Work email"
               value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input className="input" placeholder="name" aria-label="Name"
               value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <select className="select" aria-label="Role" value={form.role}
                onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {ROLE_OPTIONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
        </select>
        <input className="input" type="password" required minLength={12} placeholder="initial password (12+ characters)"
               aria-label="Initial password" value={form.password}
               onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button className="btn primary" type="submit">Add user</button>
      </form>
      {error && <div className="pill tone-red" role="alert" style={{ whiteSpace: "normal", marginTop: 10 }}>{error}</div>}
    </Card>
  );
}

export function Users() {
  const me = useSession();
  const users = useApi<{ items: UserRow[] }>("/users");
  const [notice, setNotice] = useState<string | null>(null);

  const update = async (user: UserRow, body: Record<string, unknown>) => {
    setNotice(null);
    try {
      await sendJson("PATCH", `/users/${user.id}`, body);
      setNotice(`Saved ${user.email}.`);
      users.reload();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "Could not save.");
    }
  };

  return (
    <Shell crumb="Users & roles">
      <PageHead title="Users & roles" sub="Who can sign in to this dashboard, and what each role can do." />
      <AddUser onAdded={users.reload} />
      {notice && <div className="pill tone-amber" role="status" style={{ whiteSpace: "normal", margin: "12px 0" }}>{notice}</div>}
      <Async state={users} skeleton={220}>
        {(d) => (
          <Card flush>
            <div style={{ paddingTop: 4 }} />
            <DataTable rowKey={(u) => u.id} rows={d.items}
              empty={<Empty>No users yet.</Empty>}
              columns={[
                { header: "User", width: "1.4fr", cell: (u) => <span><b>{u.name || u.email}</b><br /><span className="mono mute" style={{ fontSize: 12 }}>{u.email}</span></span> },
                { header: "Role", width: "1.2fr", cell: (u) => (
                  <select className="select" aria-label={`Role for ${u.email}`} value={u.role} disabled={u.id === me.id}
                          onChange={(e) => update(u, { role: e.target.value })}>
                    {ROLE_OPTIONS.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                  </select>
                ) },
                { header: "Status", width: ".8fr", cell: (u) => <Pill tone={u.active ? "green" : "grey"}>{u.active ? "Active" : "Disabled"}</Pill> },
                { header: "Last sign-in", width: "1fr", cell: (u) => dateTime(u.last_login_at) },
                { header: "", width: ".8fr", cell: (u) => (
                  <button className="btn sm" disabled={u.id === me.id}
                          onClick={() => update(u, { active: !u.active })}>
                    {u.active ? "Disable" : "Enable"}
                  </button>
                ) },
              ]} />
          </Card>
        )}
      </Async>
    </Shell>
  );
}
