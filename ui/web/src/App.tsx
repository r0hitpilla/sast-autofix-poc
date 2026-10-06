import { type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { ApiError } from "./api/client";
import type { Me } from "./api/types";
import { useApi } from "./api/useApi";
import { Shell } from "./components/Shell";
import { Empty, Loading } from "./components/ui";
import { LOGIN_PATH } from "./api/client";
import { can, SessionProvider, useSession } from "./lib/session";
import { Audit } from "./pages/Audit";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Health } from "./pages/Health";
import { Login } from "./pages/Login";
import { Models } from "./pages/Models";
import { NotFound } from "./pages/NotFound";
import { Overview } from "./pages/Overview";
import { PullRequestDetail, PullRequests } from "./pages/PullRequests";
import { Reports } from "./pages/Reports";
import { RunDetail } from "./pages/RunDetail";
import { Runs } from "./pages/Runs";
import { Users } from "./pages/Users";

/** Signed-out visitors go to the sign-in page; signed-in ones get the session. */
function RequireSession({ children }: { children: ReactNode }) {
  const me = useApi<Me>("/auth/me");
  if (me.error instanceof ApiError && me.error.status === 401) return <Navigate to={LOGIN_PATH} replace />;
  if (me.error) return <Shell crumb="Sign in"><Empty>Could not reach the dashboard.</Empty></Shell>;
  if (!me.data) return <Loading />;
  return <SessionProvider me={me.data}>{children}</SessionProvider>;
}

/** A page for certain roles only. The server refuses the data either way. */
function RequirePermission({ permission, children }: { permission: string; children: ReactNode }) {
  const me = useSession();
  if (can(me, permission)) return <>{children}</>;
  return (
    <Shell crumb="Not allowed">
      <Empty>Your role does not include access to this page. Ask an administrator if you need it.</Empty>
    </Shell>
  );
}

const signedIn = (page: ReactNode) => <RequireSession>{page}</RequireSession>;

export function App() {
  return (
    <Routes>
      <Route path={LOGIN_PATH} element={<Login />} />
      <Route path="/" element={signedIn(<Overview />)} />
      <Route path="/findings" element={signedIn(<Findings />)} />
      <Route path="/findings/:id" element={signedIn(<FindingDetail />)} />
      <Route path="/runs" element={signedIn(<Runs />)} />
      <Route path="/runs/:id" element={signedIn(<RunDetail />)} />
      <Route path="/pulls" element={signedIn(<PullRequests />)} />
      <Route path="/pulls/:owner/:name/:number" element={signedIn(<PullRequestDetail />)} />
      <Route path="/models" element={signedIn(<Models />)} />
      <Route path="/reports" element={signedIn(<Reports />)} />
      <Route path="/health" element={signedIn(<Health />)} />
      <Route path="/users" element={signedIn(<RequirePermission permission="users:manage"><Users /></RequirePermission>)} />
      <Route path="/audit" element={signedIn(<RequirePermission permission="audit:read"><Audit /></RequirePermission>)} />
      <Route path="*" element={signedIn(<NotFound />)} />
    </Routes>
  );
}
