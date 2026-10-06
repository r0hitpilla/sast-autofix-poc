import { Route, Routes } from "react-router-dom";
import { FindingDetail } from "./pages/FindingDetail";
import { Findings } from "./pages/Findings";
import { Health } from "./pages/Health";
import { Models } from "./pages/Models";
import { NotFound } from "./pages/NotFound";
import { Overview } from "./pages/Overview";
import { PullRequestDetail, PullRequests } from "./pages/PullRequests";
import { Reports } from "./pages/Reports";
import { RunDetail } from "./pages/RunDetail";
import { Runs } from "./pages/Runs";

export function App() {
  return (
    <Routes>
      <Route path="/" element={<Overview />} />
      <Route path="/findings" element={<Findings />} />
      <Route path="/findings/:id" element={<FindingDetail />} />
      <Route path="/runs" element={<Runs />} />
      <Route path="/runs/:id" element={<RunDetail />} />
      <Route path="/pulls" element={<PullRequests />} />
      <Route path="/pulls/:owner/:name/:number" element={<PullRequestDetail />} />
      <Route path="/models" element={<Models />} />
      <Route path="/reports" element={<Reports />} />
      <Route path="/health" element={<Health />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
