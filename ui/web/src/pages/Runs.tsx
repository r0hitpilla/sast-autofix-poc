import { useState } from "react";
import { qs } from "../api/client";
import type { Paged, RunSummary } from "../api/types";
import { useApi } from "../api/useApi";
import { Shell } from "../components/Shell";
import { Async, Card, PageHead } from "../components/ui";
import { carry, useFilters } from "../lib/filters";
import { RunsTable } from "./Overview";

const PAGE = 25;

export function Runs() {
  const { repo, days, search } = useFilters();
  const [page, setPage] = useState(0);
  const state = useApi<Paged<RunSummary>>(`/runs${qs({ repository: repo, days, limit: PAGE, offset: page * PAGE })}`, 60000);
  return (
    <Shell crumb="Autofix Runs">
      <PageHead title="Autofix Runs" sub="Scan → triage → fix → validate → publish, one run per branch push" />
      <Async state={state}>
        {(d) => (
          <Card flush>
            <div style={{ paddingTop: 4 }} />
            <RunsTable runs={d.items} link={carry(search)} />
            <div className="table-foot">
              <span>Showing {d.items.length ? page * PAGE + 1 : 0}–{page * PAGE + d.items.length} of {d.total}</span>
              <span style={{ display: "flex", gap: 6 }}>
                <button className="btn sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>‹ Prev</button>
                <button className="btn sm" disabled={(page + 1) * PAGE >= d.total} onClick={() => setPage((p) => p + 1)}>Next ›</button>
              </span>
            </div>
          </Card>
        )}
      </Async>
    </Shell>
  );
}
