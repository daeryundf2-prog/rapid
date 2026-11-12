import { QueryClientContext, useQuery } from "@tanstack/react-query";
import { useContext, useEffect } from "react";
import { api } from "../api/client";
import { getRunDashboard } from "../api/dashboard";
import { Icon } from "../icons";
import { useAppStore } from "../state/store";
import { readOnlySentence, useReadOnlyReason, useReadOnlyStore } from "./readOnly";
import "./readOnly.css";

/** `GET /api/health` (T-348: `read_only` of a `web --read-only` server; older servers omit it). */
async function getServerReadOnly(): Promise<boolean> {
  const health = await api<{ read_only?: unknown }>("/api/health");
  return health.read_only === true;
}

/**
 * Keeps `useReadOnlyStore` current: the server's switch (once) and the open run's
 * `readonly_reason` (the 접수 dashboard query, shared with the status bar).
 */
function ReadOnlySync() {
  const runId = useAppStore((s) => s.route.runId);
  const server = useQuery({
    queryKey: ["server-read-only"],
    queryFn: getServerReadOnly,
    staleTime: Number.POSITIVE_INFINITY,
    retry: false,
  });
  const dashboard = useQuery({
    queryKey: ["run-dashboard", runId ?? ""],
    queryFn: () => getRunDashboard(runId ?? ""),
    enabled: Boolean(runId),
    retry: false,
  });
  const setRun = useReadOnlyStore((s) => s.setRun);
  const setServerReadOnly = useReadOnlyStore((s) => s.setServerReadOnly);
  const runReason = runId && dashboard.data?.run_id === runId ? dashboard.data.readonly_reason : null;
  useEffect(() => setServerReadOnly(server.data === true), [server.data, setServerReadOnly]);
  useEffect(() => setRun(runId, runReason), [runId, runReason, setRun]);
  return null;
}

/**
 * The read-only band (T-348, design system "읽기 전용 띠"): one line under the top bar on every
 * stage while the open result — or the whole server — is read-only. Neutral colour, lock glyph;
 * write controls stay visible but inert with the same sentence (`useWriteBlock`).
 */
export function ReadOnlyBanner() {
  const client = useContext(QueryClientContext);
  const reason = useReadOnlyReason();
  return (
    <>
      {client ? <ReadOnlySync /> : null}
      {reason ? (
        <div className="readonly-band" data-testid="readonly-band" data-reason={reason}>
          <Icon name="lock" />
          <span>{readOnlySentence(reason)}</span>
        </div>
      ) : null}
    </>
  );
}
