/**
 * Which case and evidence the open run belongs to (AXIOM adoption E1). Filled from
 * `GET /api/runs/{id}/processing-snapshot` by `useRunCaseLink` (CaseFeature) and read by command
 * disabled reasons and the citation prefix (사건 번호 · 증거 번호).
 */

import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { create } from "zustand";
import { getProcessingSnapshot, type ProcessingSnapshot } from "../../api/cases";

export interface RunCaseLink {
  caseId: string;
  caseNumber: string;
  evidenceCitationId: string;
  evidenceNumber: string;
  examiner: string;
}

interface CaseLinkState {
  /** runId → link; `null` = loaded, no case; missing key = unknown yet. */
  byRun: Record<string, RunCaseLink | null>;
  /** runId → the snapshot query is in flight (citation copy waits for it). */
  loading: Record<string, boolean>;
  setLink: (runId: string, link: RunCaseLink | null) => void;
  setLoading: (runId: string, loading: boolean) => void;
}

export const useCaseLinks = create<CaseLinkState>((set) => ({
  byRun: {},
  loading: {},
  setLink: (runId, link) => set((state) => ({ byRun: { ...state.byRun, [runId]: link } })),
  setLoading: (runId, loading) =>
    set((state) =>
      Boolean(state.loading[runId]) === loading ? state : { loading: { ...state.loading, [runId]: loading } },
    ),
}));

/** Disabled reason of citation copy while the run's case link is still loading. */
export const CASE_LINK_LOADING_REASON = "케이스 정보를 불러오는 중입니다";

export function linkFromSnapshot(snapshot: ProcessingSnapshot | undefined): RunCaseLink | null {
  if (snapshot?.source !== "case-db" || !snapshot.case_id) return null;
  const caseInfo = snapshot.case ?? snapshot.snapshot.case ?? null;
  const evidence = snapshot.evidence ?? snapshot.snapshot.evidence ?? null;
  return {
    caseId: snapshot.case_id,
    caseNumber: String(caseInfo?.case_number ?? ""),
    evidenceCitationId: String(snapshot.evidence_citation_id ?? ""),
    evidenceNumber: String(evidence?.evidence_number ?? ""),
    examiner: String(caseInfo?.examiner ?? ""),
  };
}

export const snapshotQueryKey = (runId: string) => ["processing-snapshot", runId] as const;

/** Snapshot query for `runId`, mirrored into the link store. */
export function useRunCaseLink(runId: string | null) {
  const setLink = useCaseLinks((s) => s.setLink);
  const setLoading = useCaseLinks((s) => s.setLoading);
  const query = useQuery({
    queryKey: snapshotQueryKey(runId ?? ""),
    queryFn: () => getProcessingSnapshot(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
  const waiting = Boolean(runId) && query.data === undefined && !query.isError;
  useEffect(() => {
    if (runId) setLoading(runId, waiting);
  }, [runId, waiting, setLoading]);
  useEffect(() => {
    if (runId && query.data) setLink(runId, linkFromSnapshot(query.data));
    // A failed snapshot read (run gone) must not keep citations "loading" forever: no case known.
    else if (runId && query.isError) setLink(runId, null);
  }, [runId, query.data, query.isError, setLink]);
  return query;
}

/**
 * Citation copy is blocked while the open run's case link is loading, so a citation is never copied
 * without its 사건/증거 prefix just because the snapshot query had not answered yet.
 */
export function citationDisabledReason(runId: string | null | undefined): string | undefined {
  if (!runId || caseLinkOf(runId) !== undefined) return undefined;
  // Nothing loading (e.g. the viewer window): the copy itself resolves the link first.
  return useCaseLinks.getState().loading[runId] ? CASE_LINK_LOADING_REASON : undefined;
}

const pendingLinks = new Map<string, Promise<RunCaseLink | null>>();

/**
 * The run's case link, fetched when nothing has loaded it yet (the viewer window has no
 * CaseFeature): citation builders await this before reading `caseCitationParts`.
 */
export async function resolveCaseLink(runId: string | null | undefined): Promise<RunCaseLink | null> {
  if (!runId) return null;
  const known = caseLinkOf(runId);
  if (known !== undefined) return known;
  let pending = pendingLinks.get(runId);
  if (!pending) {
    pending = getProcessingSnapshot(runId)
      .then(linkFromSnapshot)
      .catch(() => null)
      .then((link) => {
        useCaseLinks.getState().setLink(runId, link);
        pendingLinks.delete(runId);
        return link;
      });
    pendingLinks.set(runId, pending);
  }
  return pending;
}

/** Link of `runId` as known now (non-hook; commands and citations). */
export function caseLinkOf(runId: string | null | undefined): RunCaseLink | null | undefined {
  if (!runId) return null;
  return useCaseLinks.getState().byRun[runId];
}

/** Citation prefix parts: `사건=…`, `증거=…` (empty when the run has no case). */
export function caseCitationParts(runId: string | null | undefined): string[] {
  const link = caseLinkOf(runId);
  if (!link) return [];
  const parts: string[] = [];
  if (link.caseNumber) parts.push(`사건=${link.caseNumber}`);
  if (link.evidenceNumber) parts.push(`증거=${link.evidenceNumber}`);
  return parts;
}
