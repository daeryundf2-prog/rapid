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
  setLink: (runId: string, link: RunCaseLink | null) => void;
}

export const useCaseLinks = create<CaseLinkState>((set) => ({
  byRun: {},
  setLink: (runId, link) => set((state) => ({ byRun: { ...state.byRun, [runId]: link } })),
}));

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
  const query = useQuery({
    queryKey: snapshotQueryKey(runId ?? ""),
    queryFn: () => getProcessingSnapshot(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
  useEffect(() => {
    if (runId && query.data) setLink(runId, linkFromSnapshot(query.data));
  }, [runId, query.data, setLink]);
  return query;
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
