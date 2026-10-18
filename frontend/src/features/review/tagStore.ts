/**
 * Case tags of the open run (AXIOM E3): one small store shared by the tag manager, the digit
 * keys (1–9), the 검토 tree nodes, the propagate command and the grid/viewer chips.
 * Loaded on demand; refreshed after every applied mark (onReviewApplied) and every tag edit.
 */

import { useEffect } from "react";
import { create } from "zustand";
import { getReviewCounts } from "../../api/caseDb";
import type { CaseDbHandle } from "../../api/collections";
import {
  type CaseTag,
  type CaseTagInput,
  createCaseTag,
  deleteCaseTag,
  listCaseTags,
  updateCaseTag,
} from "../../api/reviewTools";
import { ensureRunCaseDb, onReviewApplied } from "../grid/reviewActions";
import { currentReviewer } from "./author";

export type TagLoadStatus = "idle" | "loading" | "ready" | "error";

export interface CaseTagState {
  runId: string | null;
  caseId: string | null;
  /** The run has a case DB (tags exist only then). */
  exists: boolean;
  tags: CaseTag[];
  status: TagLoadStatus;
  error: string | null;
}

const INITIAL: CaseTagState = {
  runId: null,
  caseId: null,
  exists: false,
  tags: [],
  status: "idle",
  error: null,
};

export const useCaseTagStore = create<CaseTagState>(() => ({ ...INITIAL }));

/** Tests. */
export function resetCaseTagStore(): void {
  useCaseTagStore.setState({ ...INITIAL }, true);
  pending.clear();
}

const collator = new Intl.Collator("ko", { numeric: true, sensitivity: "base" });

/** Korean label order (system tags 북마크 · 우선순위 n keep their own order first). */
export function sortTags(tags: readonly CaseTag[]): CaseTag[] {
  return [...tags].sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "system" ? -1 : 1;
    return collator.compare(a.name, b.name);
  });
}

function errorText(error: unknown): string {
  return error instanceof Error && error.message ? error.message : String(error);
}

const pending = new Map<string, Promise<CaseTag[]>>();

/** Load (or reuse) the run's tags; `force` re-reads them. Resolves to the live tags. */
export function loadCaseTags(runId: string, options: { force?: boolean } = {}): Promise<CaseTag[]> {
  const state = useCaseTagStore.getState();
  if (!options.force && state.runId === runId && state.status === "ready") return Promise.resolve(state.tags);
  const inflight = pending.get(runId);
  if (inflight && !options.force) return inflight;
  if (state.runId !== runId) useCaseTagStore.setState({ ...INITIAL, runId, status: "loading" }, true);
  else useCaseTagStore.setState({ status: "loading", error: null });
  const job = (async () => {
    try {
      const counts = await getReviewCounts(runId);
      const caseId = typeof counts?.case_id === "string" ? counts.case_id : "";
      const payload = caseId && counts.exists !== false ? await listCaseTags(runId, caseId) : null;
      const tags = Array.isArray(payload?.tags) ? payload.tags.filter((tag) => !tag.deleted_at) : [];
      if (useCaseTagStore.getState().runId === runId) {
        useCaseTagStore.setState({
          caseId: caseId || null,
          exists: Boolean(payload?.exists),
          tags,
          status: "ready",
          error: null,
        });
      }
      return tags;
    } catch (error) {
      if (useCaseTagStore.getState().runId === runId) {
        useCaseTagStore.setState({ status: "error", error: errorText(error) });
      }
      throw error;
    } finally {
      pending.delete(runId);
    }
  })();
  pending.set(runId, job);
  return job;
}

/** Live tags of the run, loading them when the run changes. */
export function useCaseTags(runId: string | null): CaseTagState {
  const state = useCaseTagStore();
  useEffect(() => {
    if (runId) loadCaseTags(runId).catch(() => undefined);
  }, [runId]);
  return state.runId === runId ? state : { ...INITIAL, runId };
}

/** The tag bound to a digit key in the loaded run, if any. */
export function tagForShortcut(runId: string, digit: number): CaseTag | undefined {
  const state = useCaseTagStore.getState();
  if (state.runId !== runId) return undefined;
  return state.tags.find((tag) => tag.shortcut === digit);
}

/** The run's case DB handle for a tag edit (creates the DB once; Korean error when it cannot). */
export async function tagHandle(runId: string): Promise<CaseDbHandle> {
  const handle = await ensureRunCaseDb(runId);
  if (!handle) throw new Error("이 런에는 케이스 DB를 만들 수 없어 태그를 쓸 수 없습니다.");
  return handle;
}

export async function saveNewTag(runId: string, input: CaseTagInput): Promise<CaseTag> {
  const handle = await tagHandle(runId);
  const { tag } = await createCaseTag(runId, handle.case_id, { ...input, created_by: currentReviewer() });
  await loadCaseTags(runId, { force: true });
  return tag;
}

export async function saveTagChanges(
  runId: string,
  tagId: number,
  input: Partial<CaseTagInput>,
): Promise<CaseTag> {
  const handle = await tagHandle(runId);
  const { tag } = await updateCaseTag(runId, handle.case_id, tagId, { ...input, actor: currentReviewer() });
  await loadCaseTags(runId, { force: true });
  return tag;
}

export async function removeTag(runId: string, tagId: number): Promise<number> {
  const handle = await tagHandle(runId);
  const result = await deleteCaseTag(runId, handle.case_id, tagId, currentReviewer());
  await loadCaseTags(runId, { force: true });
  return result.removed_from_marks ?? 0;
}

// Marks changed → tag counts changed: re-read the loaded run's tags (coalesced).
let refreshTimer: ReturnType<typeof setTimeout> | undefined;
onReviewApplied((runId) => {
  if (useCaseTagStore.getState().runId !== runId) return;
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    loadCaseTags(runId, { force: true }).catch(() => undefined);
  }, 250);
});
