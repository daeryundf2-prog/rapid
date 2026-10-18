import type { GridRow } from "../../contracts/collection";
import { serializeRoute } from "../../router";
import { shiftIso } from "../../utils/time";

/** recovery.source_id → label shown in the 증거 정보 block. */
export const RECOVERY_LABELS: Record<string, string> = {
  "filesystem-scan": "파싱됨",
  "icat-long-path-fallback": "복구(icat)",
  "fls-listing-zero-byte": "목록",
  carving: "카빙",
};

/** Fallback when only `candidate_kind` is known. */
const CANDIDATE_LABELS: Record<string, string> = {
  existing: "파싱됨",
  "deleted-entry": "삭제 항목",
  "orphan-record": "고아 레코드",
  carved: "카빙",
  "partial-corrupt": "부분 손상",
};

const DELETION_LABELS: Record<string, string> = {
  deleted: "삭제됨",
  "deleted-entry": "삭제됨",
  allocated: "삭제되지 않음",
  active: "삭제되지 않음",
  existing: "삭제되지 않음",
  unallocated: "미할당 영역",
  orphan: "고아 레코드",
  unknown: "알 수 없음",
};

export function recoveryLabel(sourceId: string | null, candidateKind?: string | null): string {
  if (sourceId) return RECOVERY_LABELS[sourceId] ?? sourceId;
  if (candidateKind) return CANDIDATE_LABELS[candidateKind] ?? candidateKind;
  return "—";
}

export function deletionLabel(state: string | null): string {
  return state ? (DELETION_LABELS[state] ?? state) : "—";
}

export interface EvidenceInfo {
  sourceId: string | null;
  recovery: string;
  deletionState: string | null;
  deletion: string;
  offset: number | null;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function offsetOf(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return Math.floor(value);
  if (typeof value === "string" && /^(0x[0-9a-f]+|\d+)$/i.test(value.trim())) {
    return Number(value.trim());
  }
  return null;
}

/**
 * Reads recovery metadata from a grid row. The files collection exposes the raw
 * `recovery` object (or flat `recoverySourceId` / `deletionState` / `sourceOffset`
 * fields); artifact rows carry it under `artifact_record.recovery`. Rows that only say
 * `details.recovery_method = "carved"` (carve analysis rows, R3 §3.3) read as 카빙 at
 * `details.source_offset` (else `details.offset`).
 */
export function evidenceInfo(row: GridRow | null): EvidenceInfo {
  const fields = row?.fields ?? {};
  const nested = {
    ...record(record(fields.artifact_record).recovery),
    ...record(fields.recovery),
  };
  const details = record(fields.details);
  const carvedDetail = text(details.recovery_method) === "carved";
  const sourceId = text(fields.recoverySourceId) ?? text(nested.source_id);
  const candidateKind =
    typeof fields.recovery === "string"
      ? fields.recovery
      : (text(nested.candidate_kind) ?? (carvedDetail ? "carved" : null));
  const deletionState = text(fields.deletionState) ?? text(nested.deletion_state);
  const offset =
    offsetOf(fields.sourceOffset) ??
    offsetOf(nested.source_offset) ??
    (carvedDetail ? (offsetOf(details.source_offset) ?? offsetOf(details.offset)) : null);
  return {
    sourceId,
    recovery: recoveryLabel(sourceId, candidateKind),
    deletionState,
    deletion: deletionLabel(deletionState),
    offset,
  };
}

/** Matches API/network failures that mean "the source file is not there". */
export function isSourceMissing(error: string | null): boolean {
  return !!error && /404|not found|no such file|찾을 수 없|존재하지 않/i.test(error);
}

/** `#/case/{run}/timeline?from=<t-1h>&to=<t+1h>` for a timestamp (null when unparseable). */
export function timelineWindowHash(runId: string, timestamp: string | number, tz?: string): string | null {
  const from = shiftIso(timestamp, -3_600_000);
  const to = shiftIso(timestamp, 3_600_000);
  if (!from || !to) return null;
  return serializeRoute({ runId, collection: "timeline", from, to, ...(tz ? { tz } : {}) });
}
