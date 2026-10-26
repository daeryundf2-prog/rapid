/**
 * R7 stage 1 re-review R-2 (UI) · R-9 (UI): what the files grid says about its time basis and
 * about a sort the server could not apply.
 *
 * Backend contract (concurrent lane; every field optional, an older server sends none of them):
 * - files page `time_basis`: "ntfs" | "acquisition-copy" | "mixed" — which times the time
 *   conditions and the 수정 sort use. "acquisition-copy" = no NTFS time joined, so the times are
 *   when the evidence was copied, not when the files changed.
 * - files `sort` descriptor `empty` (the column has no values: sorting changes nothing),
 *   `applied` (false = not sorted) and `reason` (Korean, why not).
 */
import type { ServerSortState } from "../../contracts/collection";
import type { FilterState } from "../filters/filterModel";

export type FilesTimeBasis = "ntfs" | "acquisition-copy" | "mixed";

/** The page's `time_basis`, null when absent / unknown (older server). */
export function timeBasisOf(meta: Record<string, unknown> | undefined): FilesTimeBasis | null {
  const value = meta?.time_basis;
  return value === "ntfs" || value === "acquisition-copy" || value === "mixed" ? value : null;
}

export const ACQUISITION_COPY_BANNER = "시간 조건·정렬은 취득 사본 시각 기준입니다(NTFS 시각 없음)";
export const MIXED_TIME_BANNER = "일부 파일은 NTFS 시각이 없어 시간 조건·정렬이 취득 사본 시각 기준입니다";

/** One-line banner of the files grid; null when the times are NTFS times (or unknown). */
export function timeBasisBanner(basis: FilesTimeBasis | null): string | null {
  if (basis === "acquisition-copy") return ACQUISITION_COPY_BANNER;
  if (basis === "mixed") return MIXED_TIME_BANNER;
  return null;
}

/** A time condition is set (기간 · 요일 · 시간대 · 업무 외 시간). */
export function timeConditionActive(filters: Partial<FilterState>): boolean {
  return Boolean(filters.from || filters.to || filters.weekdays?.length || filters.hours || filters.offhours);
}

/** Empty state of a files grid whose time condition matched nothing on acquisition-copy times. */
export function timeBasisEmptyText(basis: FilesTimeBasis | null): string | null {
  if (basis === "acquisition-copy") {
    return (
      "시간 조건에 맞는 파일이 없습니다 — 이 런의 파일 시각은 취득 사본 시각(증거를 복사한 시점)뿐이라 " +
      "NTFS 시각 기준의 기간·요일과 맞지 않을 수 있습니다. 시간 조건을 지우거나 넓혀 보세요."
    );
  }
  if (basis === "mixed") {
    return (
      "시간 조건에 맞는 파일이 없습니다 — NTFS 시각이 없는 파일은 취득 사본 시각으로 비교했습니다. " +
      "시간 조건을 지우거나 넓혀 보세요."
    );
  }
  return null;
}

export const UNKNOWN_SORT_KEY_TEXT = "알 수 없는 정렬 키";

/**
 * Status line of a sort the server did not (or could not usefully) apply, null otherwise:
 * - unknown key (`?sort=bogus`): "알 수 없는 정렬 키(bogus) — 정렬하지 않았습니다"
 * - descriptor `applied: false`: its `reason`, else the unknown-key text
 * - descriptor `empty: true`: "크기 — 값이 없어 정렬 효과 없음"
 */
export function sortIneffectiveText(
  key: string,
  header: string | undefined,
  state: ServerSortState | null | undefined,
  knownKey: boolean,
): string | null {
  if (state && state.applied === false) {
    return state.reason
      ? `정렬하지 않았습니다: ${state.reason}`
      : `${UNKNOWN_SORT_KEY_TEXT}(${key}) — 정렬하지 않았습니다`;
  }
  if (!knownKey) return `${UNKNOWN_SORT_KEY_TEXT}(${key}) — 정렬하지 않았습니다`;
  if (state && state.status === "ready" && state.empty === true) {
    return `${header ?? key} — 값이 없어 정렬 효과 없음`;
  }
  return null;
}
