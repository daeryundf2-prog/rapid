// Lazy access to the non-row sections of the files output (R6 S3 follow-up).
//
// Paged `GET /files` responses no longer carry duplicate_content_groups,
// duplicate_detection_assessment, the duplicate / hash-cache manifests and the other large
// sections; a page lists them in `sections_available`. A UI that shows one (e.g. a duplicate-files
// panel) calls `useFilesSection` with `enabled` = "the panel is open", so nothing is fetched until
// the user opens it, and React Query keeps the section per run.

import { useQuery } from "@tanstack/react-query";
import { ApiError } from "./client";
import { type FilesSection, fetchFilesSection } from "./collections";

const SECTION_LABELS: Record<string, string> = {
  duplicate_content_groups: "중복 파일 묶음",
  fuzzy_text_duplicate_groups: "유사 텍스트 중복 묶음",
  duplicate_detection_assessment: "중복 탐지 평가",
  duplicate_content_manifest: "중복 내용 목록",
  hash_cache_manifest: "해시 캐시 목록",
  hash_cache_assessment: "해시 캐시 평가",
  signature_mismatch_candidates: "시그니처 불일치 후보",
  known_good_suppressed_candidates: "알려진 정상 파일로 숨긴 후보",
};

export function filesSectionLabel(name: string): string {
  return SECTION_LABELS[name] ?? name;
}

export const filesSectionQueryKey = (runId: string | null, name: string, offset = 0, limit = 0) =>
  ["files-section", runId, name, offset, limit] as const;

/**
 * One files-output section, fetched only while `enabled` (the UI showing it is open). `limit`
 * pages a list section (0 = whole section).
 */
export function useFilesSection<T = unknown>(
  runId: string | null,
  name: string,
  { enabled, offset = 0, limit = 0 }: { enabled: boolean; offset?: number; limit?: number },
) {
  return useQuery<FilesSection<T>, Error>({
    queryKey: filesSectionQueryKey(runId, name, offset, limit),
    queryFn: ({ signal }) => fetchFilesSection<T>(runId as string, name, { offset, limit }, signal),
    enabled: enabled && Boolean(runId),
    staleTime: Number.POSITIVE_INFINITY,
    // An absent section (404: an older run) does not become present on a retry.
    retry: (failures, error) => !(error instanceof ApiError && error.status === 404) && failures < 1,
  });
}

/** Korean status line of a section query (null once the section is loaded or before it is asked for). */
export function filesSectionStatus(
  name: string,
  query: { isLoading: boolean; isError: boolean; error: Error | null },
): string | null {
  const label = filesSectionLabel(name);
  if (query.isLoading) return `${label}을(를) 불러오는 중…`;
  if (query.isError) {
    if (query.error instanceof ApiError && query.error.status === 404)
      return `이 런의 파일 목록에는 ${label} 정보가 없습니다.`;
    return `${label}을(를) 불러오지 못했습니다: ${query.error?.message ?? "알 수 없는 오류"}`;
  }
  return null;
}
