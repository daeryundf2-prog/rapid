/**
 * Korean names of artifact types for the 유형 filter list (review #10): the domain tree already
 * names every node that maps to exactly one `artifact_type` ("작업 스케줄러" ↔
 * task-scheduler-task); a type no node names shows its id only. Groups list their types'
 * Korean names (`typeLabels`), which win over the shorter child labels ("메시지").
 */

import { DOMAINS, flattenDomainNodes } from "../tree/domains";

/**
 * Korean names of the analysis job row types (`<kind>-row`, R3 typed rows such as
 * `ntfs-timestamp-mismatch`): no tree node maps them as a type, so they are seeded here.
 */
export const ANALYSIS_TYPE_LABELS: Readonly<Record<string, string>> = {
  "ntfs-timestamp-mismatch": "NTFS 타임스탬프 불일치",
  "ntfs-logfile-transaction": "$LogFile 트랜잭션",
  "ntfs-meta-row": "MFT/USN 레코드",
  "carve-row": "카빙 결과",
  "vsc-discover-row": "볼륨 섀도우 후보",
  "vsc-compare-row": "볼륨 섀도우 비교",
  "vsc-extract-row": "볼륨 섀도우 추출",
  "ocr-batch-row": "OCR 결과",
  "cross-case-row": "교차 케이스 지표",
  "memory-import-row": "메모리 분석 가져오기",
  "triage-flags-row": "특이사항 계산",
};

let cache: Map<string, string> | null = null;

function labels(): Map<string, string> {
  if (cache) return cache;
  const out = new Map<string, string>();
  for (const domain of DOMAINS) {
    // Sub-nodes too (이메일 › 메일함 문자열 …); a group's typeLabels come before its children.
    for (const node of flattenDomainNodes(domain.nodes)) {
      const types = node.target.types;
      if (types?.length === 1 && types[0] && !out.has(types[0])) out.set(types[0], node.label);
      for (const [type, label] of Object.entries(node.typeLabels ?? {}))
        if (!out.has(type)) out.set(type, label);
    }
  }
  for (const [type, label] of Object.entries(ANALYSIS_TYPE_LABELS)) if (!out.has(type)) out.set(type, label);
  cache = out;
  return out;
}

/** Korean label of an artifact type, or null when none is known. */
export function artifactTypeLabel(type: string): string | null {
  return labels().get(type) ?? null;
}

export interface TypeOption {
  id: string;
  label: string | null;
  /** Loaded rows of this type (undefined = not counted). */
  count?: number;
}

/** 유형 list rows narrowed by the search text (Korean label or id, case-insensitive). */
export function typeOptionsFor(
  types: readonly string[],
  counts: Readonly<Record<string, number>>,
  query = "",
): TypeOption[] {
  const needle = query.trim().toLocaleLowerCase("ko-KR");
  return (
    types
      .map((id) => ({ id, label: artifactTypeLabel(id), count: counts[id] }))
      .filter(
        (option) =>
          !needle ||
          option.id.toLocaleLowerCase("ko-KR").includes(needle) ||
          (option.label ?? "").toLocaleLowerCase("ko-KR").includes(needle),
      )
      // Korean names in Korean order (never by the English id, AXIOM 7.3-3); unnamed ids after them.
      .sort((a, b) =>
        a.label && b.label
          ? a.label.localeCompare(b.label, "ko") || a.id.localeCompare(b.id)
          : a.label
            ? -1
            : b.label
              ? 1
              : a.id.localeCompare(b.id),
      )
  );
}
