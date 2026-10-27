/**
 * Korean names of artifact types for the 유형 filter list (review #10): the domain tree already
 * names every node that maps to exactly one `artifact_type` ("작업 스케줄러" ↔
 * task-scheduler-task); a type no node names shows its id only. Groups list their types'
 * Korean names (`typeLabels`), which win over the shorter child labels ("메시지").
 */

import { timestampKindLabel } from "../../utils/timeKinds";
import { AI_TYPE_LABELS, OTHER_AI_TYPE_LABELS } from "../ai/aiLabels";
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
  // R5 L3
  "carved-url-candidate": "URL 카빙 후보",
  "url-carve-row": "URL 카빙 결과",
};

/**
 * Names that win over the tree's node labels: a type listed by two nodes (registry row + file
 * row) needs a neutral name, and P2P node labels ("전송 기록", "읽기 오류") read ambiguously
 * out of their tree group in the 유형 list.
 */
export const TYPE_LABEL_OVERRIDES: Readonly<Record<string, string>> = {
  "startup-item": "시작 프로그램 항목",
  "desktop-wallpaper": "바탕 화면 배경",
  "p2p-transfer": "P2P 전송 기록",
  "p2p-torrent": "P2P 토렌트 파일",
  "p2p-shared-file": "P2P eMule 공유·완료 파일",
  "p2p-search-term": "P2P 검색어",
  "p2p-client-config": "P2P 클라이언트 설정",
  "p2p-parse-error": "P2P 읽기 오류",
  // Types no single tree node names (timeline/grid readability C9): the timeline's 영역·유형
  // column and the condition popover read these instead of the raw id.
  "browser-storage-inventory": "브라우저 저장소 목록",
  "jumplist-automatic": "점프 목록(자동, 파일 단위)",
  "jumplist-custom": "점프 목록(사용자 지정)",
  "jumplist-entry": "점프 목록 항목",
  "recent-shortcut-invalid-content": "최근 항목 바로 가기(읽기 오류)",
  "registry-deleted-cell-candidate": "레지스트리 삭제 셀 후보",
  "registry-key-recovery-candidate": "레지스트리 복구 키 후보",
  "registry-value-recovery-candidate": "레지스트리 복구 값 후보",
  "synthetic-media-image": "합성 의심 이미지",
  "synthetic-media-text": "합성 의심 텍스트",
  "windows-execution-summary": "실행 흔적 요약",
  "windows-usb-device": "USB 장치",
  "windows-mounted-device": "마운트된 장치",
  // R7 AI 사용 (갈래 D): the full type names (the tree's node names — 세션, 메시지 … — are too
  // short for the timeline's 영역·유형 column and the 유형 chips).
  ...AI_TYPE_LABELS,
  ...OTHER_AI_TYPE_LABELS,
};

let cache: Map<string, string> | null = null;

function labels(): Map<string, string> {
  if (cache) return cache;
  const out = new Map<string, string>(Object.entries(TYPE_LABEL_OVERRIDES));
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
  return labels().get(type) ?? timelineEventTypeLabel(type);
}

/**
 * Timeline event types (`artifact-<artifact type>-<time kind>`, e.g.
 * `artifact-jumplist-entry-target-created`) read as "<type name> · <time kind>" so the timeline's
 * 유형 filter list is Korean too (C9); null when the embedded type is unknown.
 */
export function timelineEventTypeLabel(eventType: string): string | null {
  if (!eventType.startsWith("artifact-")) return null;
  const rest = eventType.slice("artifact-".length);
  const known = labels();
  for (let cut = rest.lastIndexOf("-"); cut > 0; cut = rest.lastIndexOf("-", cut - 1)) {
    const name = known.get(rest.slice(0, cut));
    if (name) return `${name} · ${timestampKindLabel(rest.slice(cut + 1))}`;
  }
  return null;
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
