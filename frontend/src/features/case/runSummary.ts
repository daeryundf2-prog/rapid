/**
 * Korean summary rows of a run request (AXIOM adoption E1): the case wizard's 처리 옵션 요약 and the
 * "처리 설정 스냅샷" table (dashboard SnapshotCard, for the 처리 stage) render the SAME function over the
 * request body, so the summary the examiner confirms and the snapshot the server stored list the same
 * keys 1:1. Labels are Korean only: the mode without its raw id, 알려진 정상(known-good) on first use.
 */

import { INPUT_KINDS, RUN_MODES } from "./runForm";

export interface SummaryRow {
  key: string;
  label: string;
  value: string;
}

const yesNo = (value: unknown) => (value ? "예" : "아니오");

/**
 * Where an automatic run output goes (core/jobs.default_run_output_dir): under the case folder when
 * one is set, otherwise a folder evidence gets it INSIDE that folder and a file evidence next to it.
 */
export const AUTO_OUTPUT_TEXT =
  "자동 (케이스 폴더가 있으면 그 아래, 없으면 폴더 증거는 그 폴더 안에 · 파일 증거는 파일 옆에)";
const n = (value: number) => value.toLocaleString("ko-KR");

/** Label + formatter for every RunCreateRequest / RunRequest key (rapidtriage/core/jobs.py). */
const FIELDS: Record<string, { label: string; format: (value: unknown) => string }> = {
  mode: {
    label: "처리 모드",
    format: (v) => {
      const mode = RUN_MODES.find((m) => m.id === v);
      return mode ? mode.label : String(v ?? "—");
    },
  },
  input_kind: {
    label: "입력 종류",
    format: (v) => INPUT_KINDS.find((k) => k.id === (v ?? ""))?.label ?? String(v),
  },
  read_only: { label: "읽기 전용", format: yesNo },
  dry_run: { label: "모의 실행", format: yesNo },
  overwrite: { label: "기존 출력 덮어쓰기", format: yesNo },
  extract: { label: "파일 추출", format: yesNo },
  resume: { label: "이어서 실행", format: yesNo },
  output_dir: {
    label: "출력 폴더",
    format: (v) => (v ? String(v) : AUTO_OUTPUT_TEXT),
  },
  max_extract_size_bytes: {
    label: "최대 추출 크기",
    format: (v) => (Number(v) ? `${n(Number(v) / (1024 * 1024))} MB` : "제한 없음"),
  },
  max_file_count: { label: "최대 파일 수", format: (v) => (Number(v) ? `${n(Number(v))}개` : "제한 없음") },
  memory_cap_bytes: {
    label: "메모리 상한",
    format: (v) => (Number(v) ? `${n(Math.round(Number(v) / (1024 * 1024)))} MB` : "자동"),
  },
  e01_partition_start_sector: {
    label: "이미지 파티션 시작 섹터",
    format: (v) => (v === null || v === undefined || v === "" ? "자동" : n(Number(v))),
  },
  known_good_hash_feeds: {
    label: "알려진 정상(known-good) 해시 목록",
    format: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "없음"),
  },
  hide_known_good: { label: "알려진 정상 항목 숨기기", format: yesNo },
  known_good_max_hash_bytes: {
    label: "알려진 정상 해시 상한",
    format: (v) => (Number(v) ? `${n(Math.round(Number(v) / (1024 * 1024)))} MB` : "제한 없음"),
  },
  rules: { label: "규칙 파일", format: (v) => (v ? String(v) : "기본") },
  case_db: { label: "케이스 DB 색인", format: yesNo },
  skip_groups: {
    label: "건너뛸 처리 그룹",
    format: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "없음"),
  },
  // R7 AI 사용 기록: the ai-agent collector options (other kinds' options as written).
  collector_options: {
    label: "수집기 옵션",
    format: (v) => collectorOptionsText(v),
  },
  skip_tasks: {
    label: "건너뛸 태스크",
    format: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "없음"),
  },
};

/** "AI 사용 기록: 메시지 본문 포함 · 대형 DB 해시 안 함" of `collector_options`. */
export function collectorOptionsText(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "기본값";
  const parts: string[] = [];
  for (const [kind, options] of Object.entries(value as Record<string, unknown>)) {
    const o = (options && typeof options === "object" ? options : {}) as Record<string, unknown>;
    if (kind === "ai-agent") {
      parts.push(
        `AI 사용 기록: 메시지 본문 ${o.ai_bodies === false ? "수집 안 함(메타만)" : "포함(마스킹)"} · 대형 DB 해시 ${
          o.ai_hash_dbs === true ? "계산" : "안 함"
        }`,
      );
    } else {
      parts.push(`${kind}: ${JSON.stringify(options)}`);
    }
  }
  return parts.length ? parts.join(" / ") : "기본값";
}

/** Keys never shown: the evidence path is its own row, `wait` is transport only. */
const SKIPPED = new Set(["root", "wait", "evidence_citation_id"]);

/** One row per request key, in the order of FIELDS (unknown keys last, raw). */
export function summarizeRunRequest(request: Record<string, unknown> | null | undefined): SummaryRow[] {
  if (!request) return [];
  const keys = Object.keys(request).filter((key) => !SKIPPED.has(key));
  const known = Object.keys(FIELDS).filter((key) => keys.includes(key));
  const unknown = keys.filter((key) => !(key in FIELDS)).sort();
  return [
    ...known.map((key) => {
      const field = FIELDS[key] as { label: string; format: (value: unknown) => string };
      return { key, label: field.label, value: field.format(request[key]) };
    }),
    ...unknown.map((key) => ({ key, label: key, value: JSON.stringify(request[key]) })),
  ];
}
