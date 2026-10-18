/**
 * Korean summary rows of a run request (AXIOM adoption E1): the case wizard's 처리 옵션 요약 and the
 * 접수 "처리 설정 스냅샷" card render the SAME function over the request body, so the summary the
 * examiner confirms and the snapshot the server stored list the same keys 1:1.
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
      return mode ? `${mode.label} (${mode.id})` : String(v ?? "—");
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
    label: "E01 파티션 시작 섹터",
    format: (v) => (v === null || v === undefined || v === "" ? "자동" : n(Number(v))),
  },
  known_good_hash_feeds: {
    label: "known-good 해시 목록",
    format: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "없음"),
  },
  hide_known_good: { label: "known-good 항목 숨기기", format: yesNo },
  known_good_max_hash_bytes: {
    label: "known-good 해시 상한",
    format: (v) => (Number(v) ? `${n(Math.round(Number(v) / (1024 * 1024)))} MB` : "제한 없음"),
  },
  rules: { label: "규칙 파일", format: (v) => (v ? String(v) : "기본") },
  case_db: { label: "케이스 DB 색인", format: yesNo },
  skip_groups: {
    label: "건너뛸 처리 그룹",
    format: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "없음"),
  },
  skip_tasks: {
    label: "건너뛸 태스크",
    format: (v) => (Array.isArray(v) && v.length ? v.join(", ") : "없음"),
  },
};

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
