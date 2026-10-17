/**
 * Korean labels of run steps, shared by the 처리 plan table (ProcessStage) and the 접수
 * dashboard's "케이스 처리 세부" card. The raw step id stays available as a tooltip.
 */

/** Korean labels of run summary step statuses (processing plan table). */
const STEP_STATUS_LABEL: Record<string, string> = {
  completed: "완료",
  complete: "완료",
  ok: "완료",
  executed: "실행됨",
  skipped: "건너뜀",
  failed: "실패",
  error: "오류",
  running: "실행 중",
  queued: "대기",
  pending: "대기",
  cancelled: "취소됨",
  canceled: "취소됨",
  partial: "일부 완료",
  missing: "없음",
  blocked: "차단됨",
  unavailable: "사용할 수 없음",
  timeout: "시간 초과",
  not_run: "미실행",
  warning: "경고",
  warn: "경고",
  notice: "알림",
  info: "정보",
  none: "이상 없음",
  failed_isolated: "일부 실패(격리됨)",
  unknown: "알 수 없음",
  "operator-exercise": "분석관 확인 필요",
};

/** Korean status of a plan step; an unknown one still reads as Korean ("상태 미상(xyz)"). */
export function stepStatusLabel(status: string): string {
  const known = STEP_STATUS_LABEL[status] ?? STEP_STATUS_LABEL[status.toLowerCase()];
  if (known) return known;
  const lower = status.toLowerCase();
  if (lower.includes("warn")) return "경고";
  if (lower.includes("fail") || lower.includes("error")) return "실패";
  return `상태 미상(${status})`;
}

/**
 * Korean names of the run pipeline steps: the run summary `steps[].name` (core/run/steps.py)
 * and the run progress stages (core/run/__init__.py `begin_stage` / `complete_stage`).
 */
const STEP_NAME_LABEL: Record<string, string> = {
  // Progress stages (접수 "케이스 처리 세부" card).
  fingerprint: "증거 지문(해시)",
  artifacts: "아티팩트 수집",
  carve: "카빙",
  extract: "추출",
  persist: "결과 저장",
  report: "보고서 작성",
  completed: "완료",
  // Summary steps (처리 plan table).
  manifest: "증거 목록(매니페스트)",
  docs: "문서 텍스트 추출",
  "docs-index": "문서 색인",
  files: "파일 목록",
  "docs-extract": "문서 추출",
  "files-extract": "파일 추출",
  timeline: "타임라인",
  indicators: "지표(IOC) 요약",
  "silent-failure-detector": "누락 위험 점검",
  triage: "분류",
  prepare: "준비",
  finalize: "마무리",
  // Steps after the outputs exist (viewer-families §3.1, axiom-adoption §3.2).
  "triage-flags": "특이사항",
  derived: "통합 보기",
};

/** Korean name of a plan step (`artifacts-<kind>` → "아티팩트 수집: <kind>"); unknown ids stay as-is. */
export function stepNameLabel(name: string): string {
  const known = STEP_NAME_LABEL[name] ?? STEP_NAME_LABEL[name.toLowerCase()];
  if (known) return known;
  if (name.startsWith("artifacts-")) return `아티팩트 수집: ${name.slice("artifacts-".length)}`;
  return name;
}

/** Korean warning level of a plan step (`warning_level`); "" for none. */
export function stepWarningLabel(level: string): string {
  if (!level || level === "none") return "";
  return stepStatusLabel(level);
}
