/**
 * Test fixture (T-022): `/api/runs/{id}/dashboard` `steps` of an IMG-B-like run — 42 summary steps:
 * 39 completed, 1 partial (the browser step `failed_isolated`), 1 failed (the silent-failure
 * detector) and 1 skipped — while the collector progress reads 12/12 with 0 errors. The 접수 cards
 * and the 처리 screen must both print the same line from it.
 */

export const IMG_B_STEPS = {
  total: 42,
  completed: 39,
  partial: 1,
  failed: 1,
  skipped: 1,
  incomplete: 0,
  failed_names: ["silent-failure-detector"],
  partial_names: ["artifacts-browser"],
  skipped_names: ["ocr"],
  incomplete_names: [],
  by_status: { completed: 39, failed: 1, failed_isolated: 1, skipped: 1 },
};

/** The one step-count line both screens print for {@link IMG_B_STEPS}. */
export const IMG_B_STEPS_TEXT = "단계 42 · 완료 39 · 부분 1 · 실패 1 · 건너뜀 1";

/** 12 collector providers, all completed (the source of the old "12/12 완료·오류 0"). */
export const IMG_B_PROVIDERS = Object.fromEntries(
  Array.from({ length: 12 }, (_, index) => [
    `kind${String(index + 1).padStart(2, "0")}`,
    { status: "completed", duration_ms: 1000, artifact_count: index },
  ]),
);
