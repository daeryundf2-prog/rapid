// Why a run failed, for the 처리 screen (review WB-10/11 P1-3): the server's Korean `error` and, for
// a full result volume (`error_type` `OutputDiskFull` = code OUTPUT_DISK_FULL, T-352), what to do.

/** `RunJob.error_type` of a run stopped by a full output volume (`core/run/disk_full.py`). */
export const OUTPUT_DISK_FULL_ERROR_TYPE = "OutputDiskFull";

export interface RunFailureReason {
  /** Short label of the failure kind. */
  title: string;
  /** The server's Korean status (free space, removed run outputs). */
  text: string;
  /** What the examiner does next; empty when the server gave nothing to act on. */
  hint: string;
  diskFull: boolean;
}

export function runFailureReason(
  run: { status?: unknown; error?: string | null; error_type?: string | null } | null | undefined,
): RunFailureReason | null {
  if (!run || String(run.status ?? "") !== "failed") return null;
  const text = typeof run.error === "string" ? run.error.trim() : "";
  if (run.error_type === OUTPUT_DISK_FULL_ERROR_TYPE) {
    const extraction = text.includes("추출하지 못한 파일");
    return {
      title: "결과 폴더 여유 부족",
      text: text || "처리 중 결과 폴더의 여유 공간이 부족해 단계가 실패했습니다",
      hint: extraction
        ? "공간을 비운 뒤 새 결과 폴더로 다시 처리하세요(이어서 실행은 추출을 다시 하지 않음)"
        : "결과 폴더의 공간을 비운 뒤 이어서 실행하세요(완료된 산출물은 그대로 씀)",
      diskFull: true,
    };
  }
  if (!text) return null;
  return { title: "실패", text, hint: "", diskFull: false };
}
