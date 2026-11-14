// Review WB-10/11 P1-3: the 처리 screen names an OUTPUT_DISK_FULL failure and what to do next.
import { describe, expect, it } from "vitest";
import { OUTPUT_DISK_FULL_ERROR_TYPE, runFailureReason } from "./runFailure";

const DISK_FULL = "실패 — 결과 폴더 여유 부족(여유 12.0 MB · 쓰다 만 파일 2개 지움)";

describe("runFailureReason", () => {
  it("a disk-full failure gets its Korean title, the server text and the resume hint", () => {
    const reason = runFailureReason({
      status: "failed",
      error: DISK_FULL,
      error_type: OUTPUT_DISK_FULL_ERROR_TYPE,
    });
    expect(reason).toEqual({
      title: "결과 폴더 여유 부족",
      text: DISK_FULL,
      hint: "결과 폴더의 공간을 비운 뒤 이어서 실행하세요(완료된 산출물은 그대로 씀)",
      diskFull: true,
    });
  });

  it("a disk-full extraction points to a new result folder", () => {
    const reason = runFailureReason({
      status: "failed",
      error: "실패 — 결과 폴더 여유 부족(여유 1.0 MB · 추출하지 못한 파일 7개)",
      error_type: OUTPUT_DISK_FULL_ERROR_TYPE,
    });
    expect(reason?.hint).toContain("새 결과 폴더");
  });

  it("other failures show the server text; running or failed-without-text runs show nothing", () => {
    expect(runFailureReason({ status: "failed", error: "분석기 오류", error_type: "RuntimeError" })).toEqual({
      title: "실패",
      text: "분석기 오류",
      hint: "",
      diskFull: false,
    });
    expect(
      runFailureReason({ status: "running", error: DISK_FULL, error_type: OUTPUT_DISK_FULL_ERROR_TYPE }),
    ).toBeNull();
    expect(runFailureReason({ status: "failed", error: "" })).toBeNull();
    expect(runFailureReason(null)).toBeNull();
  });
});
