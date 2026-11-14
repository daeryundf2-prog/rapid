import { describe, expect, it } from "vitest";
import {
  EVIDENCE_INSIDE_OUTPUT_REASON,
  OUTPUT_INSIDE_EVIDENCE_REASON,
  outputOverlapReason,
  outputRequiredReason,
  QUICK_RUN_OUTPUT_SPEC,
} from "./runForm";

describe("R7 output never inside the evidence (console pre-check)", () => {
  it("refuses an output folder equal to or inside the evidence, whatever the case or separators", () => {
    expect(outputOverlapReason("D:\\ev", ["D:\\ev"])).toBe(OUTPUT_INSIDE_EVIDENCE_REASON);
    expect(outputOverlapReason("d:/EV/out", ["D:\\ev"])).toBe(OUTPUT_INSIDE_EVIDENCE_REASON);
    expect(outputOverlapReason("D:\\ev\\", ["d:/ev/"])).toBe(OUTPUT_INSIDE_EVIDENCE_REASON);
    expect(outputOverlapReason("D:\\cases\\img.E01\\out", ["D:\\cases\\img.E01"])).toBe(
      OUTPUT_INSIDE_EVIDENCE_REASON,
    );
  });

  it("refuses an output folder that contains the evidence, except a case folder", () => {
    expect(outputOverlapReason("D:\\cases", ["D:\\cases\\ev"])).toBe(EVIDENCE_INSIDE_OUTPUT_REASON);
    expect(outputOverlapReason("D:\\", ["D:\\cases\\ev"])).toBe(EVIDENCE_INSIDE_OUTPUT_REASON);
    expect(
      outputOverlapReason("D:\\cases", ["D:\\cases\\ev"], { allowEvidenceInside: true }),
    ).toBeUndefined();
    expect(outputOverlapReason("D:\\cases\\ev\\case", ["D:\\cases\\ev"], { allowEvidenceInside: true })).toBe(
      OUTPUT_INSIDE_EVIDENCE_REASON,
    );
  });

  it("allows a sibling (also one sharing the name prefix) and empty values", () => {
    expect(outputOverlapReason("D:\\ev-out", ["D:\\ev"])).toBeUndefined();
    expect(outputOverlapReason("D:\\ev2\\out", ["D:\\ev"])).toBeUndefined();
    expect(outputOverlapReason("", ["D:\\ev"])).toBeUndefined();
    expect(outputOverlapReason("D:\\out", ["", "  "])).toBeUndefined();
  });

  it("the quick run has no automatic output folder", () => {
    expect(QUICK_RUN_OUTPUT_SPEC.required).toBe(true);
    expect(QUICK_RUN_OUTPUT_SPEC.hint).not.toContain("그 폴더 안에 만듭니다");
    expect(outputRequiredReason(QUICK_RUN_OUTPUT_SPEC, "")).toBe("출력 폴더를 지정하세요 (증거 밖의 폴더)");
    expect(outputRequiredReason(QUICK_RUN_OUTPUT_SPEC, "D:\\out")).toBeUndefined();
  });
});
