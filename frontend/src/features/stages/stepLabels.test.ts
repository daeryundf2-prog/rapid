import { describe, expect, it } from "vitest";
import { stepNameLabel, stepStatusLabel, stepWarningLabel } from "./stepLabels";

describe("stepLabels (shared by 처리 plan table and 접수 processing card)", () => {
  it("labels every run progress stage in Korean", () => {
    const stages = [
      "prepare",
      "fingerprint",
      "artifacts",
      "manifest",
      "docs",
      "files",
      "carve",
      "extract",
      "timeline",
      "indicators",
      "persist",
      "report",
    ];
    for (const stage of stages) {
      const label = stepNameLabel(stage);
      expect(label, stage).not.toBe(stage);
      expect(label, stage).toMatch(/[가-힣]/);
    }
    expect(stepNameLabel("fingerprint")).toBe("증거 지문(해시)");
    expect(stepNameLabel("artifacts")).toBe("아티팩트 수집");
  });

  it("keeps summary step names and the artifacts-<kind> pattern", () => {
    expect(stepNameLabel("artifacts-browser")).toBe("아티팩트 수집: browser");
    expect(stepNameLabel("silent-failure-detector")).toBe("누락 위험 점검");
    expect(stepNameLabel("something-new")).toBe("something-new");
  });

  it("status and warning labels", () => {
    expect(stepStatusLabel("completed")).toBe("완료");
    expect(stepWarningLabel("none")).toBe("");
    expect(stepWarningLabel("warning")).toBe("경고");
  });
});

describe("stepCountText (review nit)", () => {
  it("reads string counts as numbers", async () => {
    const { stepCountText } = await import("./ProcessStage");
    expect(stepCountText({ candidate_count: "4770" })).toBe("후보 4,770");
    expect(stepCountText({ artifact_count: 12 })).toBe("아티팩트 12");
    expect(stepCountText({ candidate_count: "n/a" })).toBe("");
  });
});
