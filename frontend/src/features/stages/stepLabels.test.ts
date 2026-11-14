import { describe, expect, it } from "vitest";
import { missingDurationText, stepNameLabel, stepStatusLabel, stepWarningLabel } from "./stepLabels";

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
    expect(stepNameLabel("artifacts-browser")).toBe("아티팩트 수집: 브라우저");
    expect(stepNameLabel("silent-failure-detector")).toBe("누락 위험 점검");
    expect(stepNameLabel("something-new")).toBe("something-new");
  });

  it("T-193: collector steps read Korean — never the raw kind id", () => {
    expect(stepNameLabel("artifacts-ai-agent")).toBe("아티팩트 수집: AI 사용 기록");
    expect(stepNameLabel("artifacts-eventlog")).toBe("아티팩트 수집: 이벤트 로그(EVTX)");
    expect(stepNameLabel("artifacts-windows-prefetch")).toBe("아티팩트 수집: 프리페치(Prefetch)");
    expect(stepNameLabel("artifacts-brand-new-kind")).toBe("아티팩트 수집: 미등록 수집기");
    for (const kind of [
      "ai-agent",
      "eventlog",
      "windows-shellbags",
      "android-apk",
      "p2p",
      "kakaotalk-windows",
    ]) {
      const label = stepNameLabel(`artifacts-${kind}`);
      expect(label, kind).not.toContain(kind);
      // The part after the prefix starts in Korean (a product term may follow in parentheses).
      expect(label.slice("아티팩트 수집: ".length), kind).toMatch(/^[가-힣A-Z]/);
    }
  });

  it("T-193: a missing duration says why, never '—'", () => {
    expect(missingDurationText("completed")).toBe("측정 안 됨");
    expect(missingDurationText(undefined)).toBe("측정 안 됨");
    expect(missingDurationText("queued")).toBe("시작 전");
    expect(missingDurationText("skipped")).toBe("실행 안 함");
  });

  it("status and warning labels", () => {
    expect(stepStatusLabel("completed")).toBe("완료");
    expect(stepStatusLabel("reused")).toBe("재사용");
    expect(stepStatusLabel("completed_with_warnings")).toBe("완료(경고 있음)");
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
    // The dynamic import transforms the whole 처리 stage graph (≈3.5 s alone); under a loaded
    // parallel run it can pass the default 5 s, so it gets its own budget.
  }, 20_000);
});
