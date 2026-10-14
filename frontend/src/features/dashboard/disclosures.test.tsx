import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { RunSummary } from "../../api/runs";
import { DisclosuresCard } from "./cards";
import { disclosureDigest, disclosureItems, runWarnings } from "./disclosures";

afterEach(cleanup);

const summary: RunSummary = {
  warnings: [
    { step: "artifacts-windows-registry", level: "warning", message: "하이브 상한 16MB 적용" },
    { step: "timeline", level: "warning", message: "" },
  ],
  disclosures: {
    time_origin: "acquisition-copy",
    acquisition_copy_note: "폴더(추출 사본) 입력: 호스트 시각은 취득 시각입니다.",
    timezone: { evidence_timezone: { name: "Korea Standard Time", utc_offset: "+09:00" } },
    missing_tools: {
      yara: { available: false, note: "YARA 엔진 없음" },
      tesseract: { available: true, note: "" },
    },
    caps: { "docs-index": ["max_text_bytes", "max_documents"] },
    timeline_excluded: { out_of_range: 3, duplicates: 0, copy_time_candidates: 12 },
    documents: { text_status_counts: { ok: 10, encrypted: 2 } },
    indicators: { display_label: "지표 후보", rule_count: 0, rule_status_message: "적용된 탐지 규칙 없음" },
  },
};

describe("공개 사항 (run summary disclosures + warnings)", () => {
  it("shapes missing tools, caps, timezone, copy time and exclusions", () => {
    const items = disclosureItems(summary);
    const by = (id: string) => items.find((item) => item.id === id);
    expect(by("missing-tools")).toMatchObject({ text: "YARA 엔진 없음", tone: "warn" });
    expect(by("caps")?.text).toContain("docs-index: max_text_bytes, max_documents");
    expect(by("timezone")).toMatchObject({
      text: "저장 UTC · 증거 시스템 Korea Standard Time (UTC +09:00)",
      tone: "info",
    });
    expect(by("copy-time")?.tone).toBe("warn");
    expect(by("timeline-excluded")?.text).toContain("사본 시각만 있는 파일 12건");
    expect(by("documents")?.text).toBe("본문 있음 10 · 암호화 2");
    expect(by("indicators")).toMatchObject({ label: "지표 후보", tone: "warn" });
    expect(runWarnings(summary)).toHaveLength(1);
    expect(disclosureDigest(summary)).toBe(
      "공개 사항 — 확인 필요: 누락 도구, 상한·절단, 취득 사본 시각, 지표 후보 · 경고 1건",
    );
  });

  it("is empty for a summary that predates disclosures, and flags an unknown timezone", () => {
    expect(disclosureItems({})).toEqual([]);
    expect(disclosureDigest({})).toBe("");
    const tz = disclosureItems({ disclosures: { timezone: { evidence_timezone: null } } }).find(
      (item) => item.id === "timezone",
    );
    expect(tz?.tone).toBe("warn");
  });

  it("renders the 공개 사항 card with chips and the step warnings", () => {
    render(<DisclosuresCard items={disclosureItems(summary)} warnings={runWarnings(summary)} />);
    const card = screen.getByTestId("disclosures-card");
    expect(card.textContent).toContain("누락 도구");
    expect(card.textContent).toContain("YARA 엔진 없음");
    expect(screen.getByText("단계 경고 1건")).toBeTruthy();
    expect(card.textContent).toContain("하이브 상한 16MB 적용");
  });

  it("explains an empty card", () => {
    render(<DisclosuresCard items={[]} warnings={[]} />);
    expect(screen.getByText(/공개 사항이 없습니다/)).toBeTruthy();
  });
});
