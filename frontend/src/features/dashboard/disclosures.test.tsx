import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { RunSummary } from "../../api/runs";
import { DisclosuresCard } from "./cards";
import {
  capPolicyLine,
  disclosureDigest,
  disclosureItems,
  profileLine,
  rowTruncationItems,
  rowTruncationOf,
  rowTruncationTotalsOf,
  runWarnings,
  sizeCapsLine,
  stepLabelKo,
  utcOffsetText,
} from "./disclosures";

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

describe("처리 제한 사항 (run summary disclosures + warnings)", () => {
  it("shapes missing tools, caps, timezone, copy time and exclusions", () => {
    const items = disclosureItems(summary);
    const by = (id: string) => items.find((item) => item.id === id);
    expect(by("missing-tools")).toMatchObject({ text: "YARA 엔진 없음", tone: "warn" });
    // Step ids read in Korean; the raw flag keys stay in `detail` (tooltip), never the text.
    expect(by("caps")?.text).toBe("1단계 결과가 전수가 아닙니다: 문서 색인");
    expect(by("caps")?.detail).toContain("docs-index: max_text_bytes, max_documents");
    expect(by("timezone")).toMatchObject({
      text: "저장 UTC · 증거 시스템 한국 표준시 (UTC+09:00)",
      tone: "info",
      detail: "Korea Standard Time",
    });
    expect(by("copy-time")?.tone).toBe("warn");
    expect(by("timeline-excluded")?.text).toContain("사본 시각만 있는 파일 12건");
    expect(by("documents")?.text).toBe("본문 있음 10 · 암호화 2");
    expect(by("indicators")).toMatchObject({ label: "지표 후보", tone: "warn" });
    expect(runWarnings(summary)).toHaveLength(1);
    expect(disclosureDigest(summary)).toBe(
      "처리 제한 사항 — 확인 필요: 누락 도구, 상한·절단, 취득 사본 시각, 지표 후보 · 경고 1건",
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

  it("renders the 처리 제한 사항 card with chips and the step warnings", () => {
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

  it("never prints raw ids: bias → UTC offset, source_file_*, exclusion reasons, kind ids", () => {
    expect(utcOffsetText(undefined, -540)).toBe("UTC+09:00");
    expect(utcOffsetText(undefined, 300)).toBe("UTC-05:00");
    expect(utcOffsetText("+09:00", undefined)).toBe("UTC+09:00");
    expect(stepLabelKo("artifacts-recent-files")).toBe("아티팩트 수집: 최근 파일·LNK");
    expect(stepLabelKo("docs")).toBe("문서 텍스트 추출");
    const items = disclosureItems({
      disclosures: {
        timezone: { evidence_timezone: { name: "Korea Standard Time", bias_minutes: -540 } },
        acquisition_copy_note: "호스트 시각은 취득 시각이므로 source_file_* 로만 기록했습니다.",
        caps: { "artifacts-windows-prefetch": ["row-truncation:windows-prefetch"] },
        files: { excluded_file_count: 3, exclusion_reason_counts: { "category-not-selected": 3 } },
        collection_notes: { "cloud-export": ["클라우드 내보내기 루트 없음"] },
      },
    });
    const text = items.map((item) => `${item.label} ${item.text}`).join("\n");
    for (const raw of [
      "bias",
      "Korea Standard Time",
      "source_file_",
      "category-not-selected",
      "cloud-export",
      "row-truncation",
    ]) {
      expect(text).not.toContain(raw);
    }
    expect(text).toContain("한국 표준시 (UTC+09:00)");
    expect(text).toContain("'취득 사본 시각' 필드로만");
    expect(text).toContain("선택 안 된 범주 3");
    expect(text).toContain("클라우드 내보내기 수집 메모");
    expect(text).toContain("아티팩트 수집: Prefetch");
  });
});

describe("처리 제한 사항 r2: cap_policy, row truncation, docs size caps, profile label", () => {
  const r2: RunSummary = {
    processing: { profile_label: "Deep - parser/stage caps applied (disclosed)" },
    steps: [
      {
        name: "artifacts-eventlog",
        row_truncation: { rows_with_truncation: 3, flag_counts: { script_block_text_truncated: 3 } },
      },
      { name: "artifacts-windows-prefetch", row_truncation: { preview_only_rows: 12 } },
      { name: "files" },
    ],
    warnings: [
      { step: "artifacts-eventlog", level: "warning", message: "eventlog: 행 단위 절단 3행" },
      { step: "artifacts-windows-prefetch", level: "notice", message: "미리보기 절단 12행 (경고 아님)" },
    ],
    disclosures: {
      timezone: { evidence_timezone: { name: "UTC" } },
      indicators: {
        display_label: "지표 후보",
        rule_count: 2,
        cap_policy: { mode: "uncapped", max_indicators: null, kept: 1234, total_before_cap: 1234 },
      },
      documents: {
        text_status_counts: { ok: 3 },
        size_caps: {
          max_input_bytes: 64_000_000,
          max_archive_member_bytes: 16_000_000,
          too_large_count: 2,
          binary_rejected_count: 0,
        },
      },
    },
  };
  const by = (id: string) => disclosureItems(r2).find((item) => item.id === id);

  it("indicator cap: 상한 없음, or capped with its number", () => {
    expect(by("indicator-cap")).toMatchObject({
      label: "지표 상한",
      text: "상한 없음 — 지표 후보 1,234건 모두 기록",
      tone: "info",
    });
    expect(capPolicyLine({ mode: "capped", max_indicators: 500, kept: 500, total_before_cap: 812 })).toEqual({
      text: "상한 500개 — 전체 812건 중 500건만 기록",
      tone: "warn",
    });
    expect(capPolicyLine({ mode: "capped", max_indicators: 500, kept: 40, total_before_cap: 40 })).toEqual({
      text: "상한 500개 (도달하지 않음)",
      tone: "info",
    });
  });

  it("row truncation: payload cuts warn, preview-only cuts are a notice", () => {
    expect(rowTruncationOf(r2)).toEqual({
      eventlog: { rows_with_truncation: 3, flag_counts: { script_block_text_truncated: 3 } },
      "windows-prefetch": { preview_only_rows: 12 },
    });
    expect(by("row-truncation")).toMatchObject({
      tone: "warn",
      text: "원문 값 일부만 보존된 행: EVTX 3행",
    });
    expect(by("row-preview-truncation")).toMatchObject({
      tone: "info",
      text: "표시용 미리보기만 잘림(원본 레코드 값은 보존): Prefetch 12행",
    });
    // The server's own block wins over the steps; `artifacts-` is stripped from by_step names.
    const server: RunSummary = {
      disclosures: {
        input_row_truncation: {
          payload_truncated_rows: 4,
          preview_truncated_rows: 0,
          level: "warning",
          by_step: { "artifacts-email": { rows_with_truncation: 4 } },
        },
      },
    };
    expect(rowTruncationOf(server)).toEqual({ email: { rows_with_truncation: 4 } });
    expect(rowTruncationItems(rowTruncationOf(server), rowTruncationTotalsOf(server))).toEqual([
      expect.objectContaining({
        id: "row-truncation",
        tone: "warn",
        text: "원문 값 일부만 보존된 행 총 4건 — 이메일 4행",
      }),
    ]);
    const none: RunSummary = {
      disclosures: {
        input_row_truncation: {
          payload_truncated_rows: 0,
          preview_truncated_rows: 0,
          level: "none",
          by_step: {},
        },
      },
    };
    expect(rowTruncationItems(rowTruncationOf(none), rowTruncationTotalsOf(none))).toEqual([]);
  });

  it("docs size caps and the r2 profile label", () => {
    expect(by("docs-size-caps")).toMatchObject({
      label: "문서 크기 상한",
      text: "파일 64 MB · 압축 멤버 16 MB — 초과 2건 본문 미추출",
      tone: "warn",
    });
    expect(sizeCapsLine({ max_input_bytes: 64_000_000 })).toEqual({
      text: "파일 64 MB — 초과 문서 없음",
      tone: "info",
    });
    expect(by("profile")).toMatchObject({
      text: "정밀 — 파서·단계 상한 적용(처리 제한 사항 참조)",
      tone: "warn",
    });
    expect(profileLine("Deep - extraction without size limits").tone).toBe("info");
    expect(profileLine("Custom")).toEqual({ text: "Custom", tone: "info" });
  });

  it("counts notice-level step messages apart from warnings", () => {
    expect(disclosureDigest(r2)).toContain("경고 1건 · 알림 1건");
    render(<DisclosuresCard items={disclosureItems(r2)} warnings={runWarnings(r2)} />);
    expect(screen.getByText("단계 경고 1건 · 알림 1건")).toBeTruthy();
    expect(screen.getByTestId("disclosures-card").textContent).toContain("(알림) 미리보기 절단 12행");
  });
});
