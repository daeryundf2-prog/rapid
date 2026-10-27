import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { ItemRow, RunSummary } from "../../api/runs";
import { DisclosuresCard, StatusCard } from "./cards";
import {
  capFlagsText,
  capPolicyLine,
  disclosureDigest,
  disclosureItems,
  problemMessageKo,
  profileLine,
  rowTruncationItems,
  rowTruncationOf,
  rowTruncationTotalsOf,
  runWarnings,
  sizeCapsLine,
  stepLabelKo,
  utcOffsetText,
} from "./disclosures";
import type { RunDetail } from "./useDashboardData";

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
    expect(by("caps")?.text).toBe("1단계 결과가 전수가 아닙니다: 문서 색인(최대치 상한 도달)");
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
    expect(screen.getByText(/처리 제한 사항이 없습니다/)).toBeTruthy();
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

describe("R7 L3 (C-I2): cap flags and problem messages read Korean, raw keys only in the tooltip", () => {
  it("maps the real-run cap flags to reasons (never the key)", () => {
    expect(
      capFlagsText([
        "summary.size_caps.truncated",
        "docs:too-large",
        "docs:binary-rejected",
        "hash_cache_assessment.hash_cache_manifest.entries_truncated",
        "hash_cache_manifest.events_truncated",
        "summary.fuzzy_text_duplicates_truncated",
        "row-truncation:recent-files",
        "scan-coverage:synthetic-media",
      ]),
    ).toBe(
      "문서 크기 상한 초과, 크기 초과 문서 본문 미추출, 비인쇄 문자 비율 초과 문서 미색인, 해시 캐시 항목 목록 절단, 해시 캐시 이벤트 목록 절단, 유사 문서(퍼지 중복) 목록 절단, 행 절단(최근 파일·LNK), 스캔 범위 제한(합성 미디어)",
    );
    expect(capFlagsText(["something-new"])).toBe("기타 상한 1건");
  });

  it("rewrites /problems messages: kind names, cap reasons, English notices", () => {
    expect(problemMessageKo("상한/절단 적용 — 결과가 전수가 아님: summary.size_caps.truncated")).toBe(
      "상한/절단 적용 — 결과가 전수가 아님: 문서 크기 상한 초과",
    );
    expect(
      problemMessageKo(
        "recent-files: 행 단위 절단 10행 — 원문 일부만 보존됨 (jumplist-automatic.ole_streams_truncated 10행, jumplist-automatic.destinations_truncated 5행)",
      ),
    ).toBe("최근 파일·LNK: 행 단위 절단 10행 — 원문 일부만 보존됨");
    expect(problemMessageKo("문서 8건: 크기 상한 초과로 본문 미추출 (too-large)")).toBe(
      "문서 8건: 크기 상한 초과로 본문 미추출",
    );
    expect(problemMessageKo("No email artifact rows were collected.")).toBe("이메일: 수집된 행 없음");
    expect(
      problemMessageKo("extraction-disabled-by-default; rerun with --extract to copy and hash candidates"),
    ).toMatch(/^기본 설정으로 추출하지 않음/);
  });
});

/** The 19 검증 이슈 of run-subset10 (rapidtriage-run-summary.json processing.warnings), verbatim. */
const SUBSET10_ISSUES: Array<[string, string]> = [
  ["docs", "상한/절단 적용 — 결과가 전수가 아님: summary.size_caps.truncated"],
  ["docs", "문서 8건: 크기 상한 초과로 본문 미추출 (too-large)"],
  ["docs", "문서 80건: 비인쇄 문자 비율 초과로 본문 미색인 (binary-rejected)"],
  [
    "files",
    "상한/절단 적용 — 결과가 전수가 아님: hash_cache_assessment.hash_cache_manifest.entries_truncated, hash_cache_assessment.hash_cache_manifest.events_truncated, hash_cache_manifest.entries_truncated, hash_cache_manifest.events_truncated, summary.fuzzy_text_duplicate_profile.truncated, summary.fuzzy_text_duplicates_truncated",
  ],
  [
    "artifacts-recent-files",
    "recent-files: 행 단위 절단 10행 — 원문 일부만 보존됨 (jumplist-automatic.ole_streams_truncated 10행, jumplist-automatic.destlist_entry_candidates_truncated 10행, jumplist-automatic.destinations_truncated 5행)",
  ],
  ["artifacts-email", "No email artifact rows were collected."],
  ["artifacts-cloud-export", "No cloud-export artifact rows were collected."],
  ["artifacts-cloud-export", "cloud-export: 클라우드 내보내기 루트 없음"],
  ["artifacts-mobile-export", "No mobile-export artifact rows were collected."],
  ["artifacts-mobile-export", "mobile-export: 모바일 추출물 없음"],
  ["artifacts-kakaotalk-macos", "No kakaotalk-macos artifact rows were collected."],
  ["artifacts-android-apk", "No android-apk artifact rows were collected."],
  ["artifacts-synthetic-media", "synthetic-media: 후보 1104개 중 592개 파일 미선별 (파일 수 상한 512개)"],
  ["artifacts-eventlog", "eventlog: 표시용 미리보기 절단 33803행 (원본 레코드 값은 보존, 경고 아님)"],
  ["artifacts-windows-search-index", "No windows-search-index artifact rows were collected."],
  [
    "artifacts-windows-registry",
    "windows-registry: 행 단위 절단 5행 — 원문 일부만 보존됨 (registry-hive-strings.scan_truncated 5행)",
  ],
  [
    "artifacts-windows-prefetch",
    "windows-prefetch: 행 단위 절단 276행 — 원문 일부만 보존됨 (prefetch-file.file_reference_candidates_truncated 276행, prefetch-file.referenced_paths_truncated 106행)",
  ],
  ["artifacts-linux-system", "No linux-system artifact rows were collected."],
  ["artifacts-macos-system", "No macos-system artifact rows were collected."],
];
/** A raw key (dotted / dashed / snake id) or an English word of two letters or more. */
const RAW_TOKEN = /[a-z0-9]+(?:[._:-][a-z0-9]+)+|\b[A-Za-z]{2,}\b/g;
/** Analyst-facing product names inside Korean labels (kindLabel), not raw keys. */
const NAMES = new Set([
  "EVTX",
  "LNK",
  "Prefetch",
  "APK",
  "macOS",
  "Linux",
  "Windows",
  "Android",
  "KakaoTalk",
]);

describe("단계 상세 검증 이슈 in Korean (R-7)", () => {
  it("every run-subset10 issue reads without raw keys or English; the raw text stays as the tooltip", () => {
    const issues: ItemRow[] = SUBSET10_ISSUES.map(([step, message]) => ({ step, level: "notice", message }));
    render(
      <StatusCard
        run={{ status: "completed" } as RunDetail}
        stages={[]}
        counts={undefined}
        outputDir=""
        issues={issues}
      />,
    );
    const items = screen.getByRole("list", { name: "검증 이슈" }).querySelectorAll("li");
    expect(items).toHaveLength(19);
    const raw = [...items].flatMap((li) => (li.textContent ?? "").match(RAW_TOKEN) ?? []);
    expect(raw.filter((token) => !NAMES.has(token))).toEqual([]);
    expect(items[5]?.textContent).toBe("아티팩트 수집: 이메일 이메일: 수집된 행 없음");
    expect(items[5]?.getAttribute("title")).toBe("No email artifact rows were collected.");
  });

  it("parser error notes read in Korean (old English runs and the new server text)", () => {
    expect(problemMessageKo("email parser reported 3 isolated error(s).")).toBe(
      "이메일: 파서 오류 3건 (해당 수집기만 격리됨)",
    );
    expect(problemMessageKo("email: 파서 오류 3건 (해당 수집기만 격리됨)")).toBe(
      "이메일: 파서 오류 3건 (해당 수집기만 격리됨)",
    );
    expect(problemMessageKo("email: 수집된 행 없음")).toBe("이메일: 수집된 행 없음");
  });
});
