import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../../state/store";
import { mockFetch, type RecordedCall, renderWithQuery } from "../case/testUtils";
import { CARD_IDS, CaseDashboard } from "./CaseDashboard";
import { KEYWORD_COUNT_LIMIT } from "./cards";

const dashboardCss = readFileSync(resolve(__dirname, "dashboard.css"), "utf8");

const counts = {
  validation_issues: 1,
  outputs: 5,
  artifacts: 125,
  docs: 0,
  files: 30,
  timeline_events: 9,
  review_items: 0,
  indicators: 2,
};

function routes(overrides: Record<string, unknown> = {}) {
  return {
    "GET /api/runs/r1": {
      run_id: "r1",
      status: "completed",
      created_at: "2026-10-11T00:00:00Z",
      updated_at: "2026-10-11T00:05:00Z",
      request: { root: "D:/ev/case1.E01", mode: "fraud" },
      progress: {
        status: "completed",
        started_at: "2026-10-11T00:00:00Z",
        completed_at: "2026-10-11T00:05:00Z",
        completed_stages: [
          { stage: "fingerprint", completed_at: "2026-10-11T00:00:02Z" },
          { stage: "artifacts", completed_at: "2026-10-11T00:01:02Z" },
        ],
        providers: { registry: { status: "completed", duration_ms: 1200, artifact_count: 5 } },
        completed_count: 1,
        total_count: 1,
        error_count: 0,
      },
    },
    "GET /api/runs/r1/summary": { summary: { counts } },
    "GET /api/runs/r1/tree": {
      run_id: "r1",
      root: {},
      nodes: [
        {
          id: "artifacts",
          label: "아티팩트",
          count: 125,
          collection: "artifacts",
          children: [
            {
              id: "artifacts:eventlog",
              label: "EVTX",
              count: 100,
              collection: "artifacts",
              kind: "eventlog",
            },
            {
              id: "artifacts:browser",
              label: "브라우저",
              count: 25,
              collection: "artifacts",
              kind: "browser",
            },
          ],
        },
      ],
    },
    "GET /api/runs/r1/review-counts": {
      run_id: "r1",
      database: "/o/case.db",
      case_id: "run-r1",
      exists: true,
      by_status: { relevant: 2, excluded: 1 },
      include_in_report: 1,
      case_json: { bookmarks: 4, include_in_report: 0 },
      report_candidates: 1,
    },
    "POST /api/case-db/saved-searches/list": { saved_searches: [{ name: "계좌", keywords: ["bank"] }] },
    "GET /api/runs/r1/dashboard": {
      run_id: "r1",
      completed: true,
      profile: { mode: "fraud", description: "", keywords: ["fraud", "invoice"] },
      evidence_source: {
        path: "D:/ev/case1.E01",
        name: "case1.E01",
        kind: "image",
        image_output: "e01",
        size_bytes: 2 * 1024 ** 3,
        selected_partition: 2,
        partitions: [
          {
            number: 1,
            description: "FAT32",
            filesystem: "fat32",
            size_bytes: 1024 ** 2,
            start_sector: 63,
            byte_offset: 0,
            selected: false,
            recommended: false,
          },
          {
            number: 2,
            description: "NTFS",
            filesystem: "ntfs",
            size_bytes: 1024 ** 3,
            start_sector: 2048,
            byte_offset: 0,
            selected: true,
            recommended: true,
          },
        ],
      },
      exports: [
        {
          name: "rapidtriage-case-report.pdf",
          type: "case-report",
          label: "보고서 (PDF)",
          created_at: "2026-10-11T01:00:00Z",
          size: 10,
          status: "완료",
          download_url: "/api/runs/r1/case-report/file/pdf",
        },
        {
          name: "sel-1.zip",
          type: "extract",
          label: "선택 추출",
          created_at: "2026-10-11T00:30:00Z",
          size: null,
          status: "zip 미생성",
          item_count: 3,
          download_url: "/api/runs/r1/extract/sel-1/file",
        },
      ],
    },
    "GET /api/runs/r1/case-notes": {
      run_id: "r1",
      examiner: "",
      summary: "",
      updated_at: null,
      exists: false,
    },
    "PUT /api/runs/r1/case-notes": (call: RecordedCall) => ({
      ...(call.body as object),
      updated_at: "2026-10-11T02:00:00Z",
      exists: true,
    }),
    "GET /api/runs/r1/issues": { issues: [{ step: "artifacts", message: "parser warning" }], count: 1 },
    "GET /api/runs/r1/search": (call: RecordedCall) => {
      const keyword = new URL(call.url, "http://x").searchParams.get("keyword");
      return { summary: { match_count: keyword === "invoice" ? KEYWORD_COUNT_LIMIT : 12 } };
    },
    ...overrides,
  };
}

beforeEach(() => {
  window.localStorage.clear();
  window.history.replaceState(null, "", "/v2/#/case/r1/intake");
  resetAppStore({ route: { runId: "r1", collection: "intake" } });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const card = (title: string) => {
  const heading = screen.getByRole("heading", { name: title });
  return heading.closest("section") as HTMLElement;
};

async function renderDashboard(overrides?: Record<string, unknown>) {
  const mock = mockFetch(routes(overrides));
  renderWithQuery(<CaseDashboard runId="r1" />);
  await screen.findByRole("heading", { name: "노트·메모" });
  return mock;
}

const cardIds = () =>
  [...document.querySelectorAll<HTMLElement>(".dash-grid > .dash-card")].map((el) => el.dataset.card);

describe("CaseDashboard (접수, r7 examiner-first)", () => {
  it("renders the 9 cards in examiner order with 12-column spans (8+4 · 6+6 · 4+4+4 · 8+4)", async () => {
    await renderDashboard();
    expect(CARD_IDS).toEqual([
      "status",
      "evidence",
      "categories",
      "warnings",
      "case-info",
      "keywords",
      "start",
      "notes",
      "review",
    ]);
    expect(cardIds()).toEqual([...CARD_IDS]);
    const spans = [...document.querySelectorAll<HTMLElement>(".dash-grid > .dash-card")].map((el) =>
      Number(el.dataset.span),
    );
    expect(spans).toEqual([8, 4, 6, 6, 4, 4, 4, 8, 4]);
    // Every band fills the 12 columns exactly.
    const bands = [spans.slice(0, 2), spans.slice(2, 4), spans.slice(4, 7), spans.slice(7, 9)];
    expect(bands.map((band) => band.reduce((a, b) => a + b, 0))).toEqual([12, 12, 12, 12]);
    expect(screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)).toEqual([
      "처리 상태",
      "증거",
      "아티팩트 범주",
      "처리 경고·제한 사항",
      "사건 정보",
      "키워드 일치",
      "시작할 곳",
      "노트·메모",
      "검토·보고서",
    ]);
    // 처리 설정 스냅샷 is no longer an intake card.
    expect(screen.queryByRole("heading", { name: /스냅샷/ })).toBeNull();
  });

  it("puts a sticky status strip on top: status · mode · times · 단계 N/N · 처리 요약 보기 (no raw run id)", async () => {
    await renderDashboard();
    const head = document.querySelector(".dash-head") as HTMLElement;
    expect(head).toBeTruthy();
    expect(head.parentElement?.classList.contains("dash")).toBe(true);
    const strip = within(head).getByTestId("dash-strip");
    expect(within(strip).getByRole("heading", { level: 1 }).textContent).toBe("case1.E01");
    expect(within(strip).getByRole("heading", { level: 1 }).getAttribute("title")).toBe("런 ID r1");
    expect(strip.textContent).toContain("완료");
    expect(strip.textContent).toContain("문서·부정 조사");
    expect(strip.textContent).toContain("총 소요");
    expect(strip.textContent).toContain("총 소요05:00");
    const bar = within(strip).getByRole("progressbar", { name: "처리 단계 진행" });
    expect(bar.getAttribute("aria-valuetext")).toBe("단계 2/2 완료");
    expect(within(strip).getByRole("button", { name: /처리 요약 보기/ })).toBeTruthy();
    expect(within(strip).getByRole("button", { name: "런 ID 복사" })).toBeTruthy();
    // Each card keeps its head (the sticky title row) as the first child.
    for (const section of document.querySelectorAll(".dash-grid > .dash-card")) {
      expect(section.firstElementChild?.classList.contains("dash-card-head")).toBe(true);
    }
    // The CSS contract behind it: sticky head + sticky card heads below it.
    expect(dashboardCss).toMatch(/\.dash-head \{[^}]*position: sticky;[^}]*top: 0;/);
    expect(dashboardCss).toMatch(/\.dash-card-head \{[^}]*position: sticky;[^}]*top: var\(--dash-head-h/);
  });

  it("fills 처리 상태 · 증거 · 아티팩트 범주 · 검토·보고서 from the run, summary, tree and dashboard payloads", async () => {
    await renderDashboard();
    const evidence = card("증거");
    await within(evidence).findByText("case1.E01");
    expect(evidence.textContent).toContain("2.0 GB");
    expect(evidence.textContent).toContain("155 (파일 30 + 아티팩트 125)");
    expect(evidence.textContent).toContain("파티션 2 (NTFS, 1.0 GB)");

    const status = card("처리 상태");
    // Step ids read in Korean (shared stepLabels); the raw id stays the cell tooltip.
    expect(status.textContent).toContain("증거 지문(해시)");
    expect(status.textContent).not.toContain("fingerprint");
    expect(status.querySelector('td[title="fingerprint"]')?.textContent).toBe("증거 지문(해시)");
    expect(status.textContent).toContain("아티팩트 수집완료01:00");
    // 수집기 (provider) and 검증 이슈 sit under one collapsed "단계 상세".
    const details = within(status).getByTestId("stage-details") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    expect(details.querySelector("summary")?.textContent).toBe(
      "단계 상세 — 단계 2/2 · 수집기 1/1 · 오류 0 · 검증 이슈 1건",
    );
    expect(within(status).getByRole("table", { name: "수집기 진행" })).toBeTruthy();
    expect(status.querySelector('td[title="registry"]')).toBeTruthy();

    const categories = card("아티팩트 범주");
    await within(categories).findByRole("button", { name: "운영 체제 100건 열기" });
    expect(categories.textContent).toContain("전체 125건");
    // The permanently disabled 증거 소스 select is gone.
    expect(categories.querySelector("select")).toBeNull();

    const review = card("검토·보고서");
    await within(review).findByRole("button", { name: "관련 있음 2건 리뷰보드에서 열기" });
    expect(within(review).getByRole("button", { name: /리뷰보드 항목\(북마크\) 4건/ })).toBeTruthy();
    await within(review).findByText("rapidtriage-case-report.pdf");
    expect(review.textContent).toContain("zip 미생성 · 3건");
    expect(review.textContent).toContain("이력 2건");
  });

  it("speaks Korean: no provider / known-good / (fraud) / bias / raw run id in the rendered text", async () => {
    await renderDashboard({
      "GET /api/runs/r1/summary": {
        summary: { counts },
        warnings: [{ step: "artifacts-recent-files", level: "warning", message: "행 단위 절단 10행" }],
        disclosures: {
          timezone: { evidence_timezone: { name: "Korea Standard Time", bias_minutes: -540 } },
          acquisition_copy_note: "호스트 시각은 source_file_* 로만 기록했습니다.",
          caps: { "artifacts-windows-prefetch": ["row-truncation:windows-prefetch"] },
          files: { excluded_file_count: 2, exclusion_reason_counts: { "category-not-selected": 2 } },
        },
      },
      "GET /api/runs/r1/problems": {
        run_id: "r1",
        total: 1,
        by_level: { warning: 1 },
        limit: 20,
        groups: [
          {
            reason_id: "row-truncated",
            label_ko: "행 단위 절단 (원문 일부만 보존)",
            level: "warning",
            count: 1,
            steps: [],
            items: [{ source: "warning", step: "artifacts-recent-files", level: "warning", message: "10행" }],
          },
        ],
      },
    });
    const warnings = card("처리 경고·제한 사항");
    await within(warnings).findByText("행 단위 절단 (원문 일부만 보존)");
    await waitFor(() => expect(warnings.textContent).toContain("취득 사본 시각"));
    const pane = screen.getByTestId("intake-pane");
    const text = pane.textContent ?? "";
    for (const raw of [
      "provider",
      "known-good",
      "(fraud)",
      "bias",
      "Korea Standard Time",
      "source_file_",
      "category-not-selected",
      "스냅숏",
      "검사자",
      "케이스 처리 세부",
      "공개 사항 —",
    ]) {
      expect(text, raw).not.toContain(raw);
    }
    expect(text).toContain("수집기");
    expect(text).toContain("UTC+09:00");
    expect(text).toContain("아티팩트 수집: 최근 파일·LNK");
    // Header counts 경고 · 알림 · 제한; info-tone lines sit in a collapsed "공개 사항(정보)".
    expect(warnings.querySelector(".dash-card-meta")?.textContent).toBe("경고 1 · 알림 0 · 제한 2");
    const info = within(warnings).getByTestId("disclosures-info") as HTMLDetailsElement;
    expect(info.open).toBe(false);
    expect(info.querySelector("summary")?.textContent).toMatch(/^공개 사항\(정보\) \d+건$/);
    for (const details of warnings.querySelectorAll("details")) expect(details.open).toBe(false);
  });

  it("adds no banner landmark or live region of its own (the shell owns both)", async () => {
    await renderDashboard();
    await within(card("증거")).findByText("case1.E01");
    expect(document.querySelectorAll("header,[role=banner]")).toHaveLength(0);
    expect(document.querySelectorAll("[aria-live],[role=status],[role=alert]")).toHaveLength(0);
  });

  it("routes chart bars, review rows, shortcuts, 처리 요약 보기 and 처리 설정 보기", async () => {
    await renderDashboard();
    fireEvent.click(await screen.findByRole("button", { name: "운영 체제 100건 열기" }));
    expect(window.location.hash).toBe("#/case/r1/explore/artifacts?category=operating-system");
    expect(useAppStore.getState().route.category).toBe("operating-system");

    fireEvent.click(await screen.findByRole("button", { name: "관련 있음 2건 리뷰보드에서 열기" }));
    expect(window.location.hash).toBe("#/case/r1/review/board/relevant");
    fireEvent.click(screen.getByRole("button", { name: /리뷰보드 항목\(북마크\)/ }));
    expect(window.location.hash).toBe("#/case/r1/review/board");

    const start = card("시작할 곳");
    fireEvent.click(within(start).getByRole("button", { name: /전체 검색/ }));
    expect(window.location.hash).toBe("#/case/r1/explore/search");
    fireEvent.click(within(start).getByRole("button", { name: /^아티팩트/ }));
    expect(window.location.hash).toBe("#/case/r1/explore/artifacts");
    fireEvent.click(within(start).getByRole("button", { name: /리뷰보드/ }));
    expect(window.location.hash).toBe("#/case/r1/review/board");

    fireEvent.click(screen.getByRole("button", { name: /처리 요약 보기/ }));
    expect(window.location.hash).toBe("#/case/r1/report/outputs");
    fireEvent.click(screen.getByRole("button", { name: /처리 설정 보기/ }));
    expect(window.location.hash).toBe("#/case/r1/process");
  });

  it("counts keyword hits one at a time and opens the search node", async () => {
    const { calls } = await renderDashboard();
    const keywords = card("키워드 일치");
    await waitFor(() => expect(keywords.textContent).toContain("12"));
    await waitFor(() => expect(keywords.textContent).toContain(`${KEYWORD_COUNT_LIMIT}+`));
    const searches = calls.filter((c) => c.url.startsWith("/api/runs/r1/search"));
    expect(searches.map((c) => new URL(c.url, "http://x").searchParams.get("keyword"))).toEqual([
      "fraud",
      "invoice",
      "bank",
    ]);
    expect(searches.every((c) => c.url.includes(`limit=${KEYWORD_COUNT_LIMIT}`))).toBe(true);

    fireEvent.click(within(keywords).getByRole("button", { name: "invoice 검색 열기" }));
    expect(window.location.hash).toBe("#/case/r1/explore/search?q=invoice");
    fireEvent.click(within(keywords).getByRole("button", { name: "계좌 검색 열기" }));
    expect(window.location.hash).toBe("#/case/r1/explore/search?q=bank");
  });

  it("saves the 요약 노트 (collapsed) with the single 분석관 field through PUT /case-notes", async () => {
    const { calls } = await renderDashboard();
    const notes = card("노트·메모");
    expect(within(notes).getAllByLabelText(/분석관/)).toHaveLength(1);
    const summaryNote = within(notes).getByTestId("summary-note") as HTMLDetailsElement;
    expect(summaryNote.open).toBe(false);
    fireEvent.change(within(notes).getByLabelText("분석관"), { target: { value: "홍길동" } });
    fireEvent.change(within(notes).getByLabelText("케이스 요약"), { target: { value: "이체 경위" } });
    expect(notes.textContent).toContain("저장하지 않은 변경이 있습니다");
    fireEvent.click(within(notes).getByRole("button", { name: "요약 노트 저장" }));
    await waitFor(() => expect(notes.textContent).toContain("저장됨"));
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.url).toBe("/api/runs/r1/case-notes");
    expect(put?.body).toEqual({ examiner: "홍길동", summary: "이체 경위" });
  });

  it("collapses cards (persisted in layout v2) and hides / restores them from the ⋯ menu", async () => {
    await renderDashboard();
    const toggle = within(card("시작할 곳")).getByRole("button", { name: "시작할 곳" });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(within(card("시작할 곳")).queryByRole("button", { name: /전체 검색/ })).toBeNull();
    expect(JSON.parse(window.localStorage.getItem("rt.dashboard.layout.v2") ?? "{}")).toEqual({
      version: 2,
      collapsed: ["start"],
      hidden: [],
    });

    fireEvent.click(screen.getByRole("button", { name: "증거 카드 메뉴" }));
    const menu = screen.getByRole("menu", { name: "증거 카드 메뉴" });
    expect(within(menu).getByRole("menuitem", { name: /새로고침/ })).toBeTruthy();
    fireEvent.click(within(menu).getByRole("menuitem", { name: /숨기기/ }));
    expect(screen.queryByRole("heading", { name: "증거" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "숨긴 카드 1개 다시 표시" }));
    expect(screen.getByRole("heading", { name: "증거" })).toBeTruthy();
  });

  it("migrates a saved v1 layout once: merged cards keep a state only when all their v1 cards had it", async () => {
    window.localStorage.setItem(
      "rt.dashboard.layout.v1",
      JSON.stringify({
        collapsed: ["start", "case-memo", "notes", "snapshot"],
        hidden: ["exports", "keywords", "processing"],
      }),
    );
    await renderDashboard();
    expect(window.localStorage.getItem("rt.dashboard.layout.v1")).toBeNull();
    expect(JSON.parse(window.localStorage.getItem("rt.dashboard.layout.v2") ?? "{}")).toEqual({
      version: 2,
      collapsed: ["notes", "start"],
      hidden: ["status", "keywords"],
    });
    // 내보내기 alone hidden in v1 does not hide the merged 검토·보고서 card.
    expect(screen.getByRole("heading", { name: "검토·보고서" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "키워드 일치" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "처리 상태" })).toBeNull();
    expect(screen.getByRole("button", { name: "숨긴 카드 2개 다시 표시" })).toBeTruthy();
  });

  it("explains empty cards while the run is still processing", async () => {
    await renderDashboard({
      "GET /api/runs/r1": {
        run_id: "r1",
        status: "running",
        request: { root: "D:/ev/case1.E01", mode: "fraud" },
        progress: { status: "running", stage: "inventory", started_at: "2026-10-11T00:00:00Z" },
      },
      "GET /api/runs/r1/dashboard": {
        run_id: "r1",
        completed: false,
        profile: { mode: "fraud", description: "", keywords: ["fraud"] },
        evidence_source: { path: "D:/ev/case1.E01", name: "case1.E01", kind: "file", partitions: [] },
        exports: [],
      },
    });
    expect(card("아티팩트 범주").textContent).toContain("런이 완료되면 표시됩니다.");
    expect(card("키워드 일치").textContent).toContain("런이 완료되면 표시됩니다.");
    expect(card("처리 경고·제한 사항").textContent).toContain("런이 완료되면 표시됩니다.");
    expect(card("처리 상태").textContent).toContain("현재 단계");
    expect(card("처리 상태").textContent).toContain("진행 중");
    const scan = screen.getByRole("button", { name: /처리 요약 보기/ });
    expect(scan.getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(scan);
    expect(window.location.hash).toBe("#/case/r1/intake");
  });
});

describe("접수 layout CSS contract (container query, bands, no bleed)", () => {
  it("switches to 12 columns on the pane width (container query), single column otherwise", () => {
    expect(dashboardCss).not.toMatch(/@media \(min-width: 1200px\)/);
    expect(dashboardCss).toMatch(
      /@container dash \(min-width: 1100px\) \{\s*\.dash-grid \{\s*grid-template-columns: repeat\(12, minmax\(0, 1fr\)\);/,
    );
    // Narrow (default): one column, every card spans it.
    expect(dashboardCss).toMatch(/\.dash-grid \{[^}]*grid-template-columns: minmax\(0, 1fr\);/);
    expect(dashboardCss).toMatch(/\.dash-grid > \.dash-card \{\s*grid-column: 1 \/ -1;/);
    for (const span of [4, 6, 8]) {
      expect(dashboardCss).toContain(
        `.dash-grid > .dash-card[data-span="${span}"] {\n    grid-column: span ${span};`,
      );
    }
  });

  it("makes band cards equal height with an inner body scroller and clipped paint", () => {
    expect(dashboardCss).toMatch(/\.dash-grid \{[^}]*align-items: stretch;/);
    expect(dashboardCss).toMatch(
      /\.dash-card \{[^}]*display: flex;[^}]*flex-direction: column;[^}]*height: 100%;/,
    );
    expect(dashboardCss).toMatch(/\.dash-card \{[^}]*contain: paint;/);
    expect(dashboardCss).toMatch(
      /\.dash-card-body \{[^}]*flex: 1;[^}]*min-height: 0;[^}]*max-block-size: var\(--card-body-max\);[^}]*overflow-x: hidden;[^}]*overflow-y: auto;/,
    );
    expect(dashboardCss).toMatch(/\.dash \{[^}]*overflow: auto;[^}]*overscroll-behavior: contain;/);
    expect(dashboardCss).toMatch(/\.dash-scroll \{[^}]*overflow: auto;/);
    expect(dashboardCss).toMatch(
      /\.dash-card \.dash-wrap,[^{]*\{[^}]*white-space: normal;[^}]*overflow-wrap: anywhere;/,
    );
  });
});
