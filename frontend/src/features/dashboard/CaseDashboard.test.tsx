import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../../state/store";
import { mockFetch, type RecordedCall, renderWithQuery } from "../case/testUtils";
import { CaseDashboard } from "./CaseDashboard";
import { KEYWORD_COUNT_LIMIT } from "./cards";

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
  // The card tests below read every card: open them all (a first visit folds most, see below).
  window.localStorage.setItem("rt.dashboard.layout.v1", JSON.stringify({ collapsed: [], hidden: [] }));
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
  await screen.findByRole("heading", { name: "케이스 요약 노트" });
  return mock;
}

describe("CaseDashboard (접수)", () => {
  it("renders every card from the run, summary, tree and dashboard payloads", async () => {
    await renderDashboard();
    const evidence = card("증거 소스");
    await within(evidence).findByText("case1.E01");
    expect(evidence.textContent).toContain("2.0 GB");
    expect(evidence.textContent).toContain("155 (파일 30 + 아티팩트 125)");
    expect(evidence.textContent).toContain("파티션 2 (NTFS, 1.0 GB)");

    const processing = card("케이스 처리 세부");
    expect(processing.textContent).toContain("r1");
    // Step ids read in Korean (shared stepLabels); the raw id stays the cell tooltip.
    expect(processing.textContent).toContain("증거 지문(해시)");
    expect(processing.textContent).not.toContain("fingerprint");
    expect(processing.querySelector('td[title="fingerprint"]')?.textContent).toBe("증거 지문(해시)");
    expect(processing.textContent).toContain("1분 0초");
    expect(processing.textContent).toContain("registry");

    const categories = card("아티팩트 범주");
    await within(categories).findByRole("button", { name: "운영 체제 100건 열기" });
    expect(categories.textContent).toContain("전체 125건");

    const review = card("태그 및 리뷰 상태");
    await within(review).findByRole("button", { name: "관련 있음 2건 리뷰보드에서 열기" });
    expect(within(review).getByRole("button", { name: /리뷰보드 항목\(북마크\) 4건/ })).toBeTruthy();

    const exports = card("내보내기/보고서 이력");
    await within(exports).findByText("rapidtriage-case-report.pdf");
    expect(exports.textContent).toContain("zip 미생성 · 3건");
  });

  it("adds no banner landmark or live region of its own (the shell owns both)", async () => {
    await renderDashboard();
    await within(card("증거 소스")).findByText("case1.E01");
    expect(document.querySelectorAll("header,[role=banner]")).toHaveLength(0);
    expect(document.querySelectorAll("[aria-live],[role=status],[role=alert]")).toHaveLength(0);
  });

  it("routes chart bars, review rows, shortcuts and 스캔 요약 보기 to tree nodes", async () => {
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

    fireEvent.click(screen.getByRole("button", { name: /스캔 요약 보기/ }));
    expect(window.location.hash).toBe("#/case/r1/report/outputs");
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

  it("saves the case notes through PUT /case-notes", async () => {
    const { calls } = await renderDashboard();
    const notes = card("케이스 요약 노트");
    fireEvent.change(within(notes).getByLabelText("검사자 이름"), { target: { value: "홍길동" } });
    fireEvent.change(within(notes).getByLabelText("케이스 요약"), { target: { value: "이체 경위" } });
    expect(notes.textContent).toContain("저장하지 않은 변경이 있습니다");
    fireEvent.click(within(notes).getByRole("button", { name: "저장" }));
    await waitFor(() => expect(notes.textContent).toContain("저장됨"));
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.url).toBe("/api/runs/r1/case-notes");
    expect(put?.body).toEqual({ examiner: "홍길동", summary: "이체 경위" });
  });

  it("collapses cards (persisted) and hides / restores them from the ⋯ menu", async () => {
    await renderDashboard();
    const toggle = within(card("시작할 곳")).getByRole("button", { name: "시작할 곳" });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(within(card("시작할 곳")).queryByRole("button", { name: /전체 검색/ })).toBeNull();
    expect(JSON.parse(window.localStorage.getItem("rt.dashboard.layout.v1") ?? "{}").collapsed).toEqual([
      "start",
    ]);

    fireEvent.click(screen.getByRole("button", { name: "증거 소스 카드 메뉴" }));
    const menu = screen.getByRole("menu", { name: "증거 소스 카드 메뉴" });
    expect(within(menu).getByRole("menuitem", { name: /새로고침/ })).toBeTruthy();
    fireEvent.click(within(menu).getByRole("menuitem", { name: /숨기기/ }));
    expect(screen.queryByRole("heading", { name: "증거 소스" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "숨긴 카드 1개 다시 표시" }));
    expect(screen.getByRole("heading", { name: "증거 소스" })).toBeTruthy();
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
    expect(card("케이스 처리 세부").textContent).toContain("진행 중");
    const scan = screen.getByRole("button", { name: /스캔 요약 보기/ });
    expect(scan.getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(scan);
    expect(window.location.hash).toBe("#/case/r1/intake");
  });
});

const histogram = {
  total_events: 9,
  parsed_events: 9,
  unparsed_events: 0,
  bucket_seconds: 3600,
  bucket_count: 3,
  range_start: "2026-10-10T00:00:00Z",
  range_end: "2026-10-12T02:00:00Z",
  sources: [],
  buckets: [
    { index: 0, start: "2026-10-10T00:00:00Z", end: "2026-10-10T01:00:00Z", count: 2 },
    { index: 1, start: "2026-10-12T01:00:00Z", end: "2026-10-12T02:00:00Z", count: 6 },
    { index: 2, start: "2026-10-12T02:00:00Z", end: "2026-10-12T03:00:00Z", count: 1 },
  ],
};

const overviewRoutes = {
  "GET /api/runs/r1/timeline-histogram": histogram,
  "GET /api/runs/r1/review-map": {
    marks: [
      { citation_id: "1", status: "relevant", include_in_report: false, collection: "timeline", tags: [] },
      { citation_id: "2", status: "relevant", include_in_report: true, collection: "files", tags: [] },
      { citation_id: "3", status: "excluded", include_in_report: false, collection: "indicators", tags: [] },
    ],
  },
  "GET /api/runs/r1/problems": {
    run_id: "r1",
    total: 4,
    by_level: { warning: 3, notice: 1 },
    limit: 20,
    groups: [],
  },
};

describe("CaseDashboard 사건 개요 (F6/F7/F9)", () => {
  beforeEach(() => {
    window.localStorage.clear();
    useAppStore.getState().setTimezone("utc");
  });

  it("folds every card but evidence, problems and the settings summary on a first visit", async () => {
    await renderDashboard(overviewRoutes);
    const expanded = (title: string) =>
      within(card(title)).getByRole("button", { name: title }).getAttribute("aria-expanded");
    expect(expanded("증거 목록")).toBe("true");
    expect(expanded("처리 문제")).toBe("true");
    expect(expanded("처리 설정 스냅샷")).toBe("true");
    for (const title of ["사건 정보", "증거 소스", "아티팩트 범주", "태그 및 리뷰 상태", "시작할 곳"])
      expect(expanded(title)).toBe("false");
    // Nothing is written until the examiner changes something.
    expect(window.localStorage.getItem("rt.dashboard.layout.v1")).toBeNull();
  });

  it("says each status with its subject", async () => {
    await renderDashboard(overviewRoutes);
    const status = screen.getByTestId("dash-status");
    const terms = within(status)
      .getAllByRole("term")
      .map((node) => node.textContent);
    expect(terms).toEqual(["처리", "처리 오류"]);
    expect(status.textContent).toContain("완료");
    expect(status.textContent).toContain("0");
  });

  it("lists 먼저 할 일 that apply and routes each to its screen", async () => {
    await renderDashboard(overviewRoutes);
    const todo = screen.getByTestId("dash-todo");
    await within(todo).findByText("판정하지 않은 지표 후보 1건");
    expect(within(todo).getByText("처리 문제 3건 (오류와 경고)을 확인하세요")).toBeTruthy();
    expect(within(todo).getByText("관련 있음 1건이 보고서에 포함되지 않았습니다")).toBeTruthy();
    fireEvent.click(within(todo).getByRole("button", { name: "지표 후보 열기" }));
    expect(window.location.hash).toBe("#/case/r1/explore/indicators");
    fireEvent.click(within(todo).getByRole("button", { name: "검토 보드에서 보기" }));
    const route = useAppStore.getState().route;
    expect([route.collection, route.status, route.cf]).toEqual([
      "review",
      "relevant",
      [{ col: "report", op: ":", value: "미포함" }],
    ]);
  });

  it("says in one line when nothing needs doing", async () => {
    await renderDashboard({
      ...overviewRoutes,
      "GET /api/runs/r1/summary": { summary: { counts: { ...counts, indicators: 0 } } },
      "GET /api/runs/r1/review-map": { marks: [] },
      "GET /api/runs/r1/problems": { run_id: "r1", total: 1, by_level: { notice: 1 }, limit: 20, groups: [] },
    });
    const todo = screen.getByTestId("dash-todo");
    await within(todo).findByText(/지금 먼저 할 일이 없습니다/);
    expect(within(todo).queryByRole("listitem")).toBeNull();
  });

  it("shows key numbers with their populations and opens each collection", async () => {
    await renderDashboard(overviewRoutes);
    const overview = screen.getByTestId("dash-overview");
    const files = await within(overview).findByRole("button", { name: /^파일 후보 30건/ });
    expect(files.textContent).toContain("전체 파일 수가 아님");
    expect(within(overview).getByRole("button", { name: /^타임라인 이벤트 9건/ })).toBeTruthy();
    expect(within(overview).getByRole("button", { name: /^아티팩트 125건/ })).toBeTruthy();
    expect(within(overview).getByRole("button", { name: /^지표 후보 2건/ })).toBeTruthy();
    // 판정 3 = 관련 있음 2 + 제외 1, with the breakdown linking to the review board.
    expect(within(overview).getByRole("list", { name: "판정 내역" }).closest("li")?.textContent).toContain(
      "3판정",
    );
    fireEvent.click(within(overview).getByRole("button", { name: "제외 1건 검토 보드에서 열기" }));
    expect(window.location.hash).toBe("#/case/r1/review/board/excluded");
    fireEvent.click(files);
    expect(window.location.hash).toBe("#/case/r1/explore/files");
  });

  it("draws activity by date with counts and opens the busiest day in the timeline", async () => {
    await renderDashboard(overviewRoutes);
    const activity = screen.getByTestId("dash-activity");
    const days = await within(activity).findByRole("list", { name: "날짜별 이벤트 수 (UTC)" });
    expect(
      within(days)
        .getAllByRole("button")
        .map((b) => b.getAttribute("aria-label")),
    ).toEqual([
      "10-10 (토) 2건, 타임라인 열기",
      "10-11 (일) 0건, 타임라인 열기",
      "10-12 (월) 7건, 타임라인 열기",
    ]);
    expect(activity.textContent).toContain("7건입니다 (전체 9건의 78%)");
    expect(activity.textContent).toContain("01:00~01:59 (6건)");
    fireEvent.click(within(activity).getByRole("button", { name: "이 날 타임라인 열기" }));
    const route = useAppStore.getState().route;
    expect(route.collection).toBe("timeline");
    expect(route.from).toBe("2026-10-12T00:00:00.000Z");
    expect(route.to).toBe("2026-10-12T23:59:59.999Z");
  });

  it("replaces the numbers with the failure and a way out when processing failed", async () => {
    await renderDashboard({
      ...overviewRoutes,
      "GET /api/runs/r1": {
        run_id: "r1",
        status: "failed",
        error: "디스크 이미지를 열 수 없습니다",
        request: { root: "D:/ev/case1.E01", mode: "fraud" },
        progress: { status: "failed", error_count: 2 },
      },
    });
    const failed = screen.getByTestId("overview-failed");
    expect(failed.textContent).toContain("처리가 실패했습니다");
    expect(failed.textContent).toContain("디스크 이미지를 열 수 없습니다");
    expect(within(failed).getByRole("button", { name: /다시 실행/ })).toBeTruthy();
    fireEvent.click(within(failed).getByRole("button", { name: "처리 단계 보기" }));
    expect(useAppStore.getState().route.collection).toBe("process");
    expect(screen.getByTestId("dash-status").textContent).toContain("2");
  });

  it("says an empty run is empty instead of 0 0 0 0", async () => {
    await renderDashboard({
      ...overviewRoutes,
      "GET /api/runs/r1/summary": {
        summary: {
          counts: { ...counts, artifacts: 0, files: 0, timeline_events: 0, indicators: 0, docs: 0 },
        },
      },
    });
    const empty = await screen.findByTestId("overview-empty");
    expect(empty.textContent).toContain("이 런에서 수집된 항목이 없습니다");
    expect(screen.getByTestId("dash-activity").textContent).toContain("시각이 있는 이벤트가 없습니다");
  });
});
