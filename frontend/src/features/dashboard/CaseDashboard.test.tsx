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
    expect(processing.textContent).toContain("fingerprint");
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
