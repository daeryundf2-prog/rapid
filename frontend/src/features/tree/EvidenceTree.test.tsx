import { act, cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { getRegisteredCommands } from "./adapter";
import { buildTreeCommands } from "./commands";
import { EvidenceTree } from "./EvidenceTree";
import { buildTreeModel, filterEmptyNodes, flattenVisible, type TreeModelNode } from "./model";
import { resetTreePrefs, SHOW_EMPTY_KEY, useTreePrefs } from "./treePrefs";

const counts = {
  validation_issues: 1,
  outputs: 5,
  artifacts: 120,
  docs: 0,
  files: 30,
  timeline_events: 9,
  review_items: 0,
  indicators: 2,
};

function routes() {
  return {
    "GET /api/runs": { runs: [{ run_id: "r1", status: "completed" }] },
    "GET /api/runs/r1/summary": { summary: { counts } },
    "GET /api/runs/r1/tree": {
      run_id: "r1",
      root: {},
      nodes: [
        {
          id: "artifacts",
          label: "아티팩트",
          count: 120,
          collection: "artifacts",
          children: [
            {
              id: "artifacts-group:system",
              label: "시스템",
              count: 7,
              children: [
                {
                  id: "artifacts:windows-system",
                  label: "Windows 시스템",
                  count: 7,
                  collection: "artifacts",
                  kind: "windows-system",
                  artifact_type_counts: { "webshell-source-candidate": 2, "web-server-log": 5 },
                },
              ],
            },
            {
              id: "artifacts-group:event-log",
              label: "이벤트 로그",
              count: 100,
              children: [
                {
                  id: "artifacts:eventlog",
                  label: "EVTX",
                  count: 100,
                  collection: "artifacts",
                  kind: "eventlog",
                },
              ],
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
      by_status: { relevant: 2 },
      include_in_report: 1,
      case_json: { bookmarks: 0, include_in_report: 0 },
      report_candidates: 1,
    },
    "POST /api/case-db/saved-searches/list": {
      saved_searches: [{ name: "패스워드", keywords: ["password"] }],
    },
    "GET /api/runs/r1/dashboard": {
      run_id: "r1",
      completed: true,
      profile: { mode: "fraud", description: "", keywords: [] },
      evidence_source: {
        path: "D:/ev/case1.E01",
        name: "case1.E01",
        kind: "image",
        image_output: "e01",
        size_bytes: 1000,
        selected_partition: 2,
        partitions: [
          {
            number: 1,
            description: "",
            filesystem: "fat32",
            size_bytes: 1024,
            start_sector: 63,
            byte_offset: 0,
            selected: false,
            recommended: false,
          },
          {
            number: 2,
            description: "",
            filesystem: "ntfs",
            size_bytes: 2048,
            start_sector: 2048,
            byte_offset: 0,
            selected: true,
            recommended: true,
          },
        ],
      },
      exports: [],
    },
  };
}

beforeEach(() => {
  window.location.hash = "";
  // A route left by the previous test would pre-expand its domain.
  useAppStore.getState().syncRouteFromLocation(parseHash(""));
  mockFetch(routes());
  // The navigation tests walk every node: empty families shown (U-F7 has its own block below).
  window.localStorage.setItem(SHOW_EMPTY_KEY, "1");
  resetTreePrefs();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.removeItem(SHOW_EMPTY_KEY);
  resetTreePrefs();
});

async function renderTree() {
  renderWithQuery(<EvidenceTree runId="r1" />);
  await screen.findByText("이벤트 로그");
  await screen.findByText("case1.E01");
  await waitFor(() => expect(item("이벤트 로그").textContent).toContain("100"));
}

const item = (name: string) =>
  screen.getByRole("treeitem", { name: new RegExp(`^${name.replace(/[()[\]{}.*+?^$|\\]/g, "\\$&")}`) });

describe("EvidenceTree (탐색 domain tree)", () => {
  it("renders 증거 소스, 전체 보기 and collapsed domains with levels and counts", async () => {
    await renderTree();
    expect(screen.getByRole("tree", { name: "케이스 탐색 트리" })).toBeTruthy();
    expect(item("증거 소스").getAttribute("aria-level")).toBe("1");
    expect(item("전체 보기").getAttribute("aria-expanded")).toBe("true");
    expect(item("파일 목록").getAttribute("aria-level")).toBe("2");
    expect(item("파일 목록").textContent).toContain("30");
    expect(item("이벤트 로그").getAttribute("aria-level")).toBe("1");
    expect(item("이벤트 로그").getAttribute("aria-expanded")).toBe("false");
    expect(item("이벤트 로그").querySelector(".badge.strong")?.textContent).toBe("100");
    expect(screen.queryByText("전체 이벤트 로그(EVTX·ETL)")).toBeNull();
    fireEvent.click(item("이벤트 로그").querySelector(".case-tree-twisty") as Element);
    expect(item("전체 이벤트 로그(EVTX·ETL)").getAttribute("aria-level")).toBe("2");
    // No workflow nodes: 접수 / 리뷰보드 / 산출물 / 분석 작업 are rail stages.
    for (const gone of ["접수", "리뷰보드", "산출물", "분석 작업"]) {
      expect(screen.queryByRole("treeitem", { name: new RegExp(`^${gone}`) })).toBeNull();
    }
    await screen.findByText("패스워드");
  });

  it("dims zero-count nodes (is-empty, no strong badge) — visual-polish B2 #6", async () => {
    await renderTree();
    const zero = screen
      .getAllByRole("treeitem")
      .filter((li) => li.querySelector(":scope > .badge")?.textContent === "0");
    expect(zero.length).toBeGreaterThan(0);
    for (const li of zero) {
      expect(li.classList.contains("is-empty")).toBe(true);
      expect(li.querySelector(":scope > .badge.strong")).toBeNull();
    }
    expect(item("이벤트 로그").classList.contains("is-empty")).toBe(false);
  });

  it("uses a roving tabindex: exactly one tab stop", async () => {
    await renderTree();
    const stops = screen.getAllByRole("treeitem").filter((el) => el.getAttribute("tabindex") === "0");
    expect(stops).toHaveLength(1);
  });

  it("moves with arrows, Home and End", async () => {
    await renderTree();
    item("전체 보기").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowDown" });
    expect(document.activeElement).toBe(item("파일 목록"));
    fireEvent.keyDown(document.activeElement as Element, { key: "End" });
    expect(document.activeElement).toBe(item("위치·여행"));
    fireEvent.keyDown(document.activeElement as Element, { key: "Home" });
    expect(document.activeElement).toBe(item("증거 소스"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowUp" });
    expect(document.activeElement).toBe(item("증거 소스"));
  });

  it("expands with ArrowRight, steps to the child, and back to the parent with ArrowLeft", async () => {
    await renderTree();
    item("이벤트 로그").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    expect(item("이벤트 로그").getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    expect(document.activeElement).toBe(item("전체 이벤트 로그(EVTX·ETL)"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    expect(document.activeElement).toBe(item("이벤트 로그"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    expect(item("이벤트 로그").getAttribute("aria-expanded")).toBe("false");
  });

  it("jumps by type-ahead", async () => {
    await renderTree();
    item("증거 소스").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "메" });
    expect(document.activeElement).toBe(item("메신저·메일"));
  });

  it("Enter opens a domain node in 탐색 and marks it selected", async () => {
    await renderTree();
    item("이벤트 로그").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    item("전체 이벤트 로그(EVTX·ETL)").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "Enter" });
    expect(window.location.hash).toBe("#/case/r1/explore/artifacts/eventlog");
    await waitFor(() =>
      expect(item("전체 이벤트 로그(EVTX·ETL)").getAttribute("aria-selected")).toBe("true"),
    );
  });

  it("a typed node sends its artifact types (침해사고 › 웹셸 → artifact_type=)", async () => {
    await renderTree();
    fireEvent.click(item("침해사고").querySelector(".case-tree-twisty") as Element);
    fireEvent.click(item("웹셸"));
    expect(window.location.hash).toBe(
      "#/case/r1/explore/artifacts/windows-system?types=webshell-source-candidate",
    );
    await waitFor(() => expect(item("웹셸").getAttribute("aria-selected")).toBe("true"));
    expect(item("웹 서버 로그").getAttribute("aria-selected")).toBe("false");
  });

  it("clicking a view navigates; empty nodes stay put and explain why", async () => {
    await renderTree();
    fireEvent.click(item("파일 목록"));
    expect(window.location.hash).toBe("#/case/r1/explore/files");
    expect(item("문서/메일").getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(item("문서/메일"));
    expect(window.location.hash).toBe("#/case/r1/explore/files");
    expect(document.querySelector(".case-tree-reason")?.textContent).toBe(
      "docs-index 산출물이 없는 런입니다",
    );
    fireEvent.click(item("NTFS·파일시스템 아티팩트").querySelector(".case-tree-twisty") as Element);
    // Analysis result nodes always open their pane (never-ran state shown there).
    expect(item("복구/카빙").getAttribute("aria-disabled")).toBeNull();
    expect(item("복구/카빙").getAttribute("aria-label")).toContain("미실행");
    fireEvent.click(item("복구/카빙"));
    expect(window.location.hash).toBe("#/case/r1/explore/analysis/carve");
  });

  it("lists the evidence source with partitions; only the recovered partition opens files", async () => {
    await renderTree();
    expect(item("case1.E01").getAttribute("aria-label")).toBe("case1.E01, 150건");
    fireEvent.click(item("case1.E01").querySelector(".case-tree-twisty") as Element);
    const ntfs = item("파티션 2");
    expect(ntfs.getAttribute("aria-label")).toContain("선택됨");
    fireEvent.click(item("파티션 1"));
    expect(document.querySelector(".case-tree-reason")?.textContent).toContain("선택되지 않았습니다");
    fireEvent.click(ntfs);
    expect(window.location.hash).toBe("#/case/r1/explore/files");
    // 파일 목록 owns the files route (first match); evidence shortcuts never render as selected.
    await waitFor(() => expect(item("파일 목록").getAttribute("aria-selected")).toBe("true"));
    expect(ntfs.getAttribute("aria-selected")).toBe("false");
  });

  it("opens a saved search into the 검색 결과 view", async () => {
    await renderTree();
    const saved = await screen.findByRole("treeitem", { name: /패스워드/ });
    fireEvent.click(saved);
    expect(window.location.hash).toBe("#/case/r1/explore/search");
  });
});

describe("tree commands", () => {
  it("registers one tree.goto.* command per node with disabled reasons", () => {
    const model = buildTreeModel({ summary: { summary: { counts } } });
    const commands = buildTreeCommands("r1", model);
    const ids = commands.map((c) => c.id);
    expect(ids).toContain("tree.goto.timeline");
    expect(ids).toContain("tree.goto.domain.incident.ir-webshell");
    expect(ids).toContain("tree.focus");
    const ctx = {
      runId: "r1",
      collection: null,
      selectedRowKeys: [],
      focusedRowKey: null,
      viewerHasTarget: false,
      runIsActive: false,
    };
    expect(commands.find((c) => c.id === "tree.goto.docs")?.disabledReason?.(ctx)).toBe(
      "docs-index 산출물이 없는 런입니다",
    );
    expect(commands.find((c) => c.id === "tree.goto.files")?.disabledReason?.({ ...ctx, runId: null })).toBe(
      "열린 케이스가 없습니다",
    );
    void commands.find((c) => c.id === "tree.goto.domain.incident.ir-webshell")?.run(ctx);
    expect(window.location.hash).toBe(
      "#/case/r1/explore/artifacts/windows-system?types=webshell-source-candidate",
    );
    expect(getRegisteredCommands()).toBeDefined();
  });
});

describe("결과 없는 계열 숨김 (viewer-families U-F7)", () => {
  beforeEach(() => {
    window.localStorage.removeItem(SHOW_EMPTY_KEY);
    resetTreePrefs();
  });

  const toggle = () => screen.getByTestId("tree-empty-toggle");
  const countIn = (text: string) => Number(/(\d[\d,]*)개/.exec(text)?.[1]?.replace(/,/g, ""));

  it("hides empty families by default; the toggle's n is the number of rows it reveals; state persists", async () => {
    renderWithQuery(<EvidenceTree runId="r1" />);
    await screen.findByText("이벤트 로그");
    await waitFor(() => expect(item("이벤트 로그").textContent).toContain("100"));
    // 위치·여행 has no data in this run: hidden.
    expect(screen.queryByRole("treeitem", { name: /^위치·여행/ })).toBeNull();
    await screen.findByText("패스워드");
    expect(toggle().getAttribute("aria-pressed")).toBe("false");
    expect(toggle().textContent).toMatch(/^결과 없는 계열 \d+개 표시$/);
    const n = countIn(toggle().textContent ?? "");
    const beforeIds = new Set(screen.getAllByRole("treeitem").map((li) => li.dataset.nodeId));
    const before = beforeIds.size;
    fireEvent.click(toggle());
    expect(toggle().getAttribute("aria-pressed")).toBe("true");
    expect(toggle().textContent).toBe(`결과 없는 계열 ${n}개 숨김`);
    // n = rows that appear when every branch is expanded (a hidden domain counts once).
    const full = buildTreeModel({
      summary: { summary: { counts } },
      tree: routes()["GET /api/runs/r1/tree"] as never,
    });
    const allIds = (nodes: TreeModelNode[]): Set<string> =>
      new Set(nodes.flatMap((node) => [node.id, ...(node.children ? allIds(node.children) : [])]));
    const shownAll = filterEmptyNodes(full, true);
    const hiddenAll = filterEmptyNodes(full, false);
    const rows = (nodes: TreeModelNode[]) => flattenVisible(nodes, allIds(nodes)).length;
    const topLevelRows = (nodes: TreeModelNode[]) =>
      flattenVisible(nodes, allIds(nodes)).filter(
        (f) => f.parentId === null || !hiddenAll.hiddenIds.has(f.parentId),
      ).length;
    expect(hiddenAll.hiddenCount).toBe(n);
    expect(topLevelRows(shownAll.nodes) - rows(hiddenAll.nodes)).toBe(n);
    // Every newly shown row carries the hidden marker.
    const added = screen.getAllByRole("treeitem").filter((li) => !beforeIds.has(li.dataset.nodeId));
    expect(added.length).toBeGreaterThan(0);
    expect(added.every((li) => li.hasAttribute("data-hidden-empty"))).toBe(true);
    expect(screen.getAllByRole("treeitem").length).toBeGreaterThan(before);
    // Shown dimmed with the reason.
    const hiddenDomain = item("위치·여행");
    expect(hiddenDomain.classList.contains("is-dimmed")).toBe(true);
    expect(hiddenDomain.getAttribute("aria-description")).toMatch(/^결과 없음: /);
    expect(window.localStorage.getItem(SHOW_EMPTY_KEY)).toBe("1");
    expect(useTreePrefs.getState().showEmpty).toBe(true);
  });

  it("tree search finds hidden nodes and shows them", async () => {
    renderWithQuery(<EvidenceTree runId="r1" />);
    await screen.findByText("이벤트 로그");
    await waitFor(() => expect(item("이벤트 로그").textContent).toContain("100"));
    expect(screen.queryByRole("treeitem", { name: /^위치·여행/ })).toBeNull();
    fireEvent.change(screen.getByRole("searchbox", { name: "트리 검색" }), { target: { value: "위치" } });
    expect(item("위치·여행").hasAttribute("data-hidden-empty")).toBe(true);
  });

  it("a deep link to a hidden node reveals it (and its domain)", async () => {
    renderWithQuery(<EvidenceTree runId="r1" />);
    await screen.findByText("이벤트 로그");
    await waitFor(() => expect(item("이벤트 로그").textContent).toContain("100"));
    expect(screen.queryByRole("treeitem", { name: /^위치·여행/ })).toBeNull();
    const hidden = buildTreeModel({
      summary: { summary: { counts } },
      tree: routes()["GET /api/runs/r1/tree"] as never,
    })
      .find((n) => n.label === "위치·여행")
      ?.children?.find((c) => c.target);
    expect(hidden?.hiddenReason).toBeTruthy();
    act(() => useAppStore.getState().navigate({ runId: "r1", ...(hidden?.target ?? {}) } as never));
    await waitFor(() => expect(item(hidden?.label ?? "").getAttribute("aria-selected")).toBe("true"));
    expect(item("위치·여행").getAttribute("aria-expanded")).toBe("true");
  });

  it("T (tree.toggle-empty) flips the preference only while a tree is mounted", async () => {
    const { treeEmptyCommand, NO_TREE_REASON } = await import("./treePrefs");
    const command = treeEmptyCommand();
    const ctx = {
      runId: "r1",
      collection: null,
      selectedRowKeys: [],
      focusedRowKey: null,
      viewerHasTarget: false,
      runIsActive: false,
    };
    expect(command.shortcut).toBe("T");
    expect(command.disabledReason?.(ctx)).toBe(NO_TREE_REASON);
    renderWithQuery(<EvidenceTree runId="r1" />);
    await screen.findByText("이벤트 로그");
    expect(command.disabledReason?.(ctx)).toBeUndefined();
    await command.run(ctx);
    expect(useTreePrefs.getState().showEmpty).toBe(true);
  });
});

describe("hidden-family count is final (review #7)", () => {
  it("the toggle waits for the summary too, so n never jumps after it appears", async () => {
    window.localStorage.removeItem(SHOW_EMPTY_KEY);
    resetTreePrefs();
    const { fetchMock } = mockFetch(routes());
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const inner = fetchMock.getMockImplementation();
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).includes("/summary")) await gate;
      return (inner as (i: RequestInfo | URL, n?: RequestInit) => Promise<Response>)(input, init);
    });
    renderWithQuery(<EvidenceTree runId="r1" />);
    await screen.findByText("이벤트 로그");
    // /tree answered, the summary has not: no count yet.
    await waitFor(() => expect(item("이벤트 로그").textContent).toContain("100"));
    expect(screen.queryByTestId("tree-empty-toggle")).toBeNull();
    act(() => release());
    const toggle = await screen.findByTestId("tree-empty-toggle");
    const first = toggle.textContent;
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.getByTestId("tree-empty-toggle").textContent).toBe(first);
  });
});
