import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { getRegisteredCommands } from "./adapter";
import { buildTreeCommands } from "./commands";
import { EvidenceTree } from "./EvidenceTree";
import { buildTreeModel } from "./model";

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
  mockFetch(routes());
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function renderTree() {
  renderWithQuery(<EvidenceTree runId="r1" />);
  await screen.findByText("운영 체제");
  await screen.findByText("case1.E01");
}

const item = (name: string) => screen.getByRole("treeitem", { name: new RegExp(name) });

describe("EvidenceTree", () => {
  it("renders a tree with levels, expansion state and live counts", async () => {
    await renderTree();
    expect(screen.getByRole("tree", { name: "케이스 탐색 트리" })).toBeTruthy();
    expect(item("접수").getAttribute("aria-level")).toBe("1");
    expect(item("운영 체제").getAttribute("aria-level")).toBe("2");
    expect(item("운영 체제").getAttribute("aria-expanded")).toBe("false");
    expect(item("운영 체제").querySelector(".badge.strong")?.textContent).toBe("100");
    expect(screen.queryByText("EVTX")).toBeNull();
    fireEvent.click(item("운영 체제").querySelector(".case-tree-twisty") as Element);
    expect(item("EVTX").getAttribute("aria-level")).toBe("3");
    expect(item("EVTX").querySelector("svg[data-icon='list']")).toBeTruthy();
    expect(item("아티팩트").getAttribute("aria-expanded")).toBe("true");
    expect(item("파일/미디어").getAttribute("aria-expanded")).toBeNull();
    expect(item("파일/미디어").textContent).toContain("30");
    expect(item("리뷰보드").textContent).toContain("2");
    await screen.findByText("패스워드");
  });

  it("uses a roving tabindex: exactly one tab stop", async () => {
    await renderTree();
    const stops = screen.getAllByRole("treeitem").filter((el) => el.getAttribute("tabindex") === "0");
    expect(stops).toHaveLength(1);
  });

  it("moves with arrows, Home and End", async () => {
    await renderTree();
    item("접수").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowDown" });
    expect(document.activeElement).toBe(item("검색 결과"));
    fireEvent.keyDown(document.activeElement as Element, { key: "End" });
    expect(document.activeElement).toBe(item("산출물"));
    fireEvent.keyDown(document.activeElement as Element, { key: "Home" });
    expect(document.activeElement).toBe(item("증거 소스"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowUp" });
    expect(document.activeElement).toBe(item("증거 소스"));
  });

  it("collapses with ArrowLeft, expands with ArrowRight, and steps to the child / parent", async () => {
    await renderTree();
    item("아티팩트").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    expect(item("아티팩트").getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByText("운영 체제")).toBeNull();
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    expect(item("아티팩트").getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    expect(document.activeElement).toBe(item("운영 체제"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    expect(document.activeElement).toBe(item("EVTX"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    expect(document.activeElement).toBe(item("운영 체제"));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    expect(document.activeElement).toBe(item("아티팩트"));
  });

  it("jumps by type-ahead", async () => {
    await renderTree();
    item("접수").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "타" });
    expect(document.activeElement).toBe(item("타임라인"));
  });

  it("Enter navigates to #/case/{run}/{collection}[/{kind}]", async () => {
    await renderTree();
    item("운영 체제").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "Enter" });
    expect(window.location.hash).toBe("#/case/r1/artifacts?category=operating-system");
    await waitFor(() => expect(item("운영 체제").getAttribute("aria-selected")).toBe("true"));
    expect(item("아티팩트").getAttribute("aria-selected")).toBe("false");
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    item("EVTX").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "Enter" });
    expect(window.location.hash).toBe("#/case/r1/artifacts/eventlog");
    await waitFor(() => expect(item("EVTX").getAttribute("aria-selected")).toBe("true"));
    item("리뷰보드").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: " " });
    expect(window.location.hash).toBe("#/case/r1/review");
  });

  it("clicking a node navigates; empty data nodes stay put and explain why", async () => {
    await renderTree();
    fireEvent.click(item("파일/미디어"));
    expect(window.location.hash).toBe("#/case/r1/files");
    expect(item("문서/메일").getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(item("문서/메일"));
    expect(window.location.hash).toBe("#/case/r1/files");
    expect(document.querySelector(".case-tree-reason")?.textContent).toBe(
      "docs-index 산출물이 없는 런입니다",
    );
  });

  it("lists the evidence source with partitions; only the recovered partition opens files", async () => {
    await renderTree();
    expect(item("증거 소스").getAttribute("aria-level")).toBe("1");
    expect(item("case1.E01").getAttribute("aria-label")).toBe("case1.E01, 150건");
    fireEvent.click(item("case1.E01").querySelector(".case-tree-twisty") as Element);
    const ntfs = item("파티션 2");
    expect(ntfs.getAttribute("aria-label")).toContain("선택됨");
    expect(ntfs.getAttribute("aria-level")).toBe("3");
    fireEvent.click(item("파티션 1"));
    expect(window.location.hash).not.toBe("#/case/r1/files");
    expect(document.querySelector(".case-tree-reason")?.textContent).toContain("선택되지 않았습니다");
    fireEvent.click(ntfs);
    expect(window.location.hash).toBe("#/case/r1/files");
    // The 파일/미디어 node owns the files route; evidence shortcuts never render as selected.
    await waitFor(() => expect(item("파일/미디어").getAttribute("aria-selected")).toBe("true"));
    expect(ntfs.getAttribute("aria-selected")).toBe("false");
  });

  it("opens a saved search into the 검색 결과 node", async () => {
    await renderTree();
    const saved = await screen.findByRole("treeitem", { name: /패스워드/ });
    fireEvent.click(saved);
    expect(window.location.hash).toBe("#/case/r1/search");
  });
});

describe("tree commands", () => {
  it("registers one tree.goto.* command per node with disabled reasons", () => {
    const model = buildTreeModel({ summary: { summary: { counts } } });
    const commands = buildTreeCommands("r1", model);
    const ids = commands.map((c) => c.id);
    expect(ids).toContain("tree.goto.timeline");
    expect(ids).toContain("tree.goto.review.relevant");
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
    expect(getRegisteredCommands()).toBeDefined();
  });
});
