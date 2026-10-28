import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { EvidenceTree } from "./EvidenceTree";
import type { TreeModelNode } from "./model";

const NODE_COUNT = 100_000;

const bigModel: TreeModelNode[] = [
  {
    id: "views",
    label: "전체 보기",
    route: { collection: "artifacts" },
    toggleOnly: true,
    children: Array.from({ length: NODE_COUNT }, (_, i) => ({
      id: `n${i}`,
      label: `노드 ${i}`,
      route: { collection: "artifacts" },
    })),
  },
];

vi.mock("./useTreeModel", () => ({
  useTreeState: () => ({ model: bigModel, loading: false, treeSettled: true, liveTree: null }),
}));

// jsdom has no layout: give the scroll viewport a real size so the virtualizer computes a window.
const VIEWPORT_HEIGHT = 600;
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
    configurable: true,
    get: () => VIEWPORT_HEIGHT,
  });
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => 300 });
  HTMLElement.prototype.getBoundingClientRect = () =>
    ({
      width: 300,
      height: VIEWPORT_HEIGHT,
      top: 0,
      left: 0,
      right: 300,
      bottom: VIEWPORT_HEIGHT,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    }) as DOMRect;
});

afterEach(cleanup);

describe("EvidenceTree virtualization", () => {
  it("mounts a window of a 100k-node tree and keeps the focused item mounted", async () => {
    render(<EvidenceTree runId="r1" />);
    const mounted = () => screen.getAllByRole("treeitem");
    expect(mounted().length).toBeLessThan(200);
    expect(screen.getByRole("tree").getAttribute("role")).toBe("tree");
    expect(mounted()[0]?.getAttribute("aria-setsize")).toBe(String(NODE_COUNT + 1));

    const tree = screen.getByRole("tree");
    mounted()[0]?.focus();
    // Walk well past the rendered window (overscan 12 + viewport ~21 rows).
    for (let i = 0; i < 80; i += 1) {
      fireEvent.keyDown(document.activeElement ?? tree, { key: "ArrowDown" });
    }
    await waitFor(() => {
      const active = document.activeElement as HTMLElement;
      expect(active.getAttribute("role")).toBe("treeitem");
      expect(active.dataset.nodeId).toBe("n79");
    });
    expect(mounted().length).toBeLessThan(200);
    const focused = mounted().find((el) => el.dataset.nodeId === "n79");
    expect(focused?.getAttribute("tabindex")).toBe("0");
    expect(focused?.getAttribute("aria-level")).toBe("2");
  });

  it("End jumps to the last row and keeps it mounted", async () => {
    render(<EvidenceTree runId="r1" />);
    screen.getAllByRole("treeitem")[0]?.focus();
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "End" });
    await waitFor(() => {
      expect((document.activeElement as HTMLElement).dataset.nodeId).toBe(`n${NODE_COUNT - 1}`);
    });
    expect(screen.getAllByRole("treeitem").length).toBeLessThan(200);
  });

  it("keeps the tab stop mounted after a scroll when the focused row is hidden", async () => {
    render(<EvidenceTree runId="r1" />);
    screen.getAllByRole("treeitem")[0]?.focus();
    for (let i = 0; i < 80; i += 1) {
      fireEvent.keyDown(document.activeElement ?? document, { key: "ArrowDown" });
    }
    await waitFor(() => expect((document.activeElement as HTMLElement).dataset.nodeId).toBe("n79"));
    // "노드 1" hides the focused n79; the tab stop falls back to the 전체 보기 root (index 0).
    fireEvent.change(screen.getByRole("searchbox", { name: "트리 검색" }), { target: { value: "노드 1" } });
    const scroller = document.querySelector(".evidence-tree-scroll") as HTMLElement;
    Object.defineProperty(scroller, "scrollTop", { configurable: true, value: 140_000 });
    fireEvent.scroll(scroller);
    await waitFor(() => {
      const stops = screen.getAllByRole("treeitem").filter((el) => el.getAttribute("tabindex") === "0");
      expect(stops.map((el) => el.dataset.nodeId)).toEqual(["views"]);
    });
  });
});
