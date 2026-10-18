// biome-ignore-all lint/a11y: tests drive ARIA widgets through their DOM roles
/** r4 §2.3 연결 그래프 라이트: layered layout, keyboard-focusable SVG nodes, navigation. */
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse, queryWrapper } from "../grid/testSupport";
import { DerivedGraph, graphNodeName } from "./DerivedGraph";
import { clipLabel, GRAPH_COLUMN_X, type DerivedGraph as Graph, layoutGraph } from "./graph";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const GRAPH: Graph = {
  run_id: "run-1",
  table: "people",
  label: "사람 식별자",
  source: {
    status: "completed",
    analysis_id: "a1",
    source: "run-stage",
    generated_at: null,
    coverage: "complete",
  },
  center: "v:people:user1",
  nodes: [
    {
      id: "v:people:user1",
      type: "value",
      center: true,
      table: "people",
      table_label: "사람 식별자",
      normalized: "user1",
      label: "USER1",
      count: 8,
      in_table: true,
    },
    {
      id: "r:eventlog:0",
      type: "row",
      kind: "eventlog",
      family: "eventlog-event",
      field: "target_user_name",
      artifact_type: "eventlog-event",
      record_index: 0,
      time: "2024-05-01T10:00:00Z",
      label: "eventlog-event #0",
      collection: "artifacts",
      locator: "/artifacts/0",
    },
    {
      id: "r:windows-os-account:0",
      type: "row",
      kind: "windows-os-account",
      family: "sam-account",
      field: "user_name",
      artifact_type: "windows-sam-account",
      record_index: 0,
      time: null,
      label: "windows-sam-account #0",
      collection: "artifacts",
      locator: "/artifacts/0",
    },
    {
      id: "v:devices:10.0.0.5",
      type: "value",
      center: false,
      table: "devices",
      table_label: "장치 식별자",
      normalized: "10.0.0.5",
      label: "10.0.0.5",
      count: 7,
      in_table: true,
      rows: 1,
    },
    {
      id: "v:paths:c:\\x",
      type: "value",
      center: false,
      table: "paths",
      table_label: "접근 경로",
      normalized: "c:\\x",
      label: "C:\\x",
      count: null,
      in_table: false,
      rows: 1,
    },
  ],
  edges: [
    { source: "v:people:user1", target: "r:eventlog:0" },
    { source: "v:people:user1", target: "r:windows-os-account:0" },
    { source: "r:eventlog:0", target: "v:devices:10.0.0.5" },
    { source: "r:windows-os-account:0", target: "v:paths:c:\\x" },
  ],
  rows: 2,
  rows_read: 2,
  values: 2,
  dropped_values: 0,
  truncated: false,
  max_nodes: 200,
};

describe("layoutGraph", () => {
  it("places centre · rows · values in three columns with every edge resolved", () => {
    const layout = layoutGraph(GRAPH);
    expect(layout.columns.map((column) => column.length)).toEqual([1, 2, 2]);
    expect(layout.columns.map((column) => column[0]?.x)).toEqual([...GRAPH_COLUMN_X]);
    expect(layout.edges).toHaveLength(4);
    // Values group by table label (Korean collation): 장치 before 접근.
    expect(layout.columns[2].map((placed) => placed.node.id)).toEqual([
      "v:devices:10.0.0.5",
      "v:paths:c:\\x",
    ]);
    expect(layout.height).toBeGreaterThan(0);
    expect(clipLabel("a".repeat(40), 10)).toBe(`${"a".repeat(9)}…`);
  });

  it("names nodes in Korean", () => {
    const [center, row, , value, missing] = GRAPH.nodes;
    expect(graphNodeName(center as never, "utc")).toBe("중심 값: 사람 식별자 USER1, 건수 8");
    expect(graphNodeName(row as never, "utc")).toMatch(/^원본 행: .* #0, 2024-05-01 10:00:00.* — 열기$/);
    expect(graphNodeName(value as never, "utc")).toBe(
      "장치 식별자 값: 10.0.0.5, 건수 7, 연결 행 1 — 통합 보기 표에서 열기",
    );
    expect(graphNodeName(missing as never, "utc")).toMatch(/표에 없는 값/);
  });
});

describe("DerivedGraph", () => {
  it("renders focusable SVG nodes, moves with arrows and opens rows / values", async () => {
    const calls = installFetch({ "/derived/people/graph": () => jsonResponse(GRAPH) });
    const onNavigate = vi.fn();
    render(
      <DerivedGraph runId="run-1" table="people" normalized="user1" timezone="utc" onNavigate={onNavigate} />,
      {
        wrapper: queryWrapper().wrapper,
      },
    );
    const svg = await screen.findByRole("group", {
      name: /연결 그래프: 사람 식별자 USER1, 원본 행 2개, 연결 값 2개/,
    });
    expect(calls[0]?.url).toBe("/api/runs/run-1/derived/people/graph?value=user1");
    const nodes = screen.getAllByRole("button");
    expect(nodes).toHaveLength(5);
    expect(nodes.filter((node) => node.getAttribute("tabindex") === "0")).toHaveLength(1);
    const center = screen.getByRole("button", { name: /^중심 값/ });
    expect(center.getAttribute("tabindex")).toBe("0");
    act(() => center.focus());
    fireEvent.keyDown(center, { key: "ArrowRight" });
    await waitFor(() => expect(document.activeElement?.getAttribute("aria-label")).toMatch(/^원본 행/));
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowDown" });
    await waitFor(() =>
      expect(document.activeElement?.getAttribute("data-node-id")).toBe("r:windows-os-account:0"),
    );
    fireEvent.keyDown(document.activeElement as Element, { key: "Enter" });
    expect(onNavigate).toHaveBeenCalledTimes(1);
    expect(onNavigate.mock.calls[0]?.[0]).toMatchObject({
      runId: "run-1",
      collection: "artifacts",
      kind: "windows-os-account",
      row: { collection: "artifacts", kind: "windows-os-account", locator: "/artifacts/0" },
    });
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    await waitFor(() => expect(document.activeElement?.getAttribute("data-kind")).toBe("value"));
    fireEvent.keyDown(document.activeElement as Element, { key: "Home" });
    await waitFor(() =>
      expect(document.activeElement?.getAttribute("data-node-id")).toBe("v:devices:10.0.0.5"),
    );
    fireEvent.keyDown(document.activeElement as Element, { key: " " });
    expect(onNavigate.mock.calls[1]?.[0]).toEqual({
      runId: "run-1",
      collection: "derived",
      kind: "devices",
      q: "10.0.0.5",
    });
    // A value the (capped) table does not hold does not navigate.
    fireEvent.click(screen.getByRole("button", { name: /표에 없는 값/ }));
    expect(onNavigate).toHaveBeenCalledTimes(2);
    expect(svg.querySelectorAll("path.derived-graph-edge.is-active").length).toBeGreaterThan(0);
  });

  it("reports a Korean error", async () => {
    installFetch({
      "/derived/people/graph": () => jsonResponse({ detail: "이 통합 보기 표에 없는 값입니다" }, 404),
    });
    render(
      <DerivedGraph runId="run-1" table="people" normalized="x" timezone="utc" onNavigate={() => {}} />,
      {
        wrapper: queryWrapper().wrapper,
      },
    );
    expect((await screen.findByRole("alert")).textContent).toContain("없는 값");
  });
});
