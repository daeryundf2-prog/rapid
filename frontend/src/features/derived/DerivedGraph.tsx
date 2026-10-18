// biome-ignore-all lint/a11y/useSemanticElements: SVG nodes are focusable groups (role="button"); a <button> cannot live inside <svg>
/**
 * 연결 그래프 라이트 (r4 §2.3): one 통합 보기 value → its original rows (by family) → the other
 * identifier values on those rows, two hops, ≤ 200 nodes, drawn as plain SVG in three columns
 * (no force layout, no external library).
 *
 * Keyboard: one node is the tab stop (roving tabindex); ↑/↓ (J/K) move inside a column, ←/→ move
 * between columns, Home/End jump; Enter/Space opens — a row node opens its family grid with that
 * record selected, a value node opens its 통합 보기 table searched for the value. Connected edges
 * are highlighted for the focused node. Every node's accessible name reads its kind, label and
 * counts.
 */

import { useQuery } from "@tanstack/react-query";
import { type KeyboardEvent, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { ApiError } from "../../api/client";
import type { Route } from "../../router";
import { formatGridTime } from "../../utils/time";
import type { DerivedTableId } from "./api";
import {
  clipLabel,
  fetchDerivedGraph,
  GRAPH_NODE_HEIGHT,
  GRAPH_NODE_WIDTH,
  GRAPH_WIDTH,
  type GraphNode,
  layoutGraph,
  type PlacedNode,
} from "./graph";
import { familyLabel, kindLabel, sampleRoute } from "./tables";

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "연결 그래프를 불러오지 못했습니다";
}

export function graphNodeName(node: GraphNode, timezone: string): string {
  if (node.type === "row") {
    const time = node.time ? `, ${formatGridTime(node.time, timezone)}` : "";
    return `원본 행: ${familyLabel(node.family)} · ${kindLabel(node.kind)} #${node.record_index}${time} — 열기`;
  }
  const count = node.count !== null ? `, 건수 ${node.count.toLocaleString("ko-KR")}` : "";
  const shared = node.rows ? `, 연결 행 ${node.rows}` : "";
  if (node.center) return `중심 값: ${node.table_label} ${node.label}${count}`;
  const open = node.in_table ? " — 통합 보기 표에서 열기" : " — 표에 없는 값(상한)";
  return `${node.table_label} 값: ${node.label}${count}${shared}${open}`;
}

export function DerivedGraph({
  runId,
  table,
  normalized,
  timezone,
  onNavigate,
}: {
  runId: string;
  table: DerivedTableId;
  normalized: string;
  timezone: string;
  onNavigate: (route: Route, origin?: { row: GraphNode }) => void;
}) {
  const graph = useQuery({
    queryKey: ["derived-graph", runId, table, normalized],
    queryFn: ({ signal }) => fetchDerivedGraph(runId, table, normalized, signal),
    retry: false,
    staleTime: 60_000,
  });
  const layout = useMemo(() => (graph.data ? layoutGraph(graph.data) : null), [graph.data]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const active = layout && activeId ? layout.byId.get(activeId) : undefined;
  const current = active ?? layout?.columns[0][0];

  const connected = useMemo(() => {
    const set = new Set<string>();
    if (!layout || !current) return set;
    for (const edge of layout.edges) {
      if (edge.source === current || edge.target === current)
        set.add(`${edge.source.node.id}>${edge.target.node.id}`);
    }
    return set;
  }, [layout, current]);

  if (graph.isPending) return <p className="derived-hint">연결 그래프를 만드는 중…</p>;
  if (graph.isError)
    return (
      <p className="derived-notice" role="alert">
        {errorText(graph.error)}
      </p>
    );
  if (!layout || !graph.data) return null;
  const data = graph.data;

  const focusNode = (placed: PlacedNode | undefined) => {
    if (!placed) return;
    setActiveId(placed.node.id);
    svgRef.current?.querySelector<SVGGElement>(`[data-node-id="${CSS.escape(placed.node.id)}"]`)?.focus();
  };

  const open = (placed: PlacedNode) => {
    const node = placed.node;
    if (node.type === "row") {
      onNavigate(sampleRoute(runId, node), { row: node });
      return;
    }
    if (node.center) {
      announce(`중심 값입니다: ${node.label}`);
      return;
    }
    if (!node.in_table) {
      announce("이 값은 통합 보기 표에 없습니다(표 상한으로 빠진 값)", { politeness: "assertive" });
      return;
    }
    onNavigate({ runId, collection: "derived", kind: node.table, q: node.normalized });
  };

  const onKeyDown = (event: KeyboardEvent<SVGGElement>, placed: PlacedNode) => {
    const column = layout.columns[placed.column];
    const key = event.key;
    let next: PlacedNode | undefined;
    if (key === "ArrowDown" || key === "j" || key === "J") next = column[placed.order + 1];
    else if (key === "ArrowUp" || key === "k" || key === "K") next = column[placed.order - 1];
    else if (key === "Home") next = column[0];
    else if (key === "End") next = column[column.length - 1];
    else if (key === "ArrowRight" || key === "ArrowLeft") {
      const step = key === "ArrowRight" ? 1 : -1;
      const target = layout.columns[placed.column + step];
      if (target?.length) {
        // The nearest node by height in the neighbouring column.
        next = target.reduce((best, item) =>
          Math.abs(item.y - placed.y) < Math.abs(best.y - placed.y) ? item : best,
        );
      }
    } else if (key === "Enter" || key === " ") {
      event.preventDefault();
      event.stopPropagation();
      open(placed);
      return;
    } else return;
    event.preventDefault();
    event.stopPropagation();
    focusNode(next);
  };

  const rowsCount = layout.columns[1].length;
  const valuesCount = layout.columns[2].length;
  return (
    <div className="derived-graph" data-testid="derived-graph">
      <p className="derived-hint">
        {`원본 행 ${rowsCount}개(표본) → 다른 식별자 값 ${valuesCount}개`}
        {data.truncated ? ` · 노드 상한(${data.max_nodes})으로 값 ${data.dropped_values}개를 뺐습니다` : ""}
        {data.rows_read < rowsCount ? ` · 원본을 읽지 못한 행 ${rowsCount - data.rows_read}개` : ""}
      </p>
      <p className="derived-hint">↑↓ 같은 열 · ←→ 다른 열 · Enter 열기</p>
      <div className="derived-graph-scroll">
        <svg
          ref={svgRef}
          className="derived-graph-svg"
          role="group"
          aria-label={`연결 그래프: ${data.label} ${data.nodes.find((n) => n.id === data.center)?.label ?? ""}, 원본 행 ${rowsCount}개, 연결 값 ${valuesCount}개`}
          viewBox={`0 0 ${GRAPH_WIDTH} ${layout.height}`}
          width="100%"
          preserveAspectRatio="xMinYMin meet"
        >
          <text className="derived-graph-head" x={layout.columns[0][0]?.x ?? 16} y={16}>
            값
          </text>
          <text className="derived-graph-head" x={236} y={16}>
            원본 행 (계열별)
          </text>
          <text className="derived-graph-head" x={456} y={16}>
            다른 식별자 값 (표별)
          </text>
          <g className="derived-graph-edges">
            {layout.edges.map((edge) => {
              const id = `${edge.source.node.id}>${edge.target.node.id}`;
              const x1 = edge.source.x + GRAPH_NODE_WIDTH;
              const y1 = edge.source.y + GRAPH_NODE_HEIGHT / 2;
              const x2 = edge.target.x;
              const y2 = edge.target.y + GRAPH_NODE_HEIGHT / 2;
              const mid = (x1 + x2) / 2;
              return (
                <path
                  key={id}
                  className={`derived-graph-edge${connected.has(id) ? " is-active" : ""}`}
                  d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
                />
              );
            })}
          </g>
          {layout.nodes.map((placed) => {
            const node = placed.node;
            const name = graphNodeName(node, timezone);
            const isCurrent = current?.node.id === node.id;
            const text =
              node.type === "row"
                ? `${familyLabel(node.family)} #${node.record_index}`
                : node.center
                  ? node.label
                  : `${node.table_label}: ${node.label}`;
            return (
              <g
                key={node.id}
                role="button"
                tabIndex={isCurrent ? 0 : -1}
                aria-label={name}
                data-node-id={node.id}
                data-kind={node.type === "row" ? "row" : node.center ? "center" : "value"}
                data-missing={node.type === "value" && !node.in_table ? "" : undefined}
                className="derived-graph-node"
                transform={`translate(${placed.x},${placed.y})`}
                onFocus={() => setActiveId(node.id)}
                onClick={() => {
                  setActiveId(node.id);
                  open(placed);
                }}
                onKeyDown={(event) => onKeyDown(event, placed)}
              >
                <title>{name}</title>
                <rect width={GRAPH_NODE_WIDTH} height={GRAPH_NODE_HEIGHT} rx={4} />
                <text x={8} y={GRAPH_NODE_HEIGHT / 2} dominantBaseline="central">
                  {clipLabel(text)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
