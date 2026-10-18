/**
 * 연결 그래프 라이트 model (r4 §2.3): `GET /api/runs/{run}/derived/{table}/graph?value=` and the
 * force-free layered layout — column 0 the centre value, column 1 its original rows (grouped by
 * family), column 2 the other identifier values on those rows (grouped by table). Pure; no
 * external graph library.
 */

import { api } from "../../api/client";
import type { DerivedSample, DerivedSource, DerivedTableId } from "./api";

const enc = encodeURIComponent;

export const GRAPH_MAX_NODES = 200;

interface GraphNodeBase {
  id: string;
  label: string;
}

export interface GraphValueNode extends GraphNodeBase {
  type: "value";
  center: boolean;
  table: DerivedTableId;
  table_label: string;
  normalized: string;
  semantic?: string;
  count: number | null;
  in_table: boolean;
  /** Rows of the centre this value shares (second-hop nodes). */
  rows?: number;
}

export interface GraphRowNode
  extends GraphNodeBase,
    Pick<DerivedSample, "kind" | "collection" | "locator" | "scope" | "analysis_id" | "analysis_kind"> {
  type: "row";
  family: string;
  field: string;
  artifact_type: string;
  record_index: number;
  time: string | null;
}

export type GraphNode = GraphValueNode | GraphRowNode;

export interface DerivedGraph {
  run_id: string;
  table: DerivedTableId;
  label: string;
  source: DerivedSource;
  center: string;
  nodes: GraphNode[];
  edges: Array<{ source: string; target: string }>;
  rows: number;
  rows_read: number;
  values: number;
  dropped_values: number;
  truncated: boolean;
  max_nodes: number;
}

export function derivedGraphUrl(runId: string, table: DerivedTableId, normalized: string): string {
  return `/api/runs/${enc(runId)}/derived/${enc(table)}/graph?value=${enc(normalized)}`;
}

export function fetchDerivedGraph(
  runId: string,
  table: DerivedTableId,
  normalized: string,
  signal?: AbortSignal,
): Promise<DerivedGraph> {
  return api<DerivedGraph>(derivedGraphUrl(runId, table, normalized), { signal });
}

// --- layout -----------------------------------------------------------------------------------

export const GRAPH_COLUMN_X: readonly [number, number, number] = [16, 236, 456];
export const GRAPH_NODE_WIDTH = 196;
export const GRAPH_NODE_HEIGHT = 22;
export const GRAPH_ROW_GAP = 6;
export const GRAPH_TOP = 28;
export const GRAPH_WIDTH = GRAPH_COLUMN_X[2] + GRAPH_NODE_WIDTH + 16;

export interface PlacedNode {
  node: GraphNode;
  column: 0 | 1 | 2;
  /** Position inside its column (keyboard order). */
  order: number;
  x: number;
  y: number;
}

export interface GraphLayout {
  nodes: PlacedNode[];
  columns: [PlacedNode[], PlacedNode[], PlacedNode[]];
  byId: Map<string, PlacedNode>;
  edges: Array<{ source: PlacedNode; target: PlacedNode }>;
  height: number;
}

const collator = new Intl.Collator("ko");

/** Layered layout: three columns, nodes stacked top-down; the centre sits level with the rows' middle. */
export function layoutGraph(graph: Pick<DerivedGraph, "center" | "nodes" | "edges">): GraphLayout {
  const center = graph.nodes.find((node) => node.id === graph.center);
  const rows = graph.nodes
    .filter((node): node is GraphRowNode => node.type === "row")
    .sort(
      (a, b) =>
        collator.compare(a.family, b.family) ||
        collator.compare(a.kind, b.kind) ||
        a.record_index - b.record_index,
    );
  const values = graph.nodes
    .filter((node): node is GraphValueNode => node.type === "value" && node.id !== graph.center)
    .sort(
      (a, b) =>
        collator.compare(a.table_label, b.table_label) ||
        (b.rows ?? 0) - (a.rows ?? 0) ||
        collator.compare(a.label, b.label),
    );
  const step = GRAPH_NODE_HEIGHT + GRAPH_ROW_GAP;
  const tallest = Math.max(1, rows.length, values.length);
  const height = GRAPH_TOP + tallest * step + 8;
  const place = (list: GraphNode[], column: 0 | 1 | 2): PlacedNode[] => {
    const offset = GRAPH_TOP + ((tallest - list.length) * step) / 2;
    return list.map((node, order) => ({
      node,
      column,
      order,
      x: GRAPH_COLUMN_X[column],
      y: offset + order * step,
    }));
  };
  const columns: [PlacedNode[], PlacedNode[], PlacedNode[]] = [
    center ? place([center], 0) : [],
    place(rows, 1),
    place(values, 2),
  ];
  const nodes = [...columns[0], ...columns[1], ...columns[2]];
  const byId = new Map(nodes.map((placed) => [placed.node.id, placed]));
  const edges = graph.edges
    .map((edge) => ({ source: byId.get(edge.source), target: byId.get(edge.target) }))
    .filter((edge): edge is { source: PlacedNode; target: PlacedNode } =>
      Boolean(edge.source && edge.target),
    );
  return { nodes, columns, byId, edges, height };
}

/** Node label cut to fit the box (the full text stays in the accessible name and tooltip). */
export function clipLabel(text: string, max = 26): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
