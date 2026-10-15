import type { AnalysisState, AnalysisStatus } from "../../api/analyses";
import type { ReviewCounts, SavedSearch } from "../../api/caseDb";
import type { EvidencePartition, EvidenceSource } from "../../api/dashboard";
import type { CanonicalCounts, RunSummary, RunTree, TreeNode } from "../../api/runs";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import type { IconName } from "../../icons";
import {
  ANALYSIS_NODES,
  isPartialResult,
  latestForNode,
  nodeStateIcon,
  nodeStateLabel,
} from "../analysis/kinds";
import type { CaseRoute } from "./adapter";
import { groupByCategory, kindIcon } from "./categories";
import { DOMAINS, type DomainTarget, targetKey } from "./domains";

export type RouteTail = Omit<CaseRoute, "runId">;

export interface TreeModelNode {
  /** Unique, stable id (also the DOM key). */
  id: string;
  label: string;
  /** Number or short text ("17/24"); undefined = no count shown. */
  count?: number | string;
  route: RouteTail;
  children?: TreeModelNode[];
  /** Korean reason the node cannot be opened now (U3). */
  disabledReason?: string;
  /** Overrides plain navigation (saved searches). */
  activate?: () => void;
  /** Leading glyph (category / kind / evidence nodes). */
  icon?: IconName;
  /** Bold count (category parents, X11). */
  strongCount?: boolean;
  /** Shortcut node whose route another node owns: never rendered as selected. */
  noSelect?: boolean;
  /** Short marker after the label ("선택됨"). */
  marker?: string;
  /** Domain nodes: the full route to open (kind + `types=` / `ext=` filters). */
  target?: RouteTail & { types?: string[]; ext?: string[] };
  /** Domain nodes: selected when the current route has this key (`targetKey`). */
  selectKey?: string;
  /** Group headers (domains, 전체 보기): click / Enter expands or collapses; never navigates. */
  toggleOnly?: boolean;
}

export interface TreeModelInput {
  summary?: RunSummary;
  tree?: RunTree;
  review?: ReviewCounts;
  saved?: SavedSearch[];
  live?: { active: boolean; completed: number | null; total: number | null };
  onOpenSavedSearch?: (search: SavedSearch) => void;
  /** `GET /api/runs/{id}/dashboard` evidence_source (X2/X17). */
  evidence?: EvidenceSource;
  /** `GET /api/runs/{id}/analyses` (newest first); undefined while unknown. */
  analyses?: AnalysisState[];
}

export const REVIEW_NODES: Array<{ status: ReviewStatus; label: string }> = [
  { status: "relevant", label: "관련 있음" },
  { status: "needs-review", label: "재검토" },
  { status: "excluded", label: "제외" },
  { status: "include-in-report", label: "보고서 포함" },
];

export function reviewCount(review: ReviewCounts | undefined, status: ReviewStatus): number | undefined {
  if (!review) return undefined;
  if (status === "include-in-report") return review.report_candidates ?? 0;
  return review.by_status?.[status] ?? 0;
}

/** Kind-level artifact nodes (skipping the grouping level), largest first. */
export function artifactKindNodes(tree: RunTree | undefined): TreeNode[] {
  const found: TreeNode[] = [];
  const visit = (node: TreeNode) => {
    if (node.collection === "artifacts" && node.kind && !node.artifact_type) found.push(node);
    for (const child of node.children ?? []) visit(child);
  };
  for (const node of tree?.nodes ?? []) visit(node);
  return found
    .filter((node) => node.count > 0)
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

function dataNode(
  id: CollectionId,
  label: string,
  count: number | undefined,
  emptyReason: string,
  loaded: boolean,
  children?: TreeModelNode[],
): TreeModelNode {
  return {
    id,
    label,
    count,
    route: { collection: id },
    children: children && children.length > 0 ? children : undefined,
    disabledReason: loaded && count === 0 ? emptyReason : undefined,
  };
}

/** 아티팩트 children: category nodes (bold summed count) → kind nodes with icons (X11). */
export function categoryNodes(kinds: TreeNode[]): TreeModelNode[] {
  return groupByCategory(
    kinds,
    (node) => node.kind ?? "",
    (node) => node.count,
  ).map(({ category, total, items }) => ({
    id: `artifacts-category:${category.id}`,
    label: category.label,
    count: total,
    strongCount: true,
    icon: category.icon,
    route: { collection: "artifacts", category: category.id },
    children: items.map<TreeModelNode>((node) => ({
      id: `artifacts:${node.kind}`,
      label: node.label,
      count: node.count,
      icon: kindIcon(node.kind ?? ""),
      route: { collection: "artifacts", kind: node.kind },
    })),
  }));
}

export function formatBytes(size: number | null | undefined): string {
  if (typeof size !== "number" || !Number.isFinite(size)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = size;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(unit === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[unit]}`;
}

export function partitionLabel(partition: EvidencePartition): string {
  const fs =
    partition.filesystem && partition.filesystem !== "unknown"
      ? partition.filesystem.toUpperCase()
      : "알 수 없음";
  return `파티션 ${partition.number} (${fs}, ${formatBytes(partition.size_bytes)})`;
}

const UNSELECTED_PARTITION =
  "이 파티션은 복구 대상으로 선택되지 않았습니다 — 파일 목록은 선택된 파티션만 있습니다";

/** 증거 소스 → image (files + artifacts) → partitions (X2/X17). */
export function evidenceNode(
  evidence: EvidenceSource | undefined,
  counts: CanonicalCounts | undefined,
): TreeModelNode {
  const root: TreeModelNode = {
    id: "evidence",
    label: "증거 소스",
    icon: "hard-drive",
    route: { collection: "intake" },
    noSelect: true,
  };
  if (!evidence) return root;
  const items = counts ? (counts.files ?? 0) + (counts.artifacts ?? 0) : undefined;
  const partitions = evidence.partitions.map<TreeModelNode>((partition) => ({
    id: `evidence:partition:${partition.number}`,
    label: partitionLabel(partition),
    icon: "partition",
    marker: partition.selected ? "선택됨" : undefined,
    route: { collection: "files" },
    noSelect: true,
    disabledReason: partition.selected ? undefined : UNSELECTED_PARTITION,
  }));
  return {
    ...root,
    count: 1,
    children: [
      {
        id: "evidence:source",
        label: evidence.name,
        count: items,
        icon: evidence.kind === "folder" ? "folder" : "hard-drive",
        route: { collection: "files" },
        noSelect: true,
        children: partitions.length ? partitions : undefined,
      },
    ],
  };
}

function findServerNode(tree: RunTree | undefined, id: string): TreeNode | undefined {
  let found: TreeNode | undefined;
  const visit = (node: TreeNode) => {
    if (found) return;
    if (node.id === id) found = node;
    else for (const child of node.children ?? []) visit(child);
  };
  for (const node of tree?.nodes ?? []) visit(node);
  return found;
}

const ANALYSIS_STATUSES: readonly AnalysisStatus[] = [
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
];

/** Newest job state of an analysis node from the server tree (`analysis:<node>`), null = never ran. */
function serverAnalysisState(tree: RunTree | undefined, nodeId: string): AnalysisStatus | null {
  const status = findServerNode(tree, `analysis:${nodeId}`)?.state?.status;
  return status && (ANALYSIS_STATUSES as readonly string[]).includes(status)
    ? (status as AnalysisStatus)
    : null;
}

export const NO_DATA_REASON = "이 런에는 해당 데이터가 없습니다";
/** Count of a node whose number the server tree cannot give yet (P4 adds them). */
export const UNKNOWN_COUNT = "—";

export interface DomainCount {
  count: number | string | undefined;
  disabledReason?: string;
  marker?: string;
  icon?: IconName;
}

/** Count / dimming of one domain node from `/tree`, the summary counts and the analysis jobs. */
export function domainNodeCount(target: DomainTarget, input: TreeModelInput): DomainCount {
  const tree = input.tree;
  const counts = input.summary?.summary?.counts;
  if (target.analysis) {
    const node = ANALYSIS_NODES.find((n) => n.id === target.analysis);
    const completed = input.analyses?.find(
      (job) => (node?.kinds as string[] | undefined)?.includes(job.kind) && job.status === "completed",
    );
    const last = node ? latestForNode(input.analyses, node) : undefined;
    const status = input.analyses ? (last?.status ?? null) : serverAnalysisState(tree, target.analysis);
    const serverCount = findServerNode(tree, `analysis:${target.analysis}`)?.count;
    // No completed job: a cancelled / failed one that still wrote rows counts (partial result).
    const partial = completed
      ? undefined
      : input.analyses?.find(
          (job) => (node?.kinds as string[] | undefined)?.includes(job.kind) && isPartialResult(job),
        );
    const count = completed
      ? completed.row_count
      : partial
        ? partial.row_count
        : !input.analyses && status === "completed"
          ? serverCount
          : undefined;
    // Never disabled: the results pane explains a never-ran / running / failed job itself.
    const stateMarker =
      status === "completed"
        ? undefined
        : partial && last?.analysis_id === partial.analysis_id
          ? `${nodeStateLabel(status)} · 부분 결과`
          : nodeStateLabel(status);
    return { count, marker: stateMarker, icon: status === "completed" ? undefined : nodeStateIcon(status) };
  }
  if (target.collection === "files" && !target.fileCategory) return known(counts?.files, Boolean(counts));
  if (target.collection === "docs") return known(counts?.docs, Boolean(counts));
  if (target.collection === "indicators") return known(counts?.indicators, Boolean(counts));
  if (target.collection === "timeline") return known(counts?.timeline_events, Boolean(counts));
  if (target.collection === "files" && target.fileCategory) {
    const files = findServerNode(tree, "files");
    if (!files?.children?.length) return { count: tree ? UNKNOWN_COUNT : undefined };
    return known(findServerNode(tree, `files:${target.fileCategory}`)?.count ?? 0, true);
  }
  if (target.collection === "artifacts") {
    if (!tree) return { count: undefined };
    if (!target.kind) return { count: UNKNOWN_COUNT };
    const kindNode = findServerNode(tree, `artifacts:${target.kind}`);
    // The run has no records of this kind at all.
    if (!kindNode) return known(0, true);
    if (!target.types?.length) return known(kindNode.count, true);
    const perType = kindNode.artifact_type_counts;
    if (perType && typeof perType === "object") {
      return known(
        target.types.reduce((sum, type) => sum + (typeof perType[type] === "number" ? perType[type] : 0), 0),
        true,
      );
    }
    const typed = (kindNode.children ?? []).filter((child) => child.artifact_type);
    if (typed.length) {
      return known(
        typed
          .filter((child) => target.types?.includes(child.artifact_type as string))
          .reduce((sum, c) => sum + c.count, 0),
        true,
      );
    }
    // Per-type counts unknown for this run: only an empty kind is known to be 0.
    return kindNode.count === 0 ? known(0, true) : { count: UNKNOWN_COUNT };
  }
  return { count: undefined };
}

function known(count: number | undefined, loaded: boolean): DomainCount {
  if (count === undefined) return { count: undefined };
  return loaded && count === 0 ? { count, disabledReason: NO_DATA_REASON } : { count };
}

/** Full route of a domain node (the tree navigates with it; `types=` / `ext=` ride in the URL). */
export function domainRoute(target: DomainTarget): RouteTail & { types?: string[]; ext?: string[] } {
  const route: RouteTail & { types?: string[]; ext?: string[] } = { collection: target.collection };
  if (target.kind) route.kind = target.kind;
  if (target.fileCategory) route.category = target.fileCategory;
  if (target.types?.length) route.types = [...target.types];
  if (target.ext?.length) route.ext = [...target.ext];
  return route;
}

function domainNodes(input: TreeModelInput): TreeModelNode[] {
  return DOMAINS.map<TreeModelNode>((domain) => {
    const children = domain.nodes.map<TreeModelNode>((node) => {
      const state = domainNodeCount(node.target, input);
      const route = domainRoute(node.target);
      return {
        id: `domain:${domain.id}:${node.id}`,
        label: node.label,
        count: state.count,
        route: {
          collection: route.collection,
          ...(route.kind ? { kind: route.kind } : {}),
          ...(route.category ? { category: route.category } : {}),
        },
        target: route,
        selectKey: targetKey(node.target),
        disabledReason: state.disabledReason,
        marker: state.marker,
        icon: state.icon ?? node.icon,
      };
    });
    // Each kind counts once; typed subsets (artifact_type filters) and other views do not add.
    const kindCounts = new Map<string, number>();
    domain.nodes.forEach((node, index) => {
      const count = children[index]?.count;
      const t = node.target;
      if (t.collection === "artifacts" && t.kind && !t.types?.length && typeof count === "number") {
        kindCounts.set(t.kind, count);
      }
    });
    const total = [...kindCounts.values()].reduce((sum, n) => sum + n, 0);
    const anyKnown = kindCounts.size > 0;
    return {
      id: `domain:${domain.id}`,
      label: domain.label,
      icon: domain.icon,
      count: anyKnown ? total : undefined,
      strongCount: true,
      route: children[0]?.route ?? { collection: "artifacts" },
      noSelect: true,
      toggleOnly: true,
      children,
    };
  });
}

/**
 * 탐색 stage tree (console-ia §3–§4): 증거 소스, the "전체 보기" views, then the 15 forensic
 * domains. Workflow places (접수 · 처리 · 검토 · 보고) live on the stage rail, not here.
 */
export function buildTreeModel(input: TreeModelInput): TreeModelNode[] {
  const counts = input.summary?.summary?.counts;
  const loaded = Boolean(counts);

  const saved = (input.saved ?? []).map<TreeModelNode>((search, index) => ({
    id: `search:saved:${index}:${search.name}`,
    label: search.name,
    route: { collection: "search" },
    activate: () => input.onOpenSavedSearch?.(search),
  }));

  const views: TreeModelNode = {
    id: "views",
    label: "전체 보기",
    icon: "list",
    route: { collection: "files" },
    noSelect: true,
    toggleOnly: true,
    children: [
      dataNode("files", "전체 파일", counts?.files, "이 런에는 파일 목록이 없습니다", loaded),
      dataNode("artifacts", "전체 아티팩트", counts?.artifacts, "이 런에는 아티팩트가 없습니다", loaded),
      dataNode(
        "timeline",
        "전체 타임라인",
        counts?.timeline_events,
        "이 런에는 타임라인 산출물이 없습니다",
        loaded,
      ),
      dataNode("docs", "문서/메일", counts?.docs, "docs-index 산출물이 없는 런입니다", loaded),
      {
        id: "search",
        label: "검색 결과",
        route: { collection: "search" },
        children: saved.length ? saved : undefined,
      },
      dataNode("indicators", "IOC/위험", counts?.indicators, "이 런에는 지표가 없습니다", loaded),
    ],
  };

  return [evidenceNode(input.evidence, counts), views, ...domainNodes(input)];
}

export interface FlatNode {
  node: TreeModelNode;
  level: number;
  parentId: string | null;
}

/** Visible nodes in DOM order, honoring which parents are expanded. */
export function flattenVisible(nodes: TreeModelNode[], expanded: ReadonlySet<string>): FlatNode[] {
  const out: FlatNode[] = [];
  const walk = (list: TreeModelNode[], level: number, parentId: string | null) => {
    for (const node of list) {
      out.push({ node, level, parentId });
      if (node.children?.length && expanded.has(node.id)) walk(node.children, level + 1, node.id);
    }
  };
  walk(nodes, 1, null);
  return out;
}
