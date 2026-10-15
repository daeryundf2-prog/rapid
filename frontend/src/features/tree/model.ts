import type { AnalysisState, AnalysisStatus } from "../../api/analyses";
import type { ReviewCounts, SavedSearch } from "../../api/caseDb";
import { filesInventoryCategory } from "../../api/collections";
import type { EvidencePartition, EvidenceSource } from "../../api/dashboard";
import type { CanonicalCounts, RunSummary, RunTree, TreeNode } from "../../api/runs";
import type { CollectionId, ColumnFilter, ReviewStatus } from "../../contracts/collection";
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
import { DOMAINS, type DomainNodeDef, type DomainTarget, NON_EVIDENCE_NOTE, targetKey } from "./domains";

export type RouteTail = Omit<CaseRoute, "runId">;

/** Route a domain node opens: the tail plus its server / loaded-row filters. */
export type DomainRoute = RouteTail & {
  types?: string[];
  ext?: string[];
  cols?: string[];
  cf?: ColumnFilter[];
};

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
  /** Domain nodes: the full route to open (kind + `types=` / `ext=` / `cols=` / `cf=` filters). */
  target?: DomainRoute;
  /** Domain nodes: selected when the current route has this key (`targetKey`). */
  selectKey?: string;
  /** Group headers (domains, 전체 보기): click / Enter expands or collapses; never navigates. */
  toggleOnly?: boolean;
  /** Openable but dimmed (non-evidence string pivots); `note` says why. */
  dimmed?: boolean;
  /** Tooltip of an openable node (dimmed / skipped-provider explanations). */
  note?: string;
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

/** Every kind-level server node (`artifacts:<kind>` and routed `artifacts:<kind>@<domain>`). */
function allKindNodes(tree: RunTree | undefined): TreeNode[] {
  const found: TreeNode[] = [];
  const visit = (node: TreeNode) => {
    if (node.collection === "artifacts" && node.kind && !node.artifact_type) found.push(node);
    for (const child of node.children ?? []) visit(child);
  };
  for (const node of tree?.nodes ?? []) visit(node);
  return found;
}

/**
 * One merged node per kind: a kind whose types the server routes to several domains appears as
 * `artifacts:<kind>` plus `artifacts:<kind>@<domain>`; the merged count is their sum (each node
 * counts only the types placed in its domain once the kind is split).
 */
export function mergedKindNode(tree: RunTree | undefined, kind: string): TreeNode | undefined {
  return mergeKindNodes(allKindNodes(tree).filter((node) => node.kind === kind));
}

function mergeKindNodes(nodes: TreeNode[]): TreeNode | undefined {
  const [first] = nodes;
  if (!first) return undefined;
  const truePrimary = nodes.find((node) => node.id === `artifacts:${node.kind}`);
  const primary = truePrimary ?? first;
  if (nodes.length === 1) return primary;
  // The primary node's artifact_type_counts are the whole kind's; without one, sum the domains.
  let perType = truePrimary?.artifact_type_counts;
  if (!perType) {
    const sum: Record<string, number> = {};
    let typed = false;
    for (const node of nodes) {
      const counts = node.domain_artifact_type_counts ?? node.artifact_type_counts;
      if (!counts) continue;
      typed = true;
      for (const [type, count] of Object.entries(counts)) {
        if (typeof count === "number") sum[type] = (sum[type] ?? 0) + count;
      }
    }
    perType = typed ? sum : undefined;
  }
  return {
    ...primary,
    id: `artifacts:${primary.kind}`,
    count: nodes.reduce((sum, node) => sum + (node.count ?? 0), 0),
    ...(perType ? { artifact_type_counts: perType } : {}),
    children: nodes.flatMap((node) => node.children ?? []),
  };
}

/** Kind-level artifact nodes (skipping the grouping level), one per kind, largest first. */
export function artifactKindNodes(tree: RunTree | undefined): TreeNode[] {
  const byKind = new Map<string, TreeNode[]>();
  for (const node of allKindNodes(tree)) {
    const list = byKind.get(node.kind as string) ?? [];
    list.push(node);
    byKind.set(node.kind as string, list);
  }
  return [...byKind.values()]
    .map((nodes) => mergeKindNodes(nodes) as TreeNode)
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

/**
 * 문서/메일 count: every document candidate (the docs view lists all of them; "일치만" narrows to
 * keyword matches). `/tree` `docs.candidate_count`, else the summary's `document_candidates`,
 * else the match count of servers that only page matches.
 */
export function docsCount(input: Pick<TreeModelInput, "summary" | "tree">): number | undefined {
  const node = findServerNode(input.tree, "docs");
  if (typeof node?.candidate_count === "number") return node.candidate_count;
  const counts = input.summary?.summary?.counts;
  if (typeof counts?.document_candidates === "number") return counts.document_candidates;
  return node?.count ?? counts?.docs;
}

/** Indicators label: the server's `display_label` ("지표 후보" while no detection rule applied). */
export function indicatorsLabel(tree: RunTree | undefined, fallback: string): string {
  const node = findServerNode(tree, "indicators");
  if (!node) return fallback;
  return node.label || (node.rule_count ? fallback : "지표 후보");
}
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
  if (target.collection === "files" && target.fileScope && !target.fileCategory) {
    return inventoryTotal(input);
  }
  if (target.collection === "files" && !target.fileCategory) return known(counts?.files, Boolean(counts));
  if (target.collection === "docs") return known(docsCount(input), Boolean(counts) || Boolean(tree));
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
    const kindNode = mergedKindNode(tree, target.kind);
    // The run has no records of this kind at all.
    if (!kindNode) return known(0, true);
    const zero = zeroReason(kindNode);
    if (target.countField) {
      const value = (kindNode as unknown as Record<string, unknown>)[target.countField];
      return typeof value === "number" ? known(value, true, zero) : { count: UNKNOWN_COUNT };
    }
    if (!target.types?.length) return known(kindNode.count, true, zero);
    const perType = kindNode.artifact_type_counts;
    if (perType && typeof perType === "object") {
      return known(
        target.types.reduce((sum, type) => sum + (typeof perType[type] === "number" ? perType[type] : 0), 0),
        true,
        zero,
      );
    }
    const typed = (kindNode.children ?? []).filter((child) => child.artifact_type);
    if (typed.length) {
      return known(
        typed
          .filter((child) => target.types?.includes(child.artifact_type as string))
          .reduce((sum, c) => sum + c.count, 0),
        true,
        zero,
      );
    }
    // Per-type counts unknown for this run: only an empty kind is known to be 0.
    return kindNode.count === 0 ? known(0, true, zero) : { count: UNKNOWN_COUNT };
  }
  return { count: undefined };
}

/** Why 전체 파일(인벤토리) is empty on a run whose files output predates the inventory. */
export const NO_INVENTORY_REASON =
  "이 런의 파일 출력에는 인벤토리가 없습니다 — 선택한 범주의 후보만 기록되었습니다";

/**
 * 전체 파일(인벤토리) count: every scanned file = the candidates (`files` node count) plus the
 * inventory-only rows (`files.inventory_count`, files outside the selected categories).
 */
export function inventoryTotal(input: Pick<TreeModelInput, "summary" | "tree">): DomainCount {
  if (!input.tree) return { count: undefined };
  const node = findServerNode(input.tree, "files");
  if (typeof node?.inventory_count !== "number") return { count: 0, disabledReason: NO_INVENTORY_REASON };
  const candidates = node.count ?? input.summary?.summary?.counts?.files ?? 0;
  return known(candidates + node.inventory_count, true);
}

const SKIP_STATUS_LABEL: Record<string, string> = {
  skipped: "제공자 건너뜀",
  "failed-isolated": "제공자 실패",
  failed: "제공자 실패",
  partial: "일부만 수집",
};

/**
 * Why a 0-count node of this kind is empty: "데이터 없음" (NO_DATA_REASON, the provider ran and
 * found nothing) or "제공자 건너뜀(사유)" from the kind's `collection_status` /
 * `skip_reasons` / `collection_notes` (tree.py exposes the status only when not "completed").
 */
export function zeroReason(kindNode: TreeNode): string {
  const status = kindNode.collection_status ?? "";
  const label = SKIP_STATUS_LABEL[status];
  if (!label) return NO_DATA_REASON;
  const reasons = [
    ...Object.keys(kindNode.skip_reasons ?? {}),
    ...(kindNode.skip_reason ? [kindNode.skip_reason] : []),
    ...(kindNode.collection_notes ?? []),
  ].filter(Boolean);
  const why = reasons.length ? reasons.slice(0, 2).join("; ") : "사유 미기재";
  return status === "partial" ? `${NO_DATA_REASON} · ${label}(${why})` : `${label}(${why})`;
}

function known(count: number | undefined, loaded: boolean, emptyReason = NO_DATA_REASON): DomainCount {
  if (count === undefined) return { count: undefined };
  return loaded && count === 0 ? { count, disabledReason: emptyReason } : { count };
}

/** Full route of a domain node (the tree navigates with it; `types=` / `ext=` ride in the URL). */
export function domainRoute(target: DomainTarget): DomainRoute {
  const route: DomainRoute = { collection: target.collection };
  if (target.kind) route.kind = target.kind;
  if (target.fileScope) route.category = filesInventoryCategory(target.fileCategory);
  else if (target.fileCategory) route.category = target.fileCategory;
  if (target.types?.length) route.types = [...target.types];
  if (target.ext?.length) route.ext = [...target.ext];
  if (target.cols?.length) route.cols = [...target.cols];
  if (target.cf?.length) route.cf = target.cf.map((filter) => ({ ...filter }));
  return route;
}

/**
 * A files category node whose server node exists only in the inventory (`files:<id>` with
 * `inventory_only`, a category the scan did not select) opens the inventory scope.
 */
function effectiveTarget(target: DomainTarget, tree: RunTree | undefined): DomainTarget {
  if (target.collection !== "files" || !target.fileCategory || target.fileScope) return target;
  const node = findServerNode(tree, `files:${target.fileCategory}`);
  return node?.inventory_only || node?.source === "inventory"
    ? { ...target, fileScope: "inventory" }
    : target;
}

/**
 * Domain header count (over the flattened nodes, sub-nodes included; groups, catch-alls and
 * column-filtered views never add): evidence records, each kind once. A kind with a kind-wide node in the
 * domain counts that node minus its `nonEvidence` / `detail` typed nodes (string candidates,
 * Prefetch reference paths, the registry key tree never inflate the header); a kind with only
 * typed nodes counts the sum of its typed evidence nodes. Non-artifact nodes (files, analyses,
 * indicators) do not add. undefined = no artifact count known.
 */
export function domainTotal(
  nodes: readonly DomainNodeDef[],
  counts: ReadonlyArray<number | string | undefined>,
): number | undefined {
  const typed = new Map<string, number>();
  const excluded = new Map<string, number>();
  const wide = new Map<string, number>();
  let anyKnown = false;
  nodes.forEach((node, index) => {
    const count = counts[index];
    const t = node.target;
    if (t.collection !== "artifacts" || !t.kind || typeof count !== "number") return;
    // Catch-alls span domains, groups repeat their leaves, filtered views repeat their types.
    if (node.catchAll || node.children?.length || t.cf?.length) return;
    anyKnown = true;
    if (!t.types?.length) wide.set(t.kind, count);
    else if (node.nonEvidence || node.detail) excluded.set(t.kind, (excluded.get(t.kind) ?? 0) + count);
    else typed.set(t.kind, (typed.get(t.kind) ?? 0) + count);
  });
  if (!anyKnown) return undefined;
  let total = 0;
  for (const [kind, count] of wide) total += Math.max(0, count - (excluded.get(kind) ?? 0));
  for (const [kind, count] of typed) if (!wide.has(kind)) total += count;
  return total;
}

/** Tooltip of a column-filtered node: the filter is applied to the loaded rows. */
function filteredNote(target: DomainTarget): string {
  const filters = (target.cf ?? []).map((f) => `${f.col.replace(/^f:/, "")} ${f.op} ${f.value}`).join(", ");
  return `불러온 행에 열 필터 적용: ${filters}`;
}

function domainNodes(input: TreeModelInput): TreeModelNode[] {
  return DOMAINS.map<TreeModelNode>((domain) => {
    const flat: Array<{ def: DomainNodeDef; count: number | string | undefined }> = [];
    const toModel = (node: DomainNodeDef): TreeModelNode => {
      const target = effectiveTarget(node.target, input.tree);
      const state = domainNodeCount(target, input);
      flat.push({ def: node, count: state.count });
      const route = domainRoute(target);
      const label =
        node.target.collection === "indicators" ? indicatorsLabel(input.tree, node.label) : node.label;
      const children = node.children?.map(toModel);
      return {
        id: `domain:${domain.id}:${node.id}`,
        label,
        count: state.count,
        route: {
          collection: route.collection,
          ...(route.kind ? { kind: route.kind } : {}),
          ...(route.category ? { category: route.category } : {}),
        },
        target: route,
        selectKey: targetKey(target),
        disabledReason: state.disabledReason,
        marker: state.marker,
        icon: state.icon ?? node.icon,
        ...(children?.length ? { children } : {}),
        ...(node.nonEvidence ? { dimmed: true, note: NON_EVIDENCE_NOTE } : {}),
        ...(target.cf?.length && !node.nonEvidence ? { note: filteredNote(target) } : {}),
      };
    };
    const children = domain.nodes.map(toModel);
    const total = domainTotal(
      flat.map((entry) => entry.def),
      flat.map((entry) => entry.count),
    );
    const anyKnown = total !== undefined;
    return {
      id: `domain:${domain.id}`,
      label: domain.label,
      icon: domain.icon,
      count: anyKnown ? (total as number) : undefined,
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
      dataNode("docs", "문서/메일", docsCount(input), "docs-index 산출물이 없는 런입니다", loaded),
      {
        id: "search",
        label: "검색 결과",
        route: { collection: "search" },
        children: saved.length ? saved : undefined,
      },
      dataNode(
        "indicators",
        indicatorsLabel(input.tree, "IOC/위험"),
        counts?.indicators,
        "이 런에는 지표가 없습니다",
        loaded,
      ),
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
