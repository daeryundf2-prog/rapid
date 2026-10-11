import type { ReviewCounts, SavedSearch } from "../../api/caseDb";
import type { EvidencePartition, EvidenceSource } from "../../api/dashboard";
import type { CanonicalCounts, RunSummary, RunTree, TreeNode } from "../../api/runs";
import type { CollectionId, ReviewStatus } from "../../contracts/collection";
import type { IconName } from "../../icons";
import type { CaseRoute } from "./adapter";
import { groupByCategory, kindIcon } from "./categories";

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

export function buildTreeModel(input: TreeModelInput): TreeModelNode[] {
  const counts = input.summary?.summary?.counts;
  const loaded = Boolean(counts);
  const live = input.live;

  const kinds = categoryNodes(artifactKindNodes(input.tree));

  const saved = (input.saved ?? []).map<TreeModelNode>((search, index) => ({
    id: `search:saved:${index}:${search.name}`,
    label: search.name,
    route: { collection: "search" },
    activate: () => input.onOpenSavedSearch?.(search),
  }));

  const reviewChildren = REVIEW_NODES.map<TreeModelNode>(({ status, label }) => ({
    id: `review:${status}`,
    label,
    count: reviewCount(input.review, status),
    route: { collection: "review", status },
  }));

  const reviewTotal = input.review
    ? Object.values(input.review.by_status ?? {}).reduce((sum, value) => sum + value, 0)
    : undefined;

  const intakeCount =
    live?.active && live.total !== null ? `${live.completed ?? 0}/${live.total}` : counts?.validation_issues;

  return [
    evidenceNode(input.evidence, counts),
    { id: "intake", label: "접수", count: intakeCount, route: { collection: "intake" } },
    { id: "search", label: "검색 결과", route: { collection: "search" }, children: saved },
    dataNode("files", "파일/미디어", counts?.files, "이 런에는 파일 목록이 없습니다", loaded),
    dataNode("docs", "문서/메일", counts?.docs, "docs-index 산출물이 없는 런입니다", loaded),
    dataNode("artifacts", "아티팩트", counts?.artifacts, "이 런에는 아티팩트가 없습니다", loaded, kinds),
    dataNode("timeline", "타임라인", counts?.timeline_events, "이 런에는 타임라인 산출물이 없습니다", loaded),
    dataNode("indicators", "IOC/위험", counts?.indicators, "이 런에는 지표가 없습니다", loaded),
    {
      id: "review",
      label: "리뷰보드",
      count: reviewTotal,
      route: { collection: "review" },
      children: reviewChildren,
    },
    { id: "outputs", label: "산출물", count: counts?.outputs, route: { collection: "outputs" } },
  ];
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
