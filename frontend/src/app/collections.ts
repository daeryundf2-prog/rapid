import type { CollectionId, ReviewStatus } from "../contracts/collection";
import type { IconName } from "../icons";

/** Tree / palette order and Korean labels of the top-level collection nodes (plan §4.2). */
export const COLLECTION_NODES: ReadonlyArray<{ id: CollectionId; label: string; icon: IconName }> = [
  { id: "intake", label: "접수", icon: "inbox" },
  { id: "search", label: "검색 결과", icon: "search" },
  { id: "files", label: "파일/미디어", icon: "folder" },
  { id: "docs", label: "문서/메일", icon: "file-text" },
  { id: "artifacts", label: "아티팩트", icon: "layers" },
  { id: "timeline", label: "타임라인", icon: "clock" },
  { id: "indicators", label: "IOC/위험", icon: "shield" },
  { id: "review", label: "리뷰보드", icon: "list" },
  { id: "outputs", label: "산출물", icon: "package" },
];

export const COLLECTION_LABEL = Object.fromEntries(COLLECTION_NODES.map((n) => [n.id, n.label])) as Record<
  CollectionId,
  string
>;

/** Review status names (glossary: "선별" is only the name of this set). */
export const REVIEW_STATUS_LABEL: Record<ReviewStatus, string> = {
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
  "include-in-report": "보고서 포함",
};

export const RUN_MODE_LABEL: Record<string, string> = {
  fraud: "문서·부정 조사",
  seizure: "전수 수집",
  hacking: "침해사고",
  recovery: "복구",
};

/** Short display name of a run: last path segment of its evidence root. */
export function runDisplayName(run: {
  run_id: string;
  request?: { root?: string; output_dir?: string };
}): string {
  const root = run.request?.root || run.request?.output_dir || "";
  if (!root) return run.run_id.slice(0, 8);
  const normalized = root.replace(/[/\\]+$/, "");
  return normalized.split(/[/\\]/).pop() || normalized;
}
