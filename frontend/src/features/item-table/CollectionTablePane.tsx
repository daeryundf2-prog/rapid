import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { type ReactNode, useMemo, useRef } from "react";
import {
  getRunArtifacts,
  getRunDocs,
  getRunFiles,
  getRunIndicators,
  getRunIssues,
  getRunTimeline,
  type ItemRow,
  type TreeNode,
} from "../../api/runs";
import { useUiStore } from "../../state/ui";

interface Column {
  id: string;
  header: string;
  /** CSS grid track size, e.g. "72px" or "1fr". */
  width: string;
  cell: (row: ItemRow) => ReactNode;
}

function text(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function joinList(value: unknown): string {
  return Array.isArray(value) ? value.map(text).filter(Boolean).join(", ") : text(value);
}

function baseName(path: unknown): string {
  const p = text(path);
  const normalized = p.replace(/[/\\]+$/, "");
  return normalized.split(/[/\\]/).pop() || p;
}

const COLUMNS: Record<string, Column[]> = {
  files: [
    { id: "name", header: "이름", width: "1.4fr", cell: (r) => baseName(r.path) || text(r.name) },
    { id: "extension", header: "확장자", width: "70px", cell: (r) => text(r.extension) },
    {
      id: "size",
      header: "크기",
      width: "90px",
      cell: (r) => (typeof r.size === "number" ? r.size.toLocaleString("ko-KR") : ""),
    },
    { id: "modified", header: "수정 시각", width: "170px", cell: (r) => text(r.modified_at) },
    { id: "categories", header: "분류", width: "1fr", cell: (r) => joinList(r.categories) },
    { id: "path", header: "경로", width: "2fr", cell: (r) => text(r.path) },
  ],
  artifacts: [
    { id: "type", header: "유형", width: "1.2fr", cell: (r) => text(r.artifact_type) },
    { id: "path", header: "경로", width: "2.5fr", cell: (r) => text(r.path) },
    {
      id: "provider",
      header: "파서",
      width: "1.2fr",
      cell: (r) => text((r.provider as Record<string, unknown> | undefined)?.name),
    },
    {
      id: "supported",
      header: "지원",
      width: "60px",
      cell: (r) => (r.supported === false ? "미지원" : ""),
    },
  ],
  docs: [
    { id: "name", header: "이름", width: "1.4fr", cell: (r) => baseName(r.path) },
    { id: "kind", header: "형식", width: "70px", cell: (r) => text(r.kind) },
    {
      id: "keywords",
      header: "키워드",
      width: "80px",
      cell: (r) => (Array.isArray(r.matched_keywords) ? r.matched_keywords.length : 0),
    },
    {
      id: "size",
      header: "크기",
      width: "90px",
      cell: (r) => (typeof r.size === "number" ? r.size.toLocaleString("ko-KR") : ""),
    },
    { id: "path", header: "경로", width: "2fr", cell: (r) => text(r.path) },
  ],
  timeline: [
    { id: "timestamp", header: "시각", width: "190px", cell: (r) => text(r.timestamp) },
    { id: "source", header: "출처", width: "110px", cell: (r) => text(r.source) },
    { id: "event", header: "이벤트", width: "2fr", cell: (r) => text(r.event_type) },
    { id: "path", header: "경로", width: "2fr", cell: (r) => text(r.path) },
  ],
  indicators: [
    { id: "type", header: "유형", width: "90px", cell: (r) => text(r.type) },
    { id: "value", header: "값", width: "2.5fr", cell: (r) => text(r.value) },
    { id: "class", header: "분류", width: "110px", cell: (r) => text(r.classification) },
    { id: "count", header: "건수", width: "70px", cell: (r) => text(r.count) },
  ],
  issues: [
    { id: "step", header: "단계", width: "160px", cell: (r) => text(r.step) },
    { id: "kind", header: "종류", width: "100px", cell: (r) => text(r.kind) },
    { id: "level", header: "수준", width: "70px", cell: (r) => text(r.level) },
    { id: "message", header: "내용", width: "3fr", cell: (r) => text(r.message) },
  ],
};

async function fetchRows(runId: string, node: TreeNode): Promise<{ rows: ItemRow[]; total: number }> {
  switch (node.collection) {
    case "files": {
      const { rows, total } = await getRunFiles(runId);
      const filtered = node.category
        ? rows.filter((r) => Array.isArray(r.categories) && r.categories.includes(node.category as string))
        : rows;
      return { rows: filtered, total: node.category ? filtered.length : total };
    }
    case "artifacts": {
      const families = await getRunArtifacts(runId);
      const rows: ItemRow[] = [];
      for (const [kind, family] of Object.entries(families)) {
        if (node.kind && kind !== node.kind) continue;
        for (const row of family.artifacts ?? []) {
          if (node.artifact_type && row.artifact_type !== node.artifact_type) continue;
          rows.push({ ...row, _kind: kind });
        }
      }
      return { rows, total: rows.length };
    }
    case "docs":
      return getRunDocs(runId);
    case "timeline":
      return getRunTimeline(runId);
    case "indicators":
      return getRunIndicators(runId);
    case "issues":
      return getRunIssues(runId);
    default:
      return { rows: [], total: 0 };
  }
}

const EMPTY_TEXT: Record<string, string> = {
  review: "리뷰 선별 목록은 케이스 검토 기능과 함께 제공될 예정입니다.",
  issues: "검증 이슈가 없습니다.",
};

export function CollectionTablePane({ node }: { node: TreeNode }) {
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const selectItem = useUiStore((s) => s.selectItem);
  const selectedItem = useUiStore((s) => s.selectedItem);
  const tableFilter = useUiStore((s) => s.tableFilter);
  const scrollRef = useRef<HTMLDivElement>(null);

  const query = useQuery({
    queryKey: ["collection", selectedRunId, node.id],
    queryFn: () => fetchRows(selectedRunId as string, node),
    enabled: Boolean(selectedRunId && node.collection && COLUMNS[node.collection]),
  });

  const columns = node.collection ? COLUMNS[node.collection] : undefined;
  const allRows = query.data?.rows ?? [];
  const rows = useMemo(() => {
    const needle = tableFilter.trim().toLowerCase();
    if (!needle) return allRows;
    return allRows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle));
  }, [allRows, tableFilter]);
  const total = query.data?.total ?? node.count;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  return (
    <div className="pane" data-testid="item-table-pane">
      <div className="pane-title">
        <span>{node.label}</span>
        <span className="badge muted">
          {rows.length === total
            ? `${total.toLocaleString("ko-KR")}건`
            : `${rows.length}/${total.toLocaleString("ko-KR")}건`}
        </span>
      </div>
      {!columns ? (
        <p className="pane-empty">
          {EMPTY_TEXT[node.collection ?? ""] ?? "이 분류는 아직 표에 연결되지 않았습니다."}
        </p>
      ) : query.isPending ? (
        <p className="pane-empty">불러오는 중…</p>
      ) : query.isError ? (
        <p className="pane-empty">항목을 불러오지 못했습니다.</p>
      ) : rows.length === 0 ? (
        <p className="pane-empty">이 분류에 항목이 없습니다.</p>
      ) : (
        <div className="vtable">
          <div
            className="vtable-header"
            style={{ gridTemplateColumns: columns.map((c) => c.width).join(" ") }}
          >
            {columns.map((c) => (
              <div key={c.id} className="vtable-cell vtable-head">
                {c.header}
              </div>
            ))}
          </div>
          <div className="vtable-scroll" ref={scrollRef}>
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((item) => {
                const row = rows[item.index];
                if (!row) return null;
                return (
                  <button
                    key={item.key}
                    type="button"
                    className={`vtable-row${row === selectedItem ? " selected" : ""}`}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: item.size,
                      transform: `translateY(${item.start}px)`,
                      gridTemplateColumns: columns.map((c) => c.width).join(" "),
                    }}
                    onClick={() => selectItem(row)}
                  >
                    {columns.map((c) => (
                      <span key={c.id} className="vtable-cell">
                        {c.cell(row)}
                      </span>
                    ))}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
