import { flexRender } from "@tanstack/react-table";
import { getCoreRowModel, type LegacyColumnDef, useLegacyTable } from "@tanstack/react-table/legacy";
import { useMemo } from "react";
import type { RunListItem } from "../../api/runs";
import { StatusBadge } from "../../components/Badge";
import { useUiStore } from "../../state/ui";

function cellName(run: RunListItem): string {
  const root = run.request?.root || run.request?.output_dir || "";
  const normalized = root.replace(/[/\\]+$/, "");
  return normalized.split(/[/\\]/).pop() || root || run.run_id;
}

const columns: LegacyColumnDef<RunListItem>[] = [
  {
    id: "status",
    header: "상태",
    size: 72,
    cell: ({ row }) => <StatusBadge status={row.original.status} />,
  },
  {
    id: "name",
    header: "이름",
    cell: ({ row }) => cellName(row.original),
  },
  {
    id: "mode",
    header: "모드",
    size: 96,
    accessorFn: (run) => run.request?.mode || "case",
  },
  {
    id: "created",
    header: "생성 시각",
    size: 140,
    accessorFn: (run) => {
      const parsed = run.created_at ? new Date(run.created_at) : null;
      return parsed && !Number.isNaN(parsed.getTime())
        ? parsed.toLocaleString("ko-KR")
        : run.created_at || "";
    },
  },
  {
    id: "run_id",
    header: "실행 ID",
    size: 120,
    accessorFn: (run) => run.run_id,
  },
];

export function RunTablePane({ runs }: { runs: RunListItem[] }) {
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const selectRun = useUiStore((s) => s.selectRun);
  const table = useLegacyTable<RunListItem>({
    data: runs,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });
  const rows = useMemo(() => table.getRowModel().rows, [table]);

  return (
    <div className="pane" data-testid="item-table-pane">
      <div className="pane-title">
        <span>항목</span>
        <span className="badge muted">{runs.length}건</span>
      </div>
      <div className="pane-body">
        {runs.length === 0 ? (
          <p className="pane-empty">표시할 항목이 없습니다.</p>
        ) : (
          <table className="data-table">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th key={header.id} style={{ width: header.column.getSize() }}>
                      {flexRender(header.column.columnDef.header, header.getContext())}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className={row.original.run_id === selectedRunId ? "selected" : ""}
                  onClick={() => selectRun(row.original.run_id)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
