import type { RunListItem } from "../../api/runs";
import { StatusBadge } from "../../components/Badge";
import { useUiStore } from "../../state/ui";
import { EvidenceTree } from "./EvidenceTree";

const MODE_LABEL: Record<string, string> = {
  fraud: "문서·부정 조사",
  seizure: "전수 수집",
  hacking: "침해사고",
  recovery: "복구",
};

function runDisplayName(run: RunListItem): string {
  const root = run.request?.root || run.request?.output_dir || "";
  if (!root) return "증거 경로 없음";
  const normalized = root.replace(/[/\\]+$/, "");
  const name = normalized.split(/[/\\]/).pop();
  return name || normalized;
}

function formatRunTime(value?: string): string {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString("ko-KR", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function CaseQueuePane({ runs }: { runs: RunListItem[] }) {
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const selectRun = useUiStore((s) => s.selectRun);
  const live = runs.filter((r) => r.status !== "failed");
  const failed = runs.filter((r) => r.status === "failed");

  return (
    <div className="pane" data-testid="case-queue-pane">
      <div className="pane-title">
        <span>케이스</span>
        <span className="badge muted">{runs.length}</span>
      </div>
      <div className="pane-body">
        {runs.length === 0 ? (
          <p className="pane-empty">열린 케이스가 없습니다. v1 콘솔에서 실행한 뒤 이 목록이 채워집니다.</p>
        ) : (
          <div className="run-list" role="listbox" aria-label="케이스 목록">
            {live.map((run) => (
              <RunRow
                key={run.run_id}
                run={run}
                selected={run.run_id === selectedRunId}
                onSelect={() => selectRun(run.run_id)}
              />
            ))}
            {failed.length > 0 && (
              <details>
                <summary className="run-item-kicker" style={{ padding: "var(--space-2)" }}>
                  실패 {failed.length}건
                </summary>
                {failed.map((run) => (
                  <RunRow
                    key={run.run_id}
                    run={run}
                    selected={run.run_id === selectedRunId}
                    onSelect={() => selectRun(run.run_id)}
                  />
                ))}
              </details>
            )}
          </div>
        )}
        {selectedRunId && (
          <div className="tree-section">
            <div className="pane-title tree-section-title">
              <span>증거 트리</span>
            </div>
            <EvidenceTree />
          </div>
        )}
      </div>
    </div>
  );
}

function RunRow({ run, selected, onSelect }: { run: RunListItem; selected: boolean; onSelect: () => void }) {
  const mode = run.request?.mode || "case";
  return (
    <button
      type="button"
      className={`run-item${selected ? " selected" : ""}`}
      role="option"
      aria-selected={selected}
      onClick={onSelect}
      title={run.request?.root || run.run_id}
    >
      <span className="run-item-kicker">
        <span>{MODE_LABEL[mode] ?? mode}</span>
        <span>{formatRunTime(run.created_at)}</span>
        <StatusBadge status={run.status} />
      </span>
      <span className="run-item-name">{runDisplayName(run)}</span>
      <span className="run-item-path">{run.request?.root || ""}</span>
    </button>
  );
}
