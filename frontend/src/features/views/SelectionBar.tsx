/**
 * Compact batch bar for the explorer views: applies a review mark to the
 * selected rows through the shared implementation (grid/reviewActions.ts),
 * with the same optimistic patch + rollback the DataGrid uses.
 */

import { useState } from "react";
import { announce } from "../../a11y";
import type { GridRow } from "../../contracts/collection";
import { applyReviewAction, type BatchAction, optimisticPatch, storeNotice } from "../grid/reviewActions";

const ACTIONS: BatchAction[] = ["relevant", "needs-review", "excluded", "bookmark"];
/** Glossary labels (docs/console-glossary.md). */
const LABELS: Partial<Record<BatchAction, string>> = {
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
  bookmark: "북마크",
};

export function SelectionBar({
  runId,
  rows,
  patchRows,
  onClear,
}: {
  runId: string | null;
  rows: GridRow[];
  patchRows: (keys: string[], patch: (row: GridRow) => GridRow) => () => void;
  onClear: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; tone: "info" | "error" } | null>(null);
  if (rows.length === 0) return null;

  const run = async (action: BatchAction) => {
    if (!runId || busy) return;
    setBusy(true);
    const rollback = patchRows(
      rows.map((r) => r.rowKey),
      optimisticPatch(action),
    );
    try {
      const result = await applyReviewAction(runId, rows, action);
      const text = `${LABELS[action]}: ${result.applied}건 처리했습니다.${storeNotice(result)}`;
      setMessage({ text, tone: "info" });
      announce(text);
    } catch (error) {
      rollback();
      const text = `${LABELS[action]} 처리에 실패했습니다. ${error instanceof Error ? error.message : String(error)}`;
      setMessage({ text, tone: "error" });
      announce(text, { politeness: "assertive" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="view-selection-bar" role="toolbar" aria-label="선택 항목 작업">
      <span className="view-selection-count">{rows.length.toLocaleString("ko-KR")}개 선택</span>
      {ACTIONS.map((action) => (
        <button key={action} type="button" disabled={busy || !runId} onClick={() => void run(action)}>
          {LABELS[action]}
        </button>
      ))}
      <button type="button" className="view-link" onClick={onClear}>
        선택 해제
      </button>
      {message ? (
        <span className={message.tone === "error" ? "view-message view-message-error" : "view-message"}>
          {message.text}
        </span>
      ) : null}
    </div>
  );
}
