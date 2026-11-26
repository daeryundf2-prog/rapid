/**
 * Mount point of the action dialog (선택 항목 분석 / 관련 항목 표시) and its commands, rendered
 * once by the shell Layout like ReviewToolsHost. The commands act on the grid selection (or
 * the viewer's row) and open the dialog; the dialog talks to the action API v1.
 */

import { useEffect } from "react";
import { create } from "zustand";
import { NO_RUN_REASON } from "../../commands/reasons";
import { registerCommands } from "../../commands/registry";
import type { Command } from "../../contracts/command";
import { propagationRows } from "../review/gridTools";
import { ActionDialog, type ActionDialogTarget } from "./ActionDialog";

export const ANALYZE_COMMAND = "actions.analyze";
export const RELATED_COMMAND = "actions.related";
const NO_ROW_REASON = "그리드에서 행을 선택하거나 뷰어에 행을 여세요";

interface ActionDialogState {
  target: ActionDialogTarget | null;
  open: (target: ActionDialogTarget) => void;
  close: () => void;
}

export const useActionDialog = create<ActionDialogState>((set) => ({
  target: null,
  open: (target) => set({ target }),
  close: () => set({ target: null }),
}));

export function actionCommands(): Command[] {
  const reason = (runId: string | null) =>
    runId ? (propagationRows("selection").length ? undefined : NO_ROW_REASON) : NO_RUN_REASON;
  return [
    {
      id: ANALYZE_COMMAND,
      label: "선택 항목 분석…",
      group: "review",
      icon: "bar-chart",
      disabledReason: (ctx) => reason(ctx.runId),
      run: (ctx) => {
        const rows = propagationRows("selection");
        if (ctx.runId && rows.length)
          useActionDialog.getState().open({ mode: "analyze", runId: ctx.runId, rows });
      },
    },
    {
      id: RELATED_COMMAND,
      label: "관련 항목 표시… (같은 시간대·경로·파일 이름)",
      group: "review",
      icon: "link",
      disabledReason: (ctx) => reason(ctx.runId),
      run: (ctx) => {
        const row = propagationRows("selection")[0];
        if (ctx.runId && row) useActionDialog.getState().open({ mode: "related", runId: ctx.runId, row });
      },
    },
  ];
}

export function ActionsHost() {
  const target = useActionDialog((s) => s.target);
  const close = useActionDialog((s) => s.close);
  useEffect(() => registerCommands(actionCommands()), []);
  return target ? <ActionDialog target={target} onClose={close} /> : null;
}
