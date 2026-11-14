/**
 * `derived.*` commands (통합 보기, axiom-adoption §3.2): open a table, copy a value's citation, show
 * its original rows, load more values, rebuild the tables. Each one reports a Korean reason instead
 * of silently doing nothing.
 */

import type { QueryClient } from "@tanstack/react-query";
import { announce } from "../../a11y";
import { ApiError } from "../../api/client";
import { NO_RUN_REASON } from "../../commands/reasons";
import { registerCommands } from "../../commands/registry";
import type { Command } from "../../contracts/command";
import { useAppStore } from "../../state/store";
import { confirmWrite, joinRunPath, runOutputDir } from "../case/WriteConfirm";
import { writeClipboard } from "../viewer/commands";
import { DERIVED_TABLE_IDS, derivedMetaKey, startDerivedAnalysis } from "./api";
import { useDerivedStore } from "./store";
import { DERIVED_TABLE_LABELS, derivedCitation } from "./tables";

export const NO_VALUE_REASON = "통합 보기 표에서 값을 먼저 고르세요";
export const NOT_IN_DERIVED_REASON = "통합 보기 표를 연 상태에서만 쓸 수 있습니다";
export const NO_MORE_REASON = "더 불러올 값이 없습니다";
export const REBUILDING_REASON = "통합 보기를 만드는 중입니다";

function selectedHere() {
  const { route } = useAppStore.getState();
  const selected = useDerivedStore.getState().selected;
  if (!selected || route.collection !== "derived" || selected.runId !== route.runId) return null;
  return selected;
}

export function derivedCommands(queryClient: QueryClient): Command[] {
  const app = useAppStore.getState;
  const derived = useDerivedStore.getState;
  const openTables: Command[] = DERIVED_TABLE_IDS.map((table) => ({
    id: `derived.open.${table}`,
    label: `통합 보기: ${DERIVED_TABLE_LABELS[table]} 열기`,
    group: "navigate",
    icon: "link",
    disabledReason: () => (app().route.runId ? undefined : NO_RUN_REASON),
    run: () => {
      const runId = app().route.runId;
      if (runId) app().navigate({ runId, collection: "derived", kind: table });
    },
  }));
  return [
    ...openTables,
    {
      id: "derived.copy-citation",
      label: "통합 보기 값 인용 복사",
      group: "export",
      icon: "quote",
      disabledReason: () => {
        if (!app().route.runId) return NO_RUN_REASON;
        if (app().route.collection !== "derived") return NOT_IN_DERIVED_REASON;
        return selectedHere() ? undefined : NO_VALUE_REASON;
      },
      run: async () => {
        const selected = selectedHere();
        if (!selected) return;
        const text = derivedCitation(selected.table, selected.row, selected.runId);
        try {
          await writeClipboard(text);
          announce("인용을 복사했습니다");
        } catch (error) {
          announce(error instanceof Error ? error.message : "인용을 복사하지 못했습니다", {
            politeness: "assertive",
          });
        }
      },
    },
    {
      id: "derived.open-rows",
      label: "통합 보기 값의 원본 행 보기",
      group: "grid",
      icon: "list",
      disabledReason: () => {
        if (!app().route.runId) return NO_RUN_REASON;
        if (app().route.collection !== "derived") return NOT_IN_DERIVED_REASON;
        return selectedHere() ? undefined : NO_VALUE_REASON;
      },
      run: () => derived().focusRows?.(),
    },
    {
      id: "derived.load-more",
      label: "통합 보기 값 더 불러오기",
      group: "grid",
      icon: "download",
      disabledReason: () => {
        if (!app().route.runId) return NO_RUN_REASON;
        if (app().route.collection !== "derived") return NOT_IN_DERIVED_REASON;
        return derived().loadMore ? undefined : NO_MORE_REASON;
      },
      run: () => derived().loadMore?.(),
    },
    {
      id: "derived.rebuild",
      label: "통합 보기 다시 만들기",
      group: "case",
      icon: "refresh",
      disabledReason: () => {
        if (!app().route.runId) return NO_RUN_REASON;
        return derived().rebuilding ? REBUILDING_REASON : undefined;
      },
      run: async () => {
        const runId = app().route.runId;
        if (!runId) return;
        // A write (C-X2): say what goes where first; nothing is sent before 다시 만들기 is confirmed.
        const folder = await runOutputDir(runId);
        const ok = await confirmWrite({
          title: "통합 보기 다시 만들기",
          writes: [
            {
              what: "통합 보기 분석 결과(새 분석 1개 — 표·원본 행 색인)",
              where: joinRunPath(folder, "analyses"),
            },
          ],
          note: "이전 결과는 지우지 않고 새 분석으로 추가합니다. 원본 증거는 바꾸지 않습니다.",
          confirmLabel: "다시 만들기",
        });
        if (!ok) return;
        try {
          const created = await startDerivedAnalysis(runId);
          derived().setRebuilding(created.analysis_id);
          announce("통합 보기를 다시 만들기 시작했습니다. 완료되면 표가 새로 고쳐집니다");
          void queryClient.invalidateQueries({ queryKey: ["analyses", runId] });
        } catch (error) {
          const message = error instanceof ApiError ? error.message : "통합 보기를 시작하지 못했습니다";
          announce(message, { politeness: "assertive" });
          void queryClient.invalidateQueries({ queryKey: derivedMetaKey(runId) });
        }
      },
    },
  ];
}

/** Register the derived commands; a second mount (StrictMode / tests) keeps the first registration. */
export function registerDerivedCommands(queryClient: QueryClient): () => void {
  try {
    return registerCommands(derivedCommands(queryClient));
  } catch (error) {
    console.warn(error instanceof Error ? error.message : error);
    return () => {};
  }
}
