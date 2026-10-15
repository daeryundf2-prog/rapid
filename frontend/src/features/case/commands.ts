import { runSampleCase } from "../../api/runs";
import type { Command } from "../../contracts/command";
import { navigate, registerCommand } from "../tree/adapter";
import { useCaseDialogs } from "./dialogs";
import { EXPORT_ACTIONS, exportDisabledReason, performExport } from "./exports";
import { useSearchState } from "./searchState";

export const RUN_ACTIVE_REASON = "실행 중 런이 있습니다";
const NO_CASE = "열린 케이스가 없습니다";

export interface CaseCommandFacts {
  /** include-in-report rows (case-db + case json); undefined until loaded. */
  reportCandidates: number | undefined;
}

/**
 * Every case/search/export action as a Command. Plan 4.3 acceptance list:
 * see docs in the S4 report (row -> command id -> API -> disabled reason).
 */
export function buildCaseCommands(facts: CaseCommandFacts): Command[] {
  const dialogs = () => useCaseDialogs.getState();
  const notify = (message: string) => dialogs().setNotice(message);
  const fail = (error: unknown) =>
    dialogs().setNotice(error instanceof Error ? error.message : "작업에 실패했습니다.", true);

  const commands: Command[] = [
    {
      id: "case.switch",
      label: "케이스 전환/삭제…",
      group: "case",
      icon: "folder",
      run: () => dialogs().openDialog("picker"),
    },
    {
      id: "case.run",
      label: "실행…",
      group: "case",
      icon: "play",
      disabledReason: (ctx) => (ctx.runIsActive ? RUN_ACTIVE_REASON : undefined),
      run: () => dialogs().openDialog("run"),
    },
    {
      id: "case.import",
      label: "불러오기…",
      group: "case",
      icon: "upload",
      disabledReason: (ctx) => (ctx.runIsActive ? RUN_ACTIVE_REASON : undefined),
      run: () => dialogs().openDialog("import"),
    },
    {
      id: "case.sample",
      label: "샘플 케이스 실행",
      group: "case",
      icon: "package",
      disabledReason: (ctx) => (ctx.runIsActive ? RUN_ACTIVE_REASON : undefined),
      run: async () => {
        try {
          const payload = await runSampleCase({});
          notify("샘플 케이스를 불러왔습니다.");
          navigate({ runId: payload.run.run_id, collection: "intake" });
        } catch (error) {
          fail(error);
        }
      },
    },
    {
      id: "case.doctor",
      label: "환경 점검",
      group: "case",
      run: () => dialogs().openDialog("doctor"),
    },
    {
      id: "case.delete",
      label: "현재 케이스 삭제…",
      group: "case",
      disabledReason: (ctx) =>
        !ctx.runId ? NO_CASE : ctx.runIsActive ? "실행 중인 런은 먼저 취소해야 합니다" : undefined,
      run: (ctx) => {
        if (ctx.runId) dialogs().confirmDelete(ctx.runId);
      },
    },
    {
      id: "search.options",
      label: "검색 옵션",
      group: "search",
      disabledReason: (ctx) => (ctx.runId ? undefined : NO_CASE),
      run: () => {
        const state = useSearchState.getState();
        state.setPopoverOpen(!state.popoverOpen);
      },
    },
    {
      id: "search.save",
      label: "현재 검색 저장…",
      group: "search",
      disabledReason: (ctx) =>
        !ctx.runId
          ? NO_CASE
          : useSearchState.getState().keywords.length
            ? undefined
            : "저장할 검색어가 없습니다",
      run: () => useSearchState.getState().setPopoverOpen(true),
    },
    {
      id: "export.open",
      label: "보고서 내보내기…",
      group: "export",
      disabledReason: (ctx) => (ctx.runId ? undefined : NO_CASE),
      run: () => dialogs().openDialog("report"),
    },
  ];

  for (const action of EXPORT_ACTIONS) {
    commands.push({
      id: action.commandId,
      label: `${action.label} 내보내기`,
      group: "export",
      disabledReason: (ctx) =>
        exportDisabledReason(action, {
          runId: ctx.runId,
          runIsActive: ctx.runIsActive,
          reportCandidates: facts.reportCandidates,
        }),
      run: async (ctx) => {
        if (!ctx.runId) return;
        try {
          const name = await performExport(action.kind, ctx.runId);
          notify(`${name} 파일을 저장했습니다.`);
        } catch (error) {
          fail(error);
        }
      },
    });
  }
  return commands;
}

export function registerCaseCommands(facts: CaseCommandFacts): () => void {
  const offs = buildCaseCommands(facts).map((command) => registerCommand(command));
  return () => {
    for (const off of offs) off();
  };
}
