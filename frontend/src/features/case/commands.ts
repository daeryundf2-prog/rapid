import { runSampleCase } from "../../api/runs";
import type { Command } from "../../contracts/command";
import { navigate, registerCommand } from "../tree/adapter";
import { caseLinkOf } from "./caseLink";
import { useCaseDialogs } from "./dialogs";
import { EXPORT_ACTIONS, exportDisabledReason, performExport } from "./exports";
import { useSearchState } from "./searchState";

export const RUN_ACTIVE_REASON = "실행 중 런이 있습니다";
const NO_CASE = "열린 케이스가 없습니다";
export const NOT_LINKED_REASON = "케이스에 연결되지 않은 런입니다";
const CASE_LINK_LOADING = "케이스 정보를 불러오는 중입니다";

/** Reason a case-scoped command cannot run for the open run (undefined = linked to a case). */
function caseOfRunReason(runId: string | null): string | undefined {
  if (!runId) return NO_CASE;
  const link = caseLinkOf(runId);
  if (link === undefined) return CASE_LINK_LOADING;
  return link ? undefined : NOT_LINKED_REASON;
}

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
      id: "case.create",
      label: "케이스 만들기…",
      group: "case",
      icon: "inbox",
      run: () => dialogs().openDialog("create"),
    },
    {
      id: "case.link",
      label: "케이스에 연결…",
      group: "case",
      icon: "link",
      disabledReason: (ctx) => {
        if (!ctx.runId) return NO_CASE;
        const link = caseLinkOf(ctx.runId);
        if (link === undefined) return CASE_LINK_LOADING;
        return link ? `이미 케이스 ${link.caseNumber}에 연결된 런입니다` : undefined;
      },
      run: (ctx) => {
        if (ctx.runId) dialogs().openDialog("link", { runId: ctx.runId });
      },
    },
    {
      id: "case.edit",
      label: "사건 정보 편집…",
      group: "case",
      disabledReason: (ctx) => caseOfRunReason(ctx.runId),
      run: (ctx) => {
        const link = caseLinkOf(ctx.runId);
        if (link) dialogs().openDialog("case-edit", { caseId: link.caseId });
      },
    },
    {
      id: "case.evidence.add",
      label: "증거 추가…",
      group: "case",
      disabledReason: (ctx) => caseOfRunReason(ctx.runId),
      run: (ctx) => {
        const link = caseLinkOf(ctx.runId);
        if (link) dialogs().openDialog("evidence-add", { caseId: link.caseId });
      },
    },
    {
      id: "case.run.add",
      label: "런 추가…",
      group: "case",
      disabledReason: (ctx) => (ctx.runIsActive ? RUN_ACTIVE_REASON : caseOfRunReason(ctx.runId)),
      run: (ctx) => {
        const link = caseLinkOf(ctx.runId);
        if (link)
          dialogs().openDialog("run-add", {
            caseId: link.caseId,
            evidenceCitationId: link.evidenceCitationId,
          });
      },
    },
    {
      id: "case.run",
      label: "케이스 없이 빠른 런…",
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
