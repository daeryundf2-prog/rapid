import { runSampleCase } from "../../api/runs";
import { NO_RUN_REASON } from "../../commands/reasons";
import type { Command } from "../../contracts/command";
import { navigate, registerCommand } from "../tree/adapter";
import { caseLinkOf } from "./caseLink";
import { useCaseDialogs } from "./dialogs";
import { EXPORT_ACTIONS, exportDisabledReason } from "./exports";
import { useSearchState } from "./searchState";
import { confirmWrite, notifyWriteFailed, notifyWritten } from "./WriteConfirm";

export const RUN_ACTIVE_REASON = "실행 중 런이 있습니다";
/** One sentence for "no case open" across the console (r7 L4, C-G11). */
const NO_CASE = NO_RUN_REASON;

/** Where the server writes the practice case (`POST /api/sample-case/run` default output_dir). */
export const SAMPLE_CASE_FOLDER = "서버 사용자 폴더\\.rapidtriage\\sample-case";

/**
 * 샘플 실행 (C-G6): confirm what is written where, then build + import the practice case and open
 * it. Resolves with the new run id, or null when the analyst cancelled / it failed (toast says why).
 */
export async function runSampleWithConfirm(): Promise<string | null> {
  const ok = await confirmWrite({
    title: "샘플 케이스 실행",
    writes: [
      {
        what: "합성 샘플 증거와 그 런 결과(이전 샘플은 덮어씀)",
        where: SAMPLE_CASE_FOLDER,
      },
    ],
    note: "연습용 합성 데이터입니다. 실제 증거·다른 런은 건드리지 않습니다.",
    confirmLabel: "샘플 실행",
  });
  if (!ok) return null;
  try {
    const payload = await runSampleCase({});
    const runId = payload.run.run_id;
    const folder = payload.run.summary?.output_dir ?? null;
    notifyWritten("샘플 케이스를 만들고 열었습니다.", folder);
    navigate({ runId, collection: "intake" });
    return runId;
  } catch (error) {
    notifyWriteFailed("샘플 케이스 실행", error);
    return null;
  }
}
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
      // 상단 바 "새 런…" with a case open (C-G9): a run of THIS case when the open run is linked to
      // one, else the quick-run dialog (a separate run, said so in its title).
      id: "case.run.new",
      label: "이 케이스에 런 추가…",
      group: "case",
      icon: "play",
      disabledReason: (ctx) => {
        if (!ctx.runId) return NO_CASE;
        if (ctx.runIsActive) return RUN_ACTIVE_REASON;
        return caseLinkOf(ctx.runId) === undefined ? CASE_LINK_LOADING : undefined;
      },
      run: (ctx) => {
        const link = caseLinkOf(ctx.runId);
        if (link) {
          dialogs().openDialog("run-add", {
            caseId: link.caseId,
            evidenceCitationId: link.evidenceCitationId,
          });
        } else {
          dialogs().openDialog("run");
        }
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
      label: "샘플 케이스 실행…",
      group: "case",
      icon: "package",
      disabledReason: (ctx) => (ctx.runIsActive ? RUN_ACTIVE_REASON : undefined),
      run: async () => {
        await runSampleWithConfirm();
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
      label: `${action.label} 내보내기…`,
      group: "export",
      disabledReason: (ctx) =>
        exportDisabledReason(action, {
          runId: ctx.runId,
          runIsActive: ctx.runIsActive,
          reportCandidates: facts.reportCandidates,
        }),
      // Never a one-key write (C-G7/C-G8): the export dialog, this kind chosen, says what is
      // written where; 내보내기 there sends it.
      run: (ctx) => {
        if (ctx.runId) dialogs().openDialog("report", { exportKind: action.kind });
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
