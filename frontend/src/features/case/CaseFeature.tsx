import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { announce } from "../../a11y";
import { getReviewCounts } from "../../api/caseDb";
import { useRunLive } from "../tree/adapter";
import { useTreeCommands } from "../tree/commands";
import {
  AddEvidenceDialog,
  AddRunDialog,
  CaseEditDialog,
  LinkCaseDialog,
  ProblemsDialog,
} from "./CaseDialogs";
import { CasePicker, DeleteCaseDialog } from "./CasePicker";
import { CaseWizard } from "./CaseWizard";
import { useCaseLinks, useRunCaseLink } from "./caseLink";
import { registerCaseCommands } from "./commands";
import { DoctorDialog } from "./DoctorDialog";
import { useCaseDialogs } from "./dialogs";
import { ImportDialog } from "./ImportDialog";
import { ReportDialog } from "./ReportDialog";
import { RunDialog } from "./RunDialog";
import "./case.css";

/**
 * Mount ONCE inside the shell (S1 Layout): registers every case.* / search.* /
 * export.* / tree.* command and hosts the dialogs and the notice toast.
 * `runId` is the run of the current route (null when no case is open).
 */
export function CaseFeature({ runId }: { runId: string | null }) {
  const live = useRunLive(runId);
  const open = useCaseDialogs((s) => s.open);
  const deleteRunId = useCaseDialogs((s) => s.deleteRunId);
  const notice = useCaseDialogs((s) => s.notice);
  const close = useCaseDialogs((s) => s.close);
  const setNotice = useCaseDialogs((s) => s.setNotice);

  const review = useQuery({
    queryKey: ["review-counts", runId],
    queryFn: () => getReviewCounts(runId as string),
    enabled: Boolean(runId),
    retry: false,
  });
  const reportCandidates = review.data?.report_candidates;

  // Case / evidence of the open run (commands' disabled reasons, citation prefix).
  useRunCaseLink(runId);
  const link = useCaseLinks((s) => (runId ? s.byRun[runId] : null));
  // Re-registering publishes a new command snapshot, so case.link/edit/… re-read the link.
  // biome-ignore lint/correctness/useExhaustiveDependencies: `link` only triggers the re-register
  useEffect(() => registerCaseCommands({ reportCandidates }), [reportCandidates, link]);
  useTreeCommands(runId);
  const target = useCaseDialogs((s) => s.target);

  useEffect(() => {
    if (!notice) return;
    announce(notice, { politeness: useCaseDialogs.getState().noticeAssertive ? "assertive" : "polite" });
    const timer = window.setTimeout(() => setNotice(""), 6000);
    return () => window.clearTimeout(timer);
  }, [notice, setNotice]);

  return (
    <>
      {open === "run" && <RunDialog runIsActive={live.anyActive} onClose={close} onNotice={setNotice} />}
      {open === "import" && (
        <ImportDialog runIsActive={live.anyActive} onClose={close} onNotice={setNotice} />
      )}
      {open === "picker" && <CasePicker currentRunId={runId} onClose={close} />}
      {open === "doctor" && <DoctorDialog onClose={close} />}
      {open === "report" && (
        <ReportDialog runId={runId} runIsActive={live.active} onClose={close} onNotice={setNotice} />
      )}
      {open === "create" && <CaseWizard runIsActive={live.anyActive} onClose={close} onNotice={setNotice} />}
      {open === "link" && (target.runId ?? runId) && (
        <LinkCaseDialog runId={(target.runId ?? runId) as string} onClose={close} onNotice={setNotice} />
      )}
      {open === "case-edit" && target.caseId && (
        <CaseEditDialog caseId={target.caseId} onClose={close} onNotice={setNotice} />
      )}
      {open === "evidence-add" && target.caseId && (
        <AddEvidenceDialog caseId={target.caseId} onClose={close} onNotice={setNotice} />
      )}
      {open === "run-add" && target.caseId && (
        <AddRunDialog
          caseId={target.caseId}
          evidenceCitationId={target.evidenceCitationId}
          runIsActive={live.anyActive}
          onClose={close}
          onNotice={setNotice}
        />
      )}
      {open === "problems" && target.runId && target.reasonId && (
        <ProblemsDialog
          runId={target.runId}
          reasonId={target.reasonId}
          reasonLabel={target.reasonLabel ?? target.reasonId}
          onClose={close}
        />
      )}
      {open === "delete" && deleteRunId && (
        <DeleteCaseDialog runId={deleteRunId} currentRunId={runId} onClose={close} onNotice={setNotice} />
      )}
    </>
  );
}
