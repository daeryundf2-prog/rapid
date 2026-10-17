import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { koCompare, listCases } from "../../api/cases";
import { deleteRun, listRuns, type RunListItem } from "../../api/runs";
import { navigate } from "../tree/adapter";
import { useCaseDialogs } from "./dialogs";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";

const ACTIVE = new Set(["queued", "running"]);
const STATUS_LABEL: Record<string, string> = {
  queued: "대기",
  running: "실행 중",
  completed: "완료",
  failed: "실패",
  cancelled: "취소됨",
  canceled: "취소됨",
};

export function runLabel(run: RunListItem): string {
  const root = run.request?.root || run.request?.output_dir || "";
  const name = root
    .replace(/[/\\]+$/, "")
    .split(/[/\\]/)
    .pop();
  return name || run.run_id;
}

function RunRow({
  run,
  label,
  currentRunId,
  onClose,
}: {
  run: RunListItem;
  label: string;
  currentRunId: string | null;
  onClose: () => void;
}) {
  const confirmDelete = useCaseDialogs((s) => s.confirmDelete);
  return (
    <li className="case-actions case-tree-run" style={{ justifyContent: "space-between" }}>
      <button
        type="button"
        className="button"
        aria-current={run.run_id === currentRunId ? "true" : undefined}
        onClick={() => {
          navigate({ runId: run.run_id, collection: "intake" });
          onClose();
        }}
      >
        {label} · {STATUS_LABEL[run.status] ?? run.status}
      </button>
      <ReasonButton
        aria-label={`${label} 삭제`}
        reason={ACTIVE.has(run.status) ? "실행 중인 런은 먼저 취소해야 합니다" : undefined}
        onClick={() => confirmDelete(run.run_id)}
      >
        삭제
      </ReasonButton>
    </li>
  );
}

/**
 * Case switcher (AXIOM adoption E1): 케이스 › 증거 › 런, then the runs started without a case
 * ("케이스 없는 런", still openable and deletable). Cases and evidence in Korean natural order.
 */
export function CasePicker({ currentRunId, onClose }: { currentRunId: string | null; onClose: () => void }) {
  const runs = useQuery({ queryKey: ["runs", "picker"], queryFn: listRuns, retry: false });
  const cases = useQuery({ queryKey: ["cases"], queryFn: listCases, retry: false });
  const byId = new Map((runs.data ?? []).map((run) => [run.run_id, run]));
  const linked = new Set<string>();
  for (const item of cases.data ?? []) {
    for (const evidence of item.evidence) for (const run of evidence.runs) linked.add(run.run_id);
  }
  const sortedCases = [...(cases.data ?? [])].sort((a, b) => koCompare(a.case_number, b.case_number));
  const loose = (runs.data ?? []).filter((run) => !linked.has(run.run_id));
  const loading = runs.isPending || cases.isPending;

  return (
    <Modal title="케이스 전환" onClose={onClose} wide>
      {loading && <p aria-busy="true">케이스 목록을 불러오는 중…</p>}
      {runs.isError && <ErrorText>런 목록을 불러오지 못했습니다.</ErrorText>}
      {cases.isError && <ErrorText>케이스 목록을 불러오지 못했습니다.</ErrorText>}
      {!loading && sortedCases.length === 0 && loose.length === 0 && (
        <p>열린 케이스가 없습니다. 케이스 만들기 또는 케이스 없이 빠른 런으로 시작하세요.</p>
      )}
      {sortedCases.length > 0 && (
        <ul className="case-tree" aria-label="케이스 › 증거 › 런">
          {sortedCases.map((item) => (
            <li key={item.case_id}>
              <p className="case-tree-case">
                <strong>{item.case_number}</strong> {item.name !== item.case_number ? item.name : ""}
                <span className="case-reason">
                  {" "}
                  · 증거 {item.evidence_count} · 런 {item.run_count}
                </span>
              </p>
              {item.evidence.length === 0 ? (
                <p className="case-reason case-tree-empty">증거가 없습니다.</p>
              ) : (
                <ul aria-label={`${item.case_number} 증거`}>
                  {[...item.evidence]
                    .sort((a, b) => koCompare(a.evidence_number, b.evidence_number))
                    .map((evidence) => (
                      <li key={evidence.citation_id}>
                        <p className="case-tree-evidence">
                          증거 {evidence.evidence_number} · {evidence.display_name}
                        </p>
                        {evidence.runs.length === 0 ? (
                          <p className="case-reason case-tree-empty">런이 없습니다.</p>
                        ) : (
                          <ul aria-label={`증거 ${evidence.evidence_number} 런`}>
                            {evidence.runs.map((brief) => {
                              const run = byId.get(brief.run_id);
                              if (!run) {
                                return (
                                  <li key={brief.run_id} className="case-reason">
                                    {brief.run_id} · 목록에서 제거된 런
                                  </li>
                                );
                              }
                              return (
                                <RunRow
                                  key={brief.run_id}
                                  run={run}
                                  label={`${item.case_number} › ${evidence.evidence_number} › ${runLabel(run)}`}
                                  currentRunId={currentRunId}
                                  onClose={onClose}
                                />
                              );
                            })}
                          </ul>
                        )}
                      </li>
                    ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
      {loose.length > 0 && (
        <section aria-labelledby="case-tree-loose">
          <h3 id="case-tree-loose" className="case-tree-heading">
            케이스 없는 런
          </h3>
          <ul className="case-check-list" aria-label="케이스 없는 런 목록">
            {loose.map((run) => (
              <RunRow
                key={run.run_id}
                run={run}
                label={runLabel(run)}
                currentRunId={currentRunId}
                onClose={onClose}
              />
            ))}
          </ul>
        </section>
      )}
    </Modal>
  );
}

export function DeleteCaseDialog({
  runId,
  currentRunId,
  onClose,
  onNotice,
}: {
  runId: string;
  currentRunId: string | null;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: () => deleteRun(runId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      onNotice?.("케이스를 목록에서 제거했습니다.");
      if (runId === currentRunId) window.location.hash = "";
      onClose();
    },
  });
  return (
    <Modal title="케이스 삭제" onClose={onClose}>
      <p>
        이 케이스를 목록에서 제거합니다. 출력 폴더의 파일은 삭제되지 않으며, 같은 폴더를 불러오기로 다시 열 수
        있습니다.
      </p>
      {mutation.error && (
        <ErrorText>
          {mutation.error instanceof Error ? mutation.error.message : "삭제하지 못했습니다."}
        </ErrorText>
      )}
      <div className="case-actions">
        <button type="button" className="button" onClick={onClose}>
          취소
        </button>
        <button type="button" className="button primary" onClick={() => mutation.mutate()}>
          삭제
        </button>
      </div>
    </Modal>
  );
}
