import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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

export function CasePicker({ currentRunId, onClose }: { currentRunId: string | null; onClose: () => void }) {
  const runs = useQuery({ queryKey: ["runs", "picker"], queryFn: listRuns, retry: false });
  const confirmDelete = useCaseDialogs((s) => s.confirmDelete);

  return (
    <Modal title="케이스" onClose={onClose}>
      {runs.isPending && <p aria-busy="true">케이스 목록을 불러오는 중…</p>}
      {runs.isError && <ErrorText>케이스 목록을 불러오지 못했습니다.</ErrorText>}
      {runs.data && runs.data.length === 0 && (
        <p>열린 케이스가 없습니다. 상단의 실행 또는 불러오기로 시작하세요.</p>
      )}
      {runs.data && runs.data.length > 0 && (
        <ul className="case-check-list" aria-label="케이스 목록">
          {runs.data.map((run) => (
            <li key={run.run_id} className="case-actions" style={{ justifyContent: "space-between" }}>
              <button
                type="button"
                className="button"
                aria-current={run.run_id === currentRunId ? "true" : undefined}
                onClick={() => {
                  navigate({ runId: run.run_id, collection: "intake" });
                  onClose();
                }}
              >
                {runLabel(run)} · {STATUS_LABEL[run.status] ?? run.status}
              </button>
              <ReasonButton
                aria-label={`${runLabel(run)} 삭제`}
                reason={ACTIVE.has(run.status) ? "실행 중인 런은 먼저 취소해야 합니다" : undefined}
                onClick={() => confirmDelete(run.run_id)}
              >
                삭제
              </ReasonButton>
            </li>
          ))}
        </ul>
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
