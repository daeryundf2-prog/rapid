import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { importRun } from "../../api/runs";
import { navigate } from "../tree/adapter";
import { BrowsePanel } from "./BrowsePanel";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";

export function ImportDialog({
  runIsActive,
  onClose,
  onNotice,
}: {
  runIsActive: boolean;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const [outputDir, setOutputDir] = useState("");
  const [browsing, setBrowsing] = useState(false);

  const mutation = useMutation({
    mutationFn: () => importRun(outputDir.trim()),
    onSuccess: (job) => {
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      onNotice?.("완료된 런을 불러왔습니다.");
      navigate({ runId: job.run_id, collection: "intake" });
      onClose();
    },
  });

  const reason = runIsActive
    ? "실행 중 런이 있습니다"
    : !outputDir.trim()
      ? "불러올 런 출력 폴더를 입력하세요."
      : undefined;

  return (
    <Modal title="불러오기" onClose={onClose} wide>
      <form
        className="case-modal-body"
        style={{ padding: 0 }}
        onSubmit={(event) => {
          event.preventDefault();
          if (!reason) mutation.mutate();
        }}
      >
        <div className="case-field">
          <label htmlFor="import-dir">완료된 런의 출력 폴더</label>
          <div className="case-actions" style={{ justifyContent: "stretch" }}>
            <input
              id="import-dir"
              type="text"
              style={{ flex: 1 }}
              value={outputDir}
              onChange={(e) => setOutputDir(e.target.value)}
            />
            <button type="button" className="button" onClick={() => setBrowsing((v) => !v)}>
              찾아보기
            </button>
          </div>
        </div>
        {browsing && (
          <BrowsePanel
            directoriesOnly
            initialPath={outputDir}
            onPick={(path) => {
              setOutputDir(path);
              setBrowsing(false);
            }}
          />
        )}
        {mutation.error && (
          <ErrorText>
            {mutation.error instanceof Error ? mutation.error.message : "불러오지 못했습니다."}
          </ErrorText>
        )}
        <div className="case-actions">
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton className="button primary" type="submit" reason={reason}>
            불러오기
          </ReasonButton>
        </div>
      </form>
    </Modal>
  );
}
