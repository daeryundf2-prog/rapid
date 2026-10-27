import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../api/client";
import { createRun, getCollectProfiles, planCollect } from "../../api/runs";
import { useAppStore } from "../../state/store";
import { navigate } from "../tree/adapter";
import { AiRunOptionsField } from "./AiRunOptionsField";
import { BrowsePanel } from "./BrowsePanel";
import { runSampleWithConfirm } from "./commands";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import { RunOptionsFields } from "./RunOptionsFields";
import { RunPlanGroupsField } from "./RunPlanGroupsField";
import { buildRunBody, DEFAULT_RUN_FORM, firstRunFormError, type RunForm, validateRunForm } from "./runForm";

/** Korean names of the collection-plan profiles (core/collect_plan.PROFILE_TARGETS); the id stays the value. */
export const COLLECT_PROFILE_LABEL: Record<string, string> = {
  "windows-core": "Windows 기본",
  "macos-core": "macOS 기본",
  intrusion: "침해사고 (실행·지속성·원격 접속·계정)",
  "browser-history": "브라우저 기록·클라우드 동기화",
  "filesystem-timeline": "파일 시스템 타임라인",
  full: "전체",
};

export function collectProfileLabel(id: string): string {
  return COLLECT_PROFILE_LABEL[id] ?? id;
}

function messageOf(error: unknown): string {
  return error instanceof ApiError || error instanceof Error ? error.message : "알 수 없는 오류";
}

export function RunDialog({
  runIsActive,
  onClose,
  onNotice,
}: {
  runIsActive: boolean;
  onClose: () => void;
  onNotice?: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<RunForm>(DEFAULT_RUN_FORM);
  const [browsing, setBrowsing] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [planText, setPlanText] = useState("");
  const set = <K extends keyof RunForm>(key: K, value: RunForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const errors = validateRunForm(form);
  const invalidReason = firstRunFormError(errors);
  const submitReason = runIsActive ? "실행 중 런이 있습니다" : invalidReason;

  const profiles = useQuery({
    queryKey: ["collect-profiles"],
    queryFn: getCollectProfiles,
    enabled: advanced,
    retry: false,
  });

  const afterStart = (runId: string, message: string) => {
    void queryClient.invalidateQueries({ queryKey: ["runs"] });
    onNotice?.(message);
    navigate({ runId, collection: "intake" });
    onClose();
  };

  const start = useMutation({
    mutationFn: () => createRun(buildRunBody(form)),
    onSuccess: (job) => afterStart(job.run_id, "런을 시작했습니다."),
  });
  // 샘플 실행 (C-G6): a write confirmation first; the shared helper toasts the result and opens it.
  const sample = useMutation({
    mutationFn: () => runSampleWithConfirm(),
    onSuccess: (runId) => {
      if (!runId) return;
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      onClose();
    },
  });
  // With a run open this dialog starts a SEPARATE run (C-G9): its title says so.
  const caseOpen = useAppStore((s) => Boolean(s.route.runId));
  const plan = useMutation({
    mutationFn: () =>
      planCollect({
        root: form.root.trim(),
        profile: form.collectProfile,
        input_kind: form.inputKind || null,
      }),
    onSuccess: (payload) => setPlanText(JSON.stringify(payload, null, 2).slice(0, 1200)),
  });

  const submitError = start.error ? messageOf(start.error) : "";
  const planReason = !form.root.trim()
    ? "증거 경로를 먼저 입력하세요."
    : !form.collectProfile
      ? "수집 프로필을 선택하세요."
      : undefined;

  return (
    <Modal
      title={caseOpen ? "새 런 (케이스 없이, 열린 런과 별도)" : "케이스 없이 빠른 런"}
      onClose={onClose}
      wide
    >
      <form
        className="case-modal-body"
        style={{ padding: 0 }}
        onSubmit={(event) => {
          event.preventDefault();
          if (!submitReason) start.mutate();
        }}
      >
        <div className="case-field">
          <label htmlFor="run-root">증거 경로 (E01 / 폴더)</label>
          <div className="case-actions" style={{ justifyContent: "stretch" }}>
            <input
              id="run-root"
              type="text"
              style={{ flex: 1 }}
              value={form.root}
              aria-invalid={Boolean(errors.root)}
              onChange={(e) => set("root", e.target.value)}
            />
            <button type="button" className="button" onClick={() => setBrowsing((v) => !v)}>
              찾아보기
            </button>
          </div>
          {errors.root && form.root !== "" && <p className="case-error">{errors.root}</p>}
        </div>
        {browsing && (
          <BrowsePanel
            initialPath={form.root}
            onPick={(path) => {
              set("root", path);
              setBrowsing(false);
            }}
          />
        )}

        <RunOptionsFields
          form={form}
          errors={errors}
          onChange={set}
          advanced={advanced}
          onAdvancedChange={setAdvanced}
          extra={
            <>
              <label htmlFor="run-collect-profile">수집 프로필 (계획 미리보기 전용)</label>
              <div className="case-actions" style={{ justifyContent: "stretch" }}>
                <select
                  id="run-collect-profile"
                  style={{ flex: 1 }}
                  value={form.collectProfile}
                  onChange={(e) => set("collectProfile", e.target.value)}
                >
                  <option value="">선택 안 함</option>
                  {(profiles.data?.profiles ?? []).map((p) => (
                    <option key={p} value={p} title={p}>
                      {collectProfileLabel(p)}
                    </option>
                  ))}
                </select>
                <ReasonButton reason={planReason} quietReason onClick={() => plan.mutate()}>
                  수집 계획 보기
                </ReasonButton>
              </div>
              {plan.error && <p className="case-error">{messageOf(plan.error)}</p>}
              {planText && (
                <>
                  <p className="case-reason">수집 계획</p>
                  <pre>{planText}</pre>
                </>
              )}
            </>
          }
        />

        <RunPlanGroupsField form={form} onChange={(skipGroups) => set("skipGroups", skipGroups)} />
        <AiRunOptionsField form={form} onChange={(patch) => setForm((f) => ({ ...f, ...patch }))} />

        {submitError && <ErrorText>{submitError}</ErrorText>}
        <div className="case-actions">
          <ReasonButton
            reason={
              runIsActive ? "실행 중 런이 있습니다" : sample.isPending ? "샘플을 만드는 중입니다" : undefined
            }
            onClick={() => sample.mutate()}
            aria-busy={sample.isPending || undefined}
          >
            {sample.isPending ? "샘플 실행 중…" : "샘플 실행…"}
          </ReasonButton>
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton className="button primary" type="submit" reason={submitReason} quietReason>
            실행
          </ReasonButton>
        </div>
      </form>
    </Modal>
  );
}
