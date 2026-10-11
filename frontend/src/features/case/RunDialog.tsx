import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../api/client";
import { createRun, getCollectProfiles, planCollect, runSampleCase } from "../../api/runs";
import { navigate } from "../tree/adapter";
import { BrowsePanel } from "./BrowsePanel";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";
import { ReasonButton } from "./ReasonButton";
import {
  buildRunBody,
  DEFAULT_RUN_FORM,
  firstRunFormError,
  INPUT_KINDS,
  RUN_MODES,
  type RunForm,
  validateRunForm,
} from "./runForm";

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
  const sample = useMutation({
    mutationFn: () => runSampleCase({}),
    onSuccess: (payload) => afterStart(payload.run.run_id, "샘플 케이스를 불러왔습니다."),
  });
  const plan = useMutation({
    mutationFn: () =>
      planCollect({
        root: form.root.trim(),
        profile: form.collectProfile,
        input_kind: form.inputKind || null,
      }),
    onSuccess: (payload) => setPlanText(JSON.stringify(payload, null, 2).slice(0, 1200)),
  });

  const submitError = start.error ? messageOf(start.error) : sample.error ? messageOf(sample.error) : "";
  const planReason = !form.root.trim()
    ? "증거 경로를 먼저 입력하세요."
    : !form.collectProfile
      ? "수집 프로필을 선택하세요."
      : undefined;

  return (
    <Modal title="실행" onClose={onClose} wide>
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

        <div className="case-field">
          <label htmlFor="run-mode">모드</label>
          <select id="run-mode" value={form.mode} onChange={(e) => set("mode", e.target.value)}>
            {RUN_MODES.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </div>
        <div className="case-field">
          <label htmlFor="run-input-kind">입력 종류</label>
          <select
            id="run-input-kind"
            value={form.inputKind}
            onChange={(e) => set("inputKind", e.target.value)}
          >
            {INPUT_KINDS.map((k) => (
              <option key={k.id} value={k.id}>
                {k.label}
              </option>
            ))}
          </select>
        </div>

        <label>
          <input
            type="checkbox"
            checked={form.readOnly}
            onChange={(e) => set("readOnly", e.target.checked)}
          />{" "}
          읽기 전용 (증거 폴더에 쓰지 않음)
        </label>

        <button
          type="button"
          className="button"
          aria-expanded={advanced}
          aria-controls="run-advanced"
          onClick={() => setAdvanced((v) => !v)}
        >
          고급 옵션 {advanced ? "접기" : "펼치기"}
        </button>
        {advanced && (
          <fieldset id="run-advanced" className="case-field">
            <legend>고급 옵션</legend>
            <label htmlFor="run-output-dir">출력 폴더 (비우면 자동)</label>
            <input
              id="run-output-dir"
              type="text"
              value={form.outputDir}
              onChange={(e) => set("outputDir", e.target.value)}
            />
            <label htmlFor="run-max-mb">최대 추출 크기 (MB, 0 = 제한 없음)</label>
            <input
              id="run-max-mb"
              type="number"
              min={0}
              value={form.maxExtractMb}
              onChange={(e) => set("maxExtractMb", e.target.value)}
            />
            {errors.maxExtractMb && <p className="case-error">{errors.maxExtractMb}</p>}
            <label htmlFor="run-max-files">최대 파일 수 (0 = 제한 없음)</label>
            <input
              id="run-max-files"
              type="number"
              min={0}
              value={form.maxFileCount}
              onChange={(e) => set("maxFileCount", e.target.value)}
            />
            {errors.maxFileCount && <p className="case-error">{errors.maxFileCount}</p>}
            <label htmlFor="run-partition">E01 파티션 시작 섹터 (비우면 자동)</label>
            <input
              id="run-partition"
              type="number"
              min={0}
              value={form.partitionSector}
              onChange={(e) => set("partitionSector", e.target.value)}
            />
            {errors.partitionSector && <p className="case-error">{errors.partitionSector}</p>}
            <label htmlFor="run-feeds">known-good 해시 목록 경로 (한 줄에 하나)</label>
            <textarea
              id="run-feeds"
              rows={2}
              value={form.knownGoodFeeds}
              onChange={(e) => set("knownGoodFeeds", e.target.value)}
            />
            <label>
              <input
                type="checkbox"
                checked={form.hideKnownGood}
                onChange={(e) => set("hideKnownGood", e.target.checked)}
              />{" "}
              known-good 항목 숨기기
            </label>
            {errors.hideKnownGood && <p className="case-error">{errors.hideKnownGood}</p>}
            <label>
              <input
                type="checkbox"
                checked={form.dryRun}
                onChange={(e) => set("dryRun", e.target.checked)}
              />{" "}
              모의 실행 (결과를 쓰지 않음)
            </label>
            <label>
              <input
                type="checkbox"
                checked={form.overwrite}
                onChange={(e) => set("overwrite", e.target.checked)}
              />{" "}
              기존 출력 덮어쓰기
            </label>
            <label>
              <input
                type="checkbox"
                checked={form.extract}
                onChange={(e) => set("extract", e.target.checked)}
              />{" "}
              파일 추출
            </label>
            {errors.extract && <p className="case-error">{errors.extract}</p>}

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
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
              <ReasonButton reason={planReason} onClick={() => plan.mutate()}>
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
          </fieldset>
        )}

        {submitError && <ErrorText>{submitError}</ErrorText>}
        <div className="case-actions">
          <ReasonButton
            reason={runIsActive ? "실행 중 런이 있습니다" : undefined}
            onClick={() => sample.mutate()}
          >
            샘플 실행
          </ReasonButton>
          <button type="button" className="button" onClick={onClose}>
            취소
          </button>
          <ReasonButton className="button primary" type="submit" reason={submitReason}>
            실행
          </ReasonButton>
        </div>
      </form>
    </Modal>
  );
}
