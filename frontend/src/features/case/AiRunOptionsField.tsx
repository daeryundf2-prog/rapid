/**
 * AI 사용 기록 run options (R7 단계 3.5 갈래 D, plan §3.2/§3.5; r8 T-191): the collector options of
 * kind `ai-agent` (run plan group `ai`) — 메시지 본문 포함(마스킹, 기본 켬) and the three inputs
 * 조직 이메일 도메인 · 사건 증거 폴더 · AI 읽기 예산. Shown while the plan has the `ai` group;
 * disabled with the reason while that group is unchecked. Sent as `collector_options["ai-agent"]`
 * only for the keys that differ from the defaults (runForm.ts). The domain is checked by the
 * server (its error sentence is shown on start); the large-DB hash option is hidden until it is
 * read (T-320).
 */

import { useQuery } from "@tanstack/react-query";
import { useId } from "react";
import { previewRunPlan } from "../../api/runPlan";
import { runPlanPreviewKey } from "./RunPlanGroupsField";
import { type AiOptionFields, aiReadMbError, type RunForm } from "./runForm";

/** Run plan group of the AI usage collector (core/run/plan.py). */
export const AI_PLAN_GROUP = "ai";
export const AI_GROUP_SKIPPED_REASON = "처리 그룹에서 'AI 사용 기록'을 켜면 적용됩니다";

export function AiRunOptionsField({
  form,
  onChange,
  idPrefix = "run",
}: {
  form: RunForm;
  onChange: (patch: Partial<Pick<RunForm, AiOptionFields>>) => void;
  idPrefix?: string;
}) {
  const reasonId = useId();
  // Same query (and cache entry) as the 처리 그룹 checklist.
  const preview = useQuery({
    queryKey: runPlanPreviewKey(form),
    queryFn: () =>
      previewRunPlan({
        mode: form.mode,
        extract: form.extract,
        carve: false,
        ...(form.inputKind ? { input_kind: form.inputKind } : {}),
      }),
    retry: false,
    staleTime: 60_000,
  });
  const group = preview.data?.groups.find((item) => item.id === AI_PLAN_GROUP);
  if (!group) return null;
  const skipped = form.skipGroups.includes(AI_PLAN_GROUP);
  const id = (name: string) => `${idPrefix}-ai-${name}`;
  const describedBy = skipped ? reasonId : undefined;
  const readMbError = aiReadMbError(form.aiReadMb);
  return (
    <fieldset className="case-field run-ai-options" data-testid="run-ai-options">
      <legend>AI 사용 기록 수집 범위</legend>
      <label htmlFor={id("bodies")}>
        <input
          id={id("bodies")}
          type="checkbox"
          checked={form.aiBodies}
          disabled={skipped}
          aria-describedby={describedBy}
          onChange={(event) => onChange({ aiBodies: event.target.checked })}
        />{" "}
        메시지 본문 포함 (비밀값·API 키는 가림)
      </label>
      <label htmlFor={id("domain")}>조직 이메일 도메인 (선택)</label>
      <input
        id={id("domain")}
        type="text"
        value={form.aiOrgDomain}
        placeholder="예: example.com"
        disabled={skipped}
        aria-describedby={describedBy}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => onChange({ aiOrgDomain: event.target.value })}
      />
      <label htmlFor={id("roots")}>사건 증거 폴더 (선택, 한 줄에 하나)</label>
      <textarea
        id={id("roots")}
        rows={2}
        value={form.aiEvidenceRoots}
        placeholder="예: D:\사건\증거"
        disabled={skipped}
        aria-describedby={describedBy}
        spellCheck={false}
        onChange={(event) => onChange({ aiEvidenceRoots: event.target.value })}
      />
      <label htmlFor={id("read-mb")}>AI 읽기 예산 (MiB, 비우면 도구당 4 GiB)</label>
      <input
        id={id("read-mb")}
        type="text"
        inputMode="numeric"
        value={form.aiReadMb}
        placeholder="4096"
        disabled={skipped}
        aria-invalid={Boolean(readMbError)}
        aria-describedby={describedBy}
        onChange={(event) => onChange({ aiReadMb: event.target.value })}
      />
      {readMbError ? <p className="case-error">{readMbError}</p> : null}
      <p className="case-reason">
        본문을 끄면 메시지는 시각·역할·길이만 남습니다. 조직 도메인을 넣으면 그 밖의 계정을 개인 계정으로
        표시하고, 사건 증거 폴더를 넣으면 도구 호출이 그 폴더를 건드린 행을 표시합니다. 자격 증명 파일의 값은
        어느 경우에도 수집하지 않습니다.
      </p>
      {skipped ? (
        <p id={reasonId} className="case-reason" data-testid="run-ai-options-skipped">
          {AI_GROUP_SKIPPED_REASON}
        </p>
      ) : null}
    </fieldset>
  );
}
