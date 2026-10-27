/**
 * AI 사용 기록 run options (R7 단계 3.5 갈래 D, plan §3.2/§3.5): the collector options of kind
 * `ai-agent` (run plan group `ai`) — 메시지 본문 포함(마스킹, 기본 켬) and 대형 AI DB 해시(기본 끔).
 * Shown while the plan has the `ai` group; disabled with the reason while that group is unchecked.
 * Sent as `collector_options["ai-agent"]` only when they differ from the defaults (runForm.ts).
 */

import { useQuery } from "@tanstack/react-query";
import { useId } from "react";
import { previewRunPlan } from "../../api/runPlan";
import { runPlanPreviewKey } from "./RunPlanGroupsField";
import type { RunForm } from "./runForm";

/** Run plan group of the AI usage collector (core/run/plan.py). */
export const AI_PLAN_GROUP = "ai";
export const AI_GROUP_SKIPPED_REASON = "처리 그룹에서 'AI 사용 기록'을 켜면 적용됩니다";

export function AiRunOptionsField({
  form,
  onChange,
  idPrefix = "run",
}: {
  form: RunForm;
  onChange: (patch: Partial<Pick<RunForm, "aiBodies" | "aiHashDbs">>) => void;
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
  return (
    <fieldset className="case-field run-ai-options" data-testid="run-ai-options">
      <legend>AI 사용 기록 수집 범위</legend>
      <label htmlFor={id("bodies")}>
        <input
          id={id("bodies")}
          type="checkbox"
          checked={form.aiBodies}
          disabled={skipped}
          aria-describedby={skipped ? reasonId : undefined}
          onChange={(event) => onChange({ aiBodies: event.target.checked })}
        />{" "}
        메시지 본문 포함 (비밀값·API 키는 가림)
      </label>
      <label htmlFor={id("hash")}>
        <input
          id={id("hash")}
          type="checkbox"
          checked={form.aiHashDbs}
          disabled={skipped}
          aria-describedby={skipped ? reasonId : undefined}
          onChange={(event) => onChange({ aiHashDbs: event.target.checked })}
        />{" "}
        대형 AI 데이터베이스 해시 계산 (느림 · 복사하지 않음)
      </label>
      <p className="case-reason">
        본문을 끄면 메시지는 시각·역할·길이만 남습니다. 자격 증명 파일의 값은 어느 경우에도 수집하지 않습니다.
      </p>
      {skipped ? (
        <p id={reasonId} className="case-reason" data-testid="run-ai-options-skipped">
          {AI_GROUP_SKIPPED_REASON}
        </p>
      ) : null}
    </fieldset>
  );
}
