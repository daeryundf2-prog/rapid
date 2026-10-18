/**
 * "처리 그룹" checklist of the quick-run dialog and the case wizard step 3 (R4 V1 U-P2-3): the
 * groups `GET /api/run-plan/preview` plans for the chosen mode / options, checked by the mode
 * defaults (`default_on`). Required groups (준비 · 지문 · 보고서) stay checked and disabled with the
 * reason. Unchecked skippable groups go out as `skip_groups`; changing the mode re-applies the
 * defaults, other option changes keep the examiner's choice.
 */

import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef } from "react";
import { type PreviewGroup, previewRunPlan, type RunPlanPreview } from "../../api/runPlan";
import type { RunForm } from "./runForm";

export const REQUIRED_GROUP_REASON = "필수 그룹 — 건너뛸 수 없습니다";

/** Skippable groups the mode does not run by default (the initial `skip_groups`). */
export function defaultSkipGroups(preview: RunPlanPreview): string[] {
  return preview.groups.filter((group) => group.skippable && !group.default_on).map((group) => group.id);
}

export const runPlanPreviewKey = (form: Pick<RunForm, "mode" | "extract" | "inputKind">) =>
  ["run-plan-preview", form.mode, form.extract, form.inputKind] as const;

export function RunPlanGroupsField({
  form,
  onChange,
  idPrefix = "run",
}: {
  form: RunForm;
  onChange: (skipGroups: string[]) => void;
  idPrefix?: string;
}) {
  const reasonId = useId();
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
  const data = preview.data;
  const appliedMode = useRef<string | null>(null);
  const skipRef = useRef(form.skipGroups);
  skipRef.current = form.skipGroups;
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  useEffect(() => {
    if (!data) return;
    if (appliedMode.current !== data.mode) {
      // A new mode (or the first preview): its defaults replace any earlier choice.
      appliedMode.current = data.mode;
      onChangeRef.current(defaultSkipGroups(data));
      return;
    }
    // Same mode, other options: keep the choice for groups that still exist and are skippable.
    const skippable = new Set(data.groups.filter((group) => group.skippable).map((group) => group.id));
    const kept = skipRef.current.filter((id) => skippable.has(id));
    if (kept.length !== skipRef.current.length) onChangeRef.current(kept);
  }, [data]);

  const groups = data?.groups ?? [];
  const skipped = new Set(form.skipGroups);
  const skippable = groups.filter((group) => group.skippable);
  const running = groups.filter((group) => !group.skippable || !skipped.has(group.id)).length;
  const id = (name: string) => `${idPrefix}-plan-${name}`;
  const toggle = (group: PreviewGroup, checked: boolean) => {
    // A required group is never skipped (the server refuses "건너뛸 수 없는 그룹입니다").
    if (!group.skippable) return;
    const next = form.skipGroups.filter((value) => value !== group.id);
    onChange(checked ? next : [...next, group.id]);
  };

  return (
    <fieldset className="case-field run-plan-groups" data-testid="run-plan-groups">
      <legend>처리 그룹</legend>
      {preview.isPending ? <p className="case-reason">처리 그룹을 불러오는 중…</p> : null}
      {preview.isError ? (
        <p className="case-reason" data-testid="run-plan-groups-error">
          처리 그룹 목록을 불러오지 못했습니다 — 모드 기본값으로 실행합니다.
        </p>
      ) : null}
      {groups.length ? (
        <>
          <div className="case-actions run-plan-groups-actions">
            <span className="case-reason" data-testid="run-plan-groups-count">
              {`${groups.length}개 그룹 중 ${running}개 실행`}
            </span>
            <button
              type="button"
              className="button"
              disabled={skippable.length === 0}
              onClick={() => onChange([])}
            >
              전부 선택
            </button>
            <button
              type="button"
              className="button"
              disabled={skippable.length === 0}
              onClick={() => onChange(skippable.map((group) => group.id))}
            >
              전부 해제
            </button>
          </div>
          <ul className="run-plan-groups-list">
            {groups.map((group) => {
              const required = !group.skippable;
              const checked = required || !skipped.has(group.id);
              const tasks = group.tasks?.length ?? 0;
              return (
                <li key={group.id}>
                  <label htmlFor={id(group.id)}>
                    <input
                      id={id(group.id)}
                      type="checkbox"
                      checked={checked}
                      disabled={required}
                      aria-describedby={required ? reasonId : undefined}
                      data-group={group.id}
                      onChange={(event) => toggle(group, event.target.checked)}
                    />{" "}
                    {group.label}
                    {tasks > 1 ? <span className="case-reason"> (태스크 {tasks})</span> : null}
                    {required ? <span className="case-reason"> · 필수</span> : null}
                  </label>
                </li>
              );
            })}
          </ul>
          {groups.some((group) => !group.skippable) ? (
            <p id={reasonId} className="case-reason">
              {REQUIRED_GROUP_REASON}
            </p>
          ) : null}
        </>
      ) : null}
    </fieldset>
  );
}
