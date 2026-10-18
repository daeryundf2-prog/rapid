/**
 * "처리 그룹" checklist of the quick-run dialog and the case wizard step 3 (R4 V1 U-P2-3): the
 * groups `GET /api/run-plan/preview` plans for the chosen mode / options, checked by the mode
 * defaults (`default_on`). Required groups (준비 · 지문 · 보고서) stay checked and disabled with the
 * reason. Option-gated groups (추출(선택), 카빙(선택)) only run when their run option is on: while
 * it is off they show unchecked and disabled with the reason and never count as running. Unchecked
 * skippable groups go out as `skip_groups`; changing the mode re-applies the defaults, and so does a
 * group whose `default_on` changed between previews (turning 파일 추출 on); other option changes keep
 * the examiner's choice.
 */

import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef } from "react";
import { type PreviewGroup, previewRunPlan, type RunPlanPreview } from "../../api/runPlan";
import type { RunForm } from "./runForm";

export const REQUIRED_GROUP_REASON = "필수 그룹 — 건너뛸 수 없습니다";
export const EXTRACT_GATED_REASON = "고급 옵션의 '파일 추출'을 켜면 실행됩니다";
export const CARVE_GATED_REASON = "카빙은 이 실행에서 켤 수 없습니다 · 처리 단계의 추가 분석에서 실행하세요";

/** Run form options that gate a group: off → the server never runs it, whatever the checklist says. */
type GateForm = Pick<RunForm, "extract">;

/**
 * Why an option-gated group cannot run with these options (undefined = it can). The run form has
 * no carve option (carving is an analysis job), so the run is planned with `carve=false`.
 */
export function gatedGroupReason(groupId: string, form: GateForm): string | undefined {
  if (groupId === "extract") return form.extract ? undefined : EXTRACT_GATED_REASON;
  if (groupId === "carve") return CARVE_GATED_REASON;
  return undefined;
}

/** Skippable groups the mode does not run by default (the initial `skip_groups`), gated-off ones left out. */
export function defaultSkipGroups(preview: RunPlanPreview, form: GateForm = { extract: true }): string[] {
  return preview.groups
    .filter((group) => group.skippable && !group.default_on && !gatedGroupReason(group.id, form))
    .map((group) => group.id);
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
        // No carve option on the run form (see gatedGroupReason): the run plans carve off.
        carve: false,
        ...(form.inputKind ? { input_kind: form.inputKind } : {}),
      }),
    retry: false,
    staleTime: 60_000,
  });
  const data = preview.data;
  const appliedMode = useRef<string | null>(null);
  /** `default_on` per group of the last applied preview: a change re-applies that group's default. */
  const appliedDefaults = useRef(new Map<string, boolean>());
  const skipRef = useRef(form.skipGroups);
  skipRef.current = form.skipGroups;
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const extract = form.extract;

  useEffect(() => {
    if (!data) return;
    const gate = { extract };
    const defaults = new Map(data.groups.map((group) => [group.id, group.default_on]));
    const previous = appliedDefaults.current;
    appliedDefaults.current = defaults;
    if (appliedMode.current !== data.mode) {
      // A new mode (or the first preview): its defaults replace any earlier choice.
      appliedMode.current = data.mode;
      onChangeRef.current(defaultSkipGroups(data, gate));
      return;
    }
    // Same mode, other options: keep the choice for groups that still exist, are skippable and
    // can run; a group whose default flipped (추출 켬 → default_on) takes its new default.
    const next: string[] = [];
    for (const group of data.groups) {
      if (!group.skippable || gatedGroupReason(group.id, gate)) continue;
      const before = previous.get(group.id);
      const skip =
        before !== undefined && before !== group.default_on
          ? !group.default_on
          : skipRef.current.includes(group.id);
      if (skip) next.push(group.id);
    }
    const current = skipRef.current;
    const same = next.length === current.length && next.every((value) => current.includes(value));
    if (!same) onChangeRef.current(next);
  }, [data, extract]);

  const groups = data?.groups ?? [];
  const skipped = new Set(form.skipGroups);
  const choosable = groups.filter((group) => group.skippable && !gatedGroupReason(group.id, form));
  const runs = (group: PreviewGroup) =>
    !gatedGroupReason(group.id, form) && (!group.skippable || !skipped.has(group.id));
  const running = groups.filter(runs).length;
  const id = (name: string) => `${idPrefix}-plan-${name}`;
  const toggle = (group: PreviewGroup, checked: boolean) => {
    // A required group is never skipped (the server refuses "건너뛸 수 없는 그룹입니다"); a gated
    // group follows its run option, not the checklist.
    if (!group.skippable || gatedGroupReason(group.id, form)) return;
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
              disabled={choosable.length === 0}
              onClick={() => onChange([])}
            >
              전부 선택
            </button>
            <button
              type="button"
              className="button"
              disabled={choosable.length === 0}
              onClick={() => onChange(choosable.map((group) => group.id))}
            >
              전부 해제
            </button>
          </div>
          <ul className="run-plan-groups-list">
            {groups.map((group) => {
              const required = !group.skippable;
              const gated = gatedGroupReason(group.id, form);
              const checked = runs(group);
              const tasks = group.tasks?.length ?? 0;
              const gatedId = id(`${group.id}-gated`);
              return (
                <li key={group.id}>
                  <label htmlFor={id(group.id)}>
                    <input
                      id={id(group.id)}
                      type="checkbox"
                      checked={checked}
                      disabled={required || Boolean(gated)}
                      aria-describedby={required ? reasonId : gated ? gatedId : undefined}
                      data-group={group.id}
                      onChange={(event) => toggle(group, event.target.checked)}
                    />{" "}
                    {group.label}
                    {tasks > 1 ? <span className="case-reason"> (태스크 {tasks})</span> : null}
                    {required ? <span className="case-reason"> · 필수</span> : null}
                  </label>
                  {gated ? (
                    <span id={gatedId} className="case-reason" data-testid={`run-plan-gated-${group.id}`}>
                      {` · ${gated}`}
                    </span>
                  ) : null}
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
