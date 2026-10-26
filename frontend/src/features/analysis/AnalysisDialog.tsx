/**
 * Run dialog of one analysis kind (plan analysis-workbench-p1 §4): kind-specific form
 * (numbers, toggles, server path picker, snapshot dropdown from discover results, case
 * checkboxes), every field labelled with help text and an inline validation message, the
 * expected scope / caution note, and a submit that says why it cannot run yet.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useMemo, useState } from "react";
import { announce } from "../../a11y";
import { type AnalysisKind, fetchAnalysisRowsPage, startAnalysis } from "../../api/analyses";
import { ApiError } from "../../api/client";
import { runStartedAt } from "../../api/runs";
import { runDisplayName } from "../../app/collections";
import { Icon } from "../../icons";
import { useRuns } from "../../state/hooks";
import { useAppStore } from "../../state/store";
import { formatRunTime } from "../../utils/time";
import { BrowsePanel } from "../case/BrowsePanel";
import { ErrorText } from "../case/ErrorText";
import { Modal } from "../case/Modal";
import { ReasonButton } from "../case/ReasonButton";
import { currentTimezone } from "../grid/columns/common";
import {
  ANALYSIS_FIELDS,
  type AnalysisFormState,
  buildAnalysisOptions,
  defaultForm,
  type FieldSpec,
  type FormValue,
  firstAnalysisError,
  formLocators,
  validateAnalysisForm,
} from "./analysisForm";
import { openAnalysis, runDisabledReason } from "./commands";
import { KIND_CAUTION, kindLabel, nodeOfKind } from "./kinds";
import { analysesFor, analysesQueryKey, useAnalyses } from "./store";
import "./analysis.css";

/** A run in the cross-case list (L1 handoff): its name and start time, never the raw run ID. */
function runChoiceLabel(
  run: Parameters<typeof runDisplayName>[0] & Parameters<typeof runStartedAt>[0],
): string {
  const started = runStartedAt(run);
  return started
    ? `${runDisplayName(run)} · ${formatRunTime(started, currentTimezone())}`
    : runDisplayName(run);
}

/** 422 `[{loc: ["options", field], msg}]` → per-field Korean messages (shown under the field). */
export function serverFieldErrors(error: unknown): Record<string, string> {
  if (!(error instanceof ApiError) || error.status !== 422 || !Array.isArray(error.detail)) return {};
  const out: Record<string, string> = {};
  for (const item of error.detail as Array<{ loc?: unknown; msg?: unknown }>) {
    const loc = Array.isArray(item.loc) ? item.loc : [];
    const field = loc[0] === "options" ? loc[1] : loc[loc.length - 1];
    if (typeof field === "string" && typeof item.msg === "string" && !out[field]) out[field] = item.msg;
  }
  return out;
}

/** Folder of a typed file path (the browser lists folders; a file path would 400). */
function parentDir(path: string): string {
  const trimmed = path.trim().replace(/[\\/]+$/, "");
  const cut = Math.max(trimmed.lastIndexOf("\\"), trimmed.lastIndexOf("/"));
  return cut > 0 ? trimmed.slice(0, cut) : trimmed;
}

/** Runs another case can be compared with: completed and (when the server says) with a case DB. */
export function crossCaseChoice(run: {
  run_id: string;
  status?: unknown;
  case_db_available?: unknown;
  case_db?: unknown;
  cross_case_eligible?: unknown;
  cross_case_ineligible_reason?: unknown;
}): { eligible: boolean; reason?: string } {
  // The server's verdict (GET /api/runs `cross_case_eligible` + Korean reason) wins.
  if (run.cross_case_eligible === true) return { eligible: true };
  if (run.cross_case_eligible === false) {
    const reason =
      typeof run.cross_case_ineligible_reason === "string" && run.cross_case_ineligible_reason
        ? run.cross_case_ineligible_reason
        : "교차 케이스 비교에 쓸 수 없는 런입니다";
    return { eligible: false, reason };
  }
  // Older servers: completed runs only, and not when the case DB is known to be missing.
  if (run.status !== "completed") {
    const label =
      run.status === "failed"
        ? "실패한 런"
        : run.status === "running" || run.status === "queued"
          ? "아직 처리 중인 런"
          : "완료되지 않은 런";
    return { eligible: false, reason: `${label}이라 비교할 수 없습니다` };
  }
  const nested =
    run.case_db && typeof run.case_db === "object"
      ? (run.case_db as Record<string, unknown>).available
      : undefined;
  const available = typeof run.case_db_available === "boolean" ? run.case_db_available : nested;
  if (available === false) return { eligible: false, reason: "케이스 DB가 없어 비교할 수 없습니다" };
  return { eligible: true };
}

/** Server path labels (analysis_kinds.py resolve_*_path `label=`) → the form field they check. */
const PATH_LABEL_FIELDS: Array<[string, string]> = [
  ["추출 출력", "output_dir"],
  ["디스크 이미지", "image_path"],
  ["Volatility 출력 디렉터리", "volatility_output_dir"],
  ["스냅샷 루트", "snapshot_root"],
];

/** A 403 / 400 path refusal shown under the field it is about (plus the summary line). */
export function pathFieldErrors(error: unknown): Record<string, string> {
  if (!(error instanceof ApiError) || (error.status !== 403 && error.status !== 400)) return {};
  const message = error.message;
  for (const [label, field] of PATH_LABEL_FIELDS) {
    if (message.startsWith(label) || message.includes(`${label} 경로`)) return { [field]: message };
  }
  if (error.status === 400 && message.includes("image_path")) return { image_path: message };
  return {};
}

function messageOf(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 422) {
      const fields = Object.values(serverFieldErrors(error));
      return fields.length ? `입력값을 확인하세요: ${fields.join(" · ")}` : "입력값을 확인하세요";
    }
    if (error.status === 403) return `허용되지 않은 경로입니다: ${error.message}`;
    if (error.status === 409) return error.message || "지금은 실행할 수 없습니다";
    return error.message;
  }
  return error instanceof Error ? error.message : "알 수 없는 오류";
}

export const SNAPSHOTS_LOADING = "스냅샷 목록을 불러오는 중…";

/**
 * Snapshot roots found by the newest completed volume-shadow discovery of the run. Reactive
 * on the run's job list (it may still be loading when the dialog opens); `loading` covers
 * both the job list and the discover rows.
 */
function useSnapshotChoices(runId: string, enabled: boolean) {
  const jobs = useAnalyses(enabled ? runId : null);
  const discover = (jobs.analyses.length ? jobs.analyses : analysesFor(runId)).find(
    (job) => job.kind === "vsc-discover" && job.status === "completed",
  );
  const query = useQuery({
    queryKey: ["analysis-snapshots", runId, discover?.analysis_id ?? ""],
    queryFn: async ({ signal }) => {
      const page = await fetchAnalysisRowsPage(
        runId,
        discover?.analysis_id as string,
        { offset: 0, limit: 200, sort: { key: "details.score", order: "desc" } },
        signal,
      );
      const roots: Array<{ root: string; score: string }> = [];
      for (const row of page.rows) {
        const details = (row.details ?? {}) as Record<string, unknown>;
        const root = typeof details.snapshot_root === "string" ? details.snapshot_root : "";
        if (root && !roots.some((r) => r.root === root)) {
          roots.push({ root, score: details.score === undefined ? "" : String(details.score) });
        }
      }
      return roots;
    },
    enabled: enabled && Boolean(discover),
    retry: false,
  });
  const listLoading = enabled && jobs.loading && !discover;
  // A disabled query (kinds without a snapshot field) stays `isPending` forever: only an
  // enabled one is loading.
  return {
    discover,
    choices: query.data ?? [],
    loading: listLoading || (enabled && Boolean(discover) && query.isPending),
  };
}

interface FieldProps {
  field: FieldSpec;
  value: FormValue | undefined;
  error: string | undefined;
  showError: boolean;
  onChange: (value: FormValue) => void;
  onTouch: () => void;
  runId: string;
}

function Field({ field, value, error, showError, onChange, onTouch, runId }: FieldProps) {
  const id = useId();
  const helpId = `${id}-help`;
  const errorId = `${id}-error`;
  const visibleError = showError ? error : undefined;
  const describedBy = visibleError ? `${helpId} ${errorId}` : helpId;
  const [browsing, setBrowsing] = useState(false);
  const [showIneligible, setShowIneligible] = useState(false);
  const { runs } = useRuns();
  const snapshots = useSnapshotChoices(runId, field.type === "snapshot");
  const help = (
    <p id={helpId} className="analysis-help">
      {field.help}
    </p>
  );
  const errorLine = visibleError ? (
    <p id={errorId} className="case-error">
      {visibleError}
    </p>
  ) : null;

  if (field.type === "bool") {
    return (
      <div className="case-field analysis-field">
        {/* Explicit for/id (r7 L4, C-A1): the name never depends on label nesting. */}
        <label htmlFor={`${id}-check`}>
          <input
            id={`${id}-check`}
            type="checkbox"
            checked={value === true}
            aria-describedby={describedBy}
            onChange={(event) => onChange(event.target.checked)}
          />{" "}
          {field.label}
        </label>
        {help}
        {errorLine}
      </div>
    );
  }
  if (field.type === "multi" || field.type === "cases") {
    const list = Array.isArray(value) ? value : [];
    const choices: Array<{ id: string; label: string; reason?: string }> =
      field.type === "multi"
        ? field.choices
        : // The current run is always compared (the server adds it), so only other runs are offered;
          // failed / unfinished runs and runs without a case DB are listed disabled with the reason
          // (the server would 400 the whole request on them), after the eligible ones.
          runs
            .filter((run) => run.run_id !== runId)
            .map((run) => ({ run, choice: crossCaseChoice(run as Parameters<typeof crossCaseChoice>[0]) }))
            .sort((a, b) => Number(b.choice.eligible) - Number(a.choice.eligible))
            .map(({ run, choice }) => ({
              id: run.run_id,
              label: runChoiceLabel(run),
              ...(choice.eligible ? {} : { reason: choice.reason }),
            }));
    const toggle = (choice: string, on: boolean) => {
      onTouch();
      onChange(on ? [...list.filter((v) => v !== choice), choice] : list.filter((v) => v !== choice));
    };
    // Each choice is a checkbox named by its own label (C-A1: 카빙 서명 · OCR 언어 had none).
    const choiceId = (choice: (typeof choices)[number]) => `${id}-c-${choice.id.replace(/[^\w-]/g, "_")}`;
    const renderChoice = (choice: (typeof choices)[number]) => (
      <label
        key={choice.id}
        htmlFor={choiceId(choice)}
        className={choice.reason ? "is-unavailable" : undefined}
      >
        <input
          id={choiceId(choice)}
          type="checkbox"
          aria-label={choice.label}
          checked={list.includes(choice.id)}
          disabled={Boolean(choice.reason) && !list.includes(choice.id)}
          onChange={(event) => toggle(choice.id, event.target.checked)}
        />{" "}
        {choice.label}
        {choice.reason ? <span className="analysis-help"> — {choice.reason}</span> : null}
      </label>
    );
    // Cross-case: the eligible runs first; the (often many) ineligible ones fold away behind a
    // disclosure — a ticked one stays visible so it can be unticked.
    const folded = field.type === "cases";
    const open = folded ? choices.filter((c) => !c.reason || list.includes(c.id)) : choices;
    const hidden = folded ? choices.filter((c) => c.reason && !list.includes(c.id)) : [];
    const currentRun = field.type === "cases" ? runs.find((run) => run.run_id === runId) : undefined;
    const hiddenId = `${id}-ineligible`;
    return (
      <fieldset
        className="case-field analysis-field"
        aria-describedby={describedBy}
        aria-invalid={Boolean(visibleError)}
      >
        <legend>{field.label}</legend>
        {field.type === "cases" ? (
          <p className="analysis-help" data-testid="cross-case-current">
            <span className="badge info">현재 런</span>{" "}
            <strong title={`런 ID ${runId}`}>{currentRun ? runChoiceLabel(currentRun) : "이 런"}</strong> —
            항상 비교에 포함됩니다.
          </p>
        ) : null}
        <div className="analysis-choices">
          {open.length === 0 ? (
            <span className="analysis-help">
              {hidden.length ? "비교에 쓸 수 있는 다른 런이 없습니다." : "고를 항목이 없습니다."}
            </span>
          ) : null}
          {open.map(renderChoice)}
        </div>
        {hidden.length ? (
          <>
            <button
              type="button"
              className="button ghost"
              aria-expanded={showIneligible}
              aria-controls={hiddenId}
              onClick={() => setShowIneligible((v) => !v)}
            >
              {showIneligible
                ? `사용할 수 없는 런 ${hidden.length.toLocaleString("ko-KR")}개 숨기기`
                : `사용할 수 없는 런 ${hidden.length.toLocaleString("ko-KR")}개 보기`}
            </button>
            {showIneligible ? (
              <div className="analysis-choices" id={hiddenId} data-testid="cross-case-ineligible">
                {hidden.map(renderChoice)}
              </div>
            ) : null}
          </>
        ) : null}
        {help}
        {errorLine}
      </fieldset>
    );
  }
  if (field.type === "snapshot") {
    const text = typeof value === "string" ? value : "";
    const known = snapshots.choices.some((c) => c.root === text);
    return (
      <div className="case-field analysis-field">
        <label htmlFor={id}>{field.label}</label>
        <select
          id={id}
          value={text}
          aria-describedby={describedBy}
          aria-invalid={Boolean(visibleError)}
          aria-busy={snapshots.loading || undefined}
          onBlur={onTouch}
          onChange={(event) => {
            onTouch();
            onChange(event.target.value);
          }}
        >
          <option value="">{snapshots.loading ? SNAPSHOTS_LOADING : "스냅샷 선택"}</option>
          {text && !known ? <option value={text}>{text}</option> : null}
          {snapshots.choices.map((choice) => (
            <option key={choice.root} value={choice.root}>
              {choice.root}
              {choice.score ? ` (점수 ${choice.score})` : ""}
            </option>
          ))}
        </select>
        {snapshots.loading ? (
          <p className="analysis-help" data-testid="snapshot-loading">
            {SNAPSHOTS_LOADING}
          </p>
        ) : !snapshots.discover ? (
          <p className="analysis-help">완료된 볼륨 섀도우 탐색이 없습니다. 먼저 탐색을 실행하세요.</p>
        ) : null}
        {help}
        {errorLine}
      </div>
    );
  }
  if (field.type === "choice") {
    const current = typeof value === "string" ? value : "";
    return (
      <div className="case-field analysis-field">
        <label htmlFor={id}>{field.label}</label>
        <select
          id={id}
          value={current}
          aria-describedby={describedBy}
          aria-invalid={Boolean(visibleError)}
          onChange={(event) => {
            onTouch();
            onChange(event.target.value);
          }}
        >
          <option value="">{field.autoLabel}</option>
          {field.choices.map((choice) => (
            <option key={choice.id} value={choice.id}>
              {choice.label}
            </option>
          ))}
        </select>
        {help}
        {errorLine}
      </div>
    );
  }
  const text = typeof value === "string" ? value : "";
  if (field.type === "int") {
    // Numbers (review #4): a 120px field with its unit after it, not a full-width text box.
    return (
      <div className="case-field analysis-field">
        <label htmlFor={id}>{field.label}</label>
        <span className="analysis-number">
          <input
            id={id}
            type="text"
            inputMode="numeric"
            className="analysis-number-input"
            value={text}
            aria-describedby={describedBy}
            aria-invalid={Boolean(visibleError)}
            onBlur={onTouch}
            onChange={(event) => onChange(event.target.value)}
          />
          {field.unit ? (
            <span className="analysis-unit" aria-hidden="true">
              {field.unit}
            </span>
          ) : null}
        </span>
        {help}
        {errorLine}
      </div>
    );
  }
  return (
    <div className="case-field analysis-field">
      <label htmlFor={id}>{field.label}</label>
      <div className="analysis-input-row">
        <input
          id={id}
          type="text"
          style={{ flex: 1 }}
          value={text}
          placeholder={field.type === "text" ? field.placeholder : undefined}
          aria-describedby={describedBy}
          aria-invalid={Boolean(visibleError)}
          onBlur={onTouch}
          onChange={(event) => onChange(event.target.value)}
        />
        {field.type === "path" ? (
          <button
            type="button"
            className="button"
            aria-expanded={browsing}
            onClick={() => setBrowsing((open) => !open)}
          >
            찾아보기
          </button>
        ) : null}
      </div>
      {field.type === "path" && browsing ? (
        <BrowsePanel
          initialPath={field.pick === "file" ? parentDir(text) : text}
          directoriesOnly={field.pick !== "file"}
          filesOnly={field.pick === "file"}
          // Start at (and stay under) the run's allowed roots, not the server user's home.
          scope={{ name: field.roots === "output" ? "analysis-output" : "analysis-input", runId }}
          onPick={(path) => {
            onTouch();
            onChange(path);
            setBrowsing(false);
          }}
        />
      ) : null}
      {help}
      {errorLine}
    </div>
  );
}

export function AnalysisDialog({
  kind,
  runId,
  preset,
  onClose,
}: {
  kind: AnalysisKind;
  runId: string;
  preset?: Record<string, FormValue>;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<AnalysisFormState>(() => ({
    ...defaultForm(kind, { runId, locators: preset?.locators }),
    ...preset,
  }));
  const [touched, setTouched] = useState<Set<string>>(() => new Set(Object.keys(preset ?? {})));
  const [attempted, setAttempted] = useState(false);
  const errors = useMemo(() => validateAnalysisForm(kind, form, { runId }), [kind, form, runId]);
  const locatorCount = formLocators(form).length;
  const maxItems = Number(typeof form.max_items === "string" ? form.max_items.trim() : "");
  // Server-side validation (422) per field, cleared once that field changes.
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const blocked = runDisabledReason(kind, { runId });
  const hasSnapshot = ANALYSIS_FIELDS[kind].some((field) => field.type === "snapshot");
  const snapshots = useSnapshotChoices(runId, hasSnapshot);
  // While the job list / discover rows load, "탐색을 먼저 완료하세요" would be premature.
  const submitReason = snapshots.loading
    ? "스냅샷 목록을 불러오는 중입니다"
    : (blocked ?? firstAnalysisError(errors));
  const label = kindLabel(kind);
  const formId = useId();

  const start = useMutation({
    mutationFn: () => startAnalysis(runId, kind, buildAnalysisOptions(kind, form, { runId })),
    onSuccess: (created) => {
      announce(`${label} 분석을 요청했습니다`);
      void queryClient.invalidateQueries({ queryKey: analysesQueryKey(runId) });
      // From the 처리 stage the card shows progress; elsewhere open the results view.
      const store = useAppStore.getState();
      const node = nodeOfKind(kind)?.id ?? kind;
      if (store.route.collection === "process") store.navigate({ runId, collection: "process", kind: node });
      else openAnalysis(runId, kind, created.analysis_id);
      onClose();
    },
    onError: (error) => setServerErrors({ ...pathFieldErrors(error), ...serverFieldErrors(error) }),
  });

  return (
    <Modal
      title={`${label} 실행`}
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="button roomy" onClick={onClose}>
            취소
          </button>
          <ReasonButton
            className="button primary roomy"
            type="submit"
            form={formId}
            reason={start.isPending ? "요청을 보내는 중입니다" : submitReason}
            data-testid="analysis-submit"
            // A blocked submit still reveals every field's message (pointer and keyboard).
            onMouseDown={() => setAttempted(true)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") setAttempted(true);
            }}
          >
            {label} 실행
          </ReasonButton>
        </>
      }
    >
      <form
        id={formId}
        className="analysis-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          setAttempted(true);
          if (!submitReason && !start.isPending) start.mutate();
        }}
      >
        <div className="analysis-caution" data-testid="analysis-caution">
          <Icon name="alert" className="analysis-caution-icon" />
          <p>
            <strong>예상 범위·주의</strong> {KIND_CAUTION[kind]}
          </p>
        </div>
        {kind === "ocr-batch" ? (
          <p className="analysis-help" data-testid="analysis-target">
            대상:{" "}
            {locatorCount
              ? `선택한 이미지 ${locatorCount.toLocaleString("ko-KR")}장`
              : "런의 미디어 이미지 전체"}
          </p>
        ) : null}
        {kind === "ocr-batch" && errors.locators ? (
          <p className="case-error" role="alert" data-testid="analysis-target-warning">
            {errors.locators}
          </p>
        ) : kind === "ocr-batch" && locatorCount && maxItems > 0 && maxItems < locatorCount ? (
          <p className="analysis-help" data-testid="analysis-target-warning">
            최대 이미지 수가 선택보다 적어 앞의 {maxItems.toLocaleString("ko-KR")}장만 처리합니다.
          </p>
        ) : null}
        {ANALYSIS_FIELDS[kind].map((field) => (
          <Field
            key={field.key}
            field={field}
            runId={runId}
            value={form[field.key]}
            error={serverErrors[field.key] ?? errors[field.key]}
            showError={Boolean(serverErrors[field.key]) || attempted || touched.has(field.key)}
            onTouch={() => setTouched((prev) => (prev.has(field.key) ? prev : new Set([...prev, field.key])))}
            onChange={(value) => {
              setForm((prev) => ({ ...prev, [field.key]: value }));
              if (serverErrors[field.key]) setServerErrors(({ [field.key]: _gone, ...rest }) => rest);
            }}
          />
        ))}
        {start.error ? <ErrorText>{messageOf(start.error)}</ErrorText> : null}
      </form>
    </Modal>
  );
}
