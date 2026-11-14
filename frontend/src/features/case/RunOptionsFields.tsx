/**
 * Run options shared by the quick-run dialog and the case wizard / "런 추가" (AXIOM adoption E1):
 * mode, input kind, read-only and the advanced fieldset. `extra` is appended inside the
 * advanced fieldset (the quick-run dialog's collect-plan preview).
 */

import type { ReactNode } from "react";
import { INPUT_KINDS, type OutputFieldSpec, RUN_MODES, type RunForm, type RunFormErrors } from "./runForm";

export function RunOptionsFields({
  form,
  errors,
  onChange,
  advanced,
  onAdvancedChange,
  idPrefix = "run",
  extra,
  output,
  outputError,
}: {
  form: RunForm;
  errors: RunFormErrors;
  onChange: <K extends keyof RunForm>(key: K, value: RunForm[K]) => void;
  advanced: boolean;
  onAdvancedChange: (open: boolean) => void;
  idPrefix?: string;
  extra?: ReactNode;
  /** How 출력 폴더 reads; a required one is shown outside 고급 옵션 (E01 QA D4). */
  output?: OutputFieldSpec;
  /** Inline problem of the 출력 폴더 value (R7: never inside / around the evidence). */
  outputError?: string;
}) {
  const id = (name: string) => `${idPrefix}-${name}`;
  const outputField = (
    <>
      <label htmlFor={id("output-dir")}>
        {output?.label ?? "출력 폴더"}
        {output?.required ? <span aria-hidden="true"> *</span> : null}
      </label>
      <input
        id={id("output-dir")}
        type="text"
        value={form.outputDir}
        required={output?.required}
        aria-required={output?.required ? "true" : undefined}
        aria-describedby={
          [output ? id("output-dir-hint") : "", outputError ? id("output-dir-error") : ""]
            .filter(Boolean)
            .join(" ") || undefined
        }
        aria-invalid={outputError ? "true" : undefined}
        onChange={(e) => onChange("outputDir", e.target.value)}
      />
      {outputError ? (
        <p id={id("output-dir-error")} className="case-error" role="alert" data-testid="output-dir-error">
          {outputError}
        </p>
      ) : null}
      {output ? (
        <p id={id("output-dir-hint")} className="case-reason" data-testid="output-dir-hint">
          {output.hint}
        </p>
      ) : null}
    </>
  );
  return (
    <>
      {output?.required ? <div className="case-field">{outputField}</div> : null}
      <div className="case-field">
        <label htmlFor={id("mode")}>모드</label>
        <select id={id("mode")} value={form.mode} onChange={(e) => onChange("mode", e.target.value)}>
          {RUN_MODES.map((m) => (
            <option key={m.id} value={m.id}>
              {m.label}
            </option>
          ))}
        </select>
      </div>
      <div className="case-field">
        <label htmlFor={id("input-kind")}>입력 종류</label>
        <select
          id={id("input-kind")}
          value={form.inputKind}
          onChange={(e) => onChange("inputKind", e.target.value)}
        >
          {INPUT_KINDS.map((k) => (
            <option key={k.id} value={k.id}>
              {k.label}
            </option>
          ))}
        </select>
      </div>

      <label htmlFor={id("read-only")}>
        <input
          id={id("read-only")}
          type="checkbox"
          checked={form.readOnly}
          onChange={(e) => onChange("readOnly", e.target.checked)}
        />{" "}
        읽기 전용 (증거 원본 파일을 바꾸지 않음)
      </label>

      <button
        type="button"
        className="button"
        aria-expanded={advanced}
        aria-controls={id("advanced")}
        onClick={() => onAdvancedChange(!advanced)}
      >
        고급 옵션 {advanced ? "접기" : "펼치기"}
      </button>
      {advanced && (
        <fieldset id={id("advanced")} className="case-field">
          <legend>고급 옵션</legend>
          {output?.required ? null : outputField}
          <label htmlFor={id("max-mb")}>최대 추출 크기 (MB, 0 = 제한 없음)</label>
          <input
            id={id("max-mb")}
            type="number"
            min={0}
            value={form.maxExtractMb}
            onChange={(e) => onChange("maxExtractMb", e.target.value)}
          />
          {errors.maxExtractMb && <p className="case-error">{errors.maxExtractMb}</p>}
          <label htmlFor={id("max-files")}>최대 파일 수 (0 = 제한 없음)</label>
          <input
            id={id("max-files")}
            type="number"
            min={0}
            value={form.maxFileCount}
            onChange={(e) => onChange("maxFileCount", e.target.value)}
          />
          {errors.maxFileCount && <p className="case-error">{errors.maxFileCount}</p>}
          <label htmlFor={id("partition")}>E01 파티션 시작 섹터 (비우면 자동)</label>
          <input
            id={id("partition")}
            type="number"
            min={0}
            value={form.partitionSector}
            onChange={(e) => onChange("partitionSector", e.target.value)}
          />
          {errors.partitionSector && <p className="case-error">{errors.partitionSector}</p>}
          <label htmlFor={id("feeds")}>known-good 해시 목록 경로 (한 줄에 하나)</label>
          <textarea
            id={id("feeds")}
            rows={2}
            value={form.knownGoodFeeds}
            onChange={(e) => onChange("knownGoodFeeds", e.target.value)}
          />
          <label htmlFor={id("hide-known-good")}>
            <input
              id={id("hide-known-good")}
              type="checkbox"
              checked={form.hideKnownGood}
              onChange={(e) => onChange("hideKnownGood", e.target.checked)}
            />{" "}
            known-good 항목 숨기기
          </label>
          {errors.hideKnownGood && <p className="case-error">{errors.hideKnownGood}</p>}
          <label htmlFor={id("dry-run")}>
            <input
              id={id("dry-run")}
              type="checkbox"
              checked={form.dryRun}
              onChange={(e) => onChange("dryRun", e.target.checked)}
            />{" "}
            모의 실행 (결과를 쓰지 않음)
          </label>
          <label htmlFor={id("overwrite")}>
            <input
              id={id("overwrite")}
              type="checkbox"
              checked={form.overwrite}
              onChange={(e) => onChange("overwrite", e.target.checked)}
            />{" "}
            기존 출력 덮어쓰기
          </label>
          <label htmlFor={id("extract")}>
            <input
              id={id("extract")}
              type="checkbox"
              checked={form.extract}
              onChange={(e) => onChange("extract", e.target.checked)}
            />{" "}
            파일 추출
          </label>
          {errors.extract && <p className="case-error">{errors.extract}</p>}
          {extra}
        </fieldset>
      )}
    </>
  );
}
