/**
 * One evidence item's fields (AXIOM adoption E1): 증거 번호 · 종류 · 경로 (찾아보기) · 표시 이름 ·
 * 해시 검증 토글 (+ 기대 해시). Used by the case wizard (N items) and 증거 추가.
 */

import { useState } from "react";
import { BrowsePanel } from "./BrowsePanel";
import { EVIDENCE_TYPES, type EvidenceDraft, type EvidenceErrors } from "./wizardModel";

export function EvidenceFields({
  draft,
  errors,
  onChange,
  idPrefix,
  locked = false,
  showErrors = false,
}: {
  draft: EvidenceDraft;
  errors: EvidenceErrors;
  onChange: (next: EvidenceDraft) => void;
  idPrefix: string;
  /** Already saved to the case: read-only. */
  locked?: boolean;
  /** Show every error (after a submit attempt), not only for touched fields. */
  showErrors?: boolean;
}) {
  const [browsing, setBrowsing] = useState(false);
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const id = (name: string) => `${idPrefix}-${name}`;
  const set = <K extends keyof EvidenceDraft>(key: K, value: EvidenceDraft[K]) =>
    onChange({ ...draft, [key]: value });
  const shown = (key: keyof EvidenceErrors) => (showErrors || touched[key] ? errors[key] : undefined);
  const touch = (key: string) => setTouched((t) => ({ ...t, [key]: true }));
  const numberError = shown("evidenceNumber");
  const pathError = shown("path");
  const hashError = shown("expectedHash");

  return (
    <div className="case-evidence-fields">
      <div className="case-field">
        <label htmlFor={id("number")}>
          증거 번호 <span aria-hidden="true">*</span>
        </label>
        <input
          id={id("number")}
          type="text"
          value={draft.evidenceNumber}
          maxLength={50}
          required
          aria-required="true"
          aria-invalid={Boolean(numberError)}
          aria-describedby={numberError ? id("number-error") : undefined}
          disabled={locked}
          onBlur={() => touch("evidenceNumber")}
          onChange={(e) => set("evidenceNumber", e.target.value)}
        />
        {numberError ? (
          <p id={id("number-error")} className="case-error">
            {numberError}
          </p>
        ) : null}
      </div>
      <div className="case-field">
        <label htmlFor={id("type")}>증거 종류</label>
        <select
          id={id("type")}
          value={draft.sourceType}
          disabled={locked}
          onChange={(e) => set("sourceType", e.target.value as EvidenceDraft["sourceType"])}
        >
          {EVIDENCE_TYPES.map((type) => (
            <option key={type.id} value={type.id}>
              {type.label}
            </option>
          ))}
        </select>
      </div>
      <div className="case-field">
        <label htmlFor={id("path")}>
          증거 경로 <span aria-hidden="true">*</span>
        </label>
        <div className="case-actions" style={{ justifyContent: "stretch" }}>
          <input
            id={id("path")}
            type="text"
            style={{ flex: 1 }}
            value={draft.path}
            required
            aria-required="true"
            aria-invalid={Boolean(pathError)}
            aria-describedby={pathError ? id("path-error") : undefined}
            disabled={locked}
            onBlur={() => touch("path")}
            onChange={(e) => set("path", e.target.value)}
          />
          {locked ? null : (
            <button
              type="button"
              className="button"
              aria-expanded={browsing}
              aria-label={`증거 ${draft.evidenceNumber || ""} 경로 찾아보기`.replace(/\s+/g, " ")}
              onClick={() => setBrowsing((v) => !v)}
            >
              찾아보기
            </button>
          )}
        </div>
        {pathError ? (
          <p id={id("path-error")} className="case-error">
            {pathError}
          </p>
        ) : null}
      </div>
      {browsing && !locked ? (
        <BrowsePanel
          initialPath={draft.path}
          onPick={(path) => {
            set("path", path);
            setBrowsing(false);
          }}
        />
      ) : null}
      <div className="case-field">
        <label htmlFor={id("name")}>표시 이름 (비우면 파일·폴더 이름)</label>
        <input
          id={id("name")}
          type="text"
          value={draft.displayName}
          maxLength={200}
          disabled={locked}
          onChange={(e) => set("displayName", e.target.value)}
        />
      </div>
      <label className="case-switch">
        <input
          type="checkbox"
          role="switch"
          aria-checked={draft.verifyHash}
          checked={draft.verifyHash}
          disabled={locked}
          onChange={(e) => set("verifyHash", e.target.checked)}
        />{" "}
        해시 검증 (파일 증거의 MD5·SHA-1·SHA-256을 백그라운드에서 계산)
      </label>
      {draft.verifyHash ? (
        <div className="case-field">
          <label htmlFor={id("hash")}>기대 해시 (선택 · 획득 기록의 MD5/SHA-1/SHA-256)</label>
          <input
            id={id("hash")}
            type="text"
            className="mono"
            value={draft.expectedHash}
            maxLength={128}
            aria-invalid={Boolean(hashError)}
            aria-describedby={hashError ? id("hash-error") : undefined}
            disabled={locked}
            onBlur={() => touch("expectedHash")}
            onChange={(e) => set("expectedHash", e.target.value)}
          />
          {hashError ? (
            <p id={id("hash-error")} className="case-error">
              {hashError}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
