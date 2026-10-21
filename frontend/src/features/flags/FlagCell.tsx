/**
 * 특이사항 UI (viewer-families plan U-F4): grade chips (A 빨강 · B 주황 · C 회색 — the text and
 * border use the status colours that already pass the contrast gate on every row surface), the
 * evidence popover (근거 필드 · 오탐 주의 · 출처 링크 · "검증 필요" for provisional rules) and
 * the list used by the viewer banner. The popover also names what the rule was checked against
 * (catalogue `validation`, R6 S4: "검증: 합성 픽스처만" / "검증: 실데이터 2건(…)").
 */

import { useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Popover } from "../../components/Popover";
import type { GridRow } from "../../contracts/collection";
import { ruleById } from "./catalog";
import {
  evidenceEntries,
  flagCitation,
  flagsAccessibleName,
  isProvisional,
  type RowFlag,
  rowFlags,
  topGrade,
  validationLine,
} from "./flags";
import "./flags.css";

/** Chips shown in a grid cell before "+n". */
const CELL_CHIPS = 2;

export function GradeChip({ flag, compact = false }: { flag: RowFlag; compact?: boolean }) {
  return (
    <span className="flag-chip" data-grade={flag.grade} title={`${flag.grade} · ${flag.label}`}>
      <span className="flag-chip-grade" aria-hidden="true">
        {flag.grade}
      </span>
      {compact ? null : <span className="flag-chip-label">{flag.label}</span>}
    </span>
  );
}

/** One flag's evidence block (popover and viewer banner). */
export function FlagDetail({ flag, headingLevel = 3 }: { flag: RowFlag; headingLevel?: 3 | 4 }) {
  const rule = ruleById(flag.id);
  const evidence = evidenceEntries(flag);
  const validation = validationLine(rule);
  const Heading = headingLevel === 3 ? "h3" : "h4";
  return (
    <section
      className="flag-detail"
      data-grade={flag.grade}
      aria-label={`특이사항 ${flag.grade}: ${flag.label}`}
    >
      <Heading className="flag-detail-title">
        <GradeChip flag={flag} compact />
        <span>{flag.label}</span>
        {isProvisional(flag) ? (
          <span className="flag-provisional" title="실제 이미지로 아직 검증되지 않은 지표입니다">
            검증 필요
          </span>
        ) : null}
      </Heading>
      {rule?.rationale_ko ? <p className="flag-detail-text">{rule.rationale_ko}</p> : null}
      {evidence.length ? (
        <dl className="flag-evidence">
          {evidence.map(([key, value]) => (
            <div key={key}>
              <dt className="mono">{key}</dt>
              <dd className="mono">{value || "—"}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="flag-detail-text flag-muted">근거 필드가 기록되지 않았습니다.</p>
      )}
      {flag.note ? <p className="flag-detail-text">{flag.note}</p> : null}
      {rule?.false_positive_ko ? (
        <p className="flag-detail-text">
          <strong>오탐 주의:</strong> {rule.false_positive_ko}
        </p>
      ) : null}
      {rule?.sources.length ? (
        <p className="flag-detail-text flag-sources">
          <strong>출처:</strong>{" "}
          {rule.sources.map((url, index) => (
            <span key={url}>
              {index ? " · " : ""}
              <a href={url} target="_blank" rel="noreferrer noopener">
                {sourceName(url)}
              </a>
            </span>
          ))}
        </p>
      ) : null}
      {validation ? (
        <p
          className="flag-detail-text flag-muted flag-validation"
          data-testid="flag-validation"
          title={rule?.validation?.notes_ko || undefined}
        >
          {validation}
        </p>
      ) : null}
      <p className="flag-detail-text flag-muted mono" title="보고서 인용 형식(지표 id@버전 + 근거)">
        {flagCitation(flag, rule)}
      </p>
    </section>
  );
}

function sourceName(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/** 특이사항 cell: grade chips; the button opens the evidence popover. */
export function FlagCell({ row }: { row: GridRow }) {
  const flags = rowFlags(row);
  const [open, setOpen] = useState(false);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const id = useId();
  if (!flags.length) {
    return (
      <span className="grid-cell-empty" aria-hidden="true">
        —
      </span>
    );
  }
  const name = flagsAccessibleName(flags);
  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        tabIndex={-1}
        className="flag-cell"
        aria-label={name}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        title={name}
        onClick={(event) => {
          event.stopPropagation();
          setRect(event.currentTarget.getBoundingClientRect());
          setOpen((value) => !value);
        }}
      >
        {flags.slice(0, CELL_CHIPS).map((flag) => (
          <GradeChip key={flag.id} flag={flag} />
        ))}
        {flags.length > CELL_CHIPS ? (
          <span className="flag-more" aria-hidden="true">
            +{flags.length - CELL_CHIPS}
          </span>
        ) : null}
      </button>
      {open && rect
        ? createPortal(
            <div
              className="flag-popover-anchor popover-anchor"
              style={{ position: "fixed", left: rect.left, top: rect.bottom + 2 }}
            >
              <Popover
                id={id}
                open
                onClose={() => setOpen(false)}
                triggerRef={buttonRef}
                label="특이사항 근거"
                className="flag-popover"
              >
                <h2 className="popover-title">특이사항 근거</h2>
                {flags.map((flag) => (
                  <FlagDetail key={flag.id} flag={flag} />
                ))}
              </Popover>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}

/**
 * Viewer banner (U-F4): the row's 특이사항 at the very top of the viewer, in every mode. The
 * summary line names them (grade chips + labels); the body has each one's 근거 · 오탐 주의 · 출처.
 * Open by default when an A-grade flag is present.
 */
export function FlagBanner({ row }: { row: Pick<GridRow, "fields"> | null }) {
  const flags = rowFlags(row);
  if (!flags.length) return null;
  const top = topGrade(flags);
  return (
    <details
      className="flag-banner"
      data-grade={top ?? undefined}
      data-testid="viewer-flag-banner"
      open={top === "A"}
    >
      <summary className="flag-banner-summary" aria-label={`${flagsAccessibleName(flags)} — 근거 보기`}>
        <span className="flag-banner-title" aria-hidden="true">
          특이사항 {flags.length}건
        </span>
        <span className="flag-banner-chips" aria-hidden="true">
          {flags.slice(0, 4).map((flag) => (
            <GradeChip key={flag.id} flag={flag} />
          ))}
          {flags.length > 4 ? <span className="flag-more">+{flags.length - 4}</span> : null}
        </span>
      </summary>
      <div className="flag-banner-body">
        {flags.map((flag) => (
          <FlagDetail key={flag.id} flag={flag} />
        ))}
      </div>
    </details>
  );
}
