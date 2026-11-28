/**
 * 레코드 요약 (design-viewer-keys F18): the first lines of the detail for a decoded-record row —
 * 대상 · 시각 의미 · 증거 · 원본 + 레코드 위치, with 인용 복사 and 원본 위치 열기 side by side.
 * The model is recordHead.ts; this only lays it out and wires the two buttons.
 */

import { DisabledReason } from "../../a11y";
import { MiddlePath } from "../../components/MiddlePath";
import type { GridRow } from "../../contracts/collection";
import type { ViewerTarget } from "../../contracts/viewer";
import { FILE_LEVEL_ONLY, type RecordHeadModel, type RecordOpen } from "./recordHeadModel";

export const NO_LOCATION_OPEN_REASON = "레코드 위치 정보가 없어 원본 파일 단위까지만 추적합니다.";

export interface RecordHeadProps {
  model: RecordHeadModel;
  target: ViewerTarget;
  row: GridRow | null;
  /** 인용 복사 (the viewer.cite command): its reason when it cannot run, and the action. */
  cite: { reason?: string; run: () => void };
  onOpen: (open: RecordOpen) => void;
}

export function RecordHead({ model, target, cite, onOpen }: RecordHeadProps) {
  const open = model.open;
  return (
    <section className="record-head" aria-label="레코드 요약" data-testid="record-head">
      <dl className="record-head-lines">
        {model.target ? (
          <>
            <dt>대상</dt>
            <dd className="record-head-target viewer-break">{model.target}</dd>
          </>
        ) : null}
        {model.time ? (
          <>
            <dt>{model.time.label}</dt>
            <dd>{model.time.text}</dd>
          </>
        ) : null}
        <dt>증거</dt>
        <dd>{model.evidence ?? `런 ${target.runId}`}</dd>
        {model.sourcePath ? (
          <>
            <dt>원본</dt>
            <dd className="record-head-path">
              <MiddlePath path={model.sourcePath} whole />
            </dd>
          </>
        ) : null}
        <dt>위치</dt>
        <dd className="mono viewer-break" data-testid="record-head-locator">
          {model.locator.length
            ? model.locator.map((part) => (
                <span key={part} className="record-head-loc">
                  {part}
                </span>
              ))
            : FILE_LEVEL_ONLY}
        </dd>
      </dl>
      <div className="record-head-actions">
        <DisabledReason reason={cite.reason}>
          <button type="button" className="viewer-button" data-command="viewer.cite" onClick={cite.run}>
            인용 복사
          </button>
        </DisabledReason>
        <DisabledReason reason={open ? undefined : NO_LOCATION_OPEN_REASON}>
          <button
            type="button"
            className="viewer-button"
            data-testid="record-head-open"
            onClick={() => {
              if (open) onOpen(open);
            }}
          >
            원본 위치 열기
          </button>
        </DisabledReason>
      </div>
    </section>
  );
}
