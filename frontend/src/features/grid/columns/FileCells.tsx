import type { ReactNode } from "react";
import { ToneChip } from "../../../components/ToneChip";
import type { GridRow } from "../../../contracts/collection";
import { Icon } from "../../../icons/Icon";

/** Short label of an acquisition-copy time (r8 C.9.1, T-173): it is not a time of the evidence. */
export const COPY_TIME_LABEL = "증거 시각 아님";

/** Title of a modified cell whose time is the acquisition copy's host mtime (parser-quality r1). */
export const COPY_TIME_TITLE = `${COPY_TIME_LABEL} — 취득 사본을 만든 시각입니다`;

/**
 * 수정 cell: the chosen time. An acquisition-copy time is muted and carries a clock marker with
 * the "증거 시각 아님" name (r8 C.9.1, T-173: a marker, not italics); COPY_TIME_TITLE is the
 * cell's tooltip.
 */
export function modifiedCell(row: GridRow, text: string): ReactNode {
  if (!text) {
    return (
      <span className="grid-cell-empty" aria-hidden="true">
        —
      </span>
    );
  }
  if (row.fields.modifiedOrigin === "acquisition-copy") {
    return (
      <span className="grid-cell-text grid-cell-copytime" data-testid="files-copy-time">
        {/* Decorative: the sr-only text below names it once for assistive tech. */}
        <Icon name="clock" size={12} className="grid-copytime-mark" />
        {text}
        <span className="sr-only"> ({COPY_TIME_TITLE})</span>
      </span>
    );
  }
  return <span className="grid-cell-text">{text}</span>;
}

/** Title of an "unknown" 삭제 value: the scan could not tell allocated from deleted. */
export const DELETION_UNKNOWN_TITLE = "삭제 여부 확인 불가 — 파일시스템 목록·MFT 정보가 없습니다";

/**
 * 삭제 cell from `deletion_state`: a "삭제됨" danger chip, a neutral "할당" chip, a muted
 * "알 수 없음" (not a deletion claim); empty when the server says nothing.
 */
export function deletionCell(row: GridRow): ReactNode {
  const state = row.fields.deletion;
  if (state === "deleted") return <ToneChip tone="danger">삭제됨</ToneChip>;
  if (state === "allocated") return <ToneChip tone="">할당</ToneChip>;
  if (state === "unknown") {
    return (
      <span className="grid-cell-empty" data-testid="files-deletion-unknown" title={DELETION_UNKNOWN_TITLE}>
        알 수 없음
      </span>
    );
  }
  return (
    <span className="grid-cell-empty" aria-hidden="true">
      —
    </span>
  );
}

/** 시그니처 cell: a warn "불일치" chip (direction in the title), plain "일치", empty when unchecked. */
export function signatureCell(row: GridRow): ReactNode {
  const sig = row.fields.signature as { state?: string | null; direction?: string | null } | undefined;
  if (sig?.state === "mismatch") {
    return (
      <ToneChip tone="warn" testId="files-signature-mismatch">
        불일치
      </ToneChip>
    );
  }
  if (sig?.state === "match") return <span className="grid-cell-text">일치</span>;
  if (sig?.state === "read-error") return <span className="grid-cell-empty">읽기 오류</span>;
  return (
    <span className="grid-cell-empty" aria-hidden="true">
      —
    </span>
  );
}
