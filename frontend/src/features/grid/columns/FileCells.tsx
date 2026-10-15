import type { ReactNode } from "react";
import { ToneChip } from "../../../components/ToneChip";
import type { GridRow } from "../../../contracts/collection";

/** Title of a modified cell whose time is the acquisition copy's host mtime (parser-quality r1). */
export const COPY_TIME_TITLE = "취득 사본의 시각 — 원본 시각 아님";

/** 수정 cell: the chosen time; an acquisition-copy time renders muted with COPY_TIME_TITLE. */
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
