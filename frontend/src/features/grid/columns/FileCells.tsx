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

/** 삭제 cell: a "삭제됨" chip for deleted entries, "할당" for allocated ones, empty when unknown. */
export function deletedCell(row: GridRow): ReactNode {
  const deleted = row.fields.isDeleted;
  if (deleted === true) return <ToneChip tone="danger">삭제됨</ToneChip>;
  if (deleted === false) return <span className="grid-cell-text">할당</span>;
  return (
    <span className="grid-cell-empty" aria-hidden="true">
      —
    </span>
  );
}
