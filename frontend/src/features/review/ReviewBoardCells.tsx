/**
 * Review-board cells (design review F12): the event time with what kind of time it is, the
 * report indicator, and the reviewer. Text, never colour alone.
 */

import type { ReactNode } from "react";
import type { GridRow } from "../../contracts/collection";
import { cellTime } from "../grid/columns/common";
import { UNNAMED_REVIEWER_LABEL } from "./author";
import "./review.css";

/** What the board's 사건 시각 shows for a row: an event time, a file copy's mtime, or nothing. */
export type BoardTimeKind = "event" | "file-mtime" | "none";

export const FILE_TIME_QUALIFIER = "파일 수정";
export const NO_EVENT_TIME_REASON = "사건 시각 없음: 이 대상(파일·문서·분석 결과)은 기록에 사건 시각이 없습니다.";
export const FILE_TIME_REASON =
  "사건 시각이 아니라 사본 파일의 수정 시각(mtime)입니다. 파일 대상에는 사건 시각이 없습니다.";

/** 사건 시각 cell: the time (zone in the header) and, for a file, "파일 수정" so it is never read as the event. */
export function boardTimeCell(row: GridRow, text: string): ReactNode {
  // No time: a quiet word (the reason is the cell tooltip).
  if (!text) return <span className="review-board-muted">없음</span>;
  if (row.fields.timeKind !== "file-mtime") return cellTime(text);
  return (
    <span className="review-board-time">
      {cellTime(text)}
      <span className="review-board-time-kind">{FILE_TIME_QUALIFIER}</span>
    </span>
  );
}

/** 보고서 cell: "포함" stands out, "미포함" is quiet text (both words, so a filter can find either). */
export function boardReportCell(row: GridRow): ReactNode {
  return row.fields.includeInReport === true ? (
    <span className="review-board-report">포함</span>
  ) : (
    <span className="review-board-muted">미포함</span>
  );
}

/** 판정자 cell: the stored name; "이름 없음" quiet so a named reviewer reads first. */
export function boardReviewerCell(label: string): ReactNode {
  return label === UNNAMED_REVIEWER_LABEL ? <span className="review-board-muted">{label}</span> : label;
}
