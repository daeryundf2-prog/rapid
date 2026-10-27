import { Fragment, type ReactNode } from "react";
import { middlePathParts } from "../../../utils/pathDisplay";

/** Highlight spans `[start, end)` of a search snippet (server `snippet_highlights`). */
export type Spans = ReadonlyArray<readonly [number, number]>;

/** Parse `snippet_highlights` defensively: sorted, in range, non-overlapping. */
export function snippetSpans(value: unknown, length: number): [number, number][] {
  if (!Array.isArray(value)) return [];
  const spans: [number, number][] = [];
  for (const item of value) {
    if (!Array.isArray(item) || item.length !== 2) continue;
    const [start, end] = item;
    if (typeof start !== "number" || typeof end !== "number") continue;
    if (start < 0 || end > length || end <= start) continue;
    spans.push([start, end]);
  }
  spans.sort((a, b) => a[0] - b[0]);
  const out: [number, number][] = [];
  for (const span of spans) {
    const last = out[out.length - 1];
    if (last && span[0] < last[1]) continue;
    out.push(span);
  }
  return out;
}

/** 미리보기 cell: the match context with the matched words marked. */
export function snippetCell(text: string, spans: Spans): ReactNode {
  if (!text) return null;
  if (spans.length === 0) return <span className="grid-cell-text">{text}</span>;
  const parts: ReactNode[] = [];
  let at = 0;
  for (const [start, end] of spans) {
    if (start > at) parts.push(<Fragment key={`t${at}`}>{text.slice(at, start)}</Fragment>);
    parts.push(
      <mark key={`m${start}`} className="viewer-hit">
        {text.slice(start, end)}
      </mark>,
    );
    at = end;
  }
  if (at < text.length) parts.push(<Fragment key={`t${at}`}>{text.slice(at)}</Fragment>);
  return <span className="grid-cell-text">{parts}</span>;
}

/**
 * 경로 cell of a search hit: the path under the acquisition root (folder head ellipsized, file
 * name whole); the full evidence path is the tooltip.
 */
export function searchPathCell(display: string, full: string | null): ReactNode {
  if (!display) return null;
  const parts = middlePathParts(display);
  return (
    <span className="mid-path" title={full ?? display}>
      {parts.head ? <span className="mid-path-head">{parts.head}</span> : null}
      <span className="mid-path-tail">{parts.tail}</span>
    </span>
  );
}
