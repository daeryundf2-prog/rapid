// biome-ignore-all lint/a11y/useSemanticElements: virtualized ARIA grid; rows are positioned divs, not a <table>
// biome-ignore-all lint/a11y/useFocusableInteractive: roving tabindex — the cursor row is the tab stop, the grid container is only a programmatic focus target
// biome-ignore-all lint/a11y/noStaticElementInteractions: byte click is a mouse shortcut; the grid handles the keyboard
// biome-ignore-all lint/a11y/useKeyWithClickEvents: arrow keys on the focused grid move the same cursor
import {
  type FormEvent,
  type KeyboardEvent,
  type UIEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import { announce, useRovingTabindex } from "../../../a11y";
import { fetchHexRange, type HexRow } from "../../../api/viewer";
import {
  BYTES_PER_ROW,
  byteAscii,
  byteHex,
  bytesFromHexRows,
  CHUNK_BYTES,
  formatOffset,
  parseOffsetInput,
  ROWS_PER_CHUNK,
  rowCountForSize,
  type SignatureHit,
  scanSignatures,
} from "../hex";
import { errorText } from "../useAsync";

export const HEX_ROW_HEIGHT = 20;
/** Browsers cap element height (~33M px in Chrome); scale scrolling above this. */
const MAX_SCROLL_PX = 4_000_000;
const FALLBACK_VIEWPORT = 480;
const OVERSCAN_ROWS = 8;

type Chunk =
  | { status: "loading" }
  | { status: "ok"; bytes: Uint8Array; hits: SignatureHit[] }
  | { status: "error"; error: string };

export interface HexViewProps {
  runId: string;
  path: string;
  /** File size in bytes (preview/metadata). */
  size: number;
  highlight?: { offset?: number; length?: number };
  /** Archive entries: no range API, render the preview's bounded rows only. */
  staticRows?: HexRow[];
}

export function HexView({ runId, path, size: declaredSize, highlight, staticRows }: HexViewProps) {
  const staticBytes = useMemo(() => (staticRows ? bytesFromHexRows(staticRows) : null), [staticRows]);
  const size = staticBytes ? staticBytes.length : Math.max(0, declaredSize);
  const totalRows = rowCountForSize(size);
  const chunks = useRef(new Map<number, Chunk>());
  const [, bump] = useReducer((value: number) => value + 1, 0);
  const alive = useRef(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const wantRowFocus = useRef(false);
  const [viewport, setViewport] = useState(FALLBACK_VIEWPORT);
  const initialCursor =
    highlight?.offset !== undefined && highlight.offset < size ? Math.max(0, highlight.offset) : 0;
  const [cursor, setCursor] = useState(initialCursor);
  // Start the window at the highlighted record so the first chunk fetched is the record's, not offset 0.
  const [scrollTop, setScrollTop] = useState(() => {
    const firstRow = Math.max(0, Math.floor(initialCursor / BYTES_PER_ROW) - 2);
    const rows = rowCountForSize(size);
    if (rows * HEX_ROW_HEIGHT <= MAX_SCROLL_PX) return firstRow * HEX_ROW_HEIGHT;
    const maxFirst = Math.max(1, rows - Math.ceil(FALLBACK_VIEWPORT / HEX_ROW_HEIGHT));
    return (Math.min(firstRow, maxFirst) / maxFirst) * (MAX_SCROLL_PX - FALLBACK_VIEWPORT);
  });
  const [gotoText, setGotoText] = useState(formatOffset(initialCursor, size));
  const [gotoError, setGotoError] = useState<string | null>(null);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  if (staticBytes && !chunks.current.has(0)) {
    chunks.current.set(0, { status: "ok", bytes: staticBytes, hits: scanSignatures(staticBytes, 0) });
  }

  // Measure the scroll viewport (jsdom reports 0 → fallback height).
  useLayoutEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const measure = () => setViewport(element.clientHeight > 0 ? element.clientHeight : FALLBACK_VIEWPORT);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const visibleRows = Math.max(1, Math.ceil(viewport / HEX_ROW_HEIGHT));
  const naturalHeight = totalRows * HEX_ROW_HEIGHT;
  const scaled = naturalHeight > MAX_SCROLL_PX;
  const contentHeight = scaled ? MAX_SCROLL_PX : naturalHeight;
  const maxFirstRow = Math.max(0, totalRows - visibleRows);

  const firstRowFromScroll = useCallback(
    (top: number) => {
      if (!scaled) return Math.min(maxFirstRow, Math.max(0, Math.floor(top / HEX_ROW_HEIGHT)));
      const range = Math.max(1, contentHeight - viewport);
      return Math.min(maxFirstRow, Math.max(0, Math.round((top / range) * maxFirstRow)));
    },
    [scaled, maxFirstRow, contentHeight, viewport],
  );

  const scrollForRow = useCallback(
    (row: number) => {
      if (!scaled) return row * HEX_ROW_HEIGHT;
      const range = Math.max(1, contentHeight - viewport);
      return maxFirstRow ? (row / maxFirstRow) * range : 0;
    },
    [scaled, contentHeight, viewport, maxFirstRow],
  );

  const firstRow = firstRowFromScroll(scrollTop);

  const scrollToFirstRow = useCallback(
    (row: number) => {
      const clamped = Math.min(maxFirstRow, Math.max(0, row));
      const top = scrollForRow(clamped);
      if (scrollRef.current) scrollRef.current.scrollTop = top;
      setScrollTop(top);
    },
    [maxFirstRow, scrollForRow],
  );

  const ensureRowVisible = useCallback(
    (row: number) => {
      if (row < firstRow) scrollToFirstRow(row);
      else if (row > firstRow + visibleRows - 2) scrollToFirstRow(row - visibleRows + 2);
    },
    [firstRow, visibleRows, scrollToFirstRow],
  );

  // Put the highlighted offset in view on mount.
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only scroll to the highlight
  useEffect(() => {
    const row = Math.floor(initialCursor / BYTES_PER_ROW);
    if (row > 0) scrollToFirstRow(Math.max(0, row - 2));
  }, []);

  // Load the chunks covering the rendered window.
  const renderStart = Math.max(0, firstRow - OVERSCAN_ROWS);
  const renderEnd = Math.min(totalRows, firstRow + visibleRows + OVERSCAN_ROWS);
  useEffect(() => {
    if (staticBytes || size === 0) return;
    const firstChunk = Math.floor(renderStart / ROWS_PER_CHUNK);
    const lastChunk = Math.floor(Math.max(renderStart, renderEnd - 1) / ROWS_PER_CHUNK);
    for (let index = firstChunk; index <= lastChunk; index++) {
      if (chunks.current.has(index)) continue;
      chunks.current.set(index, { status: "loading" });
      const offset = index * CHUNK_BYTES;
      const length = Math.min(CHUNK_BYTES, size - offset);
      if (length <= 0) continue;
      fetchHexRange(runId, path, offset, length).then(
        (range) => {
          if (!alive.current) return;
          const bytes = bytesFromHexRows(range.rows);
          chunks.current.set(index, { status: "ok", bytes, hits: scanSignatures(bytes, offset) });
          bump();
        },
        (error: unknown) => {
          if (!alive.current) return;
          chunks.current.set(index, { status: "error", error: errorText(error) });
          bump();
        },
      );
    }
  }, [renderStart, renderEnd, runId, path, size, staticBytes]);

  const byteAt = (offset: number): number | null | "error" => {
    const chunk = chunks.current.get(Math.floor(offset / CHUNK_BYTES));
    if (!chunk || chunk.status === "loading") return null;
    if (chunk.status === "error") return "error";
    const value = chunk.bytes[offset % CHUNK_BYTES];
    return value === undefined ? null : value;
  };

  // Chunk map is a mutable ref; recompute on every render (cheap: ≤ 2–3 chunks).
  const visibleHits: SignatureHit[] = [];
  for (
    let index = Math.floor(renderStart / ROWS_PER_CHUNK);
    index <= Math.floor(Math.max(renderStart, renderEnd - 1) / ROWS_PER_CHUNK);
    index++
  ) {
    const chunk = chunks.current.get(index);
    if (chunk?.status === "ok") visibleHits.push(...chunk.hits);
  }
  const hitByOffset = new Map<number, SignatureHit>();
  for (const hit of visibleHits) for (let i = 0; i < hit.length; i++) hitByOffset.set(hit.offset + i, hit);

  const hlStart = highlight?.offset;
  const hlEnd = hlStart !== undefined ? hlStart + Math.max(1, highlight?.length ?? 1) : undefined;
  const inHighlight = (offset: number) =>
    hlStart !== undefined && hlEnd !== undefined && offset >= hlStart && offset < hlEnd;

  const moveCursor = (next: number) => {
    if (size === 0) return;
    const clamped = Math.min(size - 1, Math.max(0, next));
    setCursor(clamped);
    setGotoText(formatOffset(clamped, size));
    ensureRowVisible(Math.floor(clamped / BYTES_PER_ROW));
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const rowStart = cursor - (cursor % BYTES_PER_ROW);
    const page = BYTES_PER_ROW * Math.max(1, visibleRows - 1);
    const map: Record<string, number> = {
      ArrowDown: cursor + BYTES_PER_ROW,
      ArrowUp: cursor - BYTES_PER_ROW,
      ArrowRight: cursor + 1,
      ArrowLeft: cursor - 1,
      PageDown: cursor + page,
      PageUp: cursor - page,
      Home: event.ctrlKey ? 0 : rowStart,
      End: event.ctrlKey ? size - 1 : rowStart + BYTES_PER_ROW - 1,
    };
    if (event.altKey) return; // Alt+←/→ belongs to viewer history.
    const next = map[event.key];
    if (next === undefined) return;
    event.preventDefault();
    moveCursor(next);
  };

  const onGoto = (event: FormEvent) => {
    event.preventDefault();
    const value = parseOffsetInput(gotoText);
    if (value === null) {
      setGotoError("오프셋 형식이 올바르지 않습니다. 0x1F0 또는 496처럼 입력하세요.");
      announce("오프셋 형식이 올바르지 않습니다.");
      return;
    }
    if (value >= size) {
      setGotoError(`파일 크기(${size.toLocaleString("ko-KR")}바이트)를 넘는 오프셋입니다.`);
      announce("파일 크기를 넘는 오프셋입니다.");
      return;
    }
    setGotoError(null);
    moveCursor(value);
    scrollToFirstRow(Math.max(0, Math.floor(value / BYTES_PER_ROW) - 2));
    wantRowFocus.current = true;
  };

  const onScroll = (event: UIEvent<HTMLDivElement>) => setScrollTop(event.currentTarget.scrollTop);

  const cursorRow = Math.floor(cursor / BYTES_PER_ROW);
  const cursorValue = byteAt(cursor);
  const windowTop = scaled ? scrollTop : renderStart * HEX_ROW_HEIGHT;
  const rows: number[] = [];
  const renderFrom = scaled ? firstRow : renderStart;
  const renderTo = scaled ? Math.min(totalRows, firstRow + visibleRows + 1) : renderEnd;
  for (let row = renderFrom; row < renderTo; row++) rows.push(row);

  // Roving tabindex over the rendered rows: the cursor row is the single tab stop (the
  // first rendered row while the cursor is scrolled out of the window). Keys stay with the
  // grid's byte-level handler above; focusing a row (click, Tab) moves the cursor onto it.
  const roving = useRovingTabindex(gridRef, {
    orientation: "vertical",
    itemSelector: ".hex-row",
    onActiveChange: (_index, element) => {
      const row = Number(element?.dataset.row);
      if (!Number.isFinite(row) || row === cursorRow) return;
      moveCursor(row * BYTES_PER_ROW + (cursor % BYTES_PER_ROW));
    },
  });
  const cursorDomIndex = rows.indexOf(cursorRow);
  const activeDomIndex = cursorDomIndex >= 0 ? cursorDomIndex : 0;
  if (roving.activeIndex !== activeDomIndex) roving.setActiveIndex(activeDomIndex);

  // DOM focus follows the cursor row while focus is in the grid (or after goto / signature jump).
  useEffect(() => {
    const gridEl = gridRef.current;
    if (!gridEl) return;
    const active = document.activeElement;
    if (!wantRowFocus.current && !(active instanceof HTMLElement && gridEl.contains(active))) return;
    const rowEl = gridEl.querySelector<HTMLElement>(`.hex-row[data-row="${cursorRow}"]`);
    if (!rowEl) return;
    wantRowFocus.current = false;
    if (active !== rowEl) rowEl.focus({ preventScroll: true });
  });

  if (size === 0) return <p className="viewer-empty">빈 파일(0바이트)입니다.</p>;

  return (
    <div className="hex-view">
      <form className="hex-toolbar" onSubmit={onGoto}>
        <label className="hex-goto">
          <span>오프셋 이동</span>
          <input
            type="text"
            value={gotoText}
            onChange={(event) => setGotoText(event.target.value)}
            aria-label="오프셋으로 이동 (16진수 0x… 또는 10진수)"
            aria-invalid={gotoError ? true : undefined}
            aria-describedby={gotoError ? "hex-goto-error" : undefined}
            spellCheck={false}
          />
        </label>
        <button type="submit" className="viewer-button">
          이동
        </button>
        <span className="hex-status">
          커서 {formatOffset(cursor, size)} ({cursor.toLocaleString("ko-KR")}) · 값{" "}
          {typeof cursorValue === "number" ? `0x${byteHex(cursorValue)}` : "—"} · 크기{" "}
          {size.toLocaleString("ko-KR")}바이트{staticBytes ? " (미리보기 범위만)" : ""}
        </span>
      </form>
      {gotoError ? (
        <p className="viewer-error" id="hex-goto-error">
          {gotoError}
        </p>
      ) : null}
      <div className="hex-scroll" ref={scrollRef} onScroll={onScroll} data-testid="hex-scroll">
        <div className="hex-spacer" style={{ height: contentHeight }}>
          <div
            ref={gridRef}
            className="hex-grid"
            role="grid"
            aria-label="헥스 보기 — 화살표로 바이트 이동, Ctrl+Home/End로 처음·끝"
            aria-rowcount={totalRows}
            aria-colcount={3}
            tabIndex={-1}
            onKeyDown={onKeyDown}
            style={{ transform: `translateY(${windowTop}px)` }}
          >
            {rows.map((row, domIndex) => {
              const base = row * BYTES_PER_ROW;
              const count = Math.min(BYTES_PER_ROW, size - base);
              const cells: Array<number | null | "error"> = [];
              for (let i = 0; i < count; i++) cells.push(byteAt(base + i));
              const failed = cells.includes("error");
              const hexText = cells.map((v) => (typeof v === "number" ? byteHex(v) : "··")).join(" ");
              const asciiText = cells.map((v) => (typeof v === "number" ? byteAscii(v) : " ")).join("");
              const rowHighlighted = cells.some((_, i) => inHighlight(base + i));
              return (
                <div
                  key={row}
                  id={`hex-row-${row}`}
                  data-row={row}
                  {...roving.getItemProps(domIndex)}
                  role="row"
                  aria-rowindex={row + 1}
                  aria-selected={row === cursorRow}
                  aria-label={`${formatOffset(base, size)} ${failed ? "읽기 실패" : `${hexText} ${asciiText}`}`}
                  className={`hex-row${row === cursorRow ? " is-cursor-row" : ""}${rowHighlighted ? " is-hl-row" : ""}`}
                  style={{ height: HEX_ROW_HEIGHT }}
                >
                  <span role="rowheader" className="hex-offset">
                    {formatOffset(base, size)}
                  </span>
                  <span role="gridcell" className="hex-bytes" aria-hidden="true">
                    {failed
                      ? "읽기 실패"
                      : cells.map((value, i) => {
                          const offset = base + i;
                          const classes = ["hex-byte"];
                          if (inHighlight(offset)) classes.push("is-hl");
                          if (hitByOffset.has(offset)) classes.push("is-sig");
                          if (offset === cursor) classes.push("is-cursor");
                          return (
                            <span
                              key={offset}
                              className={classes.join(" ")}
                              data-offset={offset}
                              onClick={() => moveCursor(offset)}
                            >
                              {typeof value === "number" ? byteHex(value) : "··"}
                            </span>
                          );
                        })}
                  </span>
                  <span role="gridcell" className="hex-ascii" aria-hidden="true">
                    {failed
                      ? ""
                      : cells.map((value, i) => {
                          const offset = base + i;
                          const classes = ["hex-char"];
                          if (inHighlight(offset)) classes.push("is-hl");
                          if (hitByOffset.has(offset)) classes.push("is-sig");
                          if (offset === cursor) classes.push("is-cursor");
                          return (
                            <span key={offset} className={classes.join(" ")}>
                              {typeof value === "number" ? byteAscii(value) : " "}
                            </span>
                          );
                        })}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
      {visibleHits.length ? (
        <div className="hex-legend" role="group" aria-label="파일 시그니처">
          {visibleHits.slice(0, 12).map((hit) => (
            <button
              type="button"
              key={`${hit.name}-${hit.offset}`}
              className="hex-sig-chip"
              onClick={() => {
                moveCursor(hit.offset);
                wantRowFocus.current = true;
              }}
            >
              {hit.name} @ {formatOffset(hit.offset, size)}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
