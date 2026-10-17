// biome-ignore-all lint/a11y/useSemanticElements: virtualized ARIA grid of tiles; cells are positioned divs, not a <table>
/**
 * 썸네일 보기 (S9, plan X16): a virtualized ARIA grid of image tiles for the
 * files collection and the media artifact kinds. The gallery endpoint is
 * anchored on one file's folder, so the tiles come from the collection rows
 * filtered to image extensions; each visible tile loads a server-cached JPEG
 * thumbnail (`source-thumbnail`) through the authenticated blob fetch, at most
 * THUMB_CONCURRENCY at a time, and falls back to the original (source-file)
 * only when the thumbnail call fails. Only mounted tiles load.
 *
 * Keys (roving tabindex): arrows, Home/End (row), Ctrl+Home/End (all),
 * PageUp/PageDown; Enter = open in the viewer (image mode); Space = select;
 * R/X/I/B/1–5 act on the focused tile through the shared review commands
 * (the viewer target follows tile focus, as it follows grid focus).
 */

import { useVirtualizer } from "@tanstack/react-virtual";
import { type KeyboardEvent, type MouseEvent, memo, useEffect, useMemo, useRef, useState } from "react";
import { fetchSourceBlob, fetchSourceThumbnailBlob, isArchiveEntryPath } from "../../api/viewer";
import type { CollectionRef, GridRow } from "../../contracts/collection";
import { encodeRowRef } from "../../contracts/rowRef";
import { useRoute, useSelection, useViewerTarget } from "../grid/adapter";
import { formatBytes, REVIEW_LABELS } from "../grid/columns/common";
import { buildViewerTarget } from "../grid/gridCommands";
import { PAGE_SIZE, useCollectionQuery } from "../grid/useCollectionQuery";
import { MediaBlurToggle, RelatedMediaBadge } from "../review/MediaTools";
import { registerRowSource } from "../review/rowSource";
import { useViewPrefs } from "../review/viewPrefs";
import { errorText, useBlobUrl } from "../viewer/useAsync";
import { SelectionBar } from "./SelectionBar";
import {
  createLimiter,
  gridMove,
  isImageRow,
  rowSize,
  sortThumbs,
  THUMB_SORT_LABELS,
  type ThumbSort,
} from "./thumbnails";
import { useAutoLoad, useElementWidth, useViewRows } from "./useViewRows";
import { EmptyState, ErrorState, LoadingCard } from "./ViewState";

export const TILE_WIDTH = 152;
export const TILE_HEIGHT = 172;
/** Rows scanned automatically while looking for images (then "더 불러오기"). */
export const THUMB_AUTOLOAD_PAGES = 16;
export const THUMB_AUTOLOAD_ROWS = THUMB_AUTOLOAD_PAGES * PAGE_SIZE;
const MEDIA_IMAGE_REF: CollectionRef = { id: "artifacts", kind: "media-image" };

/** Parallel thumbnail requests (browser + server decode budget). */
export const THUMB_CONCURRENCY = 6;
/** Requested thumbnail edge in px (server default; tiles are ~136 px). */
export const THUMB_SIZE = 160;
const thumbSlots = createLimiter(THUMB_CONCURRENCY);

/** Thumbnail first; the original only if the thumbnail call fails (not when aborted). */
export function loadThumbBlob(runId: string, path: string, signal: AbortSignal): Promise<Blob> {
  return thumbSlots(signal, async () => {
    try {
      return await fetchSourceThumbnailBlob(runId, path, THUMB_SIZE, signal);
    } catch (error) {
      if (signal.aborted) throw error;
      return fetchSourceBlob(runId, path, signal);
    }
  });
}

function Thumb({ runId, path }: { runId: string; path: string }) {
  const archive = isArchiveEntryPath(path);
  const image = useBlobUrl(archive ? null : `thumb|${runId}|${path}`, (signal) =>
    loadThumbBlob(runId, path, signal),
  );
  if (image.url) return <img className="thumb-img" src={image.url} alt="" draggable={false} />;
  const failed = archive || image.status === "error";
  return <span className="thumb-placeholder">{failed ? "미리 보기 없음" : "불러오는 중…"}</span>;
}

const Tile = memo(function Tile({
  row,
  index,
  column,
  runId,
  active,
  selected,
  onKeyDown,
  onClick,
  onOpen,
  onFocus,
}: {
  row: GridRow;
  index: number;
  column: number;
  runId: string;
  active: boolean;
  selected: boolean;
  onKeyDown: (event: KeyboardEvent<HTMLDivElement>) => void;
  onClick: (event: MouseEvent<HTMLDivElement>, index: number) => void;
  onOpen: (index: number) => void;
  onFocus: (index: number) => void;
}) {
  const name = (row.sourcePath ?? row.title).split(/[\\/]/).pop() || row.title;
  const size = formatBytes(rowSize(row));
  const status = row.reviewStatus ? REVIEW_LABELS[row.reviewStatus] : "";
  const label = [name, size, row.timestamp ?? "", status, selected ? "선택됨" : ""]
    .filter(Boolean)
    .join(", ");
  return (
    <div
      role="gridcell"
      className="thumb-tile"
      aria-colindex={column + 1}
      aria-selected={selected}
      aria-label={label}
      tabIndex={active ? 0 : -1}
      data-thumb-index={index}
      data-active={active || undefined}
      data-review={row.reviewStatus ?? undefined}
      onKeyDown={onKeyDown}
      onClick={(event) => onClick(event, index)}
      onDoubleClick={() => onOpen(index)}
      onFocus={() => onFocus(index)}
    >
      <span className="thumb-frame">
        <Thumb runId={runId} path={row.sourcePath ?? ""} />
      </span>
      <span className="thumb-name" title={row.sourcePath ?? name}>
        {name}
      </span>
    </div>
  );
});

/** Image rows de-duplicated by source path (the files listing and media-image artifacts overlap). */
export function mergeImageRows(primary: readonly GridRow[], extra: readonly GridRow[]): GridRow[] {
  const seen = new Set<string>();
  const out: GridRow[] = [];
  for (const row of [...primary, ...extra]) {
    const key = (row.sourcePath ?? row.rowKey).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

export function ThumbnailView() {
  const route = useRoute();
  const { cq, rows: routeRows, runId } = useViewRows({ predicate: isImageRow, textFilter: true });
  // The files listing can hold its images far past the first pages: also read the media-image artifacts.
  const withArtifacts = route.collection.id === "files";
  const media = useCollectionQuery(
    { ref: MEDIA_IMAGE_REF, offset: 0, limit: PAGE_SIZE },
    { runId: withArtifacts ? route.runId : null, passive: true },
  );
  const mediaRows = useMemo(() => media.loadedRows.filter(isImageRow), [media.loadedRows]);
  const rows = useMemo(
    () => (withArtifacts ? mergeImageRows(routeRows, mediaRows) : routeRows),
    [withArtifacts, routeRows, mediaRows],
  );
  const { selectedKeys, select } = useSelection();
  const { target, publishFocusedRow, requestFocus } = useViewerTarget();
  const [sort, setSort] = useState<ThumbSort>("name-asc");
  const sorted = useMemo(() => sortThumbs(rows, sort), [rows, sort]);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const width = useElementWidth(scrollRef, 800);
  const columns = Math.max(1, Math.floor(width / TILE_WIDTH));
  const rowCount = Math.ceil(sorted.length / columns);
  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => TILE_HEIGHT,
    overscan: 2,
    initialRect: { width: 800, height: 600 },
  });
  const virtualRows = virtualizer.getVirtualItems();
  const lastVisibleRow = virtualRows.at(-1)?.index ?? 0;
  const [active, setActive] = useState(0);
  const activeIndex = Math.min(active, Math.max(sorted.length - 1, 0));
  const pendingFocus = useRef<number | null>(null);

  const wantMore = sorted.length < (lastVisibleRow + 3) * columns;
  const filesCapped = useAutoLoad(cq, wantMore, THUMB_AUTOLOAD_ROWS);
  const mediaCapped = useAutoLoad(media, wantMore, THUMB_AUTOLOAD_ROWS);
  const capped = filesCapped || mediaCapped;
  const scanned = cq.loadedCount + (withArtifacts ? media.loadedCount : 0);
  const paging =
    cq.isFetching ||
    (withArtifacts && media.isFetching) ||
    (cq.canLoadMore && !filesCapped) ||
    (withArtifacts && media.canLoadMore && !mediaCapped);
  const loadMoreAll = () => {
    if (filesCapped) cq.loadMore();
    if (mediaCapped) media.loadMore();
  };

  // Move DOM focus onto the target tile once it is rendered (tiles are virtualized).
  useEffect(() => {
    if (pendingFocus.current === null) return;
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-thumb-index="${pendingFocus.current}"]`);
    if (el) {
      pendingFocus.current = null;
      el.focus();
    }
  });

  const publish = (row: GridRow | undefined) => {
    if (!row || !runId) return;
    const same =
      target?.runId === runId &&
      target.preferredMode === "image" &&
      encodeRowRef(target.ref) === encodeRowRef(row.ref);
    if (same) return;
    publishFocusedRow(row, buildViewerTarget(runId, row, "image"));
  };

  const focusTile = (index: number) => {
    setActive(index);
    pendingFocus.current = index;
    virtualizer.scrollToIndex(Math.floor(index / columns), { align: "auto" });
  };

  const toggle = (row: GridRow) => {
    const next = new Set(selectedKeys);
    if (next.has(row.rowKey)) next.delete(row.rowKey);
    else next.add(row.rowKey);
    select([...next]);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = Number(event.currentTarget.dataset.thumbIndex ?? activeIndex);
    const row = sorted[index];
    const pageRows = Math.max(1, virtualRows.length - 2);
    const next = gridMove(index, event, columns, sorted.length, pageRows);
    if (next !== null) {
      event.preventDefault();
      if (next !== index) focusTile(next);
      return;
    }
    if (!row) return;
    if (event.key === "Enter") {
      event.preventDefault();
      onOpen(index);
    } else if (event.key === " ") {
      event.preventDefault();
      toggle(row);
    } else if (event.key === "Escape" && selectedKeys.size > 0) {
      event.preventDefault();
      select([]);
    }
  };

  const onClick = (event: MouseEvent<HTMLDivElement>, index: number) => {
    const row = sorted[index];
    if (!row) return;
    if (event.ctrlKey || event.metaKey) {
      toggle(row);
      return;
    }
    setActive(index);
    publish(row);
  };

  const onOpen = (index: number) => {
    publish(sorted[index]);
    requestFocus();
  };

  const onFocus = (index: number) => {
    setActive(index);
    publish(sorted[index]);
  };

  const selectedRows = useMemo(
    () => sorted.filter((r) => selectedKeys.has(r.rowKey)),
    [sorted, selectedKeys],
  );
  // Shell review tools (같은 해시 행에 태그 전파, digit tag keys) act on this selection too.
  const sourceRef = useRef({ selectedRows, cq });
  sourceRef.current = { selectedRows, cq };
  useEffect(
    () =>
      registerRowSource({
        getSelectedRows: () => sourceRef.current.selectedRows,
        patchRows: (keys, patch) => sourceRef.current.cq.patchRows(keys, patch),
        refetch: () => sourceRef.current.cq.refetch(),
      }),
    [],
  );
  // Examiner protection (AXIOM E3): blurred thumbnails, Shift+B / toolbar toggle, kept across reloads.
  const mediaBlur = useViewPrefs((s) => s.mediaBlur);

  if (cq.error && cq.loadedCount === 0) {
    return (
      <ErrorState message={`썸네일을 불러오지 못했습니다. ${errorText(cq.error)}`} onRetry={cq.refetch} />
    );
  }
  if (cq.isLoading) return <LoadingCard label="썸네일을 불러오는 중…" />;
  if (sorted.length === 0) {
    if (paging) {
      return <LoadingCard label={`이미지를 찾는 중… (${scanned.toLocaleString("ko-KR")}행 검사)`} />;
    }
    return (
      <EmptyState
        title="이 노드에는 썸네일로 표시할 이미지가 없습니다."
        hint="열 보기에서 전체 행을 확인하거나 필터를 조정하세요."
      >
        {capped ? (
          <button type="button" className="view-link" onClick={loadMoreAll}>
            더 불러오기
          </button>
        ) : null}
      </EmptyState>
    );
  }

  const activeRow = sorted[activeIndex];
  return (
    <div className="view-pane thumb-view" data-media-blur={mediaBlur ? "" : undefined}>
      <div className="view-toolbar">
        <span className="view-count">
          이미지 {sorted.length.toLocaleString("ko-KR")}건 ({scanned.toLocaleString("ko-KR")}행 검사)
          {paging ? " · 불러오는 중…" : ""}
        </span>
        <label className="view-field">
          정렬 기준
          <select value={sort} onChange={(event) => setSort(event.target.value as ThumbSort)}>
            {(Object.keys(THUMB_SORT_LABELS) as ThumbSort[]).map((key) => (
              <option key={key} value={key}>
                {THUMB_SORT_LABELS[key]}
              </option>
            ))}
          </select>
        </label>
        {capped ? (
          <button type="button" className="view-link" onClick={loadMoreAll}>
            더 불러오기
          </button>
        ) : null}
        <MediaBlurToggle />
        <RelatedMediaBadge
          runId={runId ?? null}
          path={activeRow?.sourcePath ?? null}
          name={
            activeRow ? (activeRow.sourcePath ?? activeRow.title).split(/[\\/]/).pop() || activeRow.title : ""
          }
        />
      </div>
      <SelectionBar runId={runId} rows={selectedRows} patchRows={cq.patchRows} onClear={() => select([])} />
      <div
        ref={scrollRef}
        className="thumb-scroll"
        role="grid"
        aria-label={`썸네일 격자, 이미지 ${sorted.length}개`}
        aria-rowcount={rowCount}
        aria-colcount={columns}
        aria-multiselectable="true"
      >
        <div className="thumb-body" style={{ height: virtualizer.getTotalSize() }}>
          {virtualRows.map((item) => {
            const start = item.index * columns;
            const tiles = sorted.slice(start, start + columns);
            return (
              // biome-ignore lint/a11y/useFocusableInteractive: rows are not focus stops; the cells carry the roving tabindex (ARIA grid)
              <div
                key={item.key}
                role="row"
                aria-rowindex={item.index + 1}
                className="thumb-row"
                style={{ transform: `translateY(${item.start}px)`, height: TILE_HEIGHT }}
              >
                {tiles.map((row, col) => {
                  const index = start + col;
                  return (
                    <Tile
                      key={row.rowKey}
                      row={row}
                      index={index}
                      column={col}
                      runId={runId ?? ""}
                      active={index === activeIndex}
                      selected={selectedKeys.has(row.rowKey)}
                      onKeyDown={onKeyDown}
                      onClick={onClick}
                      onOpen={onOpen}
                      onFocus={onFocus}
                    />
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
