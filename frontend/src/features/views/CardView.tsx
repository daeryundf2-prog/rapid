// biome-ignore-all lint/a11y/useSemanticElements: virtualised list — cards are absolutely positioned divs (role="list"/"listitem"), not <ul>/<li>
/**
 * 행(카드) 보기 (r4 §2.3, AXIOM 행 보기): a virtualised list of row cards — title (the row's
 * representative value), 유형 — 계열 subtitle, key time and source path, the date right-aligned
 * in bold, 특이사항 / 리뷰 / 태그 chips, and inline actions (인용 · 원본 열기 · 북마크) that show
 * on hover and keyboard focus.
 *
 * A11y: `role="list"` of `role="listitem"` cards (aria-setsize / aria-posinset, since only the
 * visible cards are mounted); one card is a tab stop (roving tabindex), each card's name reads
 * its title, type, time and chips. Keys: J / ↓ next, K / ↑ previous, Home / End, PageUp /
 * PageDown, Enter = open the row in the viewer, Space = select; R/X/I/B/1–5 act on the focused
 * card through the shared review commands (the viewer target follows card focus). Keys with
 * Ctrl / Meta / Alt are left to the browser and the shell. The active card is tracked by row key
 * (a refetch that reorders or drops rows keeps it, or falls back to the nearest index); when it is
 * scrolled out of the virtual window the list itself is the tab stop and forwards focus to it, and
 * focus that was inside the list returns to the active card after a refetch.
 */

import { useVirtualizer } from "@tanstack/react-virtual";
import { type FocusEvent, type KeyboardEvent, memo, useEffect, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import type { GridRow } from "../../contracts/collection";
import { encodeRowRef } from "../../contracts/rowRef";
import { useTimezone } from "../../state/hooks";
import { formatGridTime } from "../../utils/time";
import { kindLabel } from "../derived/tables";
import { artifactTypeLabel } from "../filters/typeLabels";
import { familyForType } from "../flags/catalog";
import { GRADE_NAME, rowFlags } from "../flags/flags";
import { useSelection, useViewerTarget } from "../grid/adapter";
import { REVIEW_LABELS } from "../grid/columns/common";
import { rowSummaryFacts } from "../grid/columns/families";
import { buildViewerTarget, citationText, copyText } from "../grid/gridCommands";
import { applyReviewAction, optimisticPatch, storeNotice } from "../grid/reviewActions";
import { registerRowSource } from "../review/rowSource";
import { errorText } from "../viewer/useAsync";
import { SelectionBar } from "./SelectionBar";
import { useAutoLoad, useViewRows } from "./useViewRows";
import { EmptyState, ErrorState, LoadingCard } from "./ViewState";
import "./cardMap.css";

export const CARD_HEIGHT = 104;
/** Rows paged in automatically while the list scrolls (then "더 불러오기"). */
export const CARD_AUTOLOAD_ROWS = 5_000;
const PAGE_JUMP = 8;
const MAX_CHIPS = 4;

const allRows = () => true;

/** A key the card list handles itself: no Ctrl / Meta / Alt (those belong to the browser / shell). */
export function isPlainKey(event: { ctrlKey: boolean; metaKey: boolean; altKey: boolean }): boolean {
  return !event.ctrlKey && !event.metaKey && !event.altKey;
}

/**
 * Index of the active card: the row with `activeKey`, else the last known index clamped to the
 * list (the row disappeared after a refetch), else 0.
 */
export function resolveActiveIndex(
  rows: readonly GridRow[],
  activeKey: string | null,
  fallback: number,
): number {
  if (rows.length === 0) return 0;
  if (activeKey !== null) {
    const found = rows.findIndex((row) => row.rowKey === activeKey);
    if (found >= 0) return found;
  }
  return Math.max(0, Math.min(fallback, rows.length - 1));
}

export interface CardModel {
  title: string;
  subtitle: string;
  time: string;
  date: string;
  clock: string;
  path: string;
  chips: Array<{ id: string; label: string; tone: "flag" | "review" | "tag"; grade?: string }>;
}

/** The text of one card (pure; tested). */
export function cardModel(row: GridRow, tz: string): CardModel {
  const type = row.artifactType ?? "";
  const typeText = type ? (artifactTypeLabel(type) ?? type) : "";
  const family = familyForType(type)?.label ?? (row.ref.kind ? kindLabel(row.ref.kind) : "");
  const subtitle = [typeText, family && family !== typeText ? family : ""].filter(Boolean).join(" — ");
  // C-V3: a row whose title is only its container file ("History") is titled by its family's main
  // fact (the visited URL, the executable …), and a row without a timestamp shows its family's
  // time fact, so the card's first line is the item itself.
  const container = (row.sourcePath ?? "").split(/[\\/]/).pop() ?? "";
  const summary = rowSummaryFacts(row);
  const lead = summary.facts.find((fact) => fact.value && fact.value !== container)?.value ?? "";
  const ownTitle = row.title && row.title !== container ? row.title : "";
  const time = row.timestamp ? formatGridTime(row.timestamp, tz) : (summary.time?.value ?? "");
  const [date = "", clock = ""] = time.split(" ");
  const chips: CardModel["chips"] = [];
  for (const flag of rowFlags(row).slice(0, MAX_CHIPS)) {
    chips.push({
      id: `flag:${flag.id}`,
      label: `${flag.grade} ${flag.label}`,
      tone: "flag",
      grade: flag.grade,
    });
  }
  if (row.reviewStatus)
    chips.push({ id: `review:${row.reviewStatus}`, label: REVIEW_LABELS[row.reviewStatus], tone: "review" });
  for (const tag of row.tags.slice(0, MAX_CHIPS)) chips.push({ id: `tag:${tag}`, label: tag, tone: "tag" });
  return {
    title: ownTitle || lead || row.title || container || "(제목 없음)",
    subtitle,
    time,
    date,
    clock,
    path: row.sourcePath ?? "",
    chips,
  };
}

/** Accessible name of a card: title, subtitle, time, chips (grade names spelled out), selection. */
export function cardAccessibleName(model: CardModel, selected: boolean): string {
  const chips = model.chips.map((chip) =>
    chip.tone === "flag" && chip.grade
      ? `특이사항 ${GRADE_NAME[chip.grade as keyof typeof GRADE_NAME] ?? chip.grade} ${chip.label.slice(2)}`
      : chip.label,
  );
  return [
    model.title,
    model.subtitle,
    model.time ? `시각 ${model.time}` : "시각 없음",
    ...chips,
    selected ? "선택됨" : "",
  ]
    .filter(Boolean)
    .join(", ");
}

const Card = memo(function Card({
  row,
  model,
  index,
  total,
  top,
  active,
  selected,
  onKeyDown,
  onFocus,
  onSelect,
  onOpen,
  onCite,
  onBookmark,
}: {
  row: GridRow;
  model: CardModel;
  index: number;
  total: number;
  top: number;
  active: boolean;
  selected: boolean;
  onKeyDown: (event: KeyboardEvent<HTMLDivElement>, index: number) => void;
  onFocus: (index: number) => void;
  onSelect: (index: number) => void;
  onOpen: (index: number) => void;
  onCite: (row: GridRow) => void;
  onBookmark: (row: GridRow) => void;
}) {
  const actionTab = active ? 0 : -1;
  return (
    <div
      role="listitem"
      className="card-item"
      aria-setsize={total}
      aria-posinset={index + 1}
      aria-label={cardAccessibleName(model, selected)}
      aria-current={active ? "true" : undefined}
      tabIndex={active ? 0 : -1}
      data-card-index={index}
      data-selected={selected || undefined}
      data-review={row.reviewStatus ?? undefined}
      style={{ transform: `translateY(${top}px)`, height: CARD_HEIGHT }}
      onKeyDown={(event) => onKeyDown(event, index)}
      onFocus={(event) => {
        if (event.target === event.currentTarget) onFocus(index);
      }}
      onClick={(event) => {
        if ((event.target as HTMLElement).closest("button")) return;
        if (event.ctrlKey || event.metaKey) onSelect(index);
        else onFocus(index);
      }}
      onDoubleClick={() => onOpen(index)}
    >
      <div className="card-main">
        <p className="card-title" title={model.title}>
          {model.title}
        </p>
        {model.subtitle ? <p className="card-subtitle">{model.subtitle}</p> : null}
        <p className="card-meta">
          <span className="card-time">{model.time || "시각 없음"}</span>
          {model.path ? (
            <span className="card-path mono" title={model.path}>
              {model.path}
            </span>
          ) : null}
        </p>
        {model.chips.length ? (
          <ul className="card-chips" aria-hidden="true">
            {model.chips.map((chip) => (
              <li key={chip.id} className={`card-chip is-${chip.tone}`} data-grade={chip.grade}>
                {chip.label}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
      <div className="card-side">
        <span className="card-date">{model.date || "—"}</span>
        {model.clock ? <span className="card-clock">{model.clock}</span> : null}
        <span className="card-actions">
          <button
            type="button"
            className="card-action"
            tabIndex={actionTab}
            aria-label={`${model.title} 인용 복사`}
            title="인용 복사"
            onClick={() => onCite(row)}
          >
            인용
          </button>
          <button
            type="button"
            className="card-action"
            tabIndex={actionTab}
            aria-label={`${model.title} 원본 열기`}
            title="뷰어에서 원본 열기 (Enter)"
            onClick={() => onOpen(index)}
          >
            원본 열기
          </button>
          <button
            type="button"
            className="card-action"
            tabIndex={actionTab}
            aria-label={`${model.title} 북마크 태그`}
            title="북마크 태그 (B)"
            onClick={() => onBookmark(row)}
          >
            태그
          </button>
        </span>
      </div>
    </div>
  );
});

export function CardView() {
  const { cq, rows, runId } = useViewRows({ predicate: allRows, textFilter: true });
  const { timezone } = useTimezone();
  const { selectedKeys, select } = useSelection();
  const { target, publishFocusedRow, requestFocus } = useViewerTarget();
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const models = useMemo(() => rows.map((row) => cardModel(row, timezone)), [rows, timezone]);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => CARD_HEIGHT,
    overscan: 4,
    initialRect: { width: 800, height: 600 },
  });
  const items = virtualizer.getVirtualItems();
  const lastVisible = items.at(-1)?.index ?? 0;
  // The active card by row key (a refetch may reorder / drop rows); the index is the fallback.
  const [activeKey, setActiveKey] = useState<string | null>(null);
  const lastIndex = useRef(0);
  const activeIndex = resolveActiveIndex(rows, activeKey, lastIndex.current);
  lastIndex.current = activeIndex;
  const pendingFocus = useRef<number | null>(null);
  // DOM focus was inside the list (restored onto the active card after a refetch).
  const focusInside = useRef(false);
  const capped = useAutoLoad(cq, rows.length < lastVisible + 20, CARD_AUTOLOAD_ROWS);
  const activeMounted = items.some((item) => item.index === activeIndex);

  const setActive = (index: number) => {
    lastIndex.current = index;
    setActiveKey(rows[index]?.rowKey ?? null);
  };

  // Move DOM focus onto the target card once it is rendered (cards are virtualised).
  useEffect(() => {
    if (pendingFocus.current === null) return;
    const el = scrollRef.current?.querySelector<HTMLElement>(`[data-card-index="${pendingFocus.current}"]`);
    if (el) {
      pendingFocus.current = null;
      el.focus();
    }
  });

  // Focus leaving for another element of the page ends "focus inside" (a removed card does not).
  useEffect(() => {
    const onFocusIn = (event: globalThis.FocusEvent) => {
      if (!scrollRef.current?.contains(event.target as Node)) focusInside.current = false;
    };
    const onPointerDown = (event: PointerEvent) => {
      if (!scrollRef.current?.contains(event.target as Node)) focusInside.current = false;
    };
    document.addEventListener("focusin", onFocusIn);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("focusin", onFocusIn);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, []);

  // The row ref this list last handed the viewer (the viewer "follows" the list while it shows it).
  const published = useRef<string | null>(null);
  const publish = (row: GridRow | undefined) => {
    if (!row || !runId) return;
    published.current = encodeRowRef(row.ref);
    if (target?.runId === runId && encodeRowRef(target.ref) === published.current) return;
    publishFocusedRow(row, buildViewerTarget(runId, row));
  };

  // New rows (refetch, more pages): the viewer follows the active card if it changed under it,
  // and focus that was inside the list (on a card that went away) returns to the active card.
  const activeRow = rows[activeIndex];
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-run only when the rows change
  useEffect(() => {
    const following =
      target?.runId === runId && published.current !== null && encodeRowRef(target.ref) === published.current;
    if (activeKey !== null && activeRow && following) publish(activeRow);
    const list = scrollRef.current;
    if (focusInside.current && list && !list.contains(document.activeElement)) {
      pendingFocus.current = activeIndex;
      virtualizer.scrollToIndex(activeIndex, { align: "auto" });
      list.querySelector<HTMLElement>(`[data-card-index="${activeIndex}"]`)?.focus();
    }
  }, [rows]);

  const focusCard = (index: number) => {
    const next = Math.max(0, Math.min(index, rows.length - 1));
    setActive(next);
    pendingFocus.current = next;
    virtualizer.scrollToIndex(next, { align: "auto" });
  };

  // The list is the tab stop while the active card is outside the virtual window: forward focus.
  const onListFocus = (event: FocusEvent<HTMLDivElement>) => {
    focusInside.current = true;
    if (event.target === event.currentTarget && !activeMounted) focusCard(activeIndex);
  };

  const toggle = (index: number) => {
    const row = rows[index];
    if (!row) return;
    const next = new Set(selectedKeys);
    if (next.has(row.rowKey)) next.delete(row.rowKey);
    else next.add(row.rowKey);
    select([...next]);
  };

  const onOpen = (index: number) => {
    setActive(index);
    publish(rows[index]);
    requestFocus();
  };

  const onFocus = (index: number) => {
    setActive(index);
    publish(rows[index]);
  };

  const onCite = (row: GridRow) => {
    const text = citationText(row, runId);
    copyText(text).then(
      () => announce("인용을 복사했습니다"),
      () => announce("인용을 복사하지 못했습니다", { politeness: "assertive" }),
    );
  };

  const onBookmark = (row: GridRow) => {
    if (!runId) return;
    const rollback = cq.patchRows([row.rowKey], optimisticPatch("bookmark"));
    applyReviewAction(runId, [row], "bookmark").then(
      (result) => announce(`북마크: ${result.applied}건 처리했습니다.${storeNotice(result)}`),
      (error: unknown) => {
        rollback();
        announce(`북마크 처리에 실패했습니다. ${error instanceof Error ? error.message : String(error)}`, {
          politeness: "assertive",
        });
      },
    );
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>, index: number) => {
    if (event.target !== event.currentTarget) return; // keys inside an action button stay with it
    if (!isPlainKey(event)) return; // Ctrl/Meta/Alt shortcuts belong to the browser and the shell
    const key = event.key;
    let next: number | null = null;
    if (key === "ArrowDown" || key === "j" || key === "J") next = index + 1;
    else if (key === "ArrowUp" || key === "k" || key === "K") next = index - 1;
    else if (key === "Home") next = 0;
    else if (key === "End") next = rows.length - 1;
    else if (key === "PageDown") next = index + PAGE_JUMP;
    else if (key === "PageUp") next = index - PAGE_JUMP;
    if (next !== null) {
      event.preventDefault();
      event.stopPropagation();
      focusCard(next);
      return;
    }
    if (key === "Enter") {
      event.preventDefault();
      event.stopPropagation();
      onOpen(index);
    } else if (key === " ") {
      event.preventDefault();
      event.stopPropagation();
      toggle(index);
    } else if (key === "Escape" && selectedKeys.size > 0) {
      event.preventDefault();
      select([]);
    }
  };

  const selectedRows = useMemo(() => rows.filter((r) => selectedKeys.has(r.rowKey)), [rows, selectedKeys]);
  // Shell review tools (태그 전파, digit tag keys) act on this selection too.
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

  if (cq.error && cq.loadedCount === 0) {
    return <ErrorState message={`행을 불러오지 못했습니다. ${errorText(cq.error)}`} onRetry={cq.refetch} />;
  }
  if (cq.isLoading) return <LoadingCard label="행을 불러오는 중…" />;
  if (rows.length === 0) {
    return (
      <EmptyState title="조건에 맞는 행이 없습니다." hint="조건을 줄이거나 열 보기에서 전체 행을 확인하세요.">
        {capped ? (
          <button type="button" className="view-link" onClick={() => cq.loadMore()}>
            더 불러오기
          </button>
        ) : null}
      </EmptyState>
    );
  }

  const total = cq.total ?? null;
  // Unknown total (a capped server scan) while more pages exist: "n건 이상".
  const atLeast = total === null && cq.canLoadMore;
  return (
    <div className="view-pane card-view">
      <div className="view-toolbar">
        <span className="view-count">
          {`카드 ${rows.length.toLocaleString("ko-KR")}건${atLeast ? " 이상" : ""}`}
          {total !== null && total > cq.loadedCount
            ? ` (전체 ${total.toLocaleString("ko-KR")}건 중 불러온 행)`
            : ""}
          {cq.isFetching ? " · 불러오는 중…" : ""}
        </span>
        <span className="view-hint">J/K 이동 · Enter 원본 열기 · Space 선택</span>
        {capped ? (
          <button type="button" className="view-link" onClick={() => cq.loadMore()}>
            더 불러오기
          </button>
        ) : null}
      </div>
      <SelectionBar runId={runId} rows={selectedRows} patchRows={cq.patchRows} onClear={() => select([])} />
      <div
        ref={scrollRef}
        className="card-scroll"
        role="list"
        aria-label={`행 카드 목록, ${rows.length.toLocaleString("ko-KR")}건${atLeast ? " 이상" : ""}`}
        data-testid="card-list"
        tabIndex={activeMounted ? undefined : 0}
        onFocus={onListFocus}
      >
        <div className="card-body" style={{ height: virtualizer.getTotalSize() }}>
          {items.map((item) => {
            const row = rows[item.index] as GridRow;
            return (
              <Card
                key={row.rowKey}
                row={row}
                model={models[item.index] as CardModel}
                index={item.index}
                total={rows.length}
                top={item.start}
                active={item.index === activeIndex}
                selected={selectedKeys.has(row.rowKey)}
                onKeyDown={onKeyDown}
                onFocus={onFocus}
                onSelect={toggle}
                onOpen={onOpen}
                onCite={onCite}
                onBookmark={onBookmark}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}
