// biome-ignore-all lint/a11y/useSemanticElements: ARIA grid of CSS-grid rows (like DataGrid), not a <table>
// biome-ignore-all lint/a11y/useFocusableInteractive: roving tabindex; only the focused row is focusable by design
/**
 * 통합 보기 pane (axiom-adoption §3.2): one derived table (사람 식별자 · 장치 식별자 · 접근 경로 ·
 * 첨부 · 자격 증명/토큰 · URL 분류) as a keyboard grid — search box, source-kind chips, sort — and
 * the selected value's original rows; a row opens its family grid with that record selected.
 *
 * Keyboard: ↓/J and ↑/K move one value, Home/End jump, Space selects, Enter selects and moves to
 * the original rows (Esc there returns to the value). Every control has a Korean accessible name;
 * results are announced in the app's one polite live region.
 */

import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import {
  type KeyboardEvent,
  type RefObject,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { announce } from "../../a11y";
import { ApiError } from "../../api/client";
import { CommandButton } from "../../commands/CommandButton";
import type { Route } from "../../router";
import { useRoute, useTimezone } from "../../state/hooks";
import { formatGridTime } from "../../utils/time";
import {
  DERIVED_TABLE_IDS,
  type DerivedRow,
  type DerivedSample,
  type DerivedSort,
  type DerivedTableId,
  derivedMetaKey,
  fetchDerivedMeta,
  fetchDerivedPage,
  fetchDerivedValueRows,
  isDerivedTable,
} from "./api";
import { DerivedGraph } from "./DerivedGraph";
import { useDerivedStore } from "./store";
import {
  DERIVED_COLUMNS,
  DERIVED_TABLE_HINTS,
  DERIVED_TABLE_LABELS,
  kindLabel,
  rowAccessibleName,
  SORT_LABELS,
  sampleLabel,
  sampleRoute,
} from "./tables";
import "./derived.css";

const SEARCH_DEBOUNCE_MS = 250;
const PAGE_JUMP = 10;
const collator = new Intl.Collator("ko");

function useDebounced(value: string, delay: number): string {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return error instanceof Error ? error.message : "통합 보기를 불러오지 못했습니다";
}

/**
 * One pane per (run, table): switching tables remounts it, so the search box, its debounced value
 * and the kind chip never carry the previous table's search into the new table's URL (`q=`).
 */
export function DerivedPane() {
  const { route } = useRoute();
  const table: DerivedTableId = isDerivedTable(route.kind) ? route.kind : "people";
  return <DerivedTablePane key={`${route.runId ?? ""}|${table}`} />;
}

function DerivedTablePane() {
  const { route, navigate, patchRoute } = useRoute();
  const runId = route.runId ?? "";
  const table: DerivedTableId = isDerivedTable(route.kind) ? route.kind : "people";
  const label = DERIVED_TABLE_LABELS[table];
  const { timezone } = useTimezone();
  const headingId = useId();
  const rowsHeadingId = useId();

  const [search, setSearch] = useState(route.q ?? "");
  const q = useDebounced(search.trim(), SEARCH_DEBOUNCE_MS);
  const [kind, setKind] = useState<string | undefined>(undefined);
  const [sort, setSort] = useState<DerivedSort>("count");
  const [focusIdx, setFocusIdx] = useState(0);
  const gridRef = useRef<HTMLDivElement>(null);
  const rowsPanelRef = useRef<HTMLElement>(null);
  // Enter on a value: focus moves to its original rows once they load.
  const pendingPanelFocus = useRef(false);

  const selected = useDerivedStore((s) => s.selected);
  const select = useDerivedStore((s) => s.select);
  const graphMode = useDerivedStore((s) => s.graphMode);
  const setGraphMode = useDerivedStore((s) => s.setGraphMode);
  const selectedHere = selected && selected.runId === runId && selected.table === table ? selected : null;

  // A new table (or case) mounts a new pane (keyed below), so it starts clean: the new route's
  // search (none from the tabs), no kind chip, count order, first row, no selection. Coming back from
  // an original row to the same table keeps the chosen value (its rows panel reopens).
  // biome-ignore lint/correctness/useExhaustiveDependencies: on mount (table / run) only
  useEffect(() => {
    const current = useDerivedStore.getState().selected;
    if (!current || current.runId !== runId || current.table !== table) select(null);
  }, [table, runId]);

  // `q` rides in the URL (refresh / copied link keep the search) once the debounce settles — never
  // the previous table's search while the box has just been reset.
  const settled = search.trim() === q;
  useEffect(() => {
    if (settled && (route.q ?? "") !== q) patchRoute({ q: q || undefined }, { replace: true });
  }, [settled, q, route.q, patchRoute]);

  const meta = useQuery({
    queryKey: derivedMetaKey(runId),
    queryFn: ({ signal }) => fetchDerivedMeta(runId, signal),
    enabled: Boolean(runId),
    retry: false,
  });
  const source = meta.data?.source ?? null;
  const summary = meta.data?.tables.find((entry) => entry.table === table);

  const pages = useInfiniteQuery({
    queryKey: ["derived-page", runId, source?.analysis_id ?? "", table, q, kind ?? "", sort],
    queryFn: ({ pageParam, signal }) =>
      fetchDerivedPage(runId, table, { q, kind, sort, after: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    enabled: Boolean(runId && source),
    retry: false,
  });
  const rows = useMemo(() => pages.data?.pages.flatMap((page) => page.rows) ?? [], [pages.data]);
  const first = pages.data?.pages[0];
  const matched = first?.matched ?? null;
  const total = first?.total ?? summary?.rows ?? null;
  const clampedFocus = rows.length ? Math.min(focusIdx, rows.length - 1) : -1;

  // Results are announced once per finished query (not per page).
  const announced = useRef<string>("");
  useEffect(() => {
    if (!first) return;
    const key = `${table}|${q}|${kind ?? ""}|${sort}|${first.matched}`;
    if (announced.current === key) return;
    announced.current = key;
    const filtered = q || kind;
    announce(
      filtered
        ? `${label}: ${first.matched.toLocaleString("ko-KR")}개 값이 조건에 맞습니다`
        : `${label}: 값 ${first.total.toLocaleString("ko-KR")}개`,
    );
  }, [first, table, q, kind, sort, label]);

  // Commands: load more / focus the original rows.
  const { fetchNextPage, hasNextPage, isFetchingNextPage } = pages;
  const setLoadMore = useDerivedStore((s) => s.setLoadMore);
  const setFocusRows = useDerivedStore((s) => s.setFocusRows);
  const loadMore = useCallback(() => {
    if (hasNextPage && !isFetchingNextPage) void fetchNextPage();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);
  useEffect(() => {
    setLoadMore(hasNextPage ? loadMore : null);
    return () => setLoadMore(null);
  }, [hasNextPage, loadMore, setLoadMore]);
  const focusRows = useCallback(() => {
    rowsPanelRef.current
      ?.querySelector<HTMLElement>("button.derived-sample, .derived-graph-node[tabindex='0'], [tabindex='0']")
      ?.focus();
  }, []);
  useEffect(() => {
    setFocusRows(focusRows);
    return () => setFocusRows(null);
  }, [focusRows, setFocusRows]);

  // Infinite scroll: the sentinel under the last row asks for the next page.
  const sentinelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const target = sentinelRef.current;
    if (!target || typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) loadMore();
    });
    observer.observe(target);
    return () => observer.disconnect();
  }, [loadMore]);

  const chooseRow = useCallback(
    (index: number) => {
      const row = rows[index];
      if (!row) return;
      setFocusIdx(index);
      select({ runId, table, row });
    },
    [rows, runId, table, select],
  );

  const focusRow = (index: number) => {
    const next = Math.max(0, Math.min(index, rows.length - 1));
    setFocusIdx(next);
    gridRef.current?.querySelector<HTMLElement>(`[data-row-index="${next}"]`)?.focus();
    if (next >= rows.length - 5) loadMore();
  };

  const onRowKey = (event: KeyboardEvent<HTMLDivElement>, index: number) => {
    const key = event.key;
    if (key === "ArrowDown" || key === "j" || key === "J") focusRow(index + 1);
    else if (key === "ArrowUp" || key === "k" || key === "K") focusRow(index - 1);
    else if (key === "Home") focusRow(0);
    else if (key === "End") focusRow(rows.length - 1);
    else if (key === "PageDown") focusRow(index + PAGE_JUMP);
    else if (key === "PageUp") focusRow(index - PAGE_JUMP);
    else if (key === " ") chooseRow(index);
    else if (key === "Enter") {
      chooseRow(index);
      // The panel renders its rows once the value's samples load; focus follows then.
      pendingPanelFocus.current = true;
    } else return;
    event.preventDefault();
    event.stopPropagation();
  };

  const kindChips = useMemo(() => {
    const byKind = summary?.by_kind ?? {};
    return Object.entries(byKind)
      .map(([id, n]) => ({ id, label: kindLabel(id), count: n }))
      .sort((a, b) => collator.compare(a.label, b.label));
  }, [summary]);

  const columns = DERIVED_COLUMNS[table];
  const template = columns.map((column) => column.width).join(" ");

  if (!runId) return null;

  if (meta.isPending) {
    return (
      <section className="derived-pane" aria-busy="true" aria-labelledby={headingId}>
        <h2 id={headingId} className="derived-title">
          통합 보기 · {label}
        </h2>
        <p className="derived-hint">통합 보기를 불러오는 중…</p>
      </section>
    );
  }

  if (meta.isError || !source) {
    const reason = meta.isError ? errorText(meta.error) : (meta.data?.reason ?? "통합 보기 결과가 없습니다.");
    return (
      <section className="derived-pane" aria-labelledby={headingId}>
        <h2 id={headingId} className="derived-title">
          통합 보기 · {label}
        </h2>
        <p className="derived-hint">{reason}</p>
        <div className="derived-actions">
          <CommandButton command="derived.rebuild" label="통합 보기 만들기" variant="primary" showReason />
        </div>
      </section>
    );
  }

  return (
    <section className="derived-pane" aria-labelledby={headingId} data-testid="derived-pane">
      <div className="derived-head">
        <h2 id={headingId} className="derived-title">
          통합 보기 · {label}
        </h2>
        <p className="derived-hint">{DERIVED_TABLE_HINTS[table]}</p>
        <nav className="derived-tabs" aria-label="통합 보기 표">
          {DERIVED_TABLE_IDS.map((id) => {
            const entry = meta.data?.tables.find((t) => t.table === id);
            return (
              <button
                key={id}
                type="button"
                className="derived-tab"
                aria-current={id === table ? "page" : undefined}
                onClick={() => navigate({ runId, collection: "derived", kind: id })}
              >
                {DERIVED_TABLE_LABELS[id]}
                <span className="derived-tab-count">{(entry?.rows ?? 0).toLocaleString("ko-KR")}</span>
              </button>
            );
          })}
        </nav>
        <p className="derived-status">
          {total !== null ? `값 ${total.toLocaleString("ko-KR")}개` : ""}
          {summary ? ` · 출현 ${summary.occurrences.toLocaleString("ko-KR")}건` : ""}
          {matched !== null && (q || kind) ? ` · 조건 일치 ${matched.toLocaleString("ko-KR")}개` : ""}
          {` · 불러온 ${rows.length.toLocaleString("ko-KR")}개`}
          {source.generated_at ? ` · 생성 ${formatGridTime(source.generated_at, timezone)}` : ""}
        </p>
        {source.coverage === "partial" ? (
          <p className="derived-notice" role="note">
            {source.reason ?? "통합 보기가 일부만 계산되었습니다"}
          </p>
        ) : null}
        {summary?.capped ? (
          <p className="derived-notice" role="note">
            {`상한에 도달해 새 값 ${summary.dropped_values.toLocaleString("ko-KR")}개를 더하지 않았습니다(${
              summary.cap_reason === "memory" ? "메모리 상한" : "값 수 상한"
            }). 이미 있는 값의 건수는 끝까지 셌습니다.`}
          </p>
        ) : null}
      </div>
      <div className="derived-toolbar" role="toolbar" aria-label="통합 보기 도구">
        <input
          type="search"
          className="derived-search"
          aria-label="값 검색"
          placeholder="값 검색 (값·정규화 값)"
          value={search}
          maxLength={200}
          onChange={(event) => setSearch(event.target.value)}
        />
        <label className="derived-sort">
          <span>정렬</span>
          <select
            aria-label="정렬"
            value={sort}
            onChange={(event) => setSort(event.target.value as DerivedSort)}
          >
            {(Object.keys(SORT_LABELS) as DerivedSort[]).map((id) => (
              <option key={id} value={id}>
                {SORT_LABELS[id]}
              </option>
            ))}
          </select>
        </label>
        <CommandButton command="derived.copy-citation" label="인용 복사" />
        <div className="segmented derived-mode" role="group" aria-label="값 패널 보기">
          <button type="button" aria-pressed={!graphMode} onClick={() => setGraphMode(false)}>
            원본 행
          </button>
          <button
            type="button"
            aria-pressed={graphMode}
            title="값 → 원본 행 → 그 행의 다른 식별자 값 (2단계)"
            onClick={() => setGraphMode(true)}
          >
            연결 그래프
          </button>
        </div>
        <CommandButton command="derived.rebuild" label="다시 만들기" variant="ghost" />
      </div>
      {kindChips.length > 1 ? (
        <div className="derived-chips" role="group" aria-label="출처 종류 필터">
          <button
            type="button"
            className="derived-chip"
            aria-pressed={!kind}
            onClick={() => setKind(undefined)}
          >
            전체
          </button>
          {kindChips.map((chip) => (
            <button
              key={chip.id}
              type="button"
              className="derived-chip"
              aria-pressed={kind === chip.id}
              aria-label={`${chip.label} ${chip.count.toLocaleString("ko-KR")}건만 보기`}
              onClick={() => setKind(kind === chip.id ? undefined : chip.id)}
            >
              {chip.label}
              <span className="derived-chip-count">{chip.count.toLocaleString("ko-KR")}</span>
            </button>
          ))}
        </div>
      ) : null}
      <div className="derived-body" data-graph={graphMode ? "" : undefined}>
        <div className="derived-grid-wrap">
          <div
            ref={gridRef}
            role="grid"
            className="derived-grid"
            aria-label={`${label} 표`}
            aria-rowcount={(matched ?? rows.length) + 1}
            aria-colcount={columns.length}
            aria-busy={pages.isFetching}
            data-testid="derived-grid"
            style={{ gridTemplateColumns: template }}
          >
            <div role="row" aria-rowindex={1} className="derived-row derived-row-head">
              {columns.map((column) => (
                <div key={column.id} role="columnheader" className="derived-cell derived-head-cell">
                  {column.header}
                </div>
              ))}
            </div>
            {rows.map((row, index) => (
              <div
                key={row.normalized}
                role="row"
                aria-rowindex={index + 2}
                aria-selected={selectedHere?.row.normalized === row.normalized}
                aria-label={rowAccessibleName(table, row, timezone)}
                tabIndex={index === clampedFocus ? 0 : -1}
                data-row-index={index}
                className="derived-row"
                onClick={() => chooseRow(index)}
                onFocus={() => setFocusIdx(index)}
                onKeyDown={(event) => onRowKey(event, index)}
              >
                {columns.map((column) => {
                  const text = column.text(row, timezone);
                  return (
                    <div
                      key={column.id}
                      role="gridcell"
                      className={`derived-cell${column.mono ? " derived-mono" : ""}${column.numeric ? " derived-num" : ""}`}
                      title={text}
                    >
                      {text || <span className="grid-cell-empty">—</span>}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          {pages.isPending ? <p className="derived-hint">값을 불러오는 중…</p> : null}
          {pages.isError ? (
            <p className="derived-notice" role="alert">
              {errorText(pages.error)}
            </p>
          ) : null}
          {!pages.isPending && !pages.isError && rows.length === 0 ? (
            <p className="derived-hint">
              {q || kind ? "조건에 맞는 값이 없습니다." : "이 표에는 값이 없습니다."}
            </p>
          ) : null}
          <div ref={sentinelRef} className="derived-sentinel" aria-hidden="true" />
          {hasNextPage ? (
            <div className="derived-actions">
              <CommandButton command="derived.load-more" label="값 더 불러오기" />
            </div>
          ) : null}
        </div>
        <OriginalRows
          panelRef={rowsPanelRef}
          headingId={rowsHeadingId}
          runId={runId}
          table={table}
          row={selectedHere?.row ?? null}
          timezone={timezone}
          pendingFocus={pendingPanelFocus}
          onBack={() =>
            gridRef.current?.querySelector<HTMLElement>(`[data-row-index="${clampedFocus}"]`)?.focus()
          }
          onOpen={(sample) => {
            const target = sampleRoute(runId, sample);
            if (target.row && selectedHere) {
              useDerivedStore.getState().rememberOrigin(runId, target.row, {
                table,
                normalized: selectedHere.row.normalized,
              });
            }
            navigate(target);
          }}
          onNavigate={(target) => {
            if (target.row && selectedHere) {
              useDerivedStore.getState().rememberOrigin(runId, target.row, {
                table,
                normalized: selectedHere.row.normalized,
              });
            }
            navigate(target);
          }}
        />
      </div>
    </section>
  );
}

function OriginalRows({
  panelRef,
  headingId,
  runId,
  table,
  row,
  timezone,
  pendingFocus,
  onBack,
  onOpen,
  onNavigate,
}: {
  panelRef: RefObject<HTMLElement | null>;
  headingId: string;
  runId: string;
  table: DerivedTableId;
  row: DerivedRow | null;
  timezone: string;
  pendingFocus: RefObject<boolean>;
  onBack: () => void;
  onOpen: (sample: DerivedSample) => void;
  onNavigate: (route: Route) => void;
}) {
  const graphMode = useDerivedStore((s) => s.graphMode);
  const detail = useQuery({
    queryKey: ["derived-rows", runId, table, row?.normalized ?? ""],
    queryFn: ({ signal }) => fetchDerivedValueRows(runId, table, row?.normalized ?? "", signal),
    enabled: Boolean(row) && !graphMode,
    retry: false,
  });
  const samples = detail.data?.samples ?? [];
  useEffect(() => {
    if (!pendingFocus.current || !samples.length) return;
    pendingFocus.current = false;
    panelRef.current?.querySelector<HTMLElement>("button.derived-sample")?.focus();
  }, [samples, pendingFocus, panelRef]);

  const onKey = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      onBack();
      return;
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const buttons = [...(panelRef.current?.querySelectorAll<HTMLElement>("button.derived-sample") ?? [])];
    const at = buttons.indexOf(document.activeElement as HTMLElement);
    const next = buttons[at + (event.key === "ArrowDown" ? 1 : -1)];
    if (next) {
      event.preventDefault();
      next.focus();
    }
  };

  return (
    <aside
      ref={panelRef}
      className="derived-rows"
      aria-labelledby={headingId}
      data-testid="derived-rows"
      onKeyDown={onKey}
    >
      <h3 id={headingId} className="derived-rows-title">
        {graphMode ? "연결 그래프" : "원본 행"}
        {row ? ` — ${row.value}` : ""}
      </h3>
      {!row ? (
        <p className="derived-hint">
          {graphMode
            ? "값을 고르면(클릭·Space·Enter) 값 → 원본 행 → 그 행의 다른 식별자 값을 2단계 그래프로 보여 줍니다."
            : "값을 고르면(클릭·Space·Enter) 그 값이 나온 원본 행이 여기에 나옵니다."}
        </p>
      ) : null}
      {row && graphMode ? (
        <DerivedGraph
          runId={runId}
          table={table}
          normalized={row.normalized}
          timezone={timezone}
          onNavigate={onNavigate}
        />
      ) : null}
      {row && !graphMode ? (
        <p className="derived-hint">
          {`건수 ${row.count.toLocaleString("ko-KR")} · 출처 ${Object.keys(row.families).length}개 계열 · 표본 최대 20행(계열마다 고르게)`}
        </p>
      ) : null}
      {row && table === "credentials" ? (
        <p className="derived-hint">원문은 저장하지 않습니다. 가린 값·길이·SHA-256으로만 대조하세요.</p>
      ) : null}
      {row && table === "urls" && row.examples?.length ? (
        <ul className="derived-examples" aria-label="URL 예">
          {row.examples.map((example) => (
            <li key={example} className="derived-mono">
              {example}
            </li>
          ))}
        </ul>
      ) : null}
      {detail.isPending && row && !graphMode ? <p className="derived-hint">원본 행을 불러오는 중…</p> : null}
      {detail.isError ? (
        <p className="derived-notice" role="alert">
          {errorText(detail.error)}
        </p>
      ) : null}
      {samples.length && !graphMode ? (
        <ul className="derived-samples" aria-label="원본 행 목록 (선택하면 해당 계열 표로 이동)">
          {samples.map((sample) => {
            const text = sampleLabel(sample, timezone);
            return (
              <li key={`${sample.kind}:${sample.record_index}:${sample.field}`}>
                <button
                  type="button"
                  className="derived-sample"
                  aria-label={`${text} — 원본 행 열기`}
                  title="해당 계열 표로 이동해 이 행을 선택합니다"
                  onClick={() => onOpen(sample)}
                >
                  {text}
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}
    </aside>
  );
}
