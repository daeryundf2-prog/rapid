/**
 * Filter bar (X19, visual-polish S1/S2). One line: the text filter, a "필터" button that opens
 * a popover (time range with presets, type, status, tag, extension, path) and the applied
 * conditions as removable chips. Stage toolbars (S2) swap the popover for the controls that
 * stage needs: the review board gets review status + tag, the report gets the output kind.
 * The URL stays the source of truth (filterStore / filterModel are unchanged).
 */

import { type ReactNode, type RefObject, useEffect, useId, useRef, useState } from "react";
import { Popover } from "../../components/Popover";
import type { ReviewStatus } from "../../contracts/collection";
import { Icon } from "../../icons";
import { REVIEW_LABELS } from "../grid/columns/common";
import {
  activeChips,
  activePreset,
  type FilterChip,
  type FilterState,
  hasActiveFilters,
  presetRange,
  removeChip,
  TIME_PRESET_LABELS,
  type TimePreset,
  toInputValue,
} from "./filterModel";
import { type FilterReport, useFilterStore } from "./filterStore";
import "./filters.css";
import { typeOptionsFor } from "./typeLabels";

const STATUS_ORDER: ReviewStatus[] = ["relevant", "needs-review", "excluded", "include-in-report"];
const COMMIT_DEBOUNCE_MS = 250;
const SEARCH_DEBOUNCE_MS = 200;

/** Toolbar of a stage (visual-polish S2): 탐색 = full filter popover, 검토 / 보고 = their own controls. */
export type FilterBarVariant = "explore" | "review" | "report";

/** Text input that commits on a debounce, on Enter and on blur; follows external value changes. */
function CommitInput(props: {
  label: string;
  value: string;
  placeholder?: string;
  onCommit: (value: string) => void;
  list?: string;
  className?: string;
  /** Multi-value inputs add a chip on Enter and clear themselves. */
  clearOnEnter?: boolean;
  /** Label shown above the input (popover) instead of beside it (toolbar). */
  stacked?: boolean;
}) {
  const [text, setText] = useState(props.value);
  const committed = useRef(props.value);
  const { onCommit, clearOnEnter } = props;
  useEffect(() => {
    if (props.value !== committed.current) {
      committed.current = props.value;
      setText(props.value);
    }
  }, [props.value]);
  useEffect(() => {
    if (clearOnEnter || text === committed.current) return;
    const timer = setTimeout(() => {
      committed.current = text;
      onCommit(text);
    }, COMMIT_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [text, onCommit, clearOnEnter]);
  return (
    <label className={`filter-field${props.stacked ? " is-stacked" : ""} ${props.className ?? ""}`}>
      <span className={props.stacked ? "popover-title" : "sr-only"}>{props.label}</span>
      <input
        type="text"
        value={text}
        list={props.list}
        placeholder={props.placeholder}
        onChange={(event) => setText(event.target.value)}
        onKeyDown={(event) => {
          if (event.key !== "Enter" && !(clearOnEnter && event.key === ",")) return;
          event.preventDefault();
          const value = text.trim();
          if (!value && clearOnEnter) return;
          committed.current = clearOnEnter ? "" : value;
          onCommit(value);
          if (clearOnEnter) setText("");
        }}
        onBlur={() => {
          if (clearOnEnter || text === committed.current) return;
          committed.current = text;
          onCommit(text);
        }}
      />
    </label>
  );
}

export interface FilterBarProps {
  filterRef: RefObject<HTMLInputElement | null>;
  query: string;
  onQuery: (q: string) => void;
  onReturnToGrid: () => void;
  variant?: FilterBarVariant;
  /** 검토: the board's review status (route `status`) and its setter. */
  reviewStatus?: ReviewStatus;
  onReviewStatus?: (status: ReviewStatus | undefined) => void;
  /** 보고: the output kinds the loaded rows carry (종류 choices). */
  kindOptions?: string[];
  /** Controls placed before the search field (the view switch of the column view). */
  lead?: ReactNode;
}

function toggle<T extends string>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/** Number of filter conditions the popover sets (chips count). */
function popoverCount(filters: FilterState): number {
  return (
    (filters.from || filters.to ? 1 : 0) +
    filters.statuses.length +
    filters.types.length +
    filters.tags.length +
    filters.ext.length +
    (filters.path ? 1 : 0)
  );
}

/** Popover body (탐색): time range, type, status, tag, extension, path. */
function FilterPopoverBody({ tagListId }: { tagListId: string }) {
  const filters = useFilterStore((s) => s.filters);
  const typeOptions = useFilterStore((s) => s.typeOptions);
  const tagOptions = useFilterStore((s) => s.tagOptions);
  const patch = useFilterStore((s) => s.patchFilters);
  const typeCounts = useFilterStore((s) => s.typeCounts);
  const [typeQuery, setTypeQuery] = useState("");
  const preset = activePreset(filters);
  const types = [...new Set([...typeOptions, ...filters.types])].sort((a, b) => a.localeCompare(b, "ko"));
  const shownTypes = typeOptionsFor(types, typeCounts, typeQuery);
  return (
    <>
      <fieldset className="popover-section" aria-label="시간 범위">
        <legend className="popover-title">시간 범위</legend>
        <div className="segmented filter-segment">
          {(Object.keys(TIME_PRESET_LABELS) as TimePreset[]).map((id) => (
            <button
              key={id}
              type="button"
              aria-pressed={preset === id}
              onClick={() =>
                preset === id ? patch({ from: undefined, to: undefined }) : patch(presetRange(id))
              }
            >
              {TIME_PRESET_LABELS[id]}
            </button>
          ))}
        </div>
        {/* One column (review #10): a datetime field needs the popover's full width. */}
        <div className="filter-range">
          <label className="filter-field is-stacked">
            <span className="filter-range-label">시작</span>
            <input
              type="datetime-local"
              aria-label="시작 시각"
              value={toInputValue(filters.from)}
              max={toInputValue(filters.to) || undefined}
              onChange={(event) => patch({ from: event.target.value || undefined })}
            />
          </label>
          <label className="filter-field is-stacked">
            <span className="filter-range-label">종료</span>
            <input
              type="datetime-local"
              aria-label="종료 시각"
              value={toInputValue(filters.to)}
              min={toInputValue(filters.from) || undefined}
              onChange={(event) => patch({ to: event.target.value || undefined })}
            />
          </label>
        </div>
      </fieldset>

      <fieldset className="popover-section" aria-label="아티팩트 유형">
        <legend className="popover-title">유형</legend>
        {types.length === 0 ? <span className="filter-empty">불러온 행에 유형이 없습니다.</span> : null}
        {types.length > 0 ? (
          <input
            type="search"
            className="filter-type-search"
            aria-label="유형 검색"
            placeholder="유형 검색"
            value={typeQuery}
            onChange={(event) => setTypeQuery(event.target.value)}
          />
        ) : null}
        {/* Korean name 13px + id in mono 11px, the loaded-row count right-aligned (review #10). */}
        <div className="filter-checklist">
          {types.length > 0 && shownTypes.length === 0 ? (
            <span className="filter-empty">일치하는 유형이 없습니다.</span>
          ) : null}
          {shownTypes.map((type) => (
            <label key={type.id} className="filter-type-option">
              <input
                type="checkbox"
                checked={filters.types.includes(type.id)}
                onChange={() => patch({ types: toggle(filters.types, type.id) })}
              />
              <span className="filter-type-text">
                {type.label ? <span className="filter-type-label">{type.label}</span> : null}
                <span className="filter-type-id mono">{type.id}</span>
              </span>
              {type.count !== undefined ? (
                <span
                  className="filter-type-count"
                  title={`불러온 행 ${type.count.toLocaleString("ko-KR")}개`}
                >
                  {type.count.toLocaleString("ko-KR")}
                </span>
              ) : null}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset className="popover-section" aria-label="태그·상태">
        <legend className="popover-title">상태</legend>
        <div className="segmented filter-status-grid">
          {STATUS_ORDER.map((status) => (
            <button
              key={status}
              type="button"
              aria-pressed={filters.statuses.includes(status)}
              aria-label={`상태 필터: ${REVIEW_LABELS[status]}`}
              onClick={() => patch({ statuses: toggle(filters.statuses, status) })}
            >
              <span className="status-dot" data-status={status} aria-hidden="true" />
              {REVIEW_LABELS[status]}
            </button>
          ))}
        </div>
      </fieldset>

      <div className="popover-section filter-grid">
        <CommitInput
          label="태그"
          value=""
          clearOnEnter
          stacked
          list={tagListId}
          placeholder="태그 추가 (Enter)"
          onCommit={(value) => {
            if (value && !filters.tags.includes(value)) patch({ tags: [...filters.tags, value] });
          }}
        />
        <datalist id={tagListId}>
          {tagOptions.map((tag) => (
            <option key={tag} value={tag} />
          ))}
        </datalist>
        <CommitInput
          label="확장자"
          value=""
          clearOnEnter
          stacked
          placeholder="docx (Enter)"
          onCommit={(value) => {
            const ext = value.trim().replace(/^\.+/, "").toLowerCase();
            if (ext && !filters.ext.includes(ext)) patch({ ext: [...filters.ext, ext] });
          }}
        />
        <CommitInput
          label="경로 포함"
          value={filters.path}
          stacked
          className="filter-wide"
          placeholder="경로 일부"
          onCommit={(value) => patch({ path: value.trim() })}
        />
      </div>
    </>
  );
}

export function FilterBar(props: FilterBarProps) {
  const { query, onQuery, variant = "explore" } = props;
  const filters = useFilterStore((s) => s.filters);
  const report = useFilterStore((s) => s.report);
  const tagOptions = useFilterStore((s) => s.tagOptions);
  const patch = useFilterStore((s) => s.patchFilters);
  const setFilters = useFilterStore((s) => s.setFilters);
  const clear = useFilterStore((s) => s.clearFilters);

  const [text, setText] = useState(query);
  const lastCommitted = useRef(query);
  const [popoverOpen, setPopoverOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();
  const tagListId = useId();
  const statusId = useId();
  const kindId = useId();

  useEffect(() => {
    if (query !== lastCommitted.current) {
      lastCommitted.current = query;
      setText(query);
    }
  }, [query]);
  useEffect(() => {
    if (text === lastCommitted.current) return;
    const timer = setTimeout(() => {
      lastCommitted.current = text;
      onQuery(text);
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [text, onQuery]);

  const chips = activeChips(filters, (s) => REVIEW_LABELS[s]);
  const filtersActive = hasActiveFilters(filters);
  const anyActive = filtersActive || query.trim() !== "";
  const count = popoverCount(filters);

  const removeFilterChip = (chip: FilterChip) => setFilters(removeChip(filters, chip));
  // 보고: the type filter is the output kind (종류).
  const chipLabel = (chip: FilterChip) =>
    variant === "report" && chip.key === "type" ? `종류 ${chip.value ?? ""}` : chip.label;

  return (
    <search className="filter-bar" aria-label="필터" data-variant={variant}>
      <div className="filter-row">
        {props.lead}
        <label className="filter-field filter-search">
          <span className="sr-only">검색어</span>
          <Icon name="search" className="filter-search-icon" />
          <input
            ref={props.filterRef}
            type="search"
            value={text}
            placeholder="검색어 필터 ( / )"
            aria-keyshortcuts="/"
            onChange={(event) => setText(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.preventDefault();
                if (text) setText("");
                else props.onReturnToGrid();
              } else if (event.key === "Enter") {
                event.preventDefault();
                lastCommitted.current = text;
                onQuery(text);
                props.onReturnToGrid();
              }
            }}
          />
        </label>

        {variant === "explore" ? (
          <span className="popover-anchor">
            <button
              ref={triggerRef}
              type="button"
              className="grid-btn filter-trigger"
              aria-haspopup="dialog"
              aria-expanded={popoverOpen}
              aria-controls={popoverOpen ? popoverId : undefined}
              data-testid="filter-popover-button"
              onClick={() => setPopoverOpen((open) => !open)}
            >
              <Icon name="filter" />
              <span>필터</span>
              {count ? (
                <>
                  <span className="filter-count" aria-hidden="true">
                    {count}
                  </span>
                  <span className="sr-only">{count}개 적용</span>
                </>
              ) : null}
            </button>
            <Popover
              id={popoverId}
              open={popoverOpen}
              onClose={() => setPopoverOpen(false)}
              triggerRef={triggerRef}
              label="필터 조건"
              // Opens leftwards from the button: the grid pane clips anything past its right edge.
              align="end"
              className="filter-popover"
              // Opening lands on the heading, not on "오늘" (review #10): one Tab reaches the presets.
              initialFocus=".filter-popover-title"
            >
              <h2 className="filter-popover-title" tabIndex={-1}>
                필터 조건
              </h2>
              <FilterPopoverBody tagListId={tagListId} />
              {/* Sticky footer (review #10): conditions apply as they change (URL stays the
                  source of truth); 적용 (N) closes with the count, 초기화 clears them. */}
              <div className="popover-actions filter-popover-footer">
                <button
                  type="button"
                  className="button ghost"
                  onClick={() =>
                    setFilters({
                      ...filters,
                      from: undefined,
                      to: undefined,
                      statuses: [],
                      types: [],
                      tags: [],
                      ext: [],
                      path: "",
                    })
                  }
                >
                  초기화
                </button>
                <button
                  type="button"
                  className="button primary"
                  data-testid="filter-apply"
                  onClick={() => {
                    setPopoverOpen(false);
                    triggerRef.current?.focus();
                  }}
                >
                  적용{count ? ` (${count})` : ""}
                </button>
              </div>
            </Popover>
          </span>
        ) : null}

        {variant === "review" ? (
          <>
            <label className="filter-field filter-select" htmlFor={statusId}>
              <span>리뷰 상태</span>
              <select
                id={statusId}
                value={props.reviewStatus ?? ""}
                onChange={(event) =>
                  props.onReviewStatus?.((event.target.value || undefined) as ReviewStatus | undefined)
                }
              >
                <option value="">전체</option>
                {STATUS_ORDER.map((status) => (
                  <option key={status} value={status}>
                    {REVIEW_LABELS[status]}
                  </option>
                ))}
              </select>
            </label>
            <CommitInput
              label="태그"
              value=""
              clearOnEnter
              list={tagListId}
              className="filter-narrow"
              placeholder="태그 (Enter)"
              onCommit={(value) => {
                if (value && !filters.tags.includes(value)) patch({ tags: [...filters.tags, value] });
              }}
            />
            <datalist id={tagListId}>
              {tagOptions.map((tag) => (
                <option key={tag} value={tag} />
              ))}
            </datalist>
          </>
        ) : null}

        {variant === "report" ? (
          <label className="filter-field filter-select" htmlFor={kindId}>
            <span>종류</span>
            <select
              id={kindId}
              value={filters.types.length === 1 ? filters.types[0] : ""}
              onChange={(event) => patch({ types: event.target.value ? [event.target.value] : [] })}
            >
              <option value="">전체</option>
              {[...new Set([...(props.kindOptions ?? []), ...filters.types])].map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {chips.length ? (
          <ul className="filter-chips" aria-label="적용된 필터">
            {chips.map((chip) => (
              <li key={`${chip.key}:${chip.value ?? ""}`} className="filter-chip chip">
                <span>{chipLabel(chip)}</span>
                <button
                  type="button"
                  className="chip-remove"
                  aria-label={`${chipLabel(chip)} 필터 제거`}
                  onClick={() => removeFilterChip(chip)}
                >
                  <Icon name="close" />
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {anyActive ? (
          <button
            type="button"
            className="grid-btn grid-btn-quiet filter-reset"
            onClick={() => {
              clear();
              setText("");
              lastCommitted.current = "";
              onQuery("");
            }}
          >
            필터 초기화
          </button>
        ) : null}
      </div>
      <FilterStatus report={report} active={filtersActive} />
    </search>
  );
}

export function FilterStatus(props: { report: FilterReport | null; active: boolean }) {
  const { report } = props;
  if (!props.active || !report) return null;
  const parts: string[] = [];
  if (report.scope) parts.push(report.scope);
  if (report.serverLabels.length) parts.push(`서버 필터: ${report.serverLabels.join("·")}`);
  if (report.clientLabels.length)
    parts.push(
      `불러온 ${report.loaded.toLocaleString("ko-KR")}행에서만 적용: ${report.clientLabels.join("·")}`,
    );
  // Server filters only: the server's own count (`matched`), or "n건 이상" while it is not final.
  if (!report.clientLabels.length && report.matched !== undefined) {
    parts.push(
      report.matched === null
        ? `결과 ${report.loaded.toLocaleString("ko-KR")}건 이상`
        : `결과 ${report.matched.toLocaleString("ko-KR")}건`,
    );
  } else parts.push(`결과 ${report.shown.toLocaleString("ko-KR")}건`);
  return (
    <p className="filter-status" role="status">
      {parts.join(" · ")}
      {report.capped ? " · 일부만 불러왔습니다 (범위를 좁히거나 서버 필터를 사용하세요)" : ""}
      {report.truncated ? " · 서버 결과가 상한으로 잘렸습니다" : ""}
    </p>
  );
}
