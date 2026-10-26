/**
 * Filter bar (X19, visual-polish S1/S2). One line: the text filter, a "필터" button that opens
 * a popover (time range with presets, type, status, tag, extension, path) and the applied
 * conditions as removable chips. Stage toolbars (S2) swap the popover for the controls that
 * stage needs: the review board gets review status + tag, the report gets the output kind.
 * The URL stays the source of truth (filterStore / filterModel are unchanged).
 */

import { type ReactNode, type RefObject, useEffect, useId, useRef, useState, type WheelEvent } from "react";
import { announce } from "../../a11y";
import { Popover } from "../../components/Popover";
import type { ReviewStatus } from "../../contracts/collection";
import { Icon } from "../../icons";
import { type Grade, useCatalog } from "../flags/catalog";
import { REVIEW_LABELS } from "../grid/columns/common";
import { DEFAULT_PRESET, DENSITY_LABELS, type Density, type GridPreset, PRESET_LABELS } from "../grid/types";
import { ClockSection, IncidentRange, ResultSection } from "./ConditionSections";
import {
  recentRanges,
  rememberRange,
  removeSavedCondition,
  type SavedCondition,
  saveCondition,
  savedConditions,
  type TimeRange,
} from "./conditionMemory";
import { useConditionPanel } from "./conditionPanel";
import {
  activeChips,
  activePreset,
  type FilterChip,
  hasActiveFilters,
  presetRange,
  removeChip,
  TIME_PRESET_LABELS,
  type TimePreset,
  toInputValue,
} from "./filterModel";
import { type FilterReport, useFilterStore } from "./filterStore";
import { orderedRange } from "./rowConditions";
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
  /** Collection-specific controls after the search field (문서: "일치만"). */
  extra?: ReactNode;
  /** 열 구성 / 밀도, set inside the 조건 panel (U-F1). */
  display?: DisplaySettings;
  /** Result count at the row's end. */
  resultCount?: { count: number | null; loading: boolean };
  /** Overflow at the row's end (열 선택 · 열 필터). */
  trailing?: ReactNode;
  /** Event-log channel group labels of the run (`/tree` `channel_groups`) for the 채널 chip. */
  channelGroupLabels?: Readonly<Record<string, string>>;
}

function toggle<T extends string>(list: T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/**
 * The chip strip scrolls sideways (scroll review C6): a plain vertical wheel over it moves it
 * left/right too, besides its thin scrollbar and Tab (focus scrolls a chip into view).
 */
export function chipStripWheel(event: WheelEvent<HTMLElement>): void {
  const el = event.currentTarget;
  if (el.scrollWidth <= el.clientWidth + 1) return;
  if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return;
  el.scrollLeft += event.deltaY;
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
        <IncidentRange />
        <RecentRanges onPick={(range) => patch({ from: range.from, to: range.to })} />
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
        {orderedRange(filters.from, filters.to).reversed ? (
          <p className="filter-empty" role="status">
            시작이 종료보다 늦어 두 시각을 바꿔 적용합니다(종료 시각은 그 분의 끝까지 포함).
          </p>
        ) : null}
      </fieldset>

      <ClockSection />
      <ResultSection />

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

/** Display settings moved into the 조건 panel (U-F1): column preset and row density. */
export interface DisplaySettings {
  preset: GridPreset;
  onPreset: (preset: GridPreset) => void;
  density: Density;
  onDensity: (density: Density) => void;
}

const GRADE_CHOICES: Array<{ value: Grade | undefined; label: string }> = [
  { value: undefined, label: "전체" },
  { value: "A", label: "A" },
  { value: "B", label: "B 이상" },
  { value: "C", label: "C 이상" },
];

/** 특이사항 conditions: minimum grade + specific rules (URL `flag_grade=` / `flag=`). */
function FlagConditions() {
  const filters = useFilterStore((s) => s.filters);
  const patch = useFilterStore((s) => s.patchFilters);
  const catalog = useCatalog();
  const [query, setQuery] = useState("");
  const selected = filters.flags ?? [];
  const needle = query.trim().toLocaleLowerCase("ko-KR");
  const rules = catalog.rules.filter(
    (rule) =>
      selected.includes(rule.id) ||
      (needle !== "" &&
        (rule.label_ko.toLocaleLowerCase("ko-KR").includes(needle) ||
          rule.id.toLowerCase().includes(needle))),
  );
  return (
    <fieldset className="popover-section" aria-label="특이사항">
      <legend className="popover-title">특이사항</legend>
      <div className="segmented filter-segment">
        {GRADE_CHOICES.map((choice) => (
          <button
            key={choice.label}
            type="button"
            aria-pressed={filters.flagGrade === choice.value}
            onClick={() => patch({ flagGrade: choice.value })}
          >
            {choice.label}
          </button>
        ))}
      </div>
      <input
        type="search"
        className="filter-type-search"
        aria-label="특이사항 지표 검색"
        placeholder="지표 검색 (예: 로그 삭제)"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
      />
      <div className="filter-checklist">
        {needle && rules.length === 0 ? (
          <span className="filter-empty">일치하는 지표가 없습니다.</span>
        ) : null}
        {rules.slice(0, 40).map((rule) => (
          <label key={rule.id} className="filter-type-option">
            <input
              type="checkbox"
              checked={selected.includes(rule.id)}
              onChange={() =>
                patch({
                  flags: selected.includes(rule.id)
                    ? selected.filter((id) => id !== rule.id)
                    : [...selected, rule.id],
                })
              }
            />
            <span className="filter-type-text">
              <span className="filter-type-label">
                {rule.grade} · {rule.label_ko}
              </span>
              <span className="filter-type-id mono">{rule.id}</span>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** "YYYY-MM-DD HH:mm" of a stored range bound ("…" when open). */
function rangeText(range: TimeRange): string {
  const short = (value?: string) => (value ? value.replace("T", " ").slice(0, 16) : "…");
  return `${short(range.from)} ~ ${short(range.to)}`;
}

/** The three most recent time ranges (U-F8): one click re-applies one. */
function RecentRanges({ onPick }: { onPick: (range: TimeRange) => void }) {
  const [ranges] = useState(recentRanges);
  if (!ranges.length) return null;
  return (
    <div className="filter-recent">
      <span className="filter-range-label">최근</span>
      {ranges.map((range) => (
        <button
          key={`${range.from ?? ""}|${range.to ?? ""}`}
          type="button"
          className="grid-btn grid-btn-quiet"
          aria-label={`최근 시간 범위 적용: ${rangeText(range)}`}
          onClick={() => onPick(range)}
        >
          {rangeText(range)}
        </button>
      ))}
    </div>
  );
}

/** Saved condition sets (U-F8 "조건 저장"): apply one, or delete it. */
function SavedConditions({ onApply }: { onApply: (saved: SavedCondition) => void }) {
  const [list, setList] = useState(savedConditions);
  useEffect(() => {
    const refresh = () => setList(savedConditions());
    window.addEventListener("rapidtriage:conditions-saved", refresh);
    return () => window.removeEventListener("rapidtriage:conditions-saved", refresh);
  }, []);
  if (!list.length) return null;
  return (
    <fieldset className="popover-section" aria-label="저장한 조건">
      <legend className="popover-title">저장한 조건</legend>
      <ul className="filter-saved">
        {list.map((saved) => (
          <li key={saved.name} className="filter-saved-item">
            <button type="button" className="grid-btn grid-btn-quiet" onClick={() => onApply(saved)}>
              {saved.name}
            </button>
            <button
              type="button"
              className="chip-remove"
              aria-label={`${saved.name} 저장한 조건 삭제`}
              onClick={() => setList(removeSavedCondition(saved.name))}
            >
              <Icon name="close" />
            </button>
          </li>
        ))}
      </ul>
    </fieldset>
  );
}

function DisplaySection({ display }: { display: DisplaySettings }) {
  return (
    <fieldset className="popover-section filter-display" aria-label="표시">
      <legend className="popover-title">표시</legend>
      <div className="filter-display-row">
        <label className="grid-select">
          <span>열 구성</span>
          <select
            value={display.preset}
            onChange={(event) => display.onPreset(event.target.value as GridPreset)}
          >
            {(Object.keys(PRESET_LABELS) as GridPreset[]).map((id) => (
              <option key={id} value={id}>
                {PRESET_LABELS[id]}
              </option>
            ))}
          </select>
        </label>
        <label className="grid-select">
          <span>밀도</span>
          <select
            value={display.density}
            onChange={(event) => display.onDensity(event.target.value as Density)}
          >
            {(Object.keys(DENSITY_LABELS) as Density[]).map((id) => (
              <option key={id} value={id}>
                {DENSITY_LABELS[id]}
              </option>
            ))}
          </select>
        </label>
      </div>
    </fieldset>
  );
}

/** One chip of the 조건 줄: the text opens the panel, × removes the condition. */
interface RowChip {
  id: string;
  label: string;
  remove: () => void;
}

export function FilterBar(props: FilterBarProps) {
  const { query, onQuery, variant = "explore", display } = props;
  const filters = useFilterStore((s) => s.filters);
  const report = useFilterStore((s) => s.report);
  const tagOptions = useFilterStore((s) => s.tagOptions);
  const patch = useFilterStore((s) => s.patchFilters);
  const setFilters = useFilterStore((s) => s.setFilters);
  const clear = useFilterStore((s) => s.clearFilters);
  const popoverOpen = useConditionPanel((s) => s.open);
  const setPopoverOpen = useConditionPanel((s) => s.setOpen);

  const [text, setText] = useState(query);
  const lastCommitted = useRef(query);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();
  const tagListId = useId();
  const statusId = useId();
  const kindId = useId();

  // The command (key F) needs a mounted 조건 줄; the panel starts closed on every grid.
  useEffect(() => {
    useConditionPanel.setState((s) => ({ mounted: s.mounted + 1, open: false }));
    return () => useConditionPanel.setState((s) => ({ mounted: Math.max(0, s.mounted - 1), open: false }));
  }, []);
  // Closed by the command (F again) while focus was inside: hand focus back to the 조건 button.
  const wasOpen = useRef(false);
  useEffect(() => {
    if (wasOpen.current && !popoverOpen) {
      // Remember the time range the panel closed with (최근 3개, U-F8) — not every keystroke of a
      // half-typed datetime field.
      const { from, to } = useFilterStore.getState().filters;
      if (from || to) rememberRange({ from, to });
      const active = document.activeElement;
      if (!active || active === document.body || !active.isConnected) triggerRef.current?.focus();
    }
    wasOpen.current = popoverOpen;
  }, [popoverOpen]);

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

  // 보고: the type filter is the output kind (종류).
  const chipLabel = (chip: FilterChip) =>
    variant === "report" && chip.key === "type" ? `종류 ${chip.value ?? ""}` : chip.label;
  const chips: RowChip[] = activeChips(filters, (s) => REVIEW_LABELS[s], {
    channelGroupLabels: props.channelGroupLabels,
  }).map((chip) => ({
    id: `${chip.key}:${chip.value ?? ""}`,
    label: chipLabel(chip),
    remove: () => setFilters(removeChip(filters, chip)),
  }));
  // 표시 settings (열 구성 · 밀도) are not conditions: their own chips, outside the count / label.
  const displayChips: RowChip[] = [];
  if (display && display.preset !== DEFAULT_PRESET) {
    displayChips.push({
      id: "display:preset",
      label: `열 구성 ${PRESET_LABELS[display.preset]}`,
      remove: () => display.onPreset(DEFAULT_PRESET),
    });
  }
  if (display && display.density !== "default") {
    displayChips.push({
      id: "display:density",
      label: `밀도 ${DENSITY_LABELS[display.density]}`,
      remove: () => display.onDensity("default"),
    });
  }
  const filtersActive = hasActiveFilters(filters);
  const anyActive = filtersActive || query.trim() !== "";
  const count = chips.length;
  const statusText = filterStatusText(report, filtersActive);
  const result = props.resultCount;
  const resultText = !result
    ? ""
    : result.count === null
      ? result.loading
        ? "세는 중…"
        : ""
      : `${result.count.toLocaleString("ko-KR")}건`;

  const openPanel = () => setPopoverOpen(true);
  const appliedSummary = chips.length
    ? `${chips[0]?.label ?? ""}${chips.length > 1 ? ` 외 ${chips.length - 1}` : ""}`
    : "";

  return (
    <search className="filter-bar" aria-label="조건" data-variant={variant}>
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

        {props.extra}

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

        <span className="popover-anchor">
          <button
            ref={triggerRef}
            type="button"
            className="grid-btn filter-trigger"
            aria-haspopup="dialog"
            aria-expanded={popoverOpen}
            aria-controls={popoverOpen ? popoverId : undefined}
            aria-keyshortcuts="F"
            title={
              count
                ? `조건 — ${chips.map((chip) => chip.label).join(" · ")} (F)`
                : "조건 — 검색 조건·특이사항·열 구성·밀도 (F)"
            }
            data-testid="filter-popover-button"
            onClick={() => setPopoverOpen(!popoverOpen)}
          >
            <Icon name="filter" />
            {count ? (
              // An applied condition replaces the label (U-F8, bold); the name keeps "조건".
              <>
                <span className="sr-only">조건: </span>
                <strong className="filter-trigger-applied">{appliedSummary}</strong>
              </>
            ) : (
              <span className="filter-btn-label">조건</span>
            )}
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
            label="조건"
            align="start"
            // In a portal above every pane (the viewer too), flipped into the viewport (C-D4):
            // the grid pane no longer clips it beside the open viewer.
            portal
            className="filter-popover"
            // Opening lands on the heading, not on "오늘" (review #10): one Tab reaches the presets.
            initialFocus=".filter-popover-title"
          >
            <h2 className="filter-popover-title" tabIndex={-1}>
              조건
            </h2>
            {variant === "explore" ? <FilterPopoverBody tagListId={tagListId} /> : null}
            {variant === "explore" ? <FlagConditions /> : null}
            {variant === "explore" ? (
              <SavedConditions
                onApply={(saved) => {
                  setFilters({ ...saved.filters, columns: filters.columns });
                  announce(`저장한 조건을 적용했습니다: ${saved.name}`);
                }}
              />
            ) : null}
            {display ? <DisplaySection display={display} /> : null}
            {statusText ? <p className="filter-status">{statusText}</p> : null}
            {/* Sticky footer (review #10): conditions apply as they change (URL stays the
                source of truth); 적용 (N) closes with the count, 초기화 clears them. */}
            <div className="popover-actions filter-popover-footer">
              {variant === "explore" ? (
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
                      flags: [],
                      flagGrade: undefined,
                      weekdays: undefined,
                      hours: undefined,
                      offhours: undefined,
                      partial: undefined,
                      content: undefined,
                      geo: undefined,
                    })
                  }
                >
                  초기화
                </button>
              ) : null}
              <button
                type="button"
                className="button primary"
                data-testid="filter-apply"
                onClick={() => {
                  setPopoverOpen(false);
                  triggerRef.current?.focus();
                }}
              >
                닫기{count ? ` (적용 ${count})` : ""}
              </button>
            </div>
          </Popover>
        </span>

        {displayChips.length ? (
          <ul className="filter-chips filter-display-chips" aria-label="표시 설정" onWheel={chipStripWheel}>
            {displayChips.map((chip) => (
              <li key={chip.id} className="filter-chip chip is-display">
                <button
                  type="button"
                  className="chip-open"
                  title="조건 패널의 표시 설정 열기"
                  onClick={openPanel}
                >
                  {chip.label}
                </button>
                <button
                  type="button"
                  className="chip-remove"
                  aria-label={`${chip.label} 기본값으로 되돌리기`}
                  onClick={chip.remove}
                >
                  <Icon name="close" />
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {chips.length ? (
          <ul className="filter-chips" aria-label="적용된 조건" onWheel={chipStripWheel}>
            {chips.map((chip) => (
              <li key={chip.id} className="filter-chip chip">
                <button type="button" className="chip-open" title="조건 패널 열기" onClick={openPanel}>
                  {chip.label}
                </button>
                <button
                  type="button"
                  className="chip-remove"
                  aria-label={`${chip.label} 조건 제거`}
                  onClick={chip.remove}
                >
                  <Icon name="close" />
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        {variant === "explore" && filtersActive ? (
          <button
            type="button"
            className="grid-btn grid-btn-quiet"
            data-testid="filter-save"
            aria-label="조건 저장"
            title="지금 조건을 저장해 조건 패널의 '저장한 조건'에서 다시 적용합니다"
            onClick={() => {
              const name = chips
                .map((chip) => chip.label)
                .join(" · ")
                .slice(0, 80);
              saveCondition(name, filters);
              window.dispatchEvent(new Event("rapidtriage:conditions-saved"));
              announce(`조건을 저장했습니다: ${name}`);
            }}
          >
            <Icon name="bookmark" />
            <span className="filter-btn-label">조건 저장</span>
          </button>
        ) : null}
        {anyActive ? (
          <button
            type="button"
            className="grid-btn grid-btn-quiet filter-reset"
            aria-label="조건 지우기"
            title="조건 지우기"
            onClick={() => {
              clear();
              setText("");
              lastCommitted.current = "";
              onQuery("");
            }}
          >
            <Icon name="close" />
            <span className="filter-btn-label">조건 지우기</span>
          </button>
        ) : null}
        <span className="filter-row-end">
          {resultText ? (
            <span className="filter-result" title={statusText || undefined} data-testid="filter-result-count">
              {resultText}
            </span>
          ) : null}
          {props.trailing}
        </span>
      </div>
    </search>
  );
}

/** The filter scope sentence (server vs loaded-row filters, result count); shown in the panel. */
export function filterStatusText(report: FilterReport | null, active: boolean): string {
  if (!active || !report) return "";
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
    parts.join(" · ") +
    (report.capped ? " · 일부만 불러왔습니다 (범위를 좁히거나 서버 필터를 사용하세요)" : "") +
    (report.truncated ? " · 서버 결과가 상한으로 잘렸습니다" : "")
  );
}
