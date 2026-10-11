import { type RefObject, useEffect, useId, useRef, useState } from "react";
import { useEscape } from "../../a11y/focus";
import type { ReviewStatus } from "../../contracts/collection";
import { REVIEW_LABELS } from "../grid/columns/common";
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
import "./filters.css";

const STATUS_ORDER: ReviewStatus[] = ["relevant", "needs-review", "excluded", "include-in-report"];
const COMMIT_DEBOUNCE_MS = 250;
const SEARCH_DEBOUNCE_MS = 200;

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
    <label className={`filter-field ${props.className ?? ""}`}>
      <span>{props.label}</span>
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
}

export function FilterBar(props: FilterBarProps) {
  const { query, onQuery } = props;
  const filters = useFilterStore((s) => s.filters);
  const report = useFilterStore((s) => s.report);
  const typeOptions = useFilterStore((s) => s.typeOptions);
  const tagOptions = useFilterStore((s) => s.tagOptions);
  const patch = useFilterStore((s) => s.patchFilters);
  const setFilters = useFilterStore((s) => s.setFilters);
  const clear = useFilterStore((s) => s.clearFilters);

  const [text, setText] = useState(query);
  const lastCommitted = useRef(query);
  const [typeMenu, setTypeMenu] = useState(false);
  const typeRef = useRef<HTMLDivElement>(null);
  const typeMenuId = useId();
  const tagListId = useId();

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

  useEscape(() => setTypeMenu(false), typeMenu);
  useEffect(() => {
    if (!typeMenu) return;
    const onDown = (event: MouseEvent) => {
      if (typeRef.current && !typeRef.current.contains(event.target as Node)) setTypeMenu(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [typeMenu]);

  const preset = activePreset(filters);
  const chips = activeChips(filters, (s) => REVIEW_LABELS[s]);
  const types = [...new Set([...typeOptions, ...filters.types])].sort((a, b) => a.localeCompare(b, "ko"));
  const filtersActive = hasActiveFilters(filters);
  const anyActive = filtersActive || query.trim() !== "";

  const toggle = <T extends string>(list: T[], value: T): T[] =>
    list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
  const removeFilterChip = (chip: FilterChip) => setFilters(removeChip(filters, chip));

  return (
    <search className="filter-bar" aria-label="필터">
      <div className="filter-row">
        <label className="filter-field filter-search">
          <span>검색어</span>
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

        <fieldset className="filter-group" aria-label="시간 범위">
          <span className="filter-label">시간 범위</span>
          {(Object.keys(TIME_PRESET_LABELS) as TimePreset[]).map((id) => (
            <button
              key={id}
              type="button"
              className="grid-btn filter-toggle"
              aria-pressed={preset === id}
              onClick={() =>
                preset === id ? patch({ from: undefined, to: undefined }) : patch(presetRange(id))
              }
            >
              {TIME_PRESET_LABELS[id]}
            </button>
          ))}
          <label className="filter-field">
            <span className="sr-only">시작 시각</span>
            <input
              type="datetime-local"
              aria-label="시작 시각"
              value={toInputValue(filters.from)}
              max={toInputValue(filters.to) || undefined}
              onChange={(event) => patch({ from: event.target.value || undefined })}
            />
          </label>
          <span aria-hidden="true">~</span>
          <label className="filter-field">
            <span className="sr-only">종료 시각</span>
            <input
              type="datetime-local"
              aria-label="종료 시각"
              value={toInputValue(filters.to)}
              min={toInputValue(filters.from) || undefined}
              onChange={(event) => patch({ to: event.target.value || undefined })}
            />
          </label>
        </fieldset>
      </div>

      <div className="filter-row">
        <div className="filter-type" ref={typeRef}>
          <button
            type="button"
            className="grid-btn"
            aria-expanded={typeMenu}
            aria-controls={typeMenuId}
            onClick={() => setTypeMenu((open) => !open)}
          >
            유형{filters.types.length ? ` (${filters.types.length})` : ""}
          </button>
          {typeMenu ? (
            <fieldset id={typeMenuId} className="filter-popover" aria-label="아티팩트 유형">
              {types.length === 0 ? <span className="filter-empty">불러온 행에 유형이 없습니다.</span> : null}
              {types.map((type) => (
                <label key={type} className="grid-popover-item">
                  <input
                    type="checkbox"
                    checked={filters.types.includes(type)}
                    onChange={() => patch({ types: toggle(filters.types, type) })}
                  />
                  {type}
                </label>
              ))}
            </fieldset>
          ) : null}
        </div>

        <fieldset className="filter-group" aria-label="태그·상태">
          <span className="filter-label">상태</span>
          {STATUS_ORDER.map((status) => (
            <button
              key={status}
              type="button"
              className="grid-btn filter-toggle"
              aria-pressed={filters.statuses.includes(status)}
              aria-label={`상태 필터: ${REVIEW_LABELS[status]}`}
              onClick={() => patch({ statuses: toggle(filters.statuses, status) })}
            >
              {REVIEW_LABELS[status]}
            </button>
          ))}
        </fieldset>

        <CommitInput
          label="태그"
          value=""
          clearOnEnter
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
          placeholder="docx (Enter)"
          className="filter-narrow"
          onCommit={(value) => {
            const ext = value.trim().replace(/^\.+/, "").toLowerCase();
            if (ext && !filters.ext.includes(ext)) patch({ ext: [...filters.ext, ext] });
          }}
        />

        <CommitInput
          label="경로 포함"
          value={filters.path}
          placeholder="경로 일부"
          onCommit={(value) => patch({ path: value.trim() })}
        />
      </div>

      {anyActive ? (
        <div className="filter-row filter-chips">
          {chips.map((chip) => (
            <span key={`${chip.key}:${chip.value ?? ""}`} className="filter-chip">
              {chip.label}
              <button
                type="button"
                aria-label={`${chip.label} 필터 제거`}
                onClick={() => removeFilterChip(chip)}
              >
                ×
              </button>
            </span>
          ))}
          <button
            type="button"
            className="grid-btn grid-btn-quiet"
            onClick={() => {
              clear();
              setText("");
              lastCommitted.current = "";
              onQuery("");
            }}
          >
            필터 초기화
          </button>
        </div>
      ) : null}
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
  parts.push(`결과 ${report.shown.toLocaleString("ko-KR")}건`);
  return (
    <p className="filter-status" role="status">
      {parts.join(" · ")}
      {report.capped ? " · 일부만 불러왔습니다 (범위를 좁히거나 서버 필터를 사용하세요)" : ""}
      {report.truncated ? " · 서버 결과가 상한으로 잘렸습니다" : ""}
    </p>
  );
}
