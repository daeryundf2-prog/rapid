import { type RefObject, useEffect, useId, useMemo, useRef, useState } from "react";
import { useEscape } from "../../a11y/focus";
import { DisabledReason } from "../../a11y/primitives";
import type { GridRow } from "../../contracts/collection";
import { FilterBar } from "../filters/FilterBar";
import { setAxiomMode } from "./columns/axiom";
import {
  type DiscoveredField,
  discoverFields,
  FIELD_LABELS,
  fieldMenuEntries,
  UNSHAREABLE_FIELD_REASON,
} from "./columns/fieldColumns";
import { backendLabel, formatCount } from "./gridUtils";
import { type ColumnSpec, DENSITY_LABELS, type Density, type GridPreset, PRESET_LABELS } from "./types";

export interface GridToolbarProps {
  filterRef: RefObject<HTMLInputElement | null>;
  /** Committed filter text (route `q`). */
  query: string;
  onQuery: (q: string) => void;
  /** Called when the filter input should hand focus back to the grid (Esc / Enter). */
  onReturnToGrid: () => void;
  preset: GridPreset;
  onPreset: (preset: GridPreset) => void;
  density: Density;
  onDensity: (density: Density) => void;
  columns: ColumnSpec[];
  visibility: Record<string, boolean>;
  onToggleColumn: (id: string, visible: boolean) => void;
  collectionLabel: string;
  /** "레코드 필드 추가" section (artifacts of one kind): promote details keys to columns. */
  fieldPicker?: FieldPickerProps;
  /** "열 필터" toggle: shows the column header filter row (plan analysis-workbench-p1 §4). */
  columnFilters?: { open: boolean; count: number; onToggle: () => void };
}

export interface FieldPickerProps {
  /** Every loaded row: the picker unions their details keys (only while it is open). */
  rows: GridRow[];
  /** The kind's default columns (their keys are not offered again). */
  columns: ColumnSpec[];
  /** Promoted details keys (in column order). */
  promoted: string[];
  onToggle: (key: string, on: boolean) => void;
}

/** Field list cap: the search narrows longer lists. */
const FIELD_LIST_MAX = 150;

function fieldDescription(field: DiscoveredField): string {
  const fill =
    field.count > 0
      ? `불러온 행 중 ${field.count}행에 값 있음`
      : field.present
        ? "값이 모두 비어 있음"
        : "불러온 행에 없음";
  return field.list ? `${fill} · 목록 값(전체 정렬 불가)` : fill;
}

function FieldPicker({ rows, columns, promoted, onToggle }: FieldPickerProps) {
  const [search, setSearch] = useState("");
  const titleId = useId();
  const descPrefix = useId();
  // Computed only while the picker is open; memoised on the loaded rows' identity.
  const fields = useMemo(() => discoverFields(rows, columns), [rows, columns]);
  const entries = fieldMenuEntries(fields, promoted, search);
  const shown = entries.slice(0, FIELD_LIST_MAX);
  return (
    <fieldset className="grid-fieldpicker" aria-labelledby={titleId}>
      <legend id={titleId} className="grid-fieldpicker-title">
        레코드 필드 추가
      </legend>
      <input
        type="search"
        className="grid-fieldpicker-search"
        aria-label="필드 검색"
        placeholder="필드 이름"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
      />
      <div className="grid-fieldpicker-list">
        {shown.length === 0 ? (
          <p className="grid-note">
            {search.trim() ? "일치하는 필드가 없습니다." : "불러온 행에 추가할 레코드 필드가 없습니다."}
          </p>
        ) : (
          shown.map((field, index) => {
            const label = FIELD_LABELS[field.key];
            const descId = `${descPrefix}-${index}`;
            const checkbox = (
              <input
                type="checkbox"
                aria-label={field.key}
                aria-describedby={descId}
                checked={promoted.includes(field.key)}
                onChange={(event) => {
                  if (!field.unshareable) onToggle(field.key, event.target.checked);
                }}
              />
            );
            return (
              // biome-ignore lint/a11y/noLabelWithoutControl: the checkbox may sit inside DisabledReason
              <label
                key={field.key}
                className={`grid-popover-item${field.unshareable ? " is-unavailable" : ""}`}
              >
                {field.unshareable ? (
                  <DisabledReason reason={UNSHAREABLE_FIELD_REASON}>{checkbox}</DisabledReason>
                ) : (
                  checkbox
                )}
                <span className="mono">{field.key}</span>
                {label ? <span aria-hidden="true">{label}</span> : null}
                <span className="grid-note" aria-hidden="true">
                  {field.count > 0 ? `${field.count}행` : field.present ? "빈 값" : ""}
                  {field.list ? " · 목록" : ""}
                </span>
                <span id={descId} hidden>
                  {fieldDescription(field)}
                </span>
              </label>
            );
          })
        )}
        {entries.length > shown.length ? (
          <p className="grid-note">{entries.length - shown.length}개 더 있음 · 검색으로 좁히세요.</p>
        ) : null}
      </div>
    </fieldset>
  );
}

export function GridToolbar(props: GridToolbarProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const toolbarRef = useRef<HTMLDivElement>(null);
  const menuId = useId();
  const { preset, onDensity } = props;

  // AXIOM preset: two-line titles (DataGrid sets `data-preset` on the root for the CSS; the
  // comfortable row height is chosen when the preset is picked).
  useEffect(() => {
    setAxiomMode(preset === "axiom");
    return () => setAxiomMode(false);
  }, [preset]);

  // Esc closes the column menu (shared Esc stack) and hands focus back to its button.
  useEscape(() => {
    const inside = menuRef.current?.contains(document.activeElement) ?? false;
    setMenuOpen(false);
    if (inside) menuButtonRef.current?.focus();
  }, menuOpen);

  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [menuOpen]);

  return (
    <>
      <FilterBar
        filterRef={props.filterRef}
        query={props.query}
        onQuery={props.onQuery}
        onReturnToGrid={props.onReturnToGrid}
      />
      <div
        ref={toolbarRef}
        className="grid-toolbar"
        role="toolbar"
        aria-label={`${props.collectionLabel} 그리드 도구`}
      >
        <label className="grid-select">
          <span>열 구성</span>
          <select
            value={props.preset}
            onChange={(event) => {
              const next = event.target.value as GridPreset;
              props.onPreset(next);
              if (next === "axiom") onDensity("comfortable");
            }}
          >
            {(Object.keys(PRESET_LABELS) as GridPreset[]).map((id) => (
              <option key={id} value={id}>
                {PRESET_LABELS[id]}
              </option>
            ))}
          </select>
        </label>

        <div className="grid-colmenu" ref={menuRef}>
          <button
            ref={menuButtonRef}
            type="button"
            className="grid-btn"
            aria-expanded={menuOpen}
            aria-controls={menuId}
            onClick={() => setMenuOpen((open) => !open)}
          >
            열 선택
          </button>
          {menuOpen ? (
            <fieldset id={menuId} className="grid-popover" aria-label="표시할 열">
              {props.columns.map((column, index) => (
                <label key={column.id} className="grid-popover-item">
                  <input
                    type="checkbox"
                    checked={props.visibility[column.id] !== false}
                    disabled={index === 0}
                    onChange={(event) => props.onToggleColumn(column.id, event.target.checked)}
                  />
                  {column.header}
                </label>
              ))}
              {props.fieldPicker ? <FieldPicker {...props.fieldPicker} /> : null}
            </fieldset>
          ) : null}
        </div>

        {props.columnFilters ? (
          <button
            type="button"
            className="grid-btn"
            aria-pressed={props.columnFilters.open}
            data-testid="grid-colfilter-toggle"
            onClick={props.columnFilters.onToggle}
          >
            열 필터{props.columnFilters.count ? ` (${props.columnFilters.count})` : ""}
          </button>
        ) : null}

        <label className="grid-select">
          <span>밀도</span>
          <select value={props.density} onChange={(event) => props.onDensity(event.target.value as Density)}>
            {(Object.keys(DENSITY_LABELS) as Density[]).map((id) => (
              <option key={id} value={id}>
                {DENSITY_LABELS[id]}
              </option>
            ))}
          </select>
        </label>
      </div>
    </>
  );
}

export interface GridFooterProps {
  /** Page containing the first visible row (1-based). */
  page: number;
  pageCount: number | null;
  total: number | null;
  shown: number;
  backend: string;
  elapsedMs: number;
  truncated: boolean;
  /** Text filter is active (applied to loaded rows only). */
  filtering: boolean;
  /** Path text sent to the server (artifacts `path_contains`); other columns still filter the loaded rows. */
  serverPathFilter?: string;
  scanned?: number;
  sorting: boolean;
  loadedCount: number;
  canLoadMore: boolean;
  onLoadMore: () => void;
  loading: boolean;
  /** Scope line for category nodes ("범주: 운영 체제 (5 유형)"). */
  scope?: string;
}

export const TRUNCATED_NOTICE =
  "결과가 상한 또는 시간 제한으로 일부만 표시되었습니다. 키워드나 범위를 좁혀 다시 검색하세요.";

export function GridFooter(props: GridFooterProps) {
  const seconds =
    props.elapsedMs >= 1000 ? `${(props.elapsedMs / 1000).toFixed(1)}s` : `${Math.round(props.elapsedMs)}ms`;
  return (
    <div className="grid-footer">
      {props.scope ? <span className="grid-scope">{props.scope}</span> : null}
      <span>
        {props.pageCount !== null ? `페이지 ${props.page}/${formatCount(props.pageCount)}` : "페이지 -"}
      </span>
      <span data-testid="grid-footer-total">
        총{" "}
        {props.total !== null ? `${formatCount(props.total)}건` : props.loading ? "세는 중…" : "알 수 없음"}
      </span>
      {props.loading ? (
        <span className="grid-note" data-testid="grid-footer-loading">
          불러오는 중…
        </span>
      ) : null}
      {props.backend ? (
        <span>
          {backendLabel(props.backend)} {seconds}
        </span>
      ) : null}
      {props.filtering ? (
        <span className="grid-note">
          필터 결과 {formatCount(props.shown)}건 ·{" "}
          {props.serverPathFilter
            ? `경로는 서버에서 검색${props.scanned ? `(${formatCount(props.scanned)}행 스캔)` : ""}하고, 다른 열은 불러온 ${formatCount(props.loadedCount)}행에서만 찾습니다.`
            : `서버 필터 미지원: 불러온 ${formatCount(props.loadedCount)}행에서만 찾습니다.`}
        </span>
      ) : null}
      {props.sorting ? (
        <span className="grid-note">정렬은 불러온 {formatCount(props.loadedCount)}행 기준입니다.</span>
      ) : null}
      {props.truncated ? (
        <span className="grid-note grid-warn" role="note">
          {TRUNCATED_NOTICE}
        </span>
      ) : null}
      {props.canLoadMore ? (
        <button type="button" className="grid-btn" onClick={props.onLoadMore} disabled={props.loading}>
          다음 페이지 불러오기
        </button>
      ) : null}
    </div>
  );
}
