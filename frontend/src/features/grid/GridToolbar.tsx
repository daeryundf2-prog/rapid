import { type ReactNode, type RefObject, useEffect, useId, useMemo, useRef, useState } from "react";
import { DisabledReason } from "../../a11y/primitives";
import { Popover } from "../../components/Popover";
import type { GridRow, ReviewStatus } from "../../contracts/collection";
import { Icon } from "../../icons";
import { type DisplaySettings, FilterBar, type FilterBarVariant } from "../filters/FilterBar";
import { useToolbarLead } from "../views/toolbarSlot";
import { lockedColumnId } from "./columns";
import { setAxiomMode } from "./columns/axiom";
import {
  type DiscoveredField,
  discoverFields,
  FIELD_LABELS,
  fieldMenuEntries,
  UNSHAREABLE_FIELD_REASON,
} from "./columns/fieldColumns";
import { AUTO_HIDE_LABEL, type AutoHideReason, backendLabel, formatCount } from "./gridUtils";
import type { ColumnSpec, GridPreset } from "./types";

export interface GridToolbarProps {
  filterRef: RefObject<HTMLInputElement | null>;
  /** Committed filter text (route `q`). */
  query: string;
  onQuery: (q: string) => void;
  /** Called when the filter input should hand focus back to the grid (Esc / Enter). */
  onReturnToGrid: () => void;
  /** The stage's toolbar (visual-polish S2). */
  variant?: FilterBarVariant;
  reviewStatus?: ReviewStatus;
  onReviewStatus?: (status: ReviewStatus | undefined) => void;
  kindOptions?: string[];
  /** Collection-specific toolbar controls (문서: "일치만"). */
  extra?: ReactNode;
  /** 열 구성 / 밀도 inside the 조건 panel (U-F1). */
  display?: DisplaySettings;
  resultCount?: { count: number | null; loading: boolean };
  /** Row end overflow: the 열 설정 menu (열 선택 · 열 필터). */
  trailing?: ReactNode;
  /** Event-log channel group labels of the run for the 채널 chip. */
  channelGroupLabels?: Readonly<Record<string, string>>;
}

/** 문서 toolbar: list every document, or only the keyword matches (plain `GET /docs`; every document is `all=1`). */
export function DocsMatchedToggle({ on, onChange }: { on: boolean; onChange: (on: boolean) => void }) {
  return (
    <button
      type="button"
      className="grid-btn"
      aria-pressed={on}
      data-testid="docs-matched-toggle"
      title={
        on ? "키워드 일치 문서만 표시 중 — 누르면 전체 문서" : "전체 문서 표시 중 — 누르면 키워드 일치 문서만"
      }
      onClick={() => onChange(!on)}
    >
      <Icon name="filter" />
      <span>일치만</span>
    </button>
  );
}

export interface ColumnMenuProps {
  /** The preset in effect (AXIOM two-line rows); it is chosen in the 조건 panel. */
  preset: GridPreset;
  columns: ColumnSpec[];
  visibility: Record<string, boolean>;
  onToggleColumn: (id: string, visible: boolean) => void;
  /**
   * Default columns the responsive layout keeps off screen (too narrow / no values on this page):
   * listed unchecked with "폭 부족으로 숨김 — 표시"; showing one pins it.
   */
  autoHidden?: ReadonlyMap<string, AutoHideReason>;
  collectionLabel: string;
  /** "레코드 필드 추가" section (artifacts of one kind): promote details keys to columns. */
  fieldPicker?: FieldPickerProps;
  /** "열 필터" toggle: shows the column header filter row (plan analysis-workbench-p1 §4). */
  columnFilters?: { open: boolean; count: number; onToggle: () => void };
  /** Catalogue family layout (U-F3): its auxiliary columns, added or removed together. */
  auxColumns?: { family: string; ids: string[]; onToggleAll: (on: boolean) => void };
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

/** The grid's toolbar line: the stage's filter bar (S1/S2) with the view switch in front. */
export function GridToolbar(props: GridToolbarProps) {
  const lead = useToolbarLead();
  return (
    <FilterBar
      filterRef={props.filterRef}
      query={props.query}
      onQuery={props.onQuery}
      onReturnToGrid={props.onReturnToGrid}
      variant={props.variant}
      reviewStatus={props.reviewStatus}
      onReviewStatus={props.onReviewStatus}
      kindOptions={props.kindOptions}
      lead={lead}
      extra={props.extra}
      display={props.display}
      resultCount={props.resultCount}
      trailing={props.trailing}
      channelGroupLabels={props.channelGroupLabels}
    />
  );
}

/**
 * Column controls folded into one overflow button at the end of the 조건 줄 (visual-polish S3,
 * viewer-families U-F1): the column picker (+ catalogue auxiliary columns, record fields) and the
 * column-filter row. 열 구성 and 밀도 moved into the 조건 panel.
 */
export function ColumnMenu(props: ColumnMenuProps) {
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popoverId = useId();
  const { preset } = props;

  // AXIOM preset: two-line titles (DataGrid sets `data-preset` on the root for the CSS and
  // gives the preset at least the 32px row without touching the density preference).
  useEffect(() => {
    setAxiomMode(preset === "axiom");
    return () => setAxiomMode(false);
  }, [preset]);

  const filterCount = props.columnFilters?.count ?? 0;
  const locked = lockedColumnId(props.columns);
  return (
    <span className="popover-anchor grid-colmenu">
      <button
        ref={buttonRef}
        type="button"
        className="grid-colmenu-button"
        aria-label="열 설정"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? popoverId : undefined}
        title={`${props.collectionLabel} 열 설정 — 표시할 열·열 필터`}
        data-testid="grid-column-menu"
        onClick={() => setOpen((value) => !value)}
      >
        <Icon name="columns" />
        {filterCount ? (
          <span className="filter-count" aria-hidden="true">
            {filterCount}
          </span>
        ) : null}
      </button>
      <Popover
        id={popoverId}
        open={open}
        onClose={() => setOpen(false)}
        triggerRef={buttonRef}
        label="열 설정"
        align="end"
        className="grid-colmenu-popover"
      >
        {props.columnFilters ? (
          <div className="popover-section">
            <button
              type="button"
              className="grid-btn grid-colfilter-toggle"
              aria-pressed={props.columnFilters.open}
              data-testid="grid-colfilter-toggle"
              onClick={props.columnFilters.onToggle}
            >
              <Icon name="filter" />
              <span>열 필터 행{props.columnFilters.count ? ` (${props.columnFilters.count})` : ""}</span>
            </button>
          </div>
        ) : null}

        {props.auxColumns?.ids.length ? (
          <div className="popover-section">
            {(() => {
              const aux = props.auxColumns;
              const allOn = aux.ids.every((id) => props.visibility[id] === true);
              return (
                <button
                  type="button"
                  className="grid-btn"
                  data-testid="grid-aux-columns"
                  aria-pressed={allOn}
                  onClick={() => aux.onToggleAll(!allOn)}
                >
                  <Icon name="columns" />
                  <span>
                    {aux.family} 보조 열 {aux.ids.length}개 {allOn ? "모두 빼기" : "모두 추가"}
                  </span>
                </button>
              );
            })()}
          </div>
        ) : null}

        <fieldset className="popover-section grid-popover" aria-label="표시할 열">
          <legend className="popover-title">표시할 열</legend>
          {props.columns.map((column) => {
            const auto = props.autoHidden?.get(column.id);
            const item = (
              <label key={column.id} className="grid-popover-item">
                <input
                  type="checkbox"
                  checked={props.visibility[column.id] !== false && !auto}
                  disabled={column.id === locked}
                  onChange={(event) => props.onToggleColumn(column.id, event.target.checked)}
                />
                {column.header}
              </label>
            );
            if (!auto) return item;
            return (
              <div key={column.id} className="grid-popover-row" data-testid={`grid-autohidden-${column.id}`}>
                {item}
                <button
                  type="button"
                  className="grid-popover-show"
                  aria-label={`${column.header} 표시 (${AUTO_HIDE_LABEL[auto]})`}
                  onClick={() => props.onToggleColumn(column.id, true)}
                >
                  {AUTO_HIDE_LABEL[auto]} — 표시
                </button>
              </div>
            );
          })}
        </fieldset>
        {props.fieldPicker ? <FieldPicker {...props.fieldPicker} /> : null}
      </Popover>
    </span>
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
  /** The text is searched on the server over every row (timeline `q=`), not the loaded rows. */
  serverSearch?: boolean;
  scanned?: number;
  sorting: boolean;
  loadedCount: number;
  canLoadMore: boolean;
  onLoadMore: () => void;
  loading: boolean;
  /** Sentence shown while the first page loads (the grid itself shows skeleton rows). */
  loadingText?: string;
  /** Scope line for category nodes ("범주: 운영 체제 (5 유형)"). */
  scope?: string;
  /** Checked rows (kept across pages, scrolling and refetches); "선택 N건" when any. */
  selectedCount?: number;
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
      <span
        data-testid="grid-footer-total"
        // The search engine and its time are diagnostics, not a finding: tooltip only (R7 L3, C-D16).
        title={props.backend ? `${backendLabel(props.backend) || "조회"} · ${seconds}` : undefined}
      >
        총{" "}
        {props.total !== null ? `${formatCount(props.total)}건` : props.loading ? "세는 중…" : "알 수 없음"}
      </span>
      {props.selectedCount ? (
        <span data-testid="grid-footer-selected">선택 {formatCount(props.selectedCount)}건</span>
      ) : null}
      {props.loading ? (
        <span className="grid-note" data-testid="grid-footer-loading">
          {props.loadingText ?? "불러오는 중…"}
        </span>
      ) : null}
      {props.filtering ? (
        <span className="grid-note">
          필터 결과 {formatCount(props.shown)}건 ·{" "}
          {props.serverSearch
            ? "서버 검색: 전체 이벤트에서 요약·대상·경로·이벤트 이름을 찾습니다."
            : props.serverPathFilter
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
