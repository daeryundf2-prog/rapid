import { type RefObject, useEffect, useId, useRef, useState } from "react";
import { useEscape } from "../../a11y/focus";
import { FilterBar } from "../filters/FilterBar";
import { setAxiomMode } from "./columns/axiom";
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
}

export function GridToolbar(props: GridToolbarProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const toolbarRef = useRef<HTMLDivElement>(null);
  const menuId = useId();
  const { preset, onDensity } = props;

  // AXIOM preset: two-line titles (DataGrid sets `data-preset` on the root for the CSS; the
  // comfortable row height is chosen when the preset is picked).
  useEffect(() => {
    setAxiomMode(preset === "axiom");
    return () => setAxiomMode(false);
  }, [preset]);

  useEscape(() => setMenuOpen(false), menuOpen);

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
            </fieldset>
          ) : null}
        </div>

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
      <span>총 {props.total !== null ? `${formatCount(props.total)}건` : "알 수 없음"}</span>
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
