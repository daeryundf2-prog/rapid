// biome-ignore-all lint/a11y/useSemanticElements: ARIA grid row of filter inputs inside the virtualized div grid
// biome-ignore-all lint/a11y/useFocusableInteractive: the inputs inside the cells take focus, not the row/cells
/**
 * Column header filter row (plan analysis-workbench-p1 §4, U-P1-4): one input per visible
 * column under the header row — text = contains, time = from/to, number = min/max. Inputs
 * commit on a short debounce, Enter and blur; Esc empties the focused input (and commits).
 * The values live in the URL (`cf=`) through the filter store.
 */

import { useEffect, useRef, useState } from "react";
import type { ColumnFilter } from "../../contracts/collection";
import {
  type ColumnFilterKind,
  columnFilterValue,
  filterKindOf,
  isValidBound,
  joinTimeRange,
  splitTimeRange,
} from "../filters/columnFilters";
import type { ColumnSpec } from "./types";

export const COLUMN_FILTER_DEBOUNCE_MS = 300;

interface InputProps {
  label: string;
  value: string;
  placeholder?: string;
  invalidReason?: string;
  inputMode?: "numeric" | "text";
  /** `<datalist>` id with suggestions (유형: known artifact types). */
  list?: string;
  onCommit: (value: string) => void;
}

function FilterInput({ label, value, placeholder, invalidReason, inputMode, list, onCommit }: InputProps) {
  const [text, setText] = useState(value);
  const committed = useRef(value);
  // Latest commit callback without restarting the debounce on every parent render.
  const commitRef = useRef(onCommit);
  commitRef.current = onCommit;
  useEffect(() => {
    if (value !== committed.current) {
      committed.current = value;
      setText(value);
    }
  }, [value]);
  useEffect(() => {
    if (text === committed.current) return;
    const timer = setTimeout(() => {
      committed.current = text;
      commitRef.current(text);
    }, COLUMN_FILTER_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [text]);
  const commitNow = (next: string) => {
    committed.current = next;
    commitRef.current(next);
  };
  const invalid = Boolean(invalidReason) && text.trim() !== "";
  return (
    <input
      type="text"
      className="grid-colfilter-input"
      aria-label={label}
      aria-invalid={invalid || undefined}
      title={invalid ? invalidReason : undefined}
      placeholder={placeholder}
      inputMode={inputMode}
      list={list}
      value={text}
      onChange={(event) => setText(event.target.value)}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          // Esc empties this input; it is not a "close" for the dialogs / drawer behind it.
          event.preventDefault();
          event.stopPropagation();
          setText("");
          commitNow("");
        } else if (event.key === "Enter") {
          event.preventDefault();
          commitNow(text);
        }
      }}
      onBlur={() => {
        if (text !== committed.current) commitNow(text);
      }}
    />
  );
}

export interface ColumnFilterRowProps {
  specs: ColumnSpec[];
  widths: number[];
  lefts: (number | undefined)[];
  selectWidth: number;
  height: number;
  rowIndex: number;
  filters: readonly ColumnFilter[];
  onChange: (col: string, op: ColumnFilter["op"], value: string) => void;
  /** Suggestions per column id (유형: artifact types from `/tree` artifact_type_counts). */
  suggestions?: Record<string, readonly string[]>;
}

const NUMBER_REASON = "숫자를 입력하세요";
const TIME_REASON = "날짜(2025-01-01) 또는 ISO 시각을 입력하세요";

function CellInputs({
  spec,
  kind,
  filters,
  onChange,
  listId,
}: {
  spec: ColumnSpec;
  kind: ColumnFilterKind;
  filters: readonly ColumnFilter[];
  onChange: ColumnFilterRowProps["onChange"];
  listId?: string;
}) {
  const name = `${spec.header} 필터`;
  if (kind === "number") {
    const min = columnFilterValue(filters, spec.id, ">");
    const max = columnFilterValue(filters, spec.id, "<");
    return (
      <span className="grid-colfilter-pair">
        <FilterInput
          label={`${name} (최소)`}
          placeholder="최소"
          inputMode="numeric"
          value={min}
          invalidReason={isValidBound(kind, ">", min) ? undefined : NUMBER_REASON}
          onCommit={(value) => onChange(spec.id, ">", value)}
        />
        <FilterInput
          label={`${name} (최대)`}
          placeholder="최대"
          inputMode="numeric"
          value={max}
          invalidReason={isValidBound(kind, "<", max) ? undefined : NUMBER_REASON}
          onCommit={(value) => onChange(spec.id, "<", value)}
        />
      </span>
    );
  }
  if (kind === "time") {
    const range = columnFilterValue(filters, spec.id, ":");
    const [from, to] = splitTimeRange(range);
    return (
      <span className="grid-colfilter-pair">
        <FilterInput
          label={`${name} (시작)`}
          placeholder="시작"
          value={from}
          invalidReason={isValidBound(kind, ":", from) ? undefined : TIME_REASON}
          onCommit={(value) => onChange(spec.id, ":", joinTimeRange(value, to))}
        />
        <FilterInput
          label={`${name} (끝)`}
          placeholder="끝"
          value={to}
          invalidReason={isValidBound(kind, ":", to) ? undefined : TIME_REASON}
          onCommit={(value) => onChange(spec.id, ":", joinTimeRange(from, value))}
        />
      </span>
    );
  }
  return (
    <FilterInput
      label={name}
      list={listId}
      // 유형: the text picks every known type containing it (sent as exact server values).
      placeholder={spec.id === "type" ? (listId ? "포함(목록의 유형)" : "정확히 일치") : "포함"}
      value={columnFilterValue(filters, spec.id, ":")}
      onCommit={(value) => onChange(spec.id, ":", value)}
    />
  );
}

export function ColumnFilterRow(props: ColumnFilterRowProps) {
  const { specs, widths, lefts } = props;
  return (
    <div
      role="row"
      aria-rowindex={props.rowIndex}
      className="grid-row grid-header grid-colfilter-row"
      data-testid="grid-colfilter-row"
      style={{ height: props.height }}
    >
      <div role="gridcell" className="grid-cell grid-cell-select" style={{ width: props.selectWidth }} />
      {specs.map((spec, i) => {
        const kind = filterKindOf(spec);
        return (
          <div
            key={spec.id}
            role="gridcell"
            data-col={spec.id}
            className={`grid-cell grid-colfilter-cell${lefts[i] !== undefined ? " grid-cell-first" : ""}`}
            style={{ width: widths[i], left: lefts[i] }}
          >
            {kind === "none" ? null : (
              <>
                <CellInputs
                  spec={spec}
                  kind={kind}
                  filters={props.filters}
                  onChange={props.onChange}
                  listId={props.suggestions?.[spec.id]?.length ? `colfilter-list-${spec.id}` : undefined}
                />
                {props.suggestions?.[spec.id]?.length ? (
                  <datalist id={`colfilter-list-${spec.id}`}>
                    {props.suggestions[spec.id]?.map((value) => (
                      <option key={value} value={value} />
                    ))}
                  </datalist>
                ) : null}
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
