import { QueryClientContext } from "@tanstack/react-query";
import { Fragment, useContext, useEffect, useId, useMemo, useState } from "react";
import { DisabledReason } from "../../../a11y/primitives";
import { getRunDashboard, type RunDashboard } from "../../../api/dashboard";
import type { SourceMetadata, SourcePreview } from "../../../api/viewer";
import { runDisplayName } from "../../../app/collections";
import type { GridRow, ReviewStatus } from "../../../contracts/collection";
import type { ViewerTarget } from "../../../contracts/viewer";
import { Icon } from "../../../icons";
import { serializeRoute } from "../../../router";
import { useRoute, useRuns, useTimezone } from "../../../state/hooks";
import { flatValue, isScalarish } from "../../../utils/flatValue";
import { evidenceTime, evidenceTimeTooltip, parseInstant } from "../../../utils/time";
import { timestampKindLabel } from "../../../utils/timeKinds";
import {
  caseHref,
  caseLabel,
  crossCaseOccurrences,
  crossCaseRunIds,
  occurrenceRoute,
} from "../../analysis/crossCase";
import { useFilterStore } from "../../filters/filterStore";
import { useGridLocalStore } from "../../grid/adapter";
import { defaultFieldHeaders } from "../../grid/columns/artifacts";
import { familyCoreFacts } from "../../grid/columns/families";
import { FIELD_LABELS } from "../../grid/columns/fieldColumns";
import { NTFS_EMPTY_HINT, NTFS_RUN_COMMAND } from "../../grid/columns/files";
import { timeKindsText, timelineAreaLabel, tsLabelsOf } from "../../grid/columns/timeline";
import { EmptyHintLink } from "../../grid/EmptyHintLink";
import { noteKey, useSessionNote } from "../../grid/sessionNotes";
import { usePromotedFields } from "../../grid/usePromotedFields";
import { dispatchCommand, setViewerTarget, useCommandContext, useViewerRouteMode } from "../adapter";
import { recordBanners } from "../banners";
import { bytesOfHex, filterUtf16Strings, hexDump, utf16Strings } from "../binaryValue";
import { locatorText } from "../citation";
import { ROWS_FOR_SOURCE_COMMAND, writeClipboard } from "../commands";
import { evidenceInfo, isSourceMissing, RECOVERY_LABELS } from "../evidenceInfo";
import {
  bytesLabel,
  eventLevelLabel,
  hexLabel,
  logonTypeLabel,
  numberLabel,
  severityLabel,
} from "../fieldFormat";
import { humanizeKey, layoutFields, type RecordLayout, recordLayout, type SheetEntry } from "../fieldSheets";
import { isDirectoryTarget } from "../modes";
import { artifactRowRoute, TIMELINE_WINDOW_MS, timelineWindowRoute } from "../pivots";
import { makeRecordField, type RecordField, recordByteRange } from "../record";
import { eventRecordXml, hasEventRecord, RECONSTRUCTED_LABEL } from "../recordXml";
import { isSid, useSidName } from "../sidNames";
import { isRawToken, metaLabel, metaValueLabel, sectionLabels } from "./metaLabels";

export const REVIEW_LABELS: Record<ReviewStatus, string> = {
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
  "include-in-report": "보고서 포함",
};

const PREVIEW_STATUS: Record<string, string> = {
  available: "미리보기 가능",
  "metadata-only": "메타데이터만",
  "not-available": "미리보기 없음",
  "parse-failed": "해석 실패",
  capped: "크기 상한 초과",
};

const HASH_KEYS = new Set(["md5", "sha1", "sha256", "sha512", "sha384", "ssdeep", "imphash"]);
/** Nested objects with more keys than this start collapsed. */
const NESTED_OPEN_MAX = 8;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHashBundle(value: Record<string, unknown>): boolean {
  const entries = Object.entries(value);
  return (
    entries.length > 0 && entries.every(([k, v]) => HASH_KEYS.has(k.toLowerCase()) && typeof v === "string")
  );
}

/** A record key: its Korean label (raw key as tooltip), or the raw key in mono when it has none. */
function KeyTerm({ name, label: given }: { name: string; label?: string | null }) {
  // Unknown keys read humanised (snake_case → words); a key that has no readable form stays raw mono.
  const known = given === undefined ? metaLabel(name) : given;
  const human = humanizeKey(name);
  const label = known ?? (human !== name ? human : null);
  return label ? (
    <dt title={name} data-key={name}>
      {label}
    </dt>
  ) : (
    <dt className="mono" data-key={name}>
      {name}
    </dt>
  );
}

/**
 * 20×20 copy icon button (review #3): shown on row hover / focus; a successful copy swaps the
 * icon for a check for a moment — the row's width never changes.
 */
function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  return (
    <button
      type="button"
      className="icon-btn meta-copy"
      aria-label={`${label} 복사`}
      title={copied ? "복사됨" : `${label} 복사`}
      data-copied={copied ? "" : undefined}
      onClick={() => {
        writeClipboard(text)
          .then(() => setCopied(true))
          .catch(() => setCopied(false));
      }}
    >
      <Icon name={copied ? "check" : "copy"} size={14} />
    </button>
  );
}

/** A hash: mono 11px on one line, ellipsized, the full value as tooltip, then the copy button. */
function HashValue({ value, label }: { value: string; label: string }) {
  return (
    <span className="meta-hash">
      <span className="meta-hash-text mono" title={value}>
        {value}
      </span>
      <CopyButton text={value} label={label} />
    </span>
  );
}

/** Nested groups deeper than this render their values as compact text. */
const NESTED_MAX_DEPTH = 3;

/**
 * A nested object as key/value rows: keys get their Korean label at every level (raw key as
 * tooltip, unknown keys in mono), values their Korean reading (예/아니요, 검증 필요 …).
 */
function NestedValue({
  value,
  name,
  depth = 1,
}: {
  value: Record<string, unknown>;
  name: string;
  depth?: number;
}) {
  if (isHashBundle(value)) {
    return (
      <dl className="viewer-dl viewer-dl-nested">
        {Object.entries(value).map(([k, v]) => (
          <Fragment key={k}>
            <KeyTerm name={k} />
            <dd className="meta-hash-dd">
              <HashValue value={String(v)} label={`${name}.${k}`} />
            </dd>
          </Fragment>
        ))}
      </dl>
    );
  }
  const entries = Object.entries(value);
  const labels = sectionLabels(entries.map(([k]) => k));
  const list = (
    <dl className="viewer-dl viewer-dl-nested">
      {entries.map(([k, v]) => (
        <Fragment key={k}>
          <KeyTerm name={k} label={labels.get(k)} />
          <dd className="viewer-break">
            <NestedEntry name={`${name}.${k}`} value={v} depth={depth} />
          </dd>
        </Fragment>
      ))}
    </dl>
  );
  if (entries.length <= NESTED_OPEN_MAX) return list;
  return (
    <details className="viewer-details">
      <summary>{entries.length}개 항목</summary>
      {list}
    </details>
  );
}

/** One value inside a nested group: a deeper group (to NESTED_MAX_DEPTH), a list, or a scalar. */
function NestedEntry({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  if (depth < NESTED_MAX_DEPTH && isPlainObject(value)) {
    return <NestedValue value={value} name={name} depth={depth + 1} />;
  }
  if (depth < NESTED_MAX_DEPTH && Array.isArray(value) && value.some(isPlainObject)) {
    return <NestedList name={name} items={value} depth={depth + 1} />;
  }
  return <ScalarText name={name} value={value} />;
}

/** A list holding objects: folded "N개 항목", one nested group per item. */
function NestedList({ name, items, depth }: { name: string; items: unknown[]; depth: number }) {
  return (
    <details className="viewer-details">
      <summary>{items.length}개 항목</summary>
      <ol className="viewer-nested-list">
        {items.map((item, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: read-only snapshot of a record array
          <li key={index}>
            {isPlainObject(item) ? (
              <NestedValue value={item} name={`${name}[${index}]`} depth={depth} />
            ) : (
              <ScalarText name={`${name}[${index}]`} value={item} />
            )}
          </li>
        ))}
      </ol>
    </details>
  );
}

/**
 * A scalar's reading: its Korean label (raw value as tooltip), a raw parser token in mono, or
 * the plain text. Exported for tests.
 */
export function ScalarReading({ raw, text, name }: { raw: unknown; text: string; name?: string }) {
  const label = metaValueLabel(raw, name);
  if (label) {
    return (
      <span className="meta-value-label" title={String(raw)} data-raw={String(raw)}>
        {label}
      </span>
    );
  }
  if (typeof raw === "string" && isRawToken(raw)) return <span className="mono">{text}</span>;
  return <>{text || "—"}</>;
}

/** A nested / list scalar: short text, or the same fold + full copy as top-level long values. */
function ScalarText({ name, value }: { name: string; value: unknown }) {
  const field = makeRecordField(name, value);
  if (field.truncated) return <LongValue field={field} />;
  return <ScalarReading raw={value} text={field.value} name={name} />;
}

function FieldValue({ field }: { field: RecordField }) {
  const { raw } = field;
  if (isPlainObject(raw)) return <NestedValue value={raw} name={field.key} />;
  if (Array.isArray(raw) && raw.some((item) => typeof item === "object" && item !== null)) {
    return <NestedList name={field.key} items={raw} depth={1} />;
  }
  // Scalars and arrays of scalars (comma list) use the flat text; long ones fold (U-C3).
  if (field.truncated) return <LongValue field={field} />;
  return <ScalarReading raw={raw} text={field.value} name={field.key} />;
}

/**
 * Toggle buttons keep keyboard focus across the re-render they cause (the meta view may
 * re-render or re-create the button when the grid/viewer state updates): the clicked control's
 * `data-focus-key` is remembered and focused again after the update.
 */
let pendingFocusKey: string | null = null;
/** Bumped on every keepFocus(): effects re-run only when a focus request is pending. */
let pendingFocusSeq = 0;

function focusByKey(key: string): void {
  for (const el of document.querySelectorAll<HTMLElement>("[data-focus-key]")) {
    if (el.dataset.focusKey === key) {
      if (document.activeElement !== el) el.focus();
      return;
    }
  }
}

function keepFocus(key: string): void {
  pendingFocusKey = key;
  pendingFocusSeq += 1;
}

function useRestorePendingFocus(): void {
  const seq = pendingFocusKey ? pendingFocusSeq : 0;
  // biome-ignore lint/correctness/useExhaustiveDependencies: seq marks a new pending focus request
  useEffect(() => {
    const key = pendingFocusKey;
    if (!key) return;
    focusByKey(key);
    // A late update (store → bridge → viewer) may still re-create the control or move focus.
    const timer = window.setTimeout(() => {
      focusByKey(key);
      if (pendingFocusKey === key) pendingFocusKey = null;
    }, 0);
    return () => window.clearTimeout(timer);
  }, [seq]);
}

/** A value longer than the clip: folded text + "전체 보기 (N자)" / "접기" + copy of the FULL value. */
function LongValue({ field }: { field: RecordField }) {
  const [open, setOpen] = useState(false);
  useRestorePendingFocus();
  const focusKey = `longvalue:${field.key}`;
  const count = field.full.length.toLocaleString("ko-KR");
  return (
    <span className="meta-longvalue">
      {open ? (
        <pre className="viewer-break meta-longvalue-full">{field.full}</pre>
      ) : (
        <span>{field.value}</span>
      )}
      <span className="meta-longvalue-actions">
        <button
          type="button"
          className="viewer-button"
          aria-expanded={open}
          aria-label={open ? `${field.key} 접기` : `${field.key} 전체 보기 (${count}자)`}
          data-focus-key={focusKey}
          onClick={() => {
            keepFocus(focusKey);
            setOpen((v) => !v);
          }}
        >
          {open ? "접기" : `전체 보기 (${count}자)`}
        </button>
        <CopyButton text={field.full} label={field.key} />
      </span>
    </span>
  );
}

interface ColumnToggle {
  keys: string[];
  toggle: (key: string) => void;
  /** details key → header of the kind's default column that already shows it. */
  defaults: Map<string, string>;
}

/** Details keys with scalar values can become grid columns (artifact rows of one kind). */
function promotable(field: RecordField): boolean {
  return field.fromDetails === true && isScalarish(field.raw);
}

// ---------------------------------------------------------------------------
// Record view (viewer redesign §1–§9): banners · 핵심 (field sheet) · EventData / values table ·
// 원본 레코드 (reconstructed XML) · 출처 · 기타 필드 — and, at the very bottom of the meta view,
// "내부 검증 정보(증거 아님)" folded.
// ---------------------------------------------------------------------------

/** The record's banners, above everything else (warnings an examiner must read first). */
export function RecordBanners({ row }: { row: GridRow | null }) {
  const banners = recordBanners(row);
  if (!banners.length) return null;
  return (
    <div className="meta-banners" data-testid="record-banners">
      {banners.map((banner) => (
        <p
          key={banner.id}
          className="meta-banner"
          data-tone={banner.tone}
          data-banner={banner.id}
          role={banner.tone === "danger" ? "alert" : "note"}
          title={banner.keys.join(", ")}
        >
          <strong>{banner.title}</strong>
          {banner.detail ? <span> — {banner.detail}</span> : null}
        </p>
      ))}
    </div>
  );
}

/** Sub-second-precise sibling of a time key (EVTX `timestamp_100ns`) and its raw FILETIME. */
function preciseTime(
  fields: Record<string, unknown>,
  key: string,
  raw: unknown,
): { value: unknown; filetime?: unknown } {
  const base = key === "event_created_at" || key === "time_created" ? "timestamp" : key;
  const precise = fields[`${key}_100ns`] ?? fields[`${base}_100ns`];
  const filetime = fields[`${key}_filetime`] ?? fields[`${base}_filetime`];
  const a = parseInstant(typeof precise === "string" ? precise : null);
  const b = parseInstant(typeof raw === "string" || typeof raw === "number" ? raw : null);
  const same = a && b && Math.floor(a.getTime() / 1000) === Math.floor(b.getTime() / 1000);
  return { value: same ? precise : raw, ...(filetime !== undefined ? { filetime } : {}) };
}

/** Kind chip of a time entry: the row's own `timestamp_kind` for `timestamp`, else the sheet's. */
function timeKindOf(entry: SheetEntry, fields: Record<string, unknown>): string {
  if (entry.key === "timestamp") {
    const own = fields.timestamp_kind ?? fields.timestamp_label;
    if (typeof own === "string" && own) return own;
  }
  return entry.timeKind ?? "";
}

/**
 * One evidence time: "2025-05-29 23:25:26.427 (KST+09:00) · UTC 14:25:26.427", the time-kind
 * chip, FILETIME in the tooltip and the "타임라인 ±5분" button.
 */
export function TimeValue({
  value,
  label,
  kind,
  filetime,
  runId,
}: {
  value: unknown;
  label: string;
  kind?: string;
  filetime?: unknown;
  runId: string;
}) {
  const { timezone } = useTimezone();
  const { route, navigate } = useRoute();
  const input = typeof value === "string" || typeof value === "number" ? value : null;
  const reading = evidenceTime(input, timezone);
  if (!reading) return <ScalarReading raw={value} text={flatValue(value)} />;
  const kindLabel = kind ? timestampKindLabel(kind) : "";
  const windowRoute = timelineWindowRoute(runId, reading.iso, TIMELINE_WINDOW_MS, route.tz);
  const raw = typeof filetime === "string" || typeof filetime === "number" ? filetime : null;
  return (
    <span className="meta-time" data-iso={reading.iso}>
      <span className="meta-time-text" title={evidenceTimeTooltip(input, timezone, raw)}>
        <span className="meta-time-local">{reading.local}</span>{" "}
        <span className="meta-time-zone">({reading.zone})</span>
        {reading.utc ? <span className="meta-time-utc"> · {reading.utc}</span> : null}
      </span>
      {kindLabel ? (
        <span className="meta-time-kind" title={`시각 종류: ${kind}`}>
          {kindLabel}
        </span>
      ) : null}
      {windowRoute ? (
        <button
          type="button"
          className="meta-clock meta-tl-button"
          aria-label={`${label} 타임라인 ±5분`}
          title="이 시각 전후 5분을 타임라인에서 보기"
          onClick={() => navigate(windowRoute)}
        >
          <Icon name="clock" /> ±5분
        </button>
      ) : null}
    </span>
  );
}

/** A SID with its account name from this run's SAM rows (or the well-known name). */
function SidValue({ sid, runId }: { sid: string; runId: string }) {
  const name = useSidName(runId, sid);
  return (
    <span className="meta-sid">
      <span className="mono">{sid}</span>
      {name ? (
        <span
          className="meta-sid-name"
          title={name.source === "sam" ? "이 런의 SAM 계정 행에서 확인" : "잘 알려진 SID"}
        >
          {" "}
          ({name.name})
        </span>
      ) : null}
    </span>
  );
}

/** Registry binary data: hex dump + UTF-16LE strings (garbage strings hidden with a note). */
export function BinaryPanel({ value, label }: { value: unknown; label: string }) {
  const bytes = bytesOfHex(value);
  if (!bytes) return <span className="mono viewer-break">{flatValue(value)}</span>;
  const lines = hexDump(bytes);
  const strings = utf16Strings(bytes);
  return (
    <details className="viewer-details meta-binary" data-testid="binary-panel">
      <summary>
        이진 값 {bytes.length.toLocaleString("ko-KR")}바이트
        {strings.length ? ` · UTF-16 문자열 ${strings.length}개` : ""}
      </summary>
      {strings.length ? (
        <ul className="meta-binary-strings" aria-label={`${label} UTF-16 문자열`}>
          {strings.map((text, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: strings in byte order
            <li key={index} className="mono">
              {text}
            </li>
          ))}
        </ul>
      ) : (
        <p className="meta-hint">읽을 수 있는 UTF-16 문자열이 없습니다.</p>
      )}
      <pre className="meta-hexdump" title={`${label} 헥스 덤프`}>
        {lines.map((line) => `${line.offset}  ${line.hex.padEnd(47, " ")}  ${line.ascii}`).join("\n")}
      </pre>
      {bytes.length > 4096 ? <p className="meta-hint">앞 4,096바이트만 표시합니다.</p> : null}
    </details>
  );
}

const BINARY_TEXT = /^hex(\([0-9a-f]+\))?:/i;

/** Parser `utf16le_strings` inside a value: garbage (binary read as UTF-16) dropped and counted. */
function cleanUtf16(value: unknown, depth = 0): { value: unknown; hidden: number } {
  if (depth > 4) return { value, hidden: 0 };
  if (Array.isArray(value)) {
    let hidden = 0;
    const out = value.map((item) => {
      const cleaned = cleanUtf16(item, depth + 1);
      hidden += cleaned.hidden;
      return cleaned.value;
    });
    return { value: out, hidden };
  }
  if (!isPlainObject(value)) return { value, hidden: 0 };
  let hidden = 0;
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value)) {
    if (key === "utf16le_strings" && Array.isArray(inner)) {
      const filtered = filterUtf16Strings(inner);
      out[key] = filtered.shown;
      if (filtered.hidden) out.utf16le_strings_hidden = filtered.hidden;
      hidden += filtered.hidden;
      continue;
    }
    const cleaned = cleanUtf16(inner, depth + 1);
    out[key] = cleaned.value;
    hidden += cleaned.hidden;
  }
  return { value: out, hidden };
}

/** The value of one sheet entry, by format. */
function EntryValue({
  entry,
  fields,
  runId,
}: {
  entry: SheetEntry;
  fields: Record<string, unknown>;
  runId: string;
}) {
  const raw = entry.raw;
  if (entry.missing) {
    return (
      <span className="meta-missing" data-missing="">
        레코드에 없음
      </span>
    );
  }
  const scalar = typeof raw === "string" || typeof raw === "number" || typeof raw === "boolean";
  const coded = (text: string) => (
    <span className="meta-coded" title={flatValue(raw)} data-raw={flatValue(raw)}>
      {text}
    </span>
  );
  if (entry.format === "time" && scalar) {
    const { value, filetime } = preciseTime(fields, entry.key, raw);
    return (
      <TimeValue
        value={value}
        label={entry.label}
        kind={timeKindOf(entry, fields)}
        filetime={filetime}
        runId={runId}
      />
    );
  }
  // Catalogue reading (발신 for outgoing, a Korean type name …); the raw value is the tooltip.
  if (scalar && entry.valueLabel) return coded(entry.valueLabel);
  if (scalar) {
    switch (entry.format) {
      case "eventLevel":
        return coded(eventLevelLabel(raw));
      case "logonType":
        return coded(logonTypeLabel(raw));
      case "detectionSeverity":
        return coded(severityLabel(raw));
      case "bytes":
        return coded(bytesLabel(raw));
      case "hex":
        return coded(hexLabel(raw));
      case "number":
        return coded(numberLabel(raw));
      case "sid":
        return isSid(String(raw)) ? <SidValue sid={String(raw)} runId={runId} /> : String(raw);
      case "mono":
      case "url":
      case "path": {
        const field = makeRecordField(entry.key, raw);
        if (field.truncated) return <LongValue field={field} />;
        if (entry.key === "data_hex") return <BinaryPanel value={raw} label={entry.label} />;
        return <span className="mono viewer-break">{field.value}</span>;
      }
      default:
        break;
    }
  }
  const cleaned = cleanUtf16(raw);
  const field = makeRecordField(entry.key, cleaned.value, entry.fromDetails);
  return (
    <>
      <FieldValue field={field} />
      {cleaned.hidden ? (
        <span className="meta-hint" data-testid="utf16-hidden">
          {" "}
          · 비인쇄 문자가 많은 UTF-16 문자열 {cleaned.hidden}개는 숨겼습니다(이진 데이터를 문자로 읽은 값).
        </span>
      ) : null}
    </>
  );
}

/** Copy text of an entry (full value; objects as JSON). */
function entryText(entry: SheetEntry): string {
  return flatValue(entry.raw);
}

/** A key/value list of sheet entries: label (raw key + aliases as tooltip), value, hover copy. */
function EntryList({
  entries,
  fields,
  runId,
  columns,
}: {
  entries: SheetEntry[];
  fields: Record<string, unknown>;
  runId: string;
  columns?: ColumnToggle;
}) {
  useRestorePendingFocus();
  return (
    <dl className="viewer-dl">
      {entries.map((entry) => {
        const tooltip = [
          entry.key,
          entry.derived ? "(다른 필드에서 읽음)" : "",
          entry.missing ? "(이 이벤트에 있어야 할 필드 — 파서 출력에 없음)" : "",
          entry.aliases.length ? `같은 값: ${entry.aliases.join(", ")}` : "",
        ]
          .filter(Boolean)
          .join(" · ");
        const shown = columns?.keys.includes(entry.key) ?? false;
        const name = FIELD_LABELS[entry.key] ? `${entry.key}(${FIELD_LABELS[entry.key]})` : entry.key;
        const fieldLike: RecordField = makeRecordField(entry.key, entry.raw, entry.fromDetails);
        return (
          <Fragment key={`${entry.label}:${entry.key}`}>
            <dt title={tooltip} data-key={entry.key}>
              {entry.label}
            </dt>
            <dd className="viewer-break meta-field" data-key={entry.key}>
              <span className="meta-field-value">
                <EntryValue entry={entry} fields={fields} runId={runId} />
              </span>
              <CopyButton text={entryText(entry)} label={entry.label} />
              {columns && entry.fromDetails && columns.defaults.has(entry.key) ? (
                <DisabledReason reason={`기본 열 '${columns.defaults.get(entry.key)}'에 이미 표시됩니다`}>
                  <button
                    type="button"
                    className="meta-colbtn"
                    aria-pressed={true}
                    aria-label={`${columns.defaults.get(entry.key)} 열로 표시 중`}
                  >
                    <Icon name="columns" />
                  </button>
                </DisabledReason>
              ) : columns && promotable(fieldLike) ? (
                <button
                  type="button"
                  className="meta-colbtn"
                  aria-pressed={shown}
                  aria-label={shown ? `${name} 열에서 제거` : `${name} 열로 표시`}
                  title={shown ? "열에서 제거" : "열로 표시"}
                  data-focus-key={`column:${entry.key}`}
                  onClick={() => {
                    keepFocus(`column:${entry.key}`);
                    columns.toggle(entry.key);
                  }}
                >
                  <Icon name="columns" />
                </button>
              ) : null}
            </dd>
          </Fragment>
        );
      })}
    </dl>
  );
}

/** EventData / registry values: a name/value table, always visible under 핵심. */
function ValueTable({ table }: { table: NonNullable<RecordLayout["table"]> }) {
  return (
    <table className="meta-kv" aria-label={table.label}>
      <thead>
        <tr>
          <th scope="col" className="meta-kv-cell meta-kv-head">
            이름
          </th>
          <th scope="col" className="meta-kv-cell meta-kv-head">
            값
          </th>
        </tr>
      </thead>
      <tbody>
        {table.rows.map((item, index) => {
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: rows in record order (names may repeat)
            <tr key={index}>
              <th scope="row" className="mono meta-kv-cell meta-kv-name">
                {item.name}
              </th>
              <td className="viewer-break meta-kv-cell">
                {typeof item.value === "string" && BINARY_TEXT.test(item.value) ? (
                  <BinaryPanel value={item.value} label={item.name} />
                ) : isPlainObject(item.value) ? (
                  <NestedValue value={item.value} name={`${table.key}.${item.name}`} />
                ) : (
                  <ScalarText name={`${table.key}.${item.name}`} value={item.value} />
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** "원본 레코드": the EVTX record rebuilt as Event XML (labelled as a reconstruction). */
function RecordXml({
  fields,
  offset,
  onOpenHex,
}: {
  fields: Record<string, unknown>;
  offset: number | null;
  onOpenHex: (offset: number) => void;
}) {
  const xml = eventRecordXml(fields);
  return (
    <details className="viewer-details meta-record-group" data-testid="record-xml">
      <summary>원본 레코드 — {RECONSTRUCTED_LABEL}</summary>
      <p className="meta-hint">
        서버는 원본 XML을 보내지 않습니다. 파서가 해석한 System·EventData 값으로 Event XML을 재구성했습니다.
        {offset !== null ? (
          <>
            {" "}
            <button type="button" className="viewer-button mono" onClick={() => onOpenHex(offset)}>
              헥스에서 레코드 보기 0x{offset.toString(16).toUpperCase()}
            </button>
          </>
        ) : null}
      </p>
      <span className="meta-xml-actions">
        <CopyButton text={xml} label="재구성 XML" />
      </span>
      <pre className="meta-xml">{xml}</pre>
    </details>
  );
}

/** Decoded record, evidence first: 핵심 · table · 원본 레코드 · 출처 · 기타 필드. */
function RecordSection({
  row,
  layout,
  runId,
  columns,
  onOpenHex,
}: {
  row: GridRow | null;
  layout: RecordLayout;
  runId: string;
  columns?: ColumnToggle;
  onOpenHex: (offset: number) => void;
}) {
  const fields = layoutFields(row);
  const offset = recordByteRange(row)?.offset ?? null;
  const json = JSON.stringify(isPlainObject(row?.fields.details) ? row?.fields.details : fields, null, 2);
  return (
    <section aria-labelledby="viewer-record-title" className="meta-record" data-sheet={layout.sheet.id}>
      <h3 className="viewer-subtitle" id="viewer-record-title">
        레코드
        <span className="meta-sheet-label"> · {layout.sheet.label}</span>
        <span className="meta-record-actions">
          <CopyButton text={json} label="레코드 JSON" />
        </span>
      </h3>
      {layout.core.length ? (
        <section aria-label="레코드 핵심" className="meta-record-group">
          <h4>핵심</h4>
          <EntryList entries={layout.core} fields={fields} runId={runId} columns={columns} />
        </section>
      ) : null}
      {layout.table ? (
        <section
          aria-label={`레코드 ${layout.table.label}`}
          className="meta-record-group"
          data-testid="record-table"
        >
          <h4>
            {layout.table.label} {layout.table.rows.length}개
          </h4>
          <ValueTable table={layout.table} />
        </section>
      ) : null}
      {hasEventRecord(row?.artifactType, fields) ? (
        <RecordXml fields={fields} offset={offset} onOpenHex={onOpenHex} />
      ) : null}
      {layout.provenance.length ? (
        <section aria-label="레코드 출처" className="meta-record-group">
          <h4>출처</h4>
          <EntryList entries={layout.provenance} fields={fields} runId={runId} columns={columns} />
        </section>
      ) : null}
      {layout.other.length ? (
        <section aria-label="레코드 기타 필드" className="meta-record-group" data-testid="record-other">
          <h4>기타 필드 {layout.other.length}개</h4>
          <EntryList entries={layout.other} fields={fields} runId={runId} columns={columns} />
        </section>
      ) : null}
    </section>
  );
}

/** Governance / validation keys: folded at the very bottom, never above evidence. */
function GovernanceSection({
  layout,
  row,
  runId,
}: {
  layout: RecordLayout;
  row: GridRow | null;
  runId: string;
}) {
  if (!layout.governance.length) return null;
  return (
    <details className="viewer-details meta-record-group meta-governance" data-testid="record-governance">
      <summary>내부 검증 정보(증거 아님) {layout.governance.length}개</summary>
      <p className="meta-hint">
        파서·도구의 자체 점검 항목입니다. 레코드의 내용(증거)이 아니며 보고서의 근거로 쓰지 않습니다.
      </p>
      <EntryList entries={layout.governance} fields={layoutFields(row)} runId={runId} />
    </details>
  );
}

/** Korean reading of a timeline event's `source` (C9). */
const TIMELINE_SOURCE_LABELS: Readonly<Record<string, string>> = {
  artifacts: "아티팩트 출력",
  files: "파일 목록(파일 시스템 시각)",
  docs: "문서 후보",
};

function provenanceEntries(row: GridRow | null): Array<[string, string]> {
  if (!row) return [];
  const out: Array<[string, string]> = [];
  if (row.ref.collection === "timeline") {
    // Timeline events (C9): Korean readings, the raw ids in brackets.
    const sourceType = typeof row.fields.sourceArtifactType === "string" ? row.fields.sourceArtifactType : "";
    const area = timelineAreaLabel(sourceType || row.artifactType);
    if (row.artifactType)
      out.push([
        "이벤트",
        area && area !== row.artifactType ? `${area} (${row.artifactType})` : row.artifactType,
      ]);
    const kinds = timeKindsText(tsLabelsOf(row));
    if (kinds) out.push(["시각 종류", kinds]);
    if (row.provider)
      out.push([
        "출처",
        TIMELINE_SOURCE_LABELS[row.provider]
          ? `${TIMELINE_SOURCE_LABELS[row.provider]} (${row.provider})`
          : row.provider,
      ]);
    return out;
  }
  // Output-file rows reuse artifactType for their kind (보고 종류 filter): call it 종류 there.
  if (row.artifactType)
    out.push([row.ref.collection === "outputs" ? "종류" : "아티팩트 유형", row.artifactType]);
  if (row.provider) out.push(["수집기(provider)", row.provider]);
  const record = row.fields.artifact_record;
  if (record && typeof record === "object") {
    for (const [key, value] of Object.entries(record as Record<string, unknown>)) {
      if (value === null || value === undefined || value === "") continue;
      if (typeof value === "object") continue;
      const label = key === "artifact_id" ? "아티팩트 ID" : metaLabel(key);
      out.push([label ? `레코드 ${label}` : `artifact_record.${key}`, String(value)]);
      if (out.length > 24) break;
    }
  }
  return out;
}

/**
 * Files rows: NTFS provenance from the newest NTFS-meta analysis (plan analysis-workbench-p1
 * U-P1-3). `joined` is false until such an analysis exists (the section then links to it).
 */
function ntfsProvenance(
  row: GridRow | null,
  formatTime: (value: number | string | undefined) => string,
): { joined: boolean; reason: string | null; entries: Array<[string, string]> } | null {
  if (row?.ref.collection !== "files") return null;
  const record =
    row.fields.ntfs && typeof row.fields.ntfs === "object"
      ? (row.fields.ntfs as Record<string, unknown>)
      : null;
  const text = (value: unknown) =>
    typeof value === "string" || typeof value === "number" ? String(value) : "";
  const time = (value: unknown) =>
    typeof value === "string" || typeof value === "number" ? formatTime(value) : "—";
  const joined = typeof row.fields.ntfsJoinId === "string" && row.fields.ntfsJoinId !== "";
  // An NTFS-meta analysis exists but the server did not join it (too_large / no_volume_prefix / skipped).
  const reason =
    !joined && typeof row.fields.ntfsJoinReason === "string" && row.fields.ntfsJoinReason
      ? row.fields.ntfsJoinReason
      : null;
  const entries: Array<[string, string]> = [
    ["파일 시스템", text(row.fields.filesystem) || "—"],
    ["소스 이미지 경로", text(row.fields.sourceImage) || "—"],
  ];
  if (joined) {
    entries.push(
      ["MFT 엔트리", record ? text(record.entry_number) || "—" : "일치하는 MFT 레코드 없음"],
      ["생성 시각(NTFS)", time(record?.created_at)],
      ["접근 시각(NTFS)", time(record?.accessed_at)],
      ["MFT 수정 시각", time(record?.mft_modified_at)],
    );
    if (record && typeof record.in_use === "boolean")
      entries.push(["MFT 사용 중", record.in_use ? "예" : "아니오"]);
  } else if (reason) {
    entries.push(["NTFS 조인", reason]);
  }
  return { joined, reason, entries };
}

interface MetaViewProps {
  target: ViewerTarget;
  preview: SourcePreview | null;
  metadata: SourceMetadata | null;
  metadataError: string | null;
  hashBusy: boolean;
  row: GridRow | null;
  sessionMarks: string[];
  onComputeHash: () => void;
}

/** Cross-case result row: every case (run) the indicator occurs in, each a link to open it there. */
function CrossCaseSection({ row, runId }: { row: GridRow | null; runId: string }) {
  if (row?.ref.collection !== "analysis" || row.fields.kind !== "cross-case") return null;
  const details = isPlainObject(row.fields.details) ? row.fields.details : {};
  const occurrences = crossCaseOccurrences(details);
  const indicator = typeof details.indicator === "string" ? details.indicator : null;
  const others = crossCaseRunIds(details).filter((id) => id !== runId);
  return (
    <section aria-labelledby="viewer-crosscase-title" data-testid="cross-case-links">
      <h3 className="viewer-subtitle" id="viewer-crosscase-title">
        다른 케이스
      </h3>
      {others.length === 0 ? (
        <p className="meta-hint">다른 케이스의 위치 정보가 없습니다.</p>
      ) : (
        <ul className="meta-case-links">
          {others.map((id) => {
            const hits = occurrences.filter((o) => o.runId === id);
            return (
              <li key={id}>
                <a href={caseHref(details, id)} className="meta-link">
                  {caseLabel(id)} 열기
                </a>
                {hits.length ? (
                  <ul>
                    {hits.map((hit, index) => (
                      // biome-ignore lint/suspicious/noArrayIndexKey: occurrences have no id; order is stable
                      <li key={index}>
                        <a
                          href={serializeRoute(occurrenceRoute(hit, indicator))}
                          className="meta-link mono viewer-break"
                        >
                          {hit.path ?? hit.citationId ?? hit.caseScope ?? "위치"}
                        </a>
                        {hit.caseScope ? <span className="meta-hint"> · 범위 {hit.caseScope}</span> : null}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/**
 * Timeline event (C10): what the event is about and the core facts of its source artifact row (the
 * family's core columns, read from the event's details), then the sources folded into this row
 * (display groups, `group=1`). The full source row stays one click away ("원본 아티팩트 행으로 이동").
 */
function TimelineEventSection({ row }: { row: GridRow | null }) {
  if (row?.ref.collection !== "timeline") return null;
  const details =
    row.fields.details && typeof row.fields.details === "object" && !Array.isArray(row.fields.details)
      ? (row.fields.details as Record<string, unknown>)
      : {};
  const sourceType = typeof row.fields.sourceArtifactType === "string" ? row.fields.sourceArtifactType : null;
  const core = familyCoreFacts(sourceType, details);
  const target = typeof row.fields.targetFull === "string" ? row.fields.targetFull : "";
  const sources = Array.isArray(row.fields.groupSources)
    ? (row.fields.groupSources as Array<{ artifactType: string; path: string; recordIndex: number | null }>)
    : [];
  return (
    <section aria-label="이벤트" data-testid="timeline-event-section">
      <h3 className="viewer-subtitle">이벤트{core ? ` — ${core.family}` : ""}</h3>
      <dl className="viewer-dl">
        {target ? (
          <>
            <dt>대상</dt>
            <dd className="mono viewer-break">{target}</dd>
          </>
        ) : null}
        {(core?.facts ?? []).map((fact) => (
          <Fragment key={fact.label}>
            <dt>{fact.label}</dt>
            <dd className="viewer-break">{fact.value}</dd>
          </Fragment>
        ))}
      </dl>
      {sources.length > 1 ? (
        <>
          <h4 className="viewer-subtitle">같은 대상·같은 초에 기록한 출처 {sources.length}곳</h4>
          <ul data-testid="timeline-group-sources">
            {sources.map((source) => (
              <li key={`${source.artifactType}|${source.path}`}>
                {timelineAreaLabel(source.artifactType)} —{" "}
                <span className="mono viewer-break">{source.path}</span>
                {source.recordIndex !== null ? ` (이벤트 #${source.recordIndex + 1})` : ""}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}

export function MetaView({
  target,
  preview,
  metadata,
  metadataError,
  hashBusy,
  row,
  sessionMarks,
  onComputeHash,
}: MetaViewProps) {
  const { timezone } = useTimezone();
  const { setMode } = useViewerRouteMode();
  const sessionNote = useSessionNote(noteKey(target.runId, target.ref));
  const note = sessionNote ?? (typeof row?.fields.note === "string" ? row.fields.note : "");
  const formatTime = (value: number | string | undefined) => {
    const reading = evidenceTime(value ?? null, timezone);
    return reading ? reading.text : value === undefined || value === "" ? "—" : String(value);
  };
  const directory = isDirectoryTarget(target, preview) || metadata?.is_directory === true;
  const sourceMissing = !directory && Boolean(target.sourcePath) && isSourceMissing(metadataError);
  const openHex = (offset: number) => {
    setViewerTarget({ ...target, highlight: { offset, length: 1 } }, row);
    setMode("hex");
  };
  /** A time of the record/file: the evidence format + kind chip + "타임라인 ±5분". */
  const time = (label: string, value: number | string | undefined | null, kind?: string) =>
    value === undefined || value === null || value === "" ? (
      "—"
    ) : (
      <TimeValue value={value} label={label} kind={kind} runId={target.runId} />
    );
  const hashes = metadata?.hashes || {};
  const provenance = provenanceEntries(row);
  const ntfs = ntfsProvenance(row, formatTime);
  const ntfsHintId = useId();
  const layout = recordLayout(row);
  // "열로 표시" only on artifact rows of one kind (the grid can show that kind's fields as columns).
  const artifactKind = row?.ref.collection === "artifacts" ? row.ref.kind : undefined;
  const promotedFields = usePromotedFields(artifactKind);
  const gridKind = useGridLocalStore((s) =>
    s.route.collection.id === "artifacts" ? s.route.collection.kind : undefined,
  );
  const gridVisible = useGridLocalStore((s) => s.visibleColumnIds);
  const visibleIds = gridKind === artifactKind ? gridVisible : null;
  const filterTypes = useFilterStore((s) => s.filters.types);
  const defaultHeaders = useMemo(
    () => defaultFieldHeaders(artifactKind, visibleIds, filterTypes),
    [artifactKind, visibleIds, filterTypes],
  );
  const promoted = useMemo(
    () => ({ ...promotedFields, defaults: defaultHeaders }),
    [promotedFields, defaultHeaders],
  );
  const hasRecord =
    layout.core.length + layout.provenance.length + layout.other.length + layout.governance.length > 0 ||
    layout.table !== null;
  const isArtifact = row?.ref.collection === "artifacts";
  return (
    <div className="meta-view">
      <RecordBanners row={row} />
      <TimelineEventSection row={row} />
      {sourceMissing ? (
        <p className="meta-notice" role="alert" data-testid="source-missing">
          소스를 찾을 수 없습니다 — 원본 경로: <span className="mono viewer-break">{target.sourcePath}</span>
        </p>
      ) : null}
      {directory ? (
        <p className="meta-notice" data-testid="directory-info">
          디렉터리입니다 — 미리보기와 해시가 없습니다. 디렉터리 안의 파일을 선택하세요. 경로:{" "}
          <span className="mono viewer-break">{target.sourcePath}</span>
        </p>
      ) : null}
      {hasRecord ? (
        <RecordSection
          row={row}
          layout={layout}
          runId={target.runId}
          columns={artifactKind ? promoted : undefined}
          onOpenHex={openHex}
        />
      ) : null}
      <CrossCaseSection row={row} runId={target.runId} />
      <section aria-label="출처">
        <h3 className="viewer-subtitle">출처</h3>
        <dl className="viewer-dl">
          <dt>런</dt>
          <dd className="mono">{target.runId}</dd>
          <dt>위치(locator)</dt>
          <dd className="mono viewer-break">{locatorText(target)}</dd>
          {target.ref.caseDbId !== undefined ? (
            <>
              <dt>케이스 DB ID</dt>
              <dd>{target.ref.caseDbId}</dd>
            </>
          ) : null}
          {provenance.map(([key, value]) => (
            <Fragment key={key}>
              <dt>{key}</dt>
              <dd className="viewer-break">{value}</dd>
            </Fragment>
          ))}
          {row?.timestamp ? (
            <>
              <dt>행 시각</dt>
              <dd>{time("행 시각", row.timestamp)}</dd>
            </>
          ) : null}
          {ntfs
            ? ntfs.entries.map(([key, value]) => (
                <Fragment key={key}>
                  <dt>{key}</dt>
                  <dd className="viewer-break">{value}</dd>
                </Fragment>
              ))
            : null}
        </dl>
        {ntfs && !ntfs.joined && !ntfs.reason ? (
          <p className="meta-hint" data-testid="ntfs-hint">
            <span id={ntfsHintId}>{NTFS_EMPTY_HINT}</span>{" "}
            <EmptyHintLink
              hint={{ text: NTFS_EMPTY_HINT, command: NTFS_RUN_COMMAND, commandLabel: "실행" }}
              hintId={ntfsHintId}
            />
          </p>
        ) : null}
      </section>
      <section aria-label="파일 정보">
        <h3 className="viewer-subtitle">파일</h3>
        <dl className="viewer-dl">
          <dt>경로</dt>
          <dd className="mono viewer-break">{target.sourcePath ?? "원본 경로 없음(파생 항목)"}</dd>
          {preview?.container_path ? (
            <>
              <dt>컨테이너</dt>
              <dd className="mono viewer-break">{preview.container_path}</dd>
            </>
          ) : null}
          <dt>크기</dt>
          <dd>
            {metadata || preview
              ? `${(metadata?.size ?? preview?.size ?? 0).toLocaleString("ko-KR")}바이트`
              : "—"}
          </dd>
          <dt>MIME</dt>
          <dd>{metadata?.mime_type ?? preview?.mime_type ?? "—"}</dd>
          <dt>수정 시각</dt>
          <dd>{time("수정 시각", metadata?.modified_at ?? preview?.modified_at, "modified")}</dd>
          <dt>생성 시각</dt>
          <dd>{time("생성 시각", metadata?.created_at, "created")}</dd>
        </dl>
        {metadataError ? (
          <p className="viewer-error">메타데이터를 불러오지 못했습니다: {metadataError}</p>
        ) : null}
      </section>
      {target.sourcePath ? (
        <section aria-label={isArtifact ? "컨테이너 파일 해시" : "파일 해시"}>
          <h3 className="viewer-subtitle">{isArtifact ? "컨테이너 파일 해시" : "파일 해시"}</h3>
          {isArtifact ? (
            <p className="meta-hint">
              레코드가 들어 있는 원본 파일 전체의 해시입니다(레코드 자체의 해시 아님).
            </p>
          ) : null}
          {hashes.sha256 ? (
            <dl className="viewer-dl">
              <dt>SHA-256</dt>
              <dd className="meta-hash-dd">
                <HashValue value={hashes.sha256} label="SHA-256" />
              </dd>
              <dt>SHA-1</dt>
              <dd className="meta-hash-dd">
                {hashes.sha1 ? <HashValue value={hashes.sha1} label="SHA-1" /> : "—"}
              </dd>
              <dt>MD5</dt>
              <dd className="meta-hash-dd">
                {hashes.md5 ? <HashValue value={hashes.md5} label="MD5" /> : "—"}
              </dd>
            </dl>
          ) : (
            <p className="viewer-note">
              {hashBusy ? "해시 계산 중…" : "아직 해시를 계산하지 않았습니다."}{" "}
              {!hashBusy ? (
                <button type="button" className="viewer-button" onClick={onComputeHash}>
                  지금 계산
                </button>
              ) : null}
            </p>
          )}
          {preview?.container_path ? (
            <p className="viewer-note">ZIP 내부 항목의 해시는 컨테이너(ZIP) 파일 기준입니다.</p>
          ) : null}
        </section>
      ) : null}
      <section aria-label="검증 상태">
        <h3 className="viewer-subtitle">검증 상태</h3>
        <dl className="viewer-dl">
          <dt>미리보기</dt>
          <dd>
            {PREVIEW_STATUS[preview?.viewer_metadata?.preview_status ?? ""] ??
              preview?.viewer_metadata?.preview_status ??
              "—"}
            {preview?.viewer_metadata?.parser ? ` (${preview.viewer_metadata.parser})` : ""}
          </dd>
          <dt>해시 상태</dt>
          <dd>{metadata?.hash_status === "computed" ? "계산됨" : "미계산"}</dd>
        </dl>
        {preview?.viewer_limitations?.length ? (
          <details className="viewer-details">
            <summary>뷰어 한계 {preview.viewer_limitations.length}건</summary>
            <ul>
              {preview.viewer_limitations.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </details>
        ) : null}
      </section>
      <section aria-label="리뷰 상태">
        <h3 className="viewer-subtitle">리뷰</h3>
        <dl className="viewer-dl">
          <dt>상태</dt>
          <dd>{row?.reviewStatus ? REVIEW_LABELS[row.reviewStatus] : "미검토"}</dd>
          <dt>태그</dt>
          <dd>{row?.tags.length ? row.tags.join(", ") : "없음"}</dd>
          <dt>메모</dt>
          <dd className="viewer-break" data-testid="meta-note">
            {note || "없음"}
          </dd>
          {sessionMarks.length ? (
            <>
              <dt>이번 세션 표시</dt>
              <dd>{sessionMarks.join(", ")}</dd>
            </>
          ) : null}
        </dl>
      </section>
      {/* U-F8 fixed tail: the same seven evidence facts on every row, "없음" with a reason. */}
      <EvidenceTail target={target} row={row} onOpenHex={openHex} />
      <GovernanceSection layout={layout} row={row} runId={target.runId} />
    </div>
  );
}

/**
 * The run's evidence source (partition) from the dashboard query the tree / 접수 already load (same
 * key); works without a QueryClient (unit tests render MetaView bare).
 */
function useRunEvidence(runId: string): RunDashboard["evidence_source"] | null {
  const client = useContext(QueryClientContext);
  const key = ["run-dashboard", runId];
  const [data, setData] = useState<RunDashboard | undefined>(() => client?.getQueryData<RunDashboard>(key));
  // biome-ignore lint/correctness/useExhaustiveDependencies: keyed on the run
  useEffect(() => {
    if (!client || !runId) return;
    let live = true;
    client
      .fetchQuery({ queryKey: key, queryFn: () => getRunDashboard(runId), staleTime: 60_000 })
      .then((next) => {
        if (live) setData(next);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [client, runId]);
  return data?.evidence_source ?? null;
}

/** Why a tail fact is absent (U-F8: never a bare dash). */
export const TAIL_REASONS = {
  source: "없음 — 원본 파일이 없는 파생 항목입니다",
  partition: "파티션 정보 없음(폴더·논리 증거)",
  recovery: "없음 — 파서가 복구 방법을 기록하지 않았습니다",
  deletion: "없음 — 할당 상태가 기록되지 않았습니다",
  offset: "없음 — 원본 안 오프셋이 기록되지 않았습니다",
  parser: "없음 — 파서 이름·버전이 기록되지 않았습니다",
  origin: "없음 — 파생 행이 아닙니다(이 행이 원본)",
} as const;

function parserText(row: GridRow | null): string | null {
  const fields = row?.fields ?? {};
  const details = (fields.details && typeof fields.details === "object" ? fields.details : {}) as Record<
    string,
    unknown
  >;
  // Timeline rows name their source collection as the provider, not a parser.
  const providers = row?.ref.collection === "timeline" ? [] : [row?.provider, fields.provider];
  const name = [details.parser, ...providers].find((v) => typeof v === "string" && v) as string | undefined;
  const version = [details.parser_version, details.evtx_decoder_version, fields.parserVersion].find(
    (v) => (typeof v === "string" && v) || typeof v === "number",
  );
  if (!name && version === undefined) return null;
  const versionText =
    version === undefined ? "" : /^\d/.test(String(version)) ? `v${String(version)}` : String(version);
  return [name, versionText].filter(Boolean).join(" ");
}

/**
 * 증거 정보 (U-F8, AXIOM 세부 정보 규약): 소스(파티션·경로) · 복구 방법 · 삭제된 출처 · 위치(오프셋) ·
 * 증거 번호 · 파서 버전 · 원본 행 — always present, in this order, at the end of the meta view.
 */
export function EvidenceTail({
  target,
  row,
  onOpenHex,
}: {
  target: ViewerTarget;
  row: GridRow | null;
  onOpenHex: (offset: number) => void;
}) {
  const ctx = useCommandContext();
  const { currentRun } = useRuns();
  const evidenceFacts = evidenceInfo(row);
  // Decoded records carry their byte range (EVTX record offset …) when no recovery offset exists.
  const info = { ...evidenceFacts, offset: evidenceFacts.offset ?? recordByteRange(row)?.offset ?? null };
  const evidence = useRunEvidence(target.runId);
  const partition = evidence?.partitions.find((p) => p.number === evidence.selected_partition);
  const partitionText = partition
    ? `파티션 ${partition.number}${partition.filesystem ? ` (${partition.filesystem.toUpperCase()})` : ""}`
    : TAIL_REASONS.partition;
  const parser = parserText(row);
  const sourceRecord = row?.fields.sourceRecord as { output?: unknown; row_index?: unknown } | undefined;
  const origin =
    row?.ref.collection === "timeline" && sourceRecord
      ? artifactRowRoute(target.runId, sourceRecord.output, sourceRecord.row_index)
      : null;
  return (
    <section aria-label="증거 정보" data-testid="evidence-info" className="meta-evidence-tail">
      <h3 className="viewer-subtitle">증거 정보</h3>
      <dl className="viewer-dl">
        <dt>소스</dt>
        <dd className="viewer-break">
          <span className="meta-tail-sub">{partitionText}</span>{" "}
          {target.sourcePath ? (
            <button
              type="button"
              className="viewer-button mono"
              title="이 원본에서 나온 행을 그리드에 표시합니다."
              onClick={() => void dispatchCommand(ROWS_FOR_SOURCE_COMMAND, ctx)}
            >
              {target.sourcePath}
            </button>
          ) : (
            TAIL_REASONS.source
          )}
        </dd>
        <dt>복구 방법</dt>
        <dd>
          {info.recovery !== "—" ? info.recovery : TAIL_REASONS.recovery}
          {/* R3 §3.3: a carved row names where in its source it was carved from. */}
          {info.recovery === RECOVERY_LABELS.carving && info.offset !== null
            ? ` · 오프셋 0x${info.offset.toString(16).toUpperCase()}`
            : null}
          {info.sourceId ? <span className="mono"> ({info.sourceId})</span> : null}
        </dd>
        <dt>삭제된 출처</dt>
        <dd>{info.deletion !== "—" ? info.deletion : TAIL_REASONS.deletion}</dd>
        <dt>위치</dt>
        <dd>
          {info.offset !== null ? (
            <button
              type="button"
              className="viewer-button mono"
              title="헥스 보기에서 이 오프셋을 강조해 엽니다."
              onClick={() => onOpenHex(info.offset as number)}
            >
              0x{info.offset.toString(16).toUpperCase()} ({info.offset.toLocaleString("ko-KR")})
            </button>
          ) : (
            TAIL_REASONS.offset
          )}
        </dd>
        <dt>증거 번호</dt>
        <dd className="mono viewer-break">
          {target.runId}
          {currentRun ? ` · ${runDisplayName(currentRun)}` : ""}
        </dd>
        <dt>파서 버전</dt>
        <dd className="mono">{parser ?? TAIL_REASONS.parser}</dd>
        <dt>원본 행</dt>
        <dd>
          {origin ? (
            <a className="viewer-button" href={serializeRoute(origin)}>
              원본 아티팩트 행으로 이동
            </a>
          ) : (
            TAIL_REASONS.origin
          )}
        </dd>
      </dl>
    </section>
  );
}
