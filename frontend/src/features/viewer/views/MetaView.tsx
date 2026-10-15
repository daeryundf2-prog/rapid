import { Fragment, useEffect, useId, useMemo, useState } from "react";
import { DisabledReason } from "../../../a11y/primitives";
import type { SourceMetadata, SourcePreview } from "../../../api/viewer";
import { runDisplayName } from "../../../app/collections";
import type { GridRow, ReviewStatus } from "../../../contracts/collection";
import type { ViewerTarget } from "../../../contracts/viewer";
import { Icon } from "../../../icons";
import { parseHash, serializeRoute } from "../../../router";
import { useRoute, useRuns, useTimezone } from "../../../state/hooks";
import { isScalarish } from "../../../utils/flatValue";
import { formatTimestamp } from "../../../utils/time";
import {
  caseHref,
  caseLabel,
  crossCaseOccurrences,
  crossCaseRunIds,
  occurrenceRoute,
} from "../../analysis/crossCase";
import { useGridLocalStore } from "../../grid/adapter";
import { defaultFieldHeaders } from "../../grid/columns/artifacts";
import { FIELD_LABELS } from "../../grid/columns/fieldColumns";
import { NTFS_EMPTY_HINT, NTFS_RUN_COMMAND } from "../../grid/columns/files";
import { EmptyHintLink } from "../../grid/EmptyHintLink";
import { noteKey, useSessionNote } from "../../grid/sessionNotes";
import { usePromotedFields } from "../../grid/usePromotedFields";
import { dispatchCommand, setViewerTarget, useCommandContext, useViewerRouteMode } from "../adapter";
import { locatorText } from "../citation";
import { ROWS_FOR_SOURCE_COMMAND, writeClipboard } from "../commands";
import { evidenceInfo, isSourceMissing, timelineWindowHash } from "../evidenceInfo";
import { isDirectoryTarget } from "../modes";
import {
  groupRecordFields,
  makeRecordField,
  RECORD_GROUP_LABELS,
  type RecordField,
  type RecordGroups,
} from "../record";

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

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="viewer-copy"
      aria-label={`${label} 복사`}
      onClick={() => {
        writeClipboard(text)
          .then(() => setCopied(true))
          .catch(() => setCopied(false));
      }}
    >
      {copied ? "복사됨" : "복사"}
    </button>
  );
}

/** One level of a nested object as key/value rows (deeper values stay compact text). */
function NestedValue({ value, name }: { value: Record<string, unknown>; name: string }) {
  if (isHashBundle(value)) {
    return (
      <dl className="viewer-dl viewer-dl-nested">
        {Object.entries(value).map(([k, v]) => (
          <Fragment key={k}>
            <dt className="mono">{k}</dt>
            <dd className="mono viewer-break">
              {String(v)} <CopyButton text={String(v)} label={`${name}.${k}`} />
            </dd>
          </Fragment>
        ))}
      </dl>
    );
  }
  const entries = Object.entries(value);
  const list = (
    <dl className="viewer-dl viewer-dl-nested">
      {entries.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="mono">{k}</dt>
          <dd className="viewer-break">
            <ScalarText name={`${name}.${k}`} value={v} />
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

/** A nested / list scalar: short text, or the same fold + full copy as top-level long values. */
function ScalarText({ name, value }: { name: string; value: unknown }) {
  const field = makeRecordField(name, value);
  if (field.truncated) return <LongValue field={field} />;
  return <>{field.value || "—"}</>;
}

function FieldValue({ field }: { field: RecordField }) {
  const { raw } = field;
  if (isPlainObject(raw)) return <NestedValue value={raw} name={field.key} />;
  if (Array.isArray(raw) && raw.some((item) => typeof item === "object" && item !== null)) {
    return (
      <details className="viewer-details">
        <summary>{raw.length}개 항목</summary>
        <ol className="viewer-nested-list">
          {raw.map((item, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: read-only snapshot of a record array
            <li key={index}>
              {isPlainObject(item) ? (
                <NestedValue value={item} name={`${field.key}[${index}]`} />
              ) : (
                <ScalarText name={`${field.key}[${index}]`} value={item} />
              )}
            </li>
          ))}
        </ol>
      </details>
    );
  }
  // Scalars and arrays of scalars (comma list) use the flat text; long ones fold (U-C3).
  if (field.truncated) return <LongValue field={field} />;
  return <>{field.value}</>;
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

function FieldList({ fields, columns }: { fields: RecordField[]; columns?: ColumnToggle }) {
  useRestorePendingFocus();
  return (
    <dl className="viewer-dl">
      {fields.map((field) => {
        const shown = columns?.keys.includes(field.key) ?? false;
        const name = FIELD_LABELS[field.key] ? `${field.key}(${FIELD_LABELS[field.key]})` : field.key;
        return (
          <Fragment key={field.key}>
            <dt className="mono">{field.key}</dt>
            <dd className="viewer-break meta-field">
              <span className="meta-field-value">
                <FieldValue field={field} />
              </span>
              {columns && field.fromDetails && columns.defaults.has(field.key) ? (
                <DisabledReason reason={`기본 열 '${columns.defaults.get(field.key)}'에 이미 표시됩니다`}>
                  <button
                    type="button"
                    className="meta-colbtn"
                    aria-pressed={true}
                    aria-label={`${columns.defaults.get(field.key)} 열로 표시 중`}
                  >
                    <Icon name="columns" />
                  </button>
                </DisabledReason>
              ) : columns && promotable(field) ? (
                <button
                  type="button"
                  className="meta-colbtn"
                  aria-pressed={shown}
                  aria-label={shown ? `${name} 열에서 제거` : `${name} 열로 표시`}
                  title={shown ? "열에서 제거" : "열로 표시"}
                  data-focus-key={`column:${field.key}`}
                  onClick={() => {
                    keepFocus(`column:${field.key}`);
                    columns.toggle(field.key);
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

/** Decoded record first (F2): 핵심 · 출처 · 검증 open, 기타 collapsed. */
function RecordSection({ groups, columns }: { groups: RecordGroups; columns?: ColumnToggle }) {
  return (
    <section aria-labelledby="viewer-record-title" className="meta-record">
      <h3 className="viewer-subtitle" id="viewer-record-title">
        레코드
      </h3>
      {(["core", "source", "validation"] as const).map((id) =>
        groups[id].length ? (
          <section key={id} aria-label={`레코드 ${RECORD_GROUP_LABELS[id]}`} className="meta-record-group">
            <h4>{RECORD_GROUP_LABELS[id]}</h4>
            <FieldList fields={groups[id]} columns={columns} />
          </section>
        ) : null,
      )}
      {groups.other.length ? (
        <details className="viewer-details meta-record-group">
          <summary>
            {RECORD_GROUP_LABELS.other} {groups.other.length}개
          </summary>
          <FieldList fields={groups.other} columns={columns} />
        </details>
      ) : null}
    </section>
  );
}

function provenanceEntries(row: GridRow | null): Array<[string, string]> {
  if (!row) return [];
  const out: Array<[string, string]> = [];
  if (row.artifactType) out.push(["아티팩트 유형", row.artifactType]);
  if (row.provider) out.push(["수집기(provider)", row.provider]);
  if (row.timestamp) out.push(["행 시각", row.timestamp]);
  const record = row.fields.artifact_record;
  if (record && typeof record === "object") {
    for (const [key, value] of Object.entries(record as Record<string, unknown>)) {
      if (value === null || value === undefined || value === "") continue;
      if (typeof value === "object") continue;
      out.push([`artifact_record.${key}`, String(value)]);
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
  const { route, navigate } = useRoute();
  const { currentRun } = useRuns();
  const ctx = useCommandContext();
  const { setMode } = useViewerRouteMode();
  const sessionNote = useSessionNote(noteKey(target.runId, target.ref));
  const note = sessionNote ?? (typeof row?.fields.note === "string" ? row.fields.note : "");
  const info = evidenceInfo(row);
  const formatTime = (value: number | string | undefined) => formatTimestamp(value, timezone);
  const directory = isDirectoryTarget(target, preview) || metadata?.is_directory === true;
  const sourceMissing = !directory && Boolean(target.sourcePath) && isSourceMissing(metadataError);
  const openHex = (offset: number) => {
    setViewerTarget({ ...target, highlight: { offset, length: 1 } }, row);
    setMode("hex");
  };
  const clock = (label: string, value: number | string | undefined) => {
    if (value === undefined || value === "") return null;
    const hash = timelineWindowHash(target.runId, value, route.tz);
    if (!hash) return null;
    return (
      <button
        type="button"
        className="meta-clock"
        aria-label={`${label} 전후 1시간 타임라인 보기`}
        title="이 시각 전후 1시간을 타임라인에서 보기"
        onClick={() => navigate(parseHash(hash))}
      >
        <Icon name="clock" />
      </button>
    );
  };
  const hashes = metadata?.hashes || {};
  const provenance = provenanceEntries(row);
  const ntfs = ntfsProvenance(row, formatTime);
  const ntfsHintId = useId();
  const grouped = groupRecordFields(row);
  // "열로 표시" only on artifact rows of one kind (the grid can show that kind's fields as columns).
  const artifactKind = row?.ref.collection === "artifacts" ? row.ref.kind : undefined;
  const promotedFields = usePromotedFields(artifactKind);
  const gridKind = useGridLocalStore((s) =>
    s.route.collection.id === "artifacts" ? s.route.collection.kind : undefined,
  );
  const gridVisible = useGridLocalStore((s) => s.visibleColumnIds);
  const visibleIds = gridKind === artifactKind ? gridVisible : null;
  const defaultHeaders = useMemo(
    () => defaultFieldHeaders(artifactKind, visibleIds),
    [artifactKind, visibleIds],
  );
  const promoted = useMemo(
    () => ({ ...promotedFields, defaults: defaultHeaders }),
    [promotedFields, defaultHeaders],
  );
  const groups =
    grouped.core.length + grouped.source.length + grouped.validation.length + grouped.other.length > 0
      ? grouped
      : null;
  return (
    <div className="meta-view">
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
      {groups ? <RecordSection groups={groups} columns={artifactKind ? promoted : undefined} /> : null}
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
          <dd>
            {formatTime(metadata?.modified_at ?? preview?.modified_at)}
            {clock("수정 시각", metadata?.modified_at ?? preview?.modified_at)}
          </dd>
          <dt>생성 시각</dt>
          <dd>
            {formatTime(metadata?.created_at)}
            {clock("생성 시각", metadata?.created_at)}
          </dd>
        </dl>
        {metadataError ? (
          <p className="viewer-error">메타데이터를 불러오지 못했습니다: {metadataError}</p>
        ) : null}
      </section>
      <section aria-label="증거 정보" data-testid="evidence-info">
        <h3 className="viewer-subtitle">증거 정보</h3>
        <dl className="viewer-dl">
          <dt>소스</dt>
          <dd className="viewer-break">
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
              "원본 파일 없음(파생 항목)"
            )}
          </dd>
          <dt>복구 방법</dt>
          <dd>
            {info.recovery}
            {info.sourceId ? <span className="mono"> ({info.sourceId})</span> : null}
          </dd>
          <dt>삭제 여부</dt>
          <dd>{info.deletion}</dd>
          <dt>위치</dt>
          <dd>
            {info.offset !== null ? (
              <button
                type="button"
                className="viewer-button mono"
                title="헥스 보기에서 이 오프셋을 강조해 엽니다."
                onClick={() => openHex(info.offset as number)}
              >
                0x{info.offset.toString(16).toUpperCase()} ({info.offset.toLocaleString("ko-KR")})
              </button>
            ) : (
              "—"
            )}
          </dd>
          <dt>증거 번호</dt>
          <dd className="mono viewer-break">
            {target.runId}
            {currentRun ? ` · ${runDisplayName(currentRun)}` : ""}
          </dd>
          {row?.timestamp ? (
            <>
              <dt>행 시각</dt>
              <dd>
                {formatTime(row.timestamp)}
                {clock("행 시각", row.timestamp)}
              </dd>
            </>
          ) : null}
        </dl>
      </section>
      {target.sourcePath ? (
        <section aria-label="해시">
          <h3 className="viewer-subtitle">해시</h3>
          {hashes.sha256 ? (
            <dl className="viewer-dl">
              <dt>SHA-256</dt>
              <dd className="mono viewer-break">{hashes.sha256}</dd>
              <dt>SHA-1</dt>
              <dd className="mono viewer-break">{hashes.sha1 ?? "—"}</dd>
              <dt>MD5</dt>
              <dd className="mono viewer-break">{hashes.md5 ?? "—"}</dd>
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
    </div>
  );
}
