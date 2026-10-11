import { Fragment, useState } from "react";
import type { SourceMetadata, SourcePreview } from "../../../api/viewer";
import { runDisplayName } from "../../../app/collections";
import type { GridRow, ReviewStatus } from "../../../contracts/collection";
import type { ViewerTarget } from "../../../contracts/viewer";
import { Icon } from "../../../icons";
import { parseHash } from "../../../router";
import { useRoute, useRuns, useTimezone } from "../../../state/hooks";
import { formatTimestamp } from "../../../utils/time";
import { noteKey, useSessionNote } from "../../grid/sessionNotes";
import { dispatchCommand, setViewerTarget, useCommandContext, useViewerRouteMode } from "../adapter";
import { locatorText } from "../citation";
import { ROWS_FOR_SOURCE_COMMAND, writeClipboard } from "../commands";
import { evidenceInfo, isSourceMissing, timelineWindowHash } from "../evidenceInfo";
import {
  formatValue,
  groupRecordFields,
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
          <dd className="viewer-break">{formatValue(v) || "—"}</dd>
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
                formatValue(item)
              )}
            </li>
          ))}
        </ol>
      </details>
    );
  }
  // Scalars and arrays of scalars (comma list) use the flat text.
  return <>{field.value}</>;
}

function FieldList({ fields }: { fields: RecordField[] }) {
  return (
    <dl className="viewer-dl">
      {fields.map((field) => (
        <Fragment key={field.key}>
          <dt className="mono">{field.key}</dt>
          <dd className="viewer-break">
            <FieldValue field={field} />
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

/** Decoded record first (F2): 핵심 · 출처 · 검증 open, 기타 collapsed. */
function RecordSection({ groups }: { groups: RecordGroups }) {
  return (
    <section aria-labelledby="viewer-record-title" className="meta-record">
      <h3 className="viewer-subtitle" id="viewer-record-title">
        레코드
      </h3>
      {(["core", "source", "validation"] as const).map((id) =>
        groups[id].length ? (
          <section key={id} aria-label={`레코드 ${RECORD_GROUP_LABELS[id]}`} className="meta-record-group">
            <h4>{RECORD_GROUP_LABELS[id]}</h4>
            <FieldList fields={groups[id]} />
          </section>
        ) : null,
      )}
      {groups.other.length ? (
        <details className="viewer-details meta-record-group">
          <summary>
            {RECORD_GROUP_LABELS.other} {groups.other.length}개
          </summary>
          <FieldList fields={groups.other} />
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
  const sourceMissing = Boolean(target.sourcePath) && isSourceMissing(metadataError);
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
  const grouped = groupRecordFields(row);
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
      {groups ? <RecordSection groups={groups} /> : null}
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
        </dl>
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
