import { useEffect, useRef, useState } from "react";
import {
  fetchSqliteTable,
  fetchSqliteWalPreview,
  type SourcePreview,
  type SqliteSidecarStateProfile,
  type SqliteWalPreview,
} from "../../../api/viewer";
import { errorText, useAsync } from "../useAsync";

/** R-10: Korean names of the sidecar ids the server lists in `detected_sidecars`. */
const SIDECAR_LABELS: Record<string, string> = {
  wal: "WAL",
  shm: "SHM",
  rollback_journal: "롤백 저널",
  "rollback-journal": "롤백 저널",
  journal: "롤백 저널",
};

export function sidecarLabel(id: string): string {
  return SIDECAR_LABELS[id] ?? id;
}

/** R-10: Korean WAL header / preview states (api/app/sqlite.py, core/sqlite_wal.py). */
const WAL_STATUS_LABELS: Record<string, string> = {
  parsed: "해석됨",
  "unknown-magic": "알 수 없는 형식(매직 불일치)",
  "invalid-short-header": "헤더가 짧아 해석 불가",
  "not-read": "읽지 않음",
  missing: "없음",
};

export function walHeaderStatusLabel(status: string | undefined | null): string {
  if (!status) return "미해석";
  return WAL_STATUS_LABELS[status] ?? `미분류 상태(${status})`;
}

export const SQLITE_PAGE_SIZE = 200;

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function WalBanner({
  runId,
  path,
  profile,
}: {
  runId: string;
  path: string;
  profile: SqliteSidecarStateProfile;
}) {
  const [wal, setWal] = useState<{ busy: boolean; data: SqliteWalPreview | null; error: string | null }>({
    busy: false,
    data: null,
    error: null,
  });
  const sidecars = profile.sidecars || {};
  const detected = profile.detected_sidecars || [];
  const requiresReview = Boolean(profile.requires_wal_review);
  const load = async () => {
    setWal({ busy: true, data: null, error: null });
    try {
      setWal({ busy: false, data: await fetchSqliteWalPreview(runId, path), error: null });
    } catch (error) {
      setWal({ busy: false, data: null, error: errorText(error) });
    }
  };
  const header = sidecars.wal?.header;
  return (
    <section
      className={`sqlite-wal${requiresReview ? " is-warning" : ""}`}
      aria-label="SQLite 사이드카(WAL) 상태"
      data-testid="sqlite-wal-banner"
    >
      <p className="sqlite-wal-title">
        {requiresReview
          ? "WAL/저널 사이드카가 있습니다 — 아래 행은 체크포인트 전 변경을 포함하지 않을 수 있습니다."
          : "WAL/SHM/저널 사이드카가 발견되지 않았습니다."}
      </p>
      <p className="viewer-note">
        WAL {sidecars.wal?.exists ? "있음" : "없음"} · SHM {sidecars.shm?.exists ? "있음" : "없음"} · 롤백
        저널 {sidecars.rollback_journal?.exists ? "있음" : "없음"}
        {detected.length ? ` · 발견: ${detected.map(sidecarLabel).join(", ")}` : ""}
        {sidecars.wal?.exists && header
          ? ` · WAL 헤더 ${walHeaderStatusLabel(header.status)}, 페이지 크기 ${header.page_size ?? "?"}바이트, 추정 프레임 ${header.estimated_frame_count ?? "?"}개`
          : ""}
      </p>
      {sidecars.wal?.exists ? (
        <button type="button" className="viewer-button" onClick={load} disabled={wal.busy}>
          {wal.busy ? "WAL 읽는 중…" : "WAL 프레임 미리보기"}
        </button>
      ) : null}
      {wal.error ? <p className="viewer-error">WAL 미리보기 실패: {wal.error}</p> : null}
      {wal.data ? (
        <div className="sqlite-wal-frames">
          <p className="viewer-note">
            상태 {walHeaderStatusLabel(wal.data.wal.status)} · 추정 프레임{" "}
            {wal.data.wal.estimated_frame_count ?? 0} · 미리보기{" "}
            {wal.data.wal.preview_frame_count ?? wal.data.wal.frames?.length ?? 0} · 삭제 후보{" "}
            {wal.data.recovery_scope?.deleted_record_candidate_count ?? 0}건 (신뢰 도구 검증 전에는 단서로만
            사용)
          </p>
          <table className="viewer-table">
            <thead>
              <tr>
                <th scope="col">프레임</th>
                <th scope="col">페이지</th>
                <th scope="col">커밋</th>
                <th scope="col">솔트 일치</th>
              </tr>
            </thead>
            <tbody>
              {(wal.data.wal.frames || []).map((frame) => (
                <tr key={frame.frame_index}>
                  <td>{frame.frame_index}</td>
                  <td>{frame.page_number}</td>
                  <td>{frame.is_commit_frame ? "예" : "아니오"}</td>
                  <td>{frame.salt_matches_header ? "예" : "아니오"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

interface SqliteViewProps {
  runId: string;
  preview: SourcePreview;
  highlight?: { table?: string; rowid?: number };
}

export function SqliteView({ runId, preview, highlight }: SqliteViewProps) {
  const sqlite = preview.sqlite || {};
  const previewed = sqlite.tables || [];
  // Every table the server named (viewer_hint, r7 L4): the preview itself stops at 8, and the
  // browser `urls` table sorts past that — still listed (row count unknown until opened).
  const tables: Array<{ name: string; row_count?: number | null }> = [
    ...previewed,
    ...(preview.viewer_hint?.sqlite_tables ?? [])
      .filter((name) => !previewed.some((item) => item.name === name))
      .map((name) => ({ name, row_count: null })),
  ];
  const initialTable =
    highlight?.table && tables.some((t) => t.name === highlight.table)
      ? highlight.table
      : (tables[0]?.name ?? null);
  const [table, setTable] = useState<string | null>(initialTable);
  const [offset, setOffset] = useState(0);
  // First page of the row's table: the page holding its rowid (locate_rowid), then plain paging.
  const [locate, setLocate] = useState<number | undefined>(
    highlight?.table && highlight.table === initialTable ? highlight.rowid : undefined,
  );
  const sidecar = sqlite.sidecar_state_profile || sqlite.database_metadata?.sidecar_state_profile;
  const page = useAsync(table ? `${preview.path}|${table}|${offset}|${locate ?? ""}` : null, (signal) =>
    fetchSqliteTable(runId, preview.path, table as string, offset, SQLITE_PAGE_SIZE, signal, locate),
  );
  const hiddenTables = Math.max(0, (sqlite.table_count ?? tables.length) - tables.length);
  // The offset the server actually answered (a located page starts where the rowid is).
  const base = page.status === "ok" ? page.data.pagination.offset : offset;
  const located = page.status === "ok" ? page.data.pagination.located : null;
  const rowsRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (page.status !== "ok" || !located?.found) return;
    rowsRef.current?.querySelector<HTMLElement>(".is-hl-row")?.scrollIntoView?.({ block: "center" });
  }, [page.status, located]);
  const goTo = (next: number) => {
    setLocate(undefined);
    setOffset(Math.max(0, next));
  };

  return (
    <div className="sqlite-view">
      {sidecar && Object.keys(sidecar).length ? (
        <WalBanner runId={runId} path={preview.path} profile={sidecar} />
      ) : null}
      {!tables.length ? (
        <p className="viewer-empty">{sqlite.error || "사용자 테이블이 없는 SQLite 데이터베이스입니다."}</p>
      ) : (
        <div className="sqlite-body">
          <nav className="sqlite-tables" aria-label="SQLite 테이블 목록">
            <ul>
              {tables.map((item) => (
                <li key={item.name}>
                  <button
                    type="button"
                    className="sqlite-table-button"
                    aria-current={item.name === table ? "true" : undefined}
                    onClick={() => {
                      setTable(item.name);
                      goTo(0);
                    }}
                  >
                    <span>{item.name}</span>
                    <small>
                      {item.row_count === null || item.row_count === undefined ? "" : `${item.row_count}행`}
                    </small>
                  </button>
                </li>
              ))}
            </ul>
            {hiddenTables ? (
              <p className="viewer-note">
                테이블 {hiddenTables}개는 미리보기 목록 한도(8개)를 넘어 표시하지 않습니다.
              </p>
            ) : null}
          </nav>
          <section
            className="sqlite-rows"
            aria-label={table ? `${table} 테이블 행` : "테이블 행"}
            aria-busy={page.status === "loading"}
          >
            {page.status === "loading" ? <p className="viewer-note">행을 불러오는 중…</p> : null}
            {page.status === "error" ? (
              <p className="viewer-error">테이블을 읽지 못했습니다: {page.error}</p>
            ) : null}
            {page.status === "ok" ? (
              <>
                <div className="sqlite-pager">
                  <span>
                    {page.data.pagination.returned
                      ? `${(base + 1).toLocaleString("ko-KR")}–${(base + page.data.pagination.returned).toLocaleString("ko-KR")}`
                      : "0"}{" "}
                    /{" "}
                    {page.data.pagination.total === null
                      ? "?"
                      : page.data.pagination.total.toLocaleString("ko-KR")}
                    행
                  </span>
                  <button
                    type="button"
                    className="viewer-button"
                    disabled={base === 0}
                    onClick={() => goTo(base - SQLITE_PAGE_SIZE)}
                  >
                    이전 {SQLITE_PAGE_SIZE}행
                  </button>
                  <button
                    type="button"
                    className="viewer-button"
                    disabled={!page.data.pagination.has_next}
                    onClick={() => goTo(page.data.pagination.next_offset ?? base + SQLITE_PAGE_SIZE)}
                  >
                    다음 {SQLITE_PAGE_SIZE}행
                  </button>
                </div>
                {located ? (
                  <p className="viewer-note" data-testid="sqlite-located">
                    {located.found
                      ? `원본 행: ${table} rowid ${located.rowid} (${located.row_number.toLocaleString("ko-KR")}번째 행) — 강조 표시`
                      : `원본 행 rowid ${located.rowid}이(가) 이 테이블에 없습니다(삭제되었거나 다른 스냅숏).`}
                  </p>
                ) : null}
                <div className="viewer-table-wrap" ref={rowsRef}>
                  <table className="viewer-table">
                    <thead>
                      <tr>
                        <th scope="col">rowid</th>
                        {page.data.columns.map((column) => (
                          <th scope="col" key={column}>
                            {column}
                            {page.data.primary_key_columns?.includes(column) ? " (PK)" : ""}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {page.data.rows.map((row) => {
                        const isTarget =
                          highlight?.rowid !== undefined &&
                          table === highlight.table &&
                          String(row.rowid) === String(highlight.rowid);
                        return (
                          <tr
                            key={`${row.row_number}-${row.rowid}`}
                            className={isTarget ? "is-hl-row" : undefined}
                          >
                            <td>{String(row.rowid)}</td>
                            {page.data.columns.map((column) => (
                              <td key={column}>{formatCell(row.values[column])}</td>
                            ))}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </>
            ) : null}
          </section>
        </div>
      )}
    </div>
  );
}
