import { useState } from "react";
import {
  fetchSqliteTable,
  fetchSqliteWalPreview,
  type SourcePreview,
  type SqliteSidecarStateProfile,
  type SqliteWalPreview,
} from "../../../api/viewer";
import { errorText, useAsync } from "../useAsync";

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
        {detected.length ? ` · 발견: ${detected.join(", ")}` : ""}
        {sidecars.wal?.exists && header
          ? ` · WAL 헤더 ${header.status || "미해석"}, 페이지 ${header.page_size ?? "?"}, 추정 프레임 ${header.estimated_frame_count ?? "?"}`
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
            상태 {wal.data.wal.status || "알 수 없음"} · 추정 프레임 {wal.data.wal.estimated_frame_count ?? 0}{" "}
            · 미리보기 {wal.data.wal.preview_frame_count ?? wal.data.wal.frames?.length ?? 0} · 삭제 후보{" "}
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
  const tables = sqlite.tables || [];
  const initialTable =
    highlight?.table && tables.some((t) => t.name === highlight.table)
      ? highlight.table
      : (tables[0]?.name ?? null);
  const [table, setTable] = useState<string | null>(initialTable);
  const [offset, setOffset] = useState(0);
  const sidecar = sqlite.sidecar_state_profile || sqlite.database_metadata?.sidecar_state_profile;
  const page = useAsync(table ? `${preview.path}|${table}|${offset}` : null, (signal) =>
    fetchSqliteTable(runId, preview.path, table as string, offset, SQLITE_PAGE_SIZE, signal),
  );
  const hiddenTables = Math.max(0, (sqlite.table_count ?? tables.length) - tables.length);

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
                      setOffset(0);
                    }}
                  >
                    <span>{item.name}</span>
                    <small>{item.row_count ?? "?"}행</small>
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
                      ? `${(offset + 1).toLocaleString("ko-KR")}–${(offset + page.data.pagination.returned).toLocaleString("ko-KR")}`
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
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - SQLITE_PAGE_SIZE))}
                  >
                    이전 {SQLITE_PAGE_SIZE}행
                  </button>
                  <button
                    type="button"
                    className="viewer-button"
                    disabled={!page.data.pagination.has_next}
                    onClick={() => setOffset(page.data.pagination.next_offset ?? offset + SQLITE_PAGE_SIZE)}
                  >
                    다음 {SQLITE_PAGE_SIZE}행
                  </button>
                </div>
                <div className="viewer-table-wrap">
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
