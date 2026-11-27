import { type ReactNode, useState } from "react";
import { type ArchiveEntryRow, fetchArchiveEntries, type SourcePreview } from "../../../api/viewer";
import { useAsync } from "../useAsync";

export const ARCHIVE_PAGE = 200;

/** ZIP times are DOS wall-clock values with no time zone: shown as recorded, never converted. */
export function zipTimeLabel(value: string): string {
  return value ? value.slice(0, 19).replace("T", " ") : "—";
}

/** A member path that wraps after each "/" before it wraps inside a folder or file name. */
function wrappingPath(name: string): ReactNode[] {
  const parts = name.split("/");
  return parts.flatMap((part, index) =>
    // biome-ignore lint/suspicious/noArrayIndexKey: a segment's position in the path is its identity
    index < parts.length - 1 ? [`${part}/`, <wbr key={`${index}-${part}`} />] : [part],
  );
}

/** Said under the member's name: why it does not open, or nothing for an ordinary file. */
export function entryState(entry: ArchiveEntryRow): string {
  if (entry.is_directory) return "폴더";
  if (entry.encrypted) return "암호화됨 · 열 수 없음";
  if (!entry.openable) return entry.refusal_reason;
  return entry.nested_archive ? "압축 파일(바이트만 표시)" : "";
}

interface ArchiveViewProps {
  runId: string;
  preview: SourcePreview;
  onOpenPath: (path: string) => void;
}

/** A ZIP's members from its central directory; an openable member opens in the viewer like a file. */
export function ArchiveView({ runId, preview, onOpenPath }: ArchiveViewProps) {
  const [offset, setOffset] = useState(0);
  const page = useAsync(`${runId}|${preview.path}|${offset}`, (signal) =>
    fetchArchiveEntries(runId, preview.path, offset, ARCHIVE_PAGE, signal),
  );
  if (page.status === "error") {
    return <p className="viewer-error">압축 목록을 읽지 못했습니다: {page.error}</p>;
  }
  if (page.status !== "ok") return <p className="viewer-note">압축 목록 불러오는 중…</p>;
  const { entries, total, has_next: hasNext } = page.data;
  if (total === 0) return <p className="viewer-empty">압축 파일에 항목이 없습니다.</p>;
  return (
    <div className="archive-view">
      <div className="archive-pager">
        <span>
          항목 {total.toLocaleString("ko-KR")}개
          {total > entries.length
            ? ` 중 ${(offset + 1).toLocaleString("ko-KR")}–${(offset + entries.length).toLocaleString("ko-KR")}`
            : ""}
        </span>
        {offset > 0 || hasNext ? (
          <>
            <button
              type="button"
              className="viewer-button"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - ARCHIVE_PAGE))}
            >
              이전 {ARCHIVE_PAGE}개
            </button>
            <button
              type="button"
              className="viewer-button"
              disabled={!hasNext}
              onClick={() => setOffset(offset + ARCHIVE_PAGE)}
            >
              다음 {ARCHIVE_PAGE}개
            </button>
          </>
        ) : null}
      </div>
      <div className="viewer-table-wrap">
        <table className="viewer-table archive-table">
          <thead>
            <tr>
              <th scope="col">이름</th>
              <th scope="col" className="archive-num">
                크기(바이트)
              </th>
              <th scope="col" className="archive-num">
                압축(바이트)
              </th>
              <th scope="col">수정 시각(ZIP 기록)</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.name}>
                <td className="archive-name">
                  {entry.openable ? (
                    <button
                      type="button"
                      className="archive-open"
                      title={`${entry.name} 열기`}
                      onClick={() => onOpenPath(entry.path)}
                    >
                      {wrappingPath(entry.name)}
                    </button>
                  ) : (
                    <span className="archive-closed">{wrappingPath(entry.name)}</span>
                  )}
                  {entryState(entry) ? <span className="archive-state">{entryState(entry)}</span> : null}
                </td>
                <td className="archive-num">
                  {entry.is_directory ? "—" : entry.size.toLocaleString("ko-KR")}
                </td>
                <td className="archive-num">
                  {entry.is_directory ? "—" : entry.compressed_size.toLocaleString("ko-KR")}
                </td>
                <td className="archive-time">{zipTimeLabel(entry.modified_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
