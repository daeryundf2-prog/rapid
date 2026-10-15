import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { type BrowseScope, browseDirectory } from "../../api/browse";
import { ErrorText } from "./ErrorText";

/** Server-side path picker over GET /api/browse. */
export function BrowsePanel({
  initialPath,
  directoriesOnly = false,
  filesOnly = false,
  scope,
  onPick,
}: {
  initialPath?: string;
  /** import dialog: only folders are valid selections. */
  directoriesOnly?: boolean;
  /** A file is the selection (e.g. a disk image / $MFT): folders only navigate. */
  filesOnly?: boolean;
  /**
   * Analysis dialogs: list only the run's allowed roots (top level = the roots themselves;
   * never above them, never the user's home folder).
   */
  scope?: BrowseScope;
  onPick: (path: string) => void;
}) {
  const [path, setPath] = useState<string | null>(initialPath?.trim() ? initialPath.trim() : null);
  const listing = useQuery({
    queryKey: ["browse", path, scope?.name ?? null, scope?.runId ?? null],
    queryFn: () => browseDirectory(path, false, scope),
    retry: false,
  });

  if (listing.isPending) return <p className="pane-empty">폴더를 불러오는 중…</p>;
  if (listing.isError) {
    return (
      <div className="case-browse-wrap">
        <ErrorText>
          폴더를 불러오지 못했습니다:{" "}
          {listing.error instanceof Error ? listing.error.message : "알 수 없는 오류"}
        </ErrorText>
        {scope && path !== null ? (
          // A typed path outside the allowed roots (403): start again from the roots.
          <button type="button" className="button" onClick={() => setPath(null)}>
            허용 루트 목록 보기
          </button>
        ) : null}
      </div>
    );
  }
  const data = listing.data;
  const atRoots = Boolean(scope) && (data.at_roots === true || (path === null && !data.path));
  return (
    <div className="case-browse-wrap">
      <div className="case-actions" style={{ justifyContent: "space-between" }}>
        {atRoots ? (
          <strong data-testid="browse-roots-title">{data.scope_label || "허용 루트"}</strong>
        ) : (
          <code>{data.path}</code>
        )}
        <span>
          {data.parent ? (
            <button type="button" className="button" onClick={() => setPath(data.parent)}>
              상위 폴더
            </button>
          ) : scope && !atRoots ? (
            <button type="button" className="button" onClick={() => setPath(null)}>
              허용 루트 목록
            </button>
          ) : null}{" "}
          {filesOnly || atRoots ? null : (
            <button type="button" className="button" onClick={() => onPick(data.path)}>
              이 폴더 선택
            </button>
          )}
        </span>
      </div>
      {atRoots && data.entries.length === 0 ? (
        <p className="case-reason">이 런에 허용된 루트가 없습니다.</p>
      ) : null}
      <ul
        className="case-browse"
        aria-label={atRoots ? "허용 루트" : filesOnly ? "파일 목록" : "폴더 목록"}
        style={{ listStyle: "none", margin: 0, padding: 0 }}
      >
        {data.entries
          .filter((entry) => !directoriesOnly || entry.kind === "directory")
          .map((entry) => (
            <li key={entry.path}>
              <button
                type="button"
                title={entry.path}
                onClick={() => (entry.kind === "directory" ? setPath(entry.path) : onPick(entry.path))}
                onDoubleClick={() =>
                  filesOnly && entry.kind === "directory" ? undefined : onPick(entry.path)
                }
              >
                <span aria-hidden="true">{entry.kind === "directory" ? "▸" : "·"}</span>
                <span>{entry.name}</span>
                {entry.evidence_candidate && entry.kind === "file" && (
                  <span className="badge info">증거</span>
                )}
              </button>
            </li>
          ))}
        {data.truncated && <li className="case-reason">항목이 많아 일부만 표시했습니다.</li>}
      </ul>
    </div>
  );
}
