import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { browseDirectory } from "../../api/browse";
import { ErrorText } from "./ErrorText";

/** Server-side path picker over GET /api/browse. */
export function BrowsePanel({
  initialPath,
  directoriesOnly = false,
  onPick,
}: {
  initialPath?: string;
  /** import dialog: only folders are valid selections. */
  directoriesOnly?: boolean;
  onPick: (path: string) => void;
}) {
  const [path, setPath] = useState<string | null>(initialPath?.trim() ? initialPath.trim() : null);
  const listing = useQuery({
    queryKey: ["browse", path],
    queryFn: () => browseDirectory(path),
    retry: false,
  });

  if (listing.isPending) return <p className="pane-empty">폴더를 불러오는 중…</p>;
  if (listing.isError) {
    return (
      <ErrorText>
        폴더를 불러오지 못했습니다:{" "}
        {listing.error instanceof Error ? listing.error.message : "알 수 없는 오류"}
      </ErrorText>
    );
  }
  const data = listing.data;
  return (
    <div className="case-browse-wrap">
      <div className="case-actions" style={{ justifyContent: "space-between" }}>
        <code>{data.path}</code>
        <span>
          {data.parent && (
            <button type="button" className="button" onClick={() => setPath(data.parent)}>
              상위 폴더
            </button>
          )}{" "}
          <button type="button" className="button" onClick={() => onPick(data.path)}>
            이 폴더 선택
          </button>
        </span>
      </div>
      <ul className="case-browse" aria-label="폴더 목록" style={{ listStyle: "none", margin: 0, padding: 0 }}>
        {data.entries
          .filter((entry) => !directoriesOnly || entry.kind === "directory")
          .map((entry) => (
            <li key={entry.path}>
              <button
                type="button"
                onClick={() => (entry.kind === "directory" ? setPath(entry.path) : onPick(entry.path))}
                onDoubleClick={() => onPick(entry.path)}
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
