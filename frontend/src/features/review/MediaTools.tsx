/**
 * Media gallery tools (AXIOM E3, research §7.2-7): the 미디어 흐리게 toggle (Shift+B, kept across
 * reloads) and the "관련 미디어 n" badge of the focused tile — other files with the same
 * content hash (case DB file rows, else the files output's duplicate_content_groups).
 */

import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { getRelatedMedia } from "../../api/reviewTools";
import { KEY_MAP } from "../../contracts/command";
import { keyLabel } from "../../shortcuts";
import { toggleMediaBlur } from "./commands";
import { useViewPrefs } from "./viewPrefs";
import "./review.css";

export function MediaBlurToggle() {
  const blur = useViewPrefs((s) => s.mediaBlur);
  return (
    <button
      type="button"
      className="view-link"
      aria-pressed={blur}
      aria-keyshortcuts={KEY_MAP.mediaBlur}
      title={`미디어 흐리게 (${keyLabel(KEY_MAP.mediaBlur)})`}
      data-testid="media-blur-toggle"
      onClick={toggleMediaBlur}
    >
      미디어 흐리게
    </button>
  );
}

export function RelatedMediaBadge({
  runId,
  path,
  name,
}: {
  runId: string | null;
  path: string | null;
  name: string;
}) {
  const [open, setOpen] = useState(false);
  const listId = useId();
  const related = useQuery({
    queryKey: ["related-media", runId, path],
    queryFn: ({ signal }) => getRelatedMedia(runId as string, path as string, signal),
    enabled: Boolean(runId && path),
    staleTime: 60_000,
    retry: false,
  });
  const count = related.data?.count ?? 0;
  if (!runId || !path || count === 0) return null;
  const source = related.data?.source === "case-db" ? "케이스 DB 해시" : "중복 콘텐츠 그룹";
  return (
    <span className="related-media" data-testid="related-media">
      <button
        type="button"
        className="view-link"
        aria-expanded={open}
        aria-controls={listId}
        title={`${name}과(와) 내용이 같은 파일 (${source})`}
        onClick={() => setOpen((value) => !value)}
      >
        관련 미디어 {count.toLocaleString("ko-KR")}
      </button>
      {open ? (
        <ul id={listId} className="related-media-list" aria-label={`${name}과(와) 같은 해시의 파일`}>
          {(related.data?.paths ?? []).map((item) => (
            <li key={item}>{item}</li>
          ))}
          {count > (related.data?.paths.length ?? 0) ? (
            <li>외 {(count - (related.data?.paths.length ?? 0)).toLocaleString("ko-KR")}건</li>
          ) : null}
        </ul>
      ) : null}
    </span>
  );
}
