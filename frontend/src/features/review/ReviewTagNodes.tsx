/**
 * 검토 tree: one node per case tag (AXIOM E3) — colour swatch, name, digit key and the number
 * of rows carrying it (server count over the case DB marks). User tags are always listed (also
 * at 0), system tags (우선순위 n) only once used; 북마크 has its own node above. Each node opens
 * the review board filtered to the tag. Korean label order.
 */

import type { CaseTag } from "../../api/reviewTools";
import { serializeRoute } from "../../router";
import { BOOKMARK_TAG } from "./constants";
import { sortTags } from "./tagStore";
import "./review.css";

export function visibleTagNodes(tags: readonly CaseTag[]): CaseTag[] {
  return sortTags(tags).filter((tag) => tag.name !== BOOKMARK_TAG && (tag.kind === "user" || tag.count > 0));
}

export function ReviewTagNodes({
  runId,
  tags,
  current,
}: {
  runId: string;
  tags: readonly CaseTag[];
  /** The tag the review board is filtered to (one tag only), if any. */
  current: string | null;
}) {
  return (
    <>
      {visibleTagNodes(tags).map((tag) => {
        const label = `${tag.name}${tag.shortcut ? `, 단축키 ${tag.shortcut}` : ""}, ${tag.count.toLocaleString("ko-KR")}건`;
        return (
          <li key={tag.id} data-testid="review-tag-node">
            <a
              className="stage-link"
              href={serializeRoute({ runId, collection: "review", tags: [tag.name] })}
              aria-current={current === tag.name ? "page" : undefined}
              aria-label={label}
              title={tag.description ? `${tag.name} — ${tag.description}` : tag.name}
            >
              <span className="stage-tag-label">
                <span
                  className="tag-swatch"
                  style={{ background: `var(--${tag.color_token})` }}
                  aria-hidden="true"
                />
                <span>{tag.name}</span>
                {tag.shortcut ? <span className="stage-tag-key">{tag.shortcut}</span> : null}
              </span>
              <span className="badge muted">{tag.count.toLocaleString("ko-KR")}</span>
            </a>
          </li>
        );
      })}
    </>
  );
}
