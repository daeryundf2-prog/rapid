/**
 * Banner above the tree while the run has no summary yet (R4 V1 U-P2-4): finished groups are
 * browsable, the rest is dimmed with a reason. The sentence comes from the server (`/tree`
 * `live.message`); it is plain text, not a live region (the page keeps one polite region).
 */

import type { RunTreeLive } from "../../api/runs";
import { normalizeRunStatus } from "../../api/runs";
import { Icon } from "../../icons";

/** Fallback sentence when the server sends no `message`. */
export const LIVE_BANNER_FALLBACK = "런 진행 중 · 완료된 그룹만 표시 · 검색/타임라인은 마무리 후";

export function liveBannerText(live: RunTreeLive): string {
  const message = live.message?.trim();
  if (message) return message;
  const status = normalizeRunStatus(live.run_status);
  if (status === "interrupted") return "런 중단됨 · 완료된 그룹만 표시 · 이어서 실행하면 나머지를 처리합니다";
  if (status === "cancelled") return "런 취소됨 · 완료된 그룹만 표시";
  return LIVE_BANNER_FALLBACK;
}

export function LiveRunBanner({ live }: { live: RunTreeLive | null | undefined }) {
  if (!live) return null;
  const available = live.available_kinds?.length ?? 0;
  const pending = live.pending_kinds?.length ?? 0;
  return (
    <div className="live-run-banner" data-testid="live-run-banner">
      <Icon name="info" />
      <span>
        {liveBannerText(live)}
        {available + pending > 0 ? (
          <span className="live-run-banner-counts">
            {" "}
            (열람 가능 {available} · 대기 {pending})
          </span>
        ) : null}
      </span>
    </div>
  );
}
