/**
 * 접수 (intake) node — the case dashboard (plan U8 / §4.2, §9 X1): card grid
 * with case notes, processing details, evidence source, artifact categories,
 * review status, keyword hits, export history and shortcuts.
 * Mounted in the grid slot when the route's collection is "intake".
 */

import { useRoute } from "../state/hooks";
// T-116: the dashboard cards are a lazy chunk.
import { CaseDashboard } from "./lazyViews";

export function IntakePane() {
  const { route } = useRoute();
  if (!route.runId) return <p className="pane-empty">열린 케이스가 없습니다.</p>;
  return <CaseDashboard key={route.runId} runId={route.runId} />;
}
