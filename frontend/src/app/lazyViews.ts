/**
 * Expert screens loaded on demand (T-116, code splitting): each is its own JS chunk, fetched the
 * first time the screen is opened, so the first screen (the shell and the case list) stays under
 * the 1.0 MB entry-chunk budget (`npm run check:bundle`). Loading shows "… 불러오는 중"
 * (role=status); a chunk that fails to load shows a Korean 다시 시도 message (`lazyView`).
 *
 * Import screens from here, never the feature module directly, or the chunk is pulled back into
 * the entry bundle.
 */

import { lazyView } from "../components/LazyView";

// 보기 전환 (ViewSwitch): every view but the column view (the DataGrid stays in the entry chunk).
export const ThumbnailView = lazyView("썸네일 보기", () =>
  import("../features/views/ThumbnailView").then((m) => m.ThumbnailView),
);
export const ChatView = lazyView("대화 보기", () =>
  import("../features/views/ChatView").then((m) => m.ChatView),
);
export const HistogramView = lazyView("히스토그램 보기", () =>
  import("../features/views/HistogramView").then((m) => m.HistogramView),
);
export const CardView = lazyView("행(카드) 보기", () =>
  import("../features/views/CardView").then((m) => m.CardView),
);
export const MapView = lazyView("지도 대체 보기", () =>
  import("../features/views/MapView").then((m) => m.MapView),
);

// The 탐색 panes (registerSlots TreeSlot / GridSlot): the domain tree, and the DataGrid behind the
// view switch (ExploreGrid) with the table engine and column sets.
export const EvidenceTree = lazyView("탐색 트리", () =>
  import("../features/tree/EvidenceTree").then((m) => m.EvidenceTree),
);
export const ExploreGrid = lazyView("목록", () => import("./ExploreGrid").then((m) => m.ExploreGrid));

// Collection panes of their own (registerSlots GridSlot / TreeSlot / IntakePane).
export const CaseDashboard = lazyView("케이스 현황", () =>
  import("../features/dashboard/CaseDashboard").then((m) => m.CaseDashboard),
);
export const RegistryExplorer = lazyView("레지스트리 탐색기", () =>
  import("../features/explorers/RegistryExplorer").then((m) => m.RegistryExplorer),
);
export const AnalysisPane = lazyView("분석 작업", () =>
  import("../features/analysis/AnalysisPane").then((m) => m.AnalysisPane),
);
export const DerivedPane = lazyView("통합 보기", () =>
  import("../features/derived/DerivedPane").then((m) => m.DerivedPane),
);
export const ProcessPage = lazyView("처리", () =>
  import("../features/stages/ProcessStage").then((m) => m.ProcessPage),
);
export const ProcessPanel = lazyView("처리", () =>
  import("../features/stages/ProcessStage").then((m) => m.ProcessPanel),
);
export const ReviewPanel = lazyView("검토", () =>
  import("../features/stages/ReviewReportStage").then((m) => m.ReviewPanel),
);
export const ReportPage = lazyView("보고", () =>
  import("../features/stages/ReviewReportStage").then((m) => m.ReportPage),
);
export const ReportPanel = lazyView("보고", () =>
  import("../features/stages/ReviewReportStage").then((m) => m.ReportPanel),
);

// The viewer pane (main window slot); the popout window loads it through PopoutApp (main.tsx).
export const Viewer = lazyView<{ drawer?: boolean }>("뷰어", () =>
  import("../features/viewer/Viewer").then((m) => m.Viewer),
);
