import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { shouldRetryQuery } from "./api/queryPolicy";
import { App } from "./app/App";
import { registerAppSlots } from "./app/registerSlots";
import { RegionBoundary } from "./components/RegionBoundary";
import { PopoutApp } from "./features/viewer/popout/PopoutApp";
import { isPopoutWindow } from "./features/viewer/popout/protocol";
import { canonicalizeHash, captureLaunchToken } from "./router";
import { initPrefs } from "./state/slices/prefs";
// Bundled fonts (U-V2, no CDN): Pretendard Variable subset + JetBrains Mono Variable,
// built from the npm packages by src/assets/fonts/build_fonts.py.
import "./assets/fonts/fonts.css";
import "./tokens/tokens.css";
import "./app/shell.css";
import "./tokens/controls.css";

// The viewer window (U-F2, `?popout=viewer`): the same bundle, only the viewer; it gets its token
// from the main window by postMessage and never reads a route.
const popout = isPopoutWindow();
if (!popout) {
  // `#token=` launch fragment → session storage; any route sharing the fragment is kept.
  captureLaunchToken();
  // Legacy `#/case/{run}/{collection}` links → `#/case/{run}/{stage}/{view}` (console-ia §3).
  canonicalizeHash();
}
initPrefs();
if (!popout) registerAppSlots();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // T-130: no retry on a 4xx (except 408 / 429); 5xx / network failures twice.
      retry: shouldRetryQuery,
      staleTime: 2_000,
    },
  },
});

const container = document.getElementById("root");
if (!container) throw new Error("missing #root container");

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RegionBoundary region="콘솔">{popout ? <PopoutApp /> : <App />}</RegionBoundary>
    </QueryClientProvider>
  </StrictMode>,
);
