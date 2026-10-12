import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app/App";
import { registerAppSlots } from "./app/registerSlots";
import { canonicalizeHash, captureLaunchToken } from "./router";
import { initPrefs } from "./state/slices/prefs";
// Bundled fonts (U-V2, no CDN): Pretendard Variable subset + JetBrains Mono Variable,
// built from the npm packages by src/assets/fonts/build_fonts.py.
import "./assets/fonts/fonts.css";
import "./tokens/tokens.css";
import "./app/shell.css";
import "./tokens/controls.css";

// `#token=` launch fragment → session storage; any route sharing the fragment is kept.
captureLaunchToken();
// Legacy `#/case/{run}/{collection}` links → `#/case/{run}/{stage}/{view}` (console-ia §3).
canonicalizeHash();
initPrefs();
registerAppSlots();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error instanceof Error && "status" in error) {
          const status = (error as { status: number }).status;
          if (status === 401 || status === 403) return false;
        }
        return failureCount < 2;
      },
      staleTime: 2_000,
    },
  },
});

const container = document.getElementById("root");
if (!container) throw new Error("missing #root container");

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
