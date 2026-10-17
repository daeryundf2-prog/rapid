import { defineConfig } from "@playwright/test";

/**
 * Same specs against the Vite dev server (current sources, no `npm run build`): the API runs on
 * 8710 (vite.config.ts proxies /api there) and the console is served by Vite on 5174 under /v2/.
 *   npx playwright test --config e2e/playwright.dev.config.ts
 * RAPIDTRIAGE_API_PORT / RAPIDTRIAGE_VITE_PORT move both servers (parallel worktrees).
 */
const apiPort = process.env.RAPIDTRIAGE_API_PORT || "8710";
const vitePort = process.env.RAPIDTRIAGE_VITE_PORT || "5174";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 90_000,
  retries: 0,
  webServer: [
    {
      command: "node start-server.mjs",
      url: `http://127.0.0.1:${apiPort}/v2/`,
      env: { RAPIDTRIAGE_E2E_PORT: apiPort },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npx vite --port ${vitePort} --strictPort --host 127.0.0.1`,
      cwd: "..",
      url: `http://127.0.0.1:${vitePort}/v2/`,
      env: { RAPIDTRIAGE_API_PORT: apiPort },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
  use: {
    baseURL: `http://127.0.0.1:${vitePort}`,
  },
});
