import { defineConfig } from "@playwright/test";

/**
 * Same specs against the Vite dev server (current sources, no `npm run build`): the API runs on
 * 8710 (vite.config.ts proxies /api there) and the console is served by Vite on 5174 under /v2/.
 *   npx playwright test --config e2e/playwright.dev.config.ts
 */
export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 90_000,
  retries: 0,
  webServer: [
    {
      command: "node start-server.mjs",
      url: "http://127.0.0.1:8710/v2/",
      env: { RAPIDTRIAGE_E2E_PORT: "8710" },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: "npx vite --port 5174 --strictPort --host 127.0.0.1",
      cwd: "..",
      url: "http://127.0.0.1:5174/v2/",
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
  use: {
    baseURL: "http://127.0.0.1:5174",
  },
});
