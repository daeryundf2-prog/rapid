import { defineConfig } from "@playwright/test";

/**
 * Same specs against the Vite dev server (current sources, no `npm run build`): an isolated API
 * server (start-server.mjs) plus the console served by Vite on 5174 under /v2/ (vite.config.ts
 * proxies /api to the API port).
 *   npx playwright test --config e2e/playwright.dev.config.ts
 * RAPIDTRIAGE_E2E_PORT   API port, same source as playwright.config.ts (default 8791).
 *                        RAPIDTRIAGE_API_PORT is honoured as a fallback for older scripts.
 * RAPIDTRIAGE_VITE_PORT  Vite port (default 5174); set both per parallel worktree.
 * 8710 is the user's own RapidTriage server, so it is refused outright.
 */
const apiPort = process.env.RAPIDTRIAGE_E2E_PORT || process.env.RAPIDTRIAGE_API_PORT || "8791";
if (apiPort === "8710") {
  throw new Error(
    "e2e API 포트로 8710(사용자 서버)은 쓸 수 없습니다. RAPIDTRIAGE_E2E_PORT를 다른 포트로 지정하세요. / " +
      "Port 8710 is the user's RapidTriage server and is never used for e2e; set RAPIDTRIAGE_E2E_PORT to another port.",
  );
}
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
      env: { RAPIDTRIAGE_E2E_PORT: apiPort, RAPIDTRIAGE_NO_BROWSER: "1" },
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
