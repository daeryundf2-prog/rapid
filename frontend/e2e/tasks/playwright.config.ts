import { defineConfig } from "@playwright/test";

/**
 * R8 task measurements (T-011). `scripts/r8-measure.py` uses this config; the main e2e config
 * (`npm run e2e -- e2e/tasks`) runs the same specs against the fixture server.
 *   R8_BASE_URL set  → real run: no fixture server is started, the specs talk to that server read-only.
 *   R8_BASE_URL unset → the isolated fixture server (start-server.mjs) on RAPIDTRIAGE_E2E_PORT.
 * One worker: wall-time measurements must not compete with each other.
 */
const port = process.env.RAPIDTRIAGE_E2E_PORT || "8791";
const real = Boolean(process.env.R8_BASE_URL);
const reuse = process.env.RAPIDTRIAGE_E2E_REUSE === "1";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 180_000,
  workers: 1,
  retries: 0,
  webServer: real
    ? undefined
    : {
        command: "node ../start-server.mjs",
        url: `http://127.0.0.1:${port}/v2/`,
        env: { RAPIDTRIAGE_E2E_PORT: port, RAPIDTRIAGE_NO_BROWSER: "1" },
        reuseExistingServer: reuse,
        timeout: Number(process.env.PW_WEBSERVER_TIMEOUT_MS) || 60_000,
      },
  use: {
    baseURL: real ? process.env.R8_BASE_URL : `http://127.0.0.1:${port}`,
    viewport: { width: 1280, height: 720 },
  },
});
