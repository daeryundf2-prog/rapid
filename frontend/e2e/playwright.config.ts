import { defineConfig } from "@playwright/test";

/**
 * E2E against the built console served by an isolated API server (start-server.mjs).
 *   RAPIDTRIAGE_E2E_PORT   API port (default 8791); set a different one per parallel worktree.
 *   RAPIDTRIAGE_E2E_REUSE  "1" to reuse a server already listening on that port. Off by default:
 *                          a server started from another worktree/branch would otherwise be tested
 *                          silently, so an occupied port fails the run instead.
 */
const port = process.env.RAPIDTRIAGE_E2E_PORT || "8791";
const reuse = !process.env.CI && process.env.RAPIDTRIAGE_E2E_REUSE === "1";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 90_000,
  retries: process.env.CI ? 1 : 0,
  webServer: {
    command: "node start-server.mjs",
    url: `http://127.0.0.1:${port}/v2/`,
    env: { RAPIDTRIAGE_E2E_PORT: port, RAPIDTRIAGE_NO_BROWSER: "1" },
    reuseExistingServer: reuse,
    timeout: Number(process.env.PW_WEBSERVER_TIMEOUT_MS) || 60_000,
  },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
  },
});
