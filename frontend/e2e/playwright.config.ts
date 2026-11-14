import { defineConfig } from "@playwright/test";

/**
 * E2E against the built console served by an isolated API server (start-server.mjs).
 *   RAPIDTRIAGE_E2E_PORT   API port (default 8791); set a different one per parallel worktree.
 *   RAPIDTRIAGE_E2E_REUSE  "1" to reuse a server already listening on that port. Off by default:
 *                          a server started from another worktree/branch would otherwise be tested
 *                          silently, so an occupied port fails the run instead.
 *
 * e2e/perf/ (T-203 interaction measurements, slow) is NOT part of the default run: it is collected
 * only when a CLI argument names it (`npm run e2e -- e2e/perf/interaction.spec.ts`, `npm run
 * e2e:perf`) or RAPIDTRIAGE_PERF=1. RAPIDTRIAGE_PERF_BASE_URL points the perf run at a server that
 * is already running (real data on C2) instead of starting start-server.mjs; see e2e/perf/README.md.
 */
const perfRequested =
  process.env.RAPIDTRIAGE_PERF === "1" ||
  process.argv.slice(2).some((arg) => /(^|[\\/])perf([\\/]|$)/.test(arg));
// Workers re-read this file with their own argv: hand them the decision through the environment.
if (perfRequested) process.env.RAPIDTRIAGE_PERF = "1";
const perfBaseUrl = perfRequested ? process.env.RAPIDTRIAGE_PERF_BASE_URL?.replace(/\/+$/, "") : undefined;
if (perfBaseUrl && targetsOperatorPort(perfBaseUrl)) {
  throw new Error("Port 8710 is the operator's RapidTriage server and is never measured; use another port.");
}

// R8 WB-13 review: a regex on the string end missed a base URL with a path (http://127.0.0.1:8710/v2).
function targetsOperatorPort(baseUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(`RAPIDTRIAGE_PERF_BASE_URL is not a URL: ${baseUrl}`);
  }
  return parsed.port === "8710";
}

const port = process.env.RAPIDTRIAGE_E2E_PORT || "8791";
const reuse = !process.env.CI && process.env.RAPIDTRIAGE_E2E_REUSE === "1";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  testIgnore: perfRequested ? [] : ["perf/**"],
  timeout: 90_000,
  retries: process.env.CI ? 1 : 0,
  webServer: perfBaseUrl
    ? undefined
    : {
        command: "node start-server.mjs",
        url: `http://127.0.0.1:${port}/v2/`,
        env: { RAPIDTRIAGE_E2E_PORT: port, RAPIDTRIAGE_NO_BROWSER: "1" },
        reuseExistingServer: reuse,
        timeout: Number(process.env.PW_WEBSERVER_TIMEOUT_MS) || 60_000,
      },
  use: {
    baseURL: perfBaseUrl || `http://127.0.0.1:${port}`,
  },
});
