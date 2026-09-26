// Starts the rapidtriage API server for Playwright E2E.
// Uses an isolated job store + fixed token so tests are deterministic.

import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";
const port = process.env.RAPIDTRIAGE_E2E_PORT || "8791";
const stateDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-"));

const child = spawn(
  python,
  [
    "-c",
    "import sys; from rapidtriage.cli import web_main; sys.exit(web_main())",
    "--host",
    "127.0.0.1",
    "--port",
    port,
  ],
  {
    cwd: repoRoot,
    stdio: "inherit",
    env: {
      ...process.env,
      RAPIDTRIAGE_AUTH_TOKEN: "e2e-token",
      RAPIDTRIAGE_STATE_PATH: join(stateDir, "runs.json"),
    },
  },
);

child.on("exit", (code) => process.exit(code ?? 1));
process.on("SIGTERM", () => child.kill("SIGTERM"));
process.on("SIGINT", () => child.kill("SIGINT"));
