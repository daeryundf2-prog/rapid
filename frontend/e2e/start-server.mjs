// Starts the rapidtriage API server for Playwright E2E.
// Uses an isolated job store + fixed token so tests are deterministic.

import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";
const port = process.env.RAPIDTRIAGE_E2E_PORT || "8791";
if (port === "8710") {
  console.error(
    "[e2e] 8710은 사용자 서버 포트이므로 e2e에 쓸 수 없습니다. / 8710 is the user's server port and is never used for e2e.",
  );
  process.exit(1);
}

// Fail fast with a clear message when the port is taken (another run, or a stray server) instead
// of a Python bind traceback.
await new Promise((resolve) => {
  const probe = createServer();
  probe.once("error", (err) => {
    if (err.code === "EADDRINUSE" || err.code === "EACCES") {
      console.error(
        `[e2e] 포트 ${port}이(가) 이미 사용 중입니다. RAPIDTRIAGE_E2E_PORT로 다른 포트를 지정하거나 ` +
          `그 포트를 쓰는 프로세스를 종료하세요 (실행 중인 서버를 재사용하려면 RAPIDTRIAGE_E2E_REUSE=1).\n` +
          `[e2e] Port ${port} is already in use. Set RAPIDTRIAGE_E2E_PORT to a free port or stop the ` +
          `process holding it (RAPIDTRIAGE_E2E_REUSE=1 reuses a running server).`,
      );
    } else {
      console.error(`[e2e] cannot probe port ${port}: ${err.message}`);
    }
    process.exit(1);
  });
  probe.listen(Number(port), "127.0.0.1", () => probe.close(resolve));
});
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
      // Never open the user's browser (web.py would open a #token= URL on loopback hosts).
      RAPIDTRIAGE_NO_BROWSER: "1",
      // R8 RI-04 confines POST /api/sample-case/run to the server's sample root (default
      // ~/.rapidtriage; anything else is 403 PATH_OUTSIDE_ALLOWED_ROOT). The specs create their
      // sample folders with mkdtemp(os.tmpdir()), so this isolated test server uses the system temp
      // folder as its root — never the user's home.
      RAPIDTRIAGE_SAMPLE_ROOT: tmpdir(),
    },
  },
);

child.on("exit", (code) => process.exit(code ?? 1));
process.on("SIGTERM", () => child.kill("SIGTERM"));
process.on("SIGINT", () => child.kill("SIGINT"));
