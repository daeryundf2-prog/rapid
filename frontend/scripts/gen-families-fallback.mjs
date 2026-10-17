// Writes src/features/flags/families.fallback.json — the console's bundled copy of the backend
// catalogue (rapidtriage/core/triage_rules/catalog/*.yaml, plan viewer-families §3.1 "빌드 시 프런트로
// 복사"). The YAML is read through the backend's own loader (same validation, same `version` hash),
// so the fallback can never drift from what `GET /api/meta/families` serves for this checkout.
//
//   npm run gen:families            regenerate from the YAML
//   npm run gen:families -- --check exit 1 when the committed copy is stale (CI)
//   prebuild (--if-available)       regenerate; skip only when Python / the loader module is absent
//
// Python writes the payload to a temp file (stdout noise from imports can never corrupt it) and
// exits 3 when the loader itself is unavailable (no `yaml` / `rapidtriage` module). Only that case
// — or no Python at all — is skippable with --if-available. A loader error (invalid YAML, a bad
// rule) always fails: a stale catalogue must not ship silently.
//
// scripts/families-mock.mjs stays the vitest / Playwright fixture (stable ids for tests).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const out = join(here, "..", "src", "features", "flags", "families.fallback.json");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";
const UNAVAILABLE_EXIT = 3;
const PY = [
  "import json, sys",
  "try:",
  "    from rapidtriage.core.triage_rules.catalog import load_catalog",
  "except ModuleNotFoundError as exc:",
  "    sys.stderr.write(f'module missing: {exc.name}')",
  `    sys.exit(${UNAVAILABLE_EXIT})`,
  "try:",
  "    catalog = load_catalog()",
  "except Exception as exc:",
  "    cause = exc.__cause__",
  "    if isinstance(cause, ModuleNotFoundError):",
  "        sys.stderr.write(f'module missing: {cause.name}')",
  `        sys.exit(${UNAVAILABLE_EXIT})`,
  "    raise",
  "payload = catalog.payload()",
  "with open(sys.argv[1], 'w', encoding='utf-8') as handle:",
  "    json.dump(payload, handle, ensure_ascii=False)",
].join("\n");

const tempDir = mkdtempSync(join(tmpdir(), "rt-families-"));
const tmp = join(tempDir, "payload.json");
const skippable = process.argv.includes("--if-available");
let payload;
try {
  execFileSync(python, ["-c", PY, tmp], {
    cwd: repoRoot,
    env: { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1" },
    stdio: ["ignore", "ignore", "pipe"],
  });
  payload = JSON.parse(readFileSync(tmp, "utf8"));
} catch (error) {
  const missingPython = error?.code === "ENOENT";
  const missingModule = error?.status === UNAVAILABLE_EXIT;
  const lines = String(error?.stderr ?? error?.message ?? error)
    .trim()
    .split("\n");
  const detail = lines[lines.length - 1];
  if (skippable && (missingPython || missingModule)) {
    console.warn(
      `gen:families skipped (catalogue loader unavailable: ${detail}); keeping the committed copy`,
    );
    process.exit(0);
  }
  console.error(`gen:families failed: ${detail}`);
  process.exit(1);
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
const text = `${JSON.stringify(payload, null, 1)}\n`;

if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(out, "utf8");
  } catch {
    // missing = stale
  }
  if (current !== text) {
    console.error(`families.fallback.json is stale (catalog ${payload.version}); run npm run gen:families`);
    process.exit(1);
  }
  console.log(`families.fallback.json up to date (catalog ${payload.version})`);
} else {
  writeFileSync(out, text);
  console.log(
    `${payload.families.length} families, ${payload.rules.length} rules (catalog ${payload.version}) -> ${out}`,
  );
}
