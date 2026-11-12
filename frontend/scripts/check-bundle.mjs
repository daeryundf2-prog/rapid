// Bundle budget + bundle-matches-source check (T-156, D57).
//
// The built console bundle (rapidtriage/web/static/v2/**) stays in Git and only the coordinator
// commits it. This check proves the committed copy is what the current source builds to, and that
// the bundle stays inside its size budget.
//
//   npm run check:bundle                      build into a temp dir, compare + enforce budget
//   npm run check:bundle -- --built <dir>     compare an existing fresh build instead of building
//
// It never writes to rapidtriage/web/static/v2: the build goes to a temp outDir that is removed
// afterwards. It does not run `prebuild` (families fallback regeneration) — it checks the source
// as committed; `npm run gen:families -- --check` guards that file separately.
//
// Budget is a ratchet: the baseline (current size + 2%) may only be lowered when the bundle
// shrinks (T-116 lowers JS to 1.0 MB). Exit 0 = match + within budget, 1 = failure.
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const frontendRoot = join(here, "..");
const committedDir = join(frontendRoot, "..", "rapidtriage", "web", "static", "v2");

// Ratchet baseline (2026-11-12, feat/r6-ux 7790624): JS 1,879,137 B single chunk (spec baseline),
// CSS 150,268 B, fonts 269,432 B. Limits = baseline + 2%, rounded up.
// Re-baselined 2026-11-12 after WB-5/WB-6 (T-036 undo, T-086, T-130, T-144, T-169..T-174 merged):
// JS 1,916,766 B, CSS 153,462 B -> limits + 1.5%. Shrinking is T-116's job (code splitting).
const BUDGET = {
  js: 1_945_518,
  css: 155_764,
  font: 274_821,
};

const KIND = { ".js": "js", ".css": "css", ".woff2": "font", ".woff": "font", ".ttf": "font" };

function listFiles(root) {
  const out = new Map();
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else {
        const buf = readFileSync(full);
        out.set(relative(root, full).split(sep).join("/"), {
          size: buf.length,
          sha256: createHash("sha256").update(buf).digest("hex"),
        });
      }
    }
  };
  walk(root);
  return out;
}

async function buildFresh() {
  const outDir = mkdtempSync(join(tmpdir(), "rt-check-bundle-"));
  const { build } = await import("vite");
  await build({
    root: frontendRoot,
    configFile: join(frontendRoot, "vite.config.ts"),
    logLevel: "warn",
    build: { outDir, emptyOutDir: true },
  });
  return outDir;
}

const builtArg = process.argv.indexOf("--built");
let freshDir;
let cleanup = false;
if (builtArg !== -1) {
  freshDir = process.argv[builtArg + 1];
  if (!freshDir) {
    console.error("check:bundle: --built needs a directory");
    process.exit(1);
  }
} else {
  freshDir = await buildFresh();
  cleanup = true;
}

const errors = [];
try {
  const fresh = listFiles(freshDir);
  const committed = listFiles(committedDir);

  // 1. Bundle matches source.
  for (const [path, f] of fresh) {
    const c = committed.get(path);
    if (!c) errors.push(`missing in committed bundle: ${path}`);
    else if (c.sha256 !== f.sha256)
      errors.push(`content differs: ${path} (committed ${c.size} B, fresh ${f.size} B)`);
  }
  for (const path of committed.keys()) {
    if (!fresh.has(path)) errors.push(`stale file in committed bundle (not built from source): ${path}`);
  }
  if (errors.length > 0) {
    errors.push(
      "committed rapidtriage/web/static/v2 is stale — the coordinator rebuilds it with `npm run build` and commits it (D57).",
    );
  }

  // 2. Size budget (measured on the fresh build).
  const totals = { js: 0, css: 0, font: 0 };
  for (const [path, f] of fresh) {
    const kind = KIND[extname(path)];
    if (kind) totals[kind] += f.size;
  }
  for (const kind of Object.keys(BUDGET)) {
    const line = `${kind.padEnd(4)} ${totals[kind].toLocaleString("en-US").padStart(10)} B / budget ${BUDGET[kind].toLocaleString("en-US")} B`;
    if (totals[kind] > BUDGET[kind]) errors.push(`over budget: ${line}`);
    else console.log(`check:bundle: ${line}`);
  }
} finally {
  if (cleanup) rmSync(freshDir, { recursive: true, force: true });
}

if (errors.length > 0) {
  for (const e of errors) console.error(`check:bundle: FAIL ${e}`);
  process.exit(1);
}
console.log("check:bundle: OK — committed bundle matches source and is within budget");
