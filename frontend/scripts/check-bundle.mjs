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
// Budget is a ratchet: limits may only be lowered when the bundle shrinks. Exit 0 = match + within
// budget, 1 = failure.
//
// Since T-116 (code splitting) the bundle is many chunks: the entry chunk, the chunks it imports
// statically (index.html `modulepreload` links) and lazy chunks fetched when a screen first opens
// (`src/app/lazyViews.ts`, `components/LazyView.tsx`). "Initial JS" = the entry script + every
// modulepreload chunk of index.html = the JS the first screen downloads; it has its own budget,
// next to the total over every chunk. "Data" = JSON assets fetched at run time (the families
// fallback catalogue, `features/flags/catalog.ts`).
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const frontendRoot = join(here, "..");
const committedDir = join(frontendRoot, "..", "rapidtriage", "web", "static", "v2");

// Ratchet history:
// 2026-11-12 (feat/r6-ux 7790624): JS 1,879,137 B single chunk, CSS 150,268 B, fonts 269,432 B.
// 2026-11-12 after WB-5/WB-6: JS 1,916,766 B, CSS 153,462 B -> JS limit 1,945,518 B (+1.5%).
// 2026-11-14 T-116 (wb12/t-116 on 9ca9e5d), code splitting. Before: one 1,936,205 B JS chunk
//   (the first screen loaded all of it, the families fallback catalogue included).
//   After: initial JS 897,583 B (entry 696 B + `app` 896,171 B + runtime 716 B), total JS
//   1,703,601 B in 39 chunks, families fallback catalogue 279,550 B as a JSON asset (fetched only
//   when the server has no catalogue), CSS 153,867 B (one file, same rules and order), fonts
//   269,432 B.
// Limits: initial JS 1,000,000 B (the T-116 acceptance line, 1.0 MB); total JS and data =
// T-116 baseline + 2% (total JS 1,738,000 B is below the earlier 1,945,518 B); CSS and fonts keep
// their limits.
const BUDGET = {
  initialJs: 1_000_000,
  js: 1_738_000,
  data: 285_200,
  css: 155_764,
  font: 274_821,
};

const LABEL = { initialJs: "initial js", js: "js (all)", data: "data", css: "css", font: "font" };
const KIND = {
  ".js": "js",
  ".json": "data",
  ".css": "css",
  ".woff2": "font",
  ".woff": "font",
  ".ttf": "font",
};

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

/**
 * The JS the first screen loads: index.html's module entry script plus its `modulepreload` links
 * (Vite lists every chunk the entry imports statically there), as bundle-relative paths.
 */
function initialScripts(dir) {
  const html = readFileSync(join(dir, "index.html"), "utf8");
  const out = new Set();
  const tag = /<(script|link)\b[^>]*>/g;
  for (const [element, name] of html.matchAll(tag)) {
    const attr = (key) => element.match(new RegExp(`\\s${key}="([^"]*)"`))?.[1];
    const url =
      name === "script"
        ? attr("type") === "module" && attr("src")
        : attr("rel") === "modulepreload" && attr("href");
    if (!url || !url.endsWith(".js")) continue;
    // "/v2/assets/x.js" (vite base "/v2/") -> "assets/x.js"
    out.add(url.replace(/^\/v2\//, "").replace(/^\.?\//, ""));
  }
  return [...out];
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
  const totals = { initialJs: 0, js: 0, data: 0, css: 0, font: 0 };
  let jsChunks = 0;
  for (const [path, f] of fresh) {
    const kind = KIND[extname(path)];
    if (kind) totals[kind] += f.size;
    if (kind === "js") jsChunks++;
  }
  const initial = initialScripts(freshDir);
  if (initial.length === 0) errors.push("index.html names no entry script (cannot measure initial JS)");
  for (const path of initial) {
    const f = fresh.get(path);
    if (!f) errors.push(`index.html names a script missing from the build: ${path}`);
    else totals.initialJs += f.size;
  }
  console.log(`check:bundle: ${jsChunks} JS chunks, ${initial.length} loaded by the first screen`);
  for (const kind of Object.keys(BUDGET)) {
    const line = `${LABEL[kind].padEnd(10)} ${totals[kind].toLocaleString("en-US").padStart(10)} B / budget ${BUDGET[kind].toLocaleString("en-US")} B`;
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
