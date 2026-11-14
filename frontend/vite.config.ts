import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

type ChunkingContext = { getModuleInfo(id: string): { importedIds: readonly string[] } | null };

const src = (path: string) => fileURLToPath(new URL(`./src/${path}`, import.meta.url));

/**
 * A Rolldown chunk group (T-116) holding every module reachable from `roots` by *static* imports.
 * Rolldown's automatic splitting gives each set of modules shared by a different set of lazy
 * screens a small chunk of its own (~80 chunks, ~30 loaded by the first screen), and every
 * cross-chunk import costs bytes and a request. Two groups undo that:
 *   app     — everything the entry (main.tsx) imports statically: the first screen loads the tiny
 *             entry + this one chunk (`npm run check:bundle` holds it to the 1.0 MB budget);
 *   explore — what opening a case loads together: the tree, the grid (ExploreGrid) and the viewer.
 * The lazy screens (`lazyView`, src/app/lazyViews.ts) stay automatic chunks importing from these.
 * Groups are applied in priority order, so a module the first screen needs stays in `app`.
 */
function staticGroup(name: string, roots: string[]) {
  let reachable: Set<string> | null = null;
  const norm = (id: string) => id.replaceAll("\\", "/");
  return (moduleId: string, ctx: ChunkingContext): string | null => {
    if (!reachable) {
      const seen = new Set<string>();
      const stack = [...roots];
      while (stack.length > 0) {
        const id = stack.pop() as string;
        if (seen.has(norm(id))) continue;
        seen.add(norm(id));
        for (const next of ctx.getModuleInfo(id)?.importedIds ?? []) stack.push(next);
      }
      reachable = seen;
    }
    return reachable.has(norm(moduleId)) ? name : null;
  };
}

/**
 * JSON assets (the families fallback catalogue, fetched by URL — `flags/catalog.ts`) are written
 * minified: the source file stays pretty-printed for review, the served copy carries no whitespace.
 */
const minifyJsonAssets: Plugin = {
  name: "rapidtriage-minify-json-assets",
  apply: "build",
  generateBundle(_options, bundle) {
    for (const file of Object.values(bundle)) {
      if (file.type !== "asset" || !file.fileName.endsWith(".json")) continue;
      const text = typeof file.source === "string" ? file.source : new TextDecoder().decode(file.source);
      file.source = JSON.stringify(JSON.parse(text));
    }
  },
};

export default defineConfig({
  plugins: [react(), minifyJsonAssets],
  base: "/v2/",
  build: {
    outDir: "../rapidtriage/web/static/v2",
    emptyOutDir: true,
    // The `app` chunk is ~0.9 MB by design; `npm run check:bundle` holds the first-screen JS to its
    // 1.0 MB budget, so Vite's generic 500 kB per-chunk warning is raised to match.
    chunkSizeWarningLimit: 1000,
    // One stylesheet as before T-116: lazy screens split only JS, so the cascade order (and the
    // CSS budget) is unchanged and no screen paints unstyled while its chunk loads.
    cssCodeSplit: false,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: staticGroup("app", [src("main.tsx")]), debugName: "app", priority: 2 },
            {
              name: staticGroup("explore", [
                src("app/ExploreGrid.tsx"),
                src("features/tree/EvidenceTree.tsx"),
                src("features/viewer/Viewer.tsx"),
              ]),
              debugName: "explore",
              priority: 1,
            },
          ],
        },
      },
    },
  },
  server: {
    port: 5174,
    proxy: {
      // RAPIDTRIAGE_API_PORT lets parallel worktrees run their own API (default 8710).
      "/api": `http://127.0.0.1:${process.env.RAPIDTRIAGE_API_PORT || "8710"}`,
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/testSetup.ts"],
    // T-154: child processes (not worker threads) so a stuck jsdom file cannot wedge the run and
    // every worker exits with the run. A fixed worker count (not cores - 1) caps CPU contention,
    // so per-file wall time and the timeouts below hold on a loaded machine too.
    pool: "forks",
    maxWorkers: 8,
    testTimeout: 10_000,
    hookTimeout: 10_000,
    teardownTimeout: 5_000,
  },
});
