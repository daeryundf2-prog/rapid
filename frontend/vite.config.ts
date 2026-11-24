import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

const here = fileURLToPath(new URL(".", import.meta.url));

/**
 * Inputs of the shipped console (D16 #10): everything under src/ except tests and the generated
 * schema type declarations (types only, no runtime code), plus the page, the build config and the
 * dependency pins. Keep aligned with tests/test_d16_time.py `console_source_digest`, which fails
 * when the committed bundle in rapidtriage/web/static/v2 was not rebuilt from these files.
 */
function sourceFiles(): string[] {
  const files = readdirSync(join(here, "src"), { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && !entry.name.startsWith("."))
    .map((entry) => relative(here, join(entry.parentPath, entry.name)).split(sep).join("/"))
    .filter(
      (path) =>
        !path.startsWith("src/schemas/") && !/\.test\.tsx?$/.test(path) && path !== "src/testSetup.ts",
    );
  return [...files, "index.html", "vite.config.ts", "package.json", "package-lock.json"].sort();
}

/** sha256 over `path NUL sha256(bytes) LF` of every source file, sorted by path. */
function consoleSourceDigest(): string {
  const digest = createHash("sha256");
  for (const path of sourceFiles()) {
    const content = createHash("sha256")
      .update(readFileSync(join(here, path)))
      .digest("hex");
    digest.update(`${path}\0${content}\n`);
  }
  return digest.digest("hex");
}

/** `<meta name="rapidtriage-console-source">` in the built page: the source the bundle came from. */
function consoleSourceStamp(): Plugin {
  return {
    name: "rapidtriage-console-source",
    apply: "build",
    transformIndexHtml: () => [
      {
        tag: "meta",
        attrs: { name: "rapidtriage-console-source", content: `sha256:${consoleSourceDigest()}` },
        injectTo: "head",
      },
    ],
  };
}

export default defineConfig({
  plugins: [react(), consoleSourceStamp()],
  base: "/v2/",
  build: {
    outDir: "../rapidtriage/web/static/v2",
    emptyOutDir: true,
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
  },
});
