import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
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
