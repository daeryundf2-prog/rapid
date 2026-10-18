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
  },
});
