import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 90_000,
  retries: process.env.CI ? 1 : 0,
  webServer: {
    command: "node start-server.mjs",
    url: "http://127.0.0.1:8791/v2/",
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
  use: {
    baseURL: "http://127.0.0.1:8791",
  },
});
