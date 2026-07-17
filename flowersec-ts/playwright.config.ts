import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser-e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  use: {
    browserName: "chromium",
    headless: true,
  },
});
