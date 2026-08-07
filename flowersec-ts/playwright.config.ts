import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./browser-e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  use: {
    headless: true,
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: "chromium",
      grep: /Chromium (runs|WebTransport)/,
      use: {
        browserName: "chromium",
        channel: "chromium",
      },
    },
    {
      name: "firefox-compat",
      grep: /Firefox reports/,
      use: { browserName: "firefox" },
    },
    {
      name: "webkit-smoke",
      grep: /WebKit reports/,
      use: { browserName: "webkit" },
    },
  ],
});
