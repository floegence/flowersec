import { defineConfig } from "@playwright/test";

const externalParityTitle = "Chromium runs the WebSocket client profile";
const externalParityRequested = process.env.FLOWERSEC_PARITY_READY_BASE64 !== undefined ||
  process.argv.some((argument) => argument.includes(externalParityTitle));
const chromiumTests = externalParityRequested
  ? /(Chromium (runs|WebTransport)|Portable browsers run)/
  : /(Chromium (?!runs the WebSocket client profile)(runs|WebTransport)|Portable browsers run)/;

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
      grep: chromiumTests,
      use: {
        browserName: "chromium",
        channel: "chromium",
      },
    },
    {
      name: "firefox-compat",
      grep: /(Firefox reports|Portable browsers run)/,
      use: { browserName: "firefox" },
    },
    {
      name: "webkit-smoke",
      grep: /(WebKit reports|Portable browsers run)/,
      use: { browserName: "webkit" },
    },
  ],
});
