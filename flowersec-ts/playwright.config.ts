import { defineConfig } from "@playwright/test";

const externalParityTitle = "Chromium runs the WebSocket client profile";
const externalParityRequested = process.env.FLOWERSEC_PARITY_READY_BASE64 !== undefined ||
  process.argv.some((argument) => argument.includes(externalParityTitle));
const chromiumTests = externalParityRequested
  ? /(Chromium (runs|WebTransport)|Portable browsers run)/
  : /(Chromium (?!runs the WebSocket client profile)(runs|WebTransport)|Portable browsers run)/;
const publicCAHost = process.env.FLOWERSEC_BROWSER_PUBLIC_CA_HOST;
if (publicCAHost !== undefined && !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(publicCAHost)) {
  throw new Error("FLOWERSEC_BROWSER_PUBLIC_CA_HOST must be a canonical DNS hostname");
}

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
        launchOptions: publicCAHost === undefined ? undefined : {
          args: [
            "--proxy-server=direct://",
            "--proxy-bypass-list=*",
            `--host-resolver-rules=MAP ${publicCAHost} 127.0.0.1`,
          ],
        },
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
