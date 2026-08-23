import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { chromium, firefox, webkit } from "@playwright/test";

const requested = process.argv.slice(2);
const browserNames = requested.length === 0 ? ["chromium"] : requested;
const browsers = { chromium, firefox, webkit };
for (const name of browserNames) {
  if (!(name in browsers)) throw new Error(`unsupported Playwright browser: ${name}`);
}

const executable = (name) => browsers[name].executablePath();
const isExecutable = (file) => {
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
};
const missing = browserNames.filter((name) => !isExecutable(executable(name)));

if (missing.length > 0) {
  if (process.getuid?.() === 0) {
    throw new Error(`Playwright ${missing.join(", ")} is not authenticated; provision root browser archives with scripts/test-host-init.sh`);
  }
  const downloadHost = process.env.PLAYWRIGHT_DOWNLOAD_HOST ?? "https://npmmirror.com/mirrors/playwright";
  const downloadTimeout = process.env.PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT ?? "120000";
  const env = {
    ...process.env,
    PLAYWRIGHT_DOWNLOAD_HOST: downloadHost,
    PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT: downloadTimeout,
  };
  try {
    execFileSync(process.execPath, ["./node_modules/playwright/cli.js", "install", ...missing], {
      cwd: new URL("..", import.meta.url),
      stdio: "inherit",
      env,
    });
  } catch (error) {
    throw new Error(`Playwright ${missing.join(", ")} download failed from ${downloadHost} (timeout ${downloadTimeout}ms)`, { cause: error });
  }
}

for (const name of browserNames) {
  if (!isExecutable(executable(name))) {
    throw new Error(`Playwright ${name} executable is unavailable at ${path.resolve(executable(name))}`);
  }
}
