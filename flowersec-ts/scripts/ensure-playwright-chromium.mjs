import { execFileSync } from "node:child_process";
import fs from "node:fs";

import { chromium } from "@playwright/test";

const executable = chromium.executablePath();
if (!fs.existsSync(executable)) {
  execFileSync(process.execPath, ["./node_modules/playwright/cli.js", "install", "chromium"], {
    cwd: new URL("..", import.meta.url),
    stdio: "inherit",
  });
}
