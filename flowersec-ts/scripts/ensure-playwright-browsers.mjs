import { execFileSync } from "node:child_process";
import fs from "node:fs";

import { chromium, webkit } from "@playwright/test";

const missing = [
  ["chromium", chromium.executablePath()],
  ["webkit", webkit.executablePath()],
].flatMap(([name, executable]) => fs.existsSync(executable) ? [] : [name]);

if (missing.length > 0) {
  execFileSync(process.execPath, ["./node_modules/playwright/cli.js", "install", ...missing], {
    cwd: new URL("..", import.meta.url),
    stdio: "inherit",
  });
}
