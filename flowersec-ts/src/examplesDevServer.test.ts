import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("examples/ts/dev-server.mjs", () => {
  it("--help is stable and does not require Go binaries", () => {
    const scriptPath = path.join(process.cwd(), "..", "examples", "ts", "dev-server.mjs");
    expect(fs.existsSync(scriptPath)).toBe(true);

    const out = execFileSync(process.execPath, [scriptPath, "--help"], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

    expect(out).toContain("Usage:");
    expect(out).toContain("node ./examples/ts/dev-server.mjs");
    expect(out).toContain("--no-direct");
    expect(out).toContain("--no-tunnel");
  });
});

