import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("package exports", () => {
  it("resolves stable subpath exports from packed tarball", () => {
    expect(() =>
      execFileSync(process.execPath, ["./scripts/verify-package-exports.mjs"], {
        cwd: pkgRoot,
        stdio: "pipe",
      })
    ).not.toThrow();
  });
});
