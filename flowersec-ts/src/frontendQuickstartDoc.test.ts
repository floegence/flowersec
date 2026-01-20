import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("docs/FRONTEND_QUICKSTART.md", () => {
  it("exists and references stable entrypoints", () => {
    const docPath = path.join(process.cwd(), "..", "docs", "FRONTEND_QUICKSTART.md");
    const doc = fs.readFileSync(docPath, "utf8");

    expect(doc).toContain("docs/INTEGRATION_GUIDE.md");
    expect(doc).toContain("node ./examples/ts/dev-server.mjs");

    // Stable TypeScript entrypoints.
    expect(doc).toContain('from "@flowersec/core/browser"');
    expect(doc).toContain("connectBrowser");
    expect(doc).toContain('from "@flowersec/core/node"');
    expect(doc).toContain("connectNode");

    // Stable error code contract example (one-time tokens).
    expect(doc).toContain("token_replay");
  });
});

