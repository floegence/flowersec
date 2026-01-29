import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("docs/PROXY.md", () => {
  it("documents the stable proxy stream kinds and v1 meta fields", () => {
    const docPath = path.join(process.cwd(), "..", "docs", "PROXY.md");
    const doc = fs.readFileSync(docPath, "utf8");

    expect(doc).toContain("flowersec-proxy/http1");
    expect(doc).toContain("flowersec-proxy/ws");

    // v1 meta fields we rely on cross-language.
    expect(doc).toContain("\"v\": 1");
    expect(doc).toContain("\"request_id\"");
    expect(doc).toContain("\"timeout_ms\"");
    expect(doc).toContain("\"conn_id\"");
    expect(doc).toContain("\"sec-websocket-protocol\"");
  });
});

