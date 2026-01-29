import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

describe("docs/API_SURFACE.md", () => {
  it("mentions stable TypeScript entrypoints", () => {
    const docPath = path.join(process.cwd(), "..", "docs", "API_SURFACE.md");
    const doc = fs.readFileSync(docPath, "utf8");

    expect(doc).toContain("## TypeScript: stable exports");

    expect(doc).toContain("`@floegence/flowersec-core`");
    expect(doc).toContain("`connect(...)`");
    expect(doc).toContain("`connectTunnel(...)`");
    expect(doc).toContain("`connectDirect(...)`");

    expect(doc).toContain("`@floegence/flowersec-core/node`");
    expect(doc).toContain("`connectNode(...)`");
    expect(doc).toContain("`connectTunnelNode(...)`");
    expect(doc).toContain("`connectDirectNode(...)`");

    expect(doc).toContain("`@floegence/flowersec-core/browser`");
    expect(doc).toContain("`connectBrowser(...)`");
    expect(doc).toContain("`connectTunnelBrowser(...)`");
    expect(doc).toContain("`connectDirectBrowser(...)`");

    expect(doc).toContain("`@floegence/flowersec-core/proxy`");
  });
});
