import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { ensureBuiltDist, getFreePort, startDevServer } from "./e2e/demoTestUtils.js";

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

  it("serves artifact bootstrap endpoints and browser demo pages", { timeout: 180000 }, async () => {
    ensureBuiltDist();

    const port = await getFreePort();
    const origin = `http://127.0.0.1:${port}`;
    const devServer = await startDevServer(port, origin);

    try {
      expect(devServer.ready.status).toBe("ready");
      expect(devServer.ready.origin).toBe(origin);
      expect(devServer.ready.browser_tunnel_url).toBe(`${origin}/examples/ts/browser-tunnel/`);
      expect(devServer.ready.browser_direct_url).toBe(`${origin}/examples/ts/browser-direct/`);
      expect(devServer.ready.browser_proxy_sandbox_url).toBe(`${origin}/examples/ts/proxy-sandbox/`);
      expect(devServer.ready.controlplane_http_url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);

      const statusResp = await fetch(`${origin}/__demo/status`);
      expect(statusResp.ok).toBe(true);
      const statusBody = (await statusResp.json()) as { status?: string; controlplane?: unknown; direct?: unknown };
      expect(statusBody.status).toBe("ready");
      expect(statusBody.controlplane).toBeTruthy();
      expect(statusBody.direct).toBeTruthy();

      const tunnelArtifactResp = await fetch(`${origin}/__demo/connect/artifact`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ endpoint_id: "server-1" }),
      });
      expect(tunnelArtifactResp.ok).toBe(true);
      const tunnelArtifactBody = (await tunnelArtifactResp.json()) as { connect_artifact?: { transport?: string } };
      expect(tunnelArtifactBody.connect_artifact?.transport).toBe("tunnel");

      const proxyArtifactResp = await fetch(`${origin}/__demo/proxy/artifact`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ endpoint_id: "server-1" }),
      });
      expect(proxyArtifactResp.ok).toBe(true);
      const proxyArtifactBody = (await proxyArtifactResp.json()) as {
        connect_artifact?: { scoped?: Array<{ scope?: string; payload?: { mode?: string } }> };
      };
      const runtimeScope = proxyArtifactBody.connect_artifact?.scoped?.find((entry) => entry.scope === "proxy.runtime");
      expect(runtimeScope?.payload?.mode).toBe("service_worker");

      const directInfoResp = await fetch(`${origin}/__demo/direct/info`);
      expect(directInfoResp.ok).toBe(true);
      const directInfoBody = (await directInfoResp.json()) as { ws_url?: string; channel_id?: string };
      expect(directInfoBody.ws_url).toMatch(/^ws:\/\/127\.0\.0\.1:\d+\/ws$/);
      expect(directInfoBody.channel_id).toBeTruthy();

      const directArtifactResp = await fetch(`${origin}/__demo/direct/artifact`);
      expect(directArtifactResp.ok).toBe(true);
      const directArtifactBody = (await directArtifactResp.json()) as {
        connect_artifact?: { transport?: string; direct_info?: { ws_url?: string } };
      };
      expect(directArtifactBody.connect_artifact?.transport).toBe("direct");
      expect(directArtifactBody.connect_artifact?.direct_info?.ws_url).toBe(directInfoBody.ws_url);

      const tunnelPage = await (await fetch(`${origin}/examples/ts/browser-tunnel/`)).text();
      expect(tunnelPage).toContain("Fetch Artifact");
      expect(tunnelPage).toContain("connectBrowser");

      const directPage = await (await fetch(`${origin}/examples/ts/browser-direct/`)).text();
      expect(directPage).toContain("Fetch Artifact");
      expect(directPage).toContain("connectBrowser");

      const proxyPage = await (await fetch(`${origin}/examples/ts/proxy-sandbox/`)).text();
      expect(proxyPage).toContain("connectArtifactProxyBrowser");
      expect(proxyPage).toContain("proxy.runtime");
    } finally {
      await devServer.stop();
    }
  });
});
