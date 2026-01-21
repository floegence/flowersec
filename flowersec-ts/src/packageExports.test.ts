import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function hasBuildOutput(): boolean {
  return existsSync(path.join(pkgRoot, "dist", "facade.js"));
}

describe("package exports", () => {
  const run = hasBuildOutput() ? it : it.skip;
  run("resolves stable subpath exports (requires build output)", () => {
    const script = `
      import assert from "node:assert/strict";

      const core = await import("@floegence/flowersec-core");
      assert.equal(typeof core.connect, "function");
      assert.equal(typeof core.connectTunnel, "function");
      assert.equal(typeof core.connectDirect, "function");
      assert.equal(typeof core.FlowersecError, "function");
      assert.equal("RpcCallError" in core, false);

      const node = await import("@floegence/flowersec-core/node");
      assert.equal(typeof node.connectNode, "function");
      assert.equal(typeof node.connectTunnelNode, "function");
      assert.equal(typeof node.connectDirectNode, "function");
      assert.equal(typeof node.createNodeWsFactory, "function");

      const browser = await import("@floegence/flowersec-core/browser");
      assert.equal(typeof browser.connectBrowser, "function");
      assert.equal(typeof browser.connectTunnelBrowser, "function");
      assert.equal(typeof browser.connectDirectBrowser, "function");

      const rpc = await import("@floegence/flowersec-core/rpc");
      assert.equal(typeof rpc.RpcClient, "function");
      assert.equal(typeof rpc.RpcServer, "function");
      assert.equal(typeof rpc.RpcCallError, "function");
      assert.equal(typeof rpc.callTyped, "function");

      const yamux = await import("@floegence/flowersec-core/yamux");
      assert.equal(typeof yamux.YamuxSession, "function");
      assert.equal(typeof yamux.ByteReader, "function");

      const e2ee = await import("@floegence/flowersec-core/e2ee");
      assert.equal(typeof e2ee.clientHandshake, "function");
      assert.equal(typeof e2ee.SecureChannel, "function");

      const ws = await import("@floegence/flowersec-core/ws");
      assert.equal(typeof ws.WebSocketBinaryTransport, "function");

      const obs = await import("@floegence/flowersec-core/observability");
      assert.equal(typeof obs.normalizeObserver, "function");
      assert.equal(typeof obs.nowSeconds, "function");

      const sh = await import("@floegence/flowersec-core/streamhello");
      assert.equal(typeof sh.readStreamHello, "function");
      assert.equal(typeof sh.writeStreamHello, "function");

      const rpcGen = await import("@floegence/flowersec-core/gen/flowersec/rpc/v1.gen");
      assert.equal(typeof rpcGen.assertRpcError, "function");
    `;

    expect(() =>
      execFileSync(process.execPath, ["--input-type=module", "-"], {
        cwd: pkgRoot,
        input: script,
        stdio: "pipe",
      })
    ).not.toThrow();
  });
});
