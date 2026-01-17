import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { connectTunnelClientRpc } from "../tunnel-client/connect.js";
import { createDemoClient } from "../gen/flowersec/demo/v1.rpc.gen.js";

const require = createRequire(import.meta.url);
const WS = require("ws");

describe("go<->ts integration", () => {
  test("ts client talks to go server endpoint through tunnel", { timeout: 60000 }, async () => {
      const goCwd = path.join(process.cwd(), "..", "go");
      const p = spawn("go", ["run", "./cmd/flowersec-e2e-harness"], {
        cwd: goCwd,
        stdio: ["ignore", "pipe", "pipe"]
      });

      let line = "";
      p.stdout.setEncoding("utf8");
      p.stdout.on("data", (d: string) => {
        line += d;
      });

      await waitForLine(() => line, 20000);
      const firstLine = line.split("\n")[0]!;
      const ready = JSON.parse(firstLine) as { grant_client: any };

      const client = await connectTunnelClientRpc(ready.grant_client, {
        origin: "https://app.redeven.com",
        wsFactory: (url, origin) => new WS(url, { headers: { Origin: origin } })
      });
      try {
        const demo = createDemoClient(client.rpcProxy);
        const notified = waitNotify(demo, 2000);
        await expect(demo.ping({})).resolves.toEqual({ ok: true });
        await expect(notified).resolves.toEqual({ hello: "world" });
      } finally {
        client.close();
        p.kill("SIGTERM");
        await once(p, "exit");
      }
    });
});

async function waitForLine(get: () => string, timeoutMs: number): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (get().includes("\n")) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("timeout waiting for harness output");
}

function waitNotify(demo: { onHello: (h: (payload: any) => void) => () => void }, timeoutMs: number) {
  return new Promise<any>((resolve, reject) => {
    let unsub = () => {};
    const t = setTimeout(() => {
      unsub();
      reject(new Error("timeout waiting for notification"));
    }, timeoutMs);
    t.unref?.();
    unsub = demo.onHello((payload) => {
      clearTimeout(t);
      unsub();
      resolve(payload);
    });
  });
}
