import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { connectDemoTunnel } from "../_examples/flowersec/demo/v1.facade.gen.js";
import { connectTunnel } from "../facade.js";

const require = createRequire(import.meta.url);
const WS = require("ws");

describe("go<->ts integration", () => {
  test("ts client talks to go server endpoint through tunnel", { timeout: 60000 }, async () => {
      const goCwd = path.join(process.cwd(), "..", "flowersec-go");
      const p = spawn("go", ["run", "./internal/cmd/flowersec-e2e-harness"], {
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

      const sess = await connectDemoTunnel(ready.grant_client, {
        origin: "https://app.redeven.com",
        wsFactory: (url, origin) => new WS(url, { headers: { Origin: origin } })
      });
      try {
        const notified = waitNotify(sess.demo, 2000);
        await expect(sess.demo.ping({})).resolves.toEqual({ ok: true });
        await expect(notified).resolves.toEqual({ hello: "world" });
      } finally {
        sess.close();
        p.kill("SIGTERM");
        await once(p, "exit");
      }
    });

  test("invalid tunnel grant is rejected before websocket dial", async () => {
      const wsFactory = () => {
        throw new Error("wsFactory should not be called for invalid grant");
      };

      const badGrant = {
        tunnel_url: "ws://example.invalid",
        channel_id: "contract_ts_integration",
        channel_init_expire_at_unix_s: Math.floor(Date.now() / 1000) + 120,
        idle_timeout_seconds: 60,
        role: 1,
        token: "tok",
        e2ee_psk_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        allowed_suites: [2],
        default_suite: 1,
      };

      await expect(connectTunnel(badGrant as any, { origin: "https://app.redeven.com", wsFactory })).rejects.toMatchObject({
        stage: "validate",
        code: "invalid_suite",
        path: "tunnel",
      });
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
