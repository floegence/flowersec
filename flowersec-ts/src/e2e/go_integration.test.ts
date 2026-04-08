import { createRequire } from "node:module";
import { spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { createDemoSession, connectDemoTunnel } from "../_examples/flowersec/demo/v1.facade.gen.js";
import type { ConnectArtifact } from "../connect/artifact.js";
import { requestConnectArtifact, requestEntryConnectArtifact } from "../controlplane/index.js";
import { connect, connectTunnel } from "../facade.js";
import { connectNode, createNodeReconnectConfig } from "../node/index.js";
import { extractProxyRuntimeScopeV1 } from "../proxy/runtimeScope.js";

import { createLineReader, readJsonLine } from "./interopUtils.js";

const require = createRequire(import.meta.url);
const WS = require("ws");

type HarnessReady = Readonly<{
  ws_url: string;
  grant_client: unknown;
  controlplane_base_url: string;
  entry_ticket: string;
}>;

describe("go<->ts integration", () => {
  test("ts client talks to go server endpoint through tunnel", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const sess = await connectDemoTunnel(ready.grant_client as any, {
        origin: "https://app.redeven.com",
        wsFactory: (url, origin) => new WS(url, { headers: { Origin: origin } }),
      });
      try {
        const notified = waitNotify(sess.demo, 2000);
        await expect(sess.demo.ping({})).resolves.toEqual({ ok: true });
        await expect(notified).resolves.toEqual({ hello: "world" });
      } finally {
        sess.close();
      }
    });
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

  test("artifact-first connectNode path talks to the Go tunnel harness", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const artifact: ConnectArtifact = {
        v: 1,
        transport: "tunnel",
        tunnel_grant: ready.grant_client as any,
      };

      const client = await connectNode(artifact, {
        origin: "https://app.redeven.com",
      });
      const sess = createDemoSession(client);
      try {
        const notified = waitNotify(sess.demo, 2000);
        await expect(sess.demo.ping({})).resolves.toEqual({ ok: true });
        await expect(notified).resolves.toEqual({ hello: "world" });
      } finally {
        sess.close();
      }
    });
  });

  test("artifact-first connect() auto path talks to the Go tunnel harness", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const artifact: ConnectArtifact = {
        v: 1,
        transport: "tunnel",
        tunnel_grant: ready.grant_client as any,
      };

      const client = await connect(artifact, {
        origin: "https://app.redeven.com",
        wsFactory: (url, origin) => new WS(url, { headers: { Origin: origin } }),
      });
      const sess = createDemoSession(client);
      try {
        const notified = waitNotify(sess.demo, 2000);
        await expect(sess.demo.ping({})).resolves.toEqual({ ok: true });
        await expect(notified).resolves.toEqual({ hello: "world" });
      } finally {
        sess.close();
      }
    });
  });

  test("ts controlplane helper fetches a Go-issued artifact and connectNode uses it", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const artifact = await requestConnectArtifact({
        baseUrl: ready.controlplane_base_url,
        endpointId: "server-1",
        correlation: { traceId: "trace-go-helper-1" },
      });

      expect(artifact.transport).toBe("tunnel");
      expect(artifact.correlation?.trace_id).toBe("trace-go-helper-1");
      expect(artifact.correlation?.session_id).toMatch(/^session-/);

      const client = await connectNode(artifact, { origin: "https://app.redeven.com" });
      const sess = createDemoSession(client);
      try {
        await expect(sess.demo.ping({})).resolves.toEqual({ ok: true });
      } finally {
        sess.close();
      }
    });
  });

  test("ts entry controlplane helper talks to Go /entry handler", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const artifact = await requestEntryConnectArtifact({
        baseUrl: ready.controlplane_base_url,
        endpointId: "server-1",
        entryTicket: ready.entry_ticket,
      });

      const client = await connectNode(artifact, { origin: "https://app.redeven.com" });
      const sess = createDemoSession(client);
      try {
        await expect(sess.demo.ping({})).resolves.toEqual({ ok: true });
      } finally {
        sess.close();
      }
    });
  });

  test("node reconnect config fetches fresh artifacts from Go controlplane/http", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const reconnectConfig = createNodeReconnectConfig({
        artifactControlplane: {
          baseUrl: ready.controlplane_base_url,
          endpointId: "server-1",
        },
        connect: {
          origin: "https://app.redeven.com",
        },
      });

      const client1 = await reconnectConfig.connectOnce({ signal: new AbortController().signal, observer: {} });
      const sess1 = createDemoSession(client1);
      try {
        await expect(sess1.demo.ping({})).resolves.toEqual({ ok: true });
      } finally {
        sess1.close();
      }

      const client2 = await reconnectConfig.connectOnce({ signal: new AbortController().signal, observer: {} });
      const sess2 = createDemoSession(client2);
      try {
        await expect(sess2.demo.ping({})).resolves.toEqual({ ok: true });
      } finally {
        sess2.close();
      }
    });
  });

  test("proxy.runtime service_worker and controller_bridge payloads round-trip from Go to TS", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const serviceWorkerArtifact = await requestConnectArtifact({
        baseUrl: ready.controlplane_base_url,
        endpointId: "server-1",
        payload: {
          proxy_mode: "service_worker",
          service_worker_script_url: "/proxy-sw.js",
          service_worker_scope: "/",
        },
      });
      const serviceWorkerScope = extractProxyRuntimeScopeV1(serviceWorkerArtifact, "service_worker");
      expect(serviceWorkerScope.serviceWorker).toEqual({ scriptUrl: "/proxy-sw.js", scope: "/" });

      const controllerArtifact = await requestConnectArtifact({
        baseUrl: ready.controlplane_base_url,
        endpointId: "server-1",
        payload: {
          proxy_mode: "controller_bridge",
          allowed_origin: "https://app.redeven.com",
        },
      });
      const controllerScope = extractProxyRuntimeScopeV1(controllerArtifact, "controller_bridge");
      expect(controllerScope.controllerBridge.allowedOrigins).toEqual(["https://app.redeven.com"]);
    });
  });

  test("stable proxy helpers refuse Go-issued experimental proxy.runtime@2 regardless of critical flag", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const criticalArtifact = await requestConnectArtifact({
        baseUrl: ready.controlplane_base_url,
        endpointId: "server-1",
        payload: {
          proxy_mode: "service_worker",
          scope_version: 2,
          critical: true,
        },
      });
      expect(() => extractProxyRuntimeScopeV1(criticalArtifact, "service_worker")).toThrow(
        "unsupported proxy.runtime scope_version: 2"
      );

      const optionalArtifact = await requestConnectArtifact({
        baseUrl: ready.controlplane_base_url,
        endpointId: "server-1",
        payload: {
          proxy_mode: "service_worker",
          scope_version: 2,
          critical: false,
        },
      });
      expect(() => extractProxyRuntimeScopeV1(optionalArtifact, "service_worker")).toThrow(
        "unsupported proxy.runtime scope_version: 2"
      );
    });
  });

  test("go strict decoder rejects unknown request fields with the stable error envelope", { timeout: 60000 }, async () => {
    await withGoHarness(async (ready) => {
      const response = await fetch(new URL("/v1/connect/artifact", ready.controlplane_base_url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          endpoint_id: "server-1",
          unknown: true,
        }),
      });
      const body = (await response.json()) as { error?: { code?: string; message?: string } };
      expect(response.status).toBe(400);
      expect(body.error?.code).toBe("invalid_request");
      expect(body.error?.message).toContain("unknown request field");
    });
  });
});

async function withGoHarness(task: (ready: HarnessReady) => Promise<void>): Promise<void> {
  const goCwd = path.join(process.cwd(), "..", "flowersec-go");
  const proc = spawn("go", ["run", "./internal/cmd/flowersec-e2e-harness"], {
    cwd: goCwd,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const reader = createLineReader(proc.stdout);
  const ready = await readJsonLine<HarnessReady>(reader, 20000);

  try {
    await task(ready);
  } finally {
    proc.kill("SIGTERM");
    await once(proc, "exit");
  }
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
