import { describe, expect, test, vi } from "vitest";

import { Role, Suite, type ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { AllowPlaintextForLoopback } from "../client-connect/transportSecurity.js";
import { base64urlEncode } from "../utils/base64url.js";
import type { WebSocketLike } from "../ws-client/binaryTransport.js";
import { connectTunnel } from "./index.js";

class FakeWebSocket implements WebSocketLike {
  binaryType = "arraybuffer";
  readyState = 0;
  bufferedAmount = 0;
  readonly sent: Array<string | ArrayBuffer | Uint8Array> = [];
  closed = false;
  closeWhenOpenListenerIsAdded = false;
  private readonly listeners = new Map<string, Set<(event: unknown) => void>>();

  send(data: string | ArrayBuffer | Uint8Array): void {
    this.sent.push(data);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 3;
    this.emit("close", {});
  }

  addEventListener(type: "open" | "message" | "error" | "close", listener: (event: unknown) => void): void {
    const listeners = this.listeners.get(type) ?? new Set();
    listeners.add(listener);
    this.listeners.set(type, listeners);
    if (type === "open" && this.closeWhenOpenListenerIsAdded) this.readyState = 3;
  }

  removeEventListener(type: "open" | "message" | "error" | "close", listener: (event: unknown) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  openThen(runAfterOpen: () => void): void {
    this.readyState = 1;
    this.emit("open", {});
    runAfterOpen();
  }

  listenerCount(): number {
    let count = 0;
    for (const listeners of this.listeners.values()) count += listeners.size;
    return count;
  }

  private emit(type: string, event: unknown): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

describe("endpoint tunnel cancellation", () => {
  test.each([
    ["missing", "   ", "missing_channel_id"],
    ["too long", "x".repeat(257), "invalid_input"],
  ])("rejects %s channel_id before creating a websocket", async (_name, channelId, code) => {
    const grant = makeGrant();
    grant.channel_id = channelId;
    const wsFactory = vi.fn<() => WebSocketLike>();

    await expect(connectTunnel(grant, {
      origin: "http://127.0.0.1",
      wsFactory,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    })).rejects.toMatchObject({ path: "tunnel", stage: "validate", code });
    expect(wsFactory).not.toHaveBeenCalled();
  });

  test("rejects an invalid PSK before policy evaluation or websocket creation", async () => {
    const grant = makeGrant();
    grant.e2ee_psk_b64u = "invalid-psk";
    const transportSecurityPolicy = vi.fn(() => true);
    const wsFactory = vi.fn<() => WebSocketLike>();

    await expect(connectTunnel(grant, {
      origin: "http://127.0.0.1",
      wsFactory,
      transportSecurityPolicy,
    })).rejects.toMatchObject({
      path: "tunnel",
      stage: "validate",
      code: "invalid_psk",
    });

    expect(transportSecurityPolicy).not.toHaveBeenCalled();
    expect(wsFactory).not.toHaveBeenCalled();
  });

  test.each([
    ["connectTimeoutMs", { connectTimeoutMs: -1 }],
    ["handshakeTimeoutMs", { handshakeTimeoutMs: Number.NaN }],
  ])("rejects invalid %s before policy evaluation or websocket creation", async (_name, timeoutOptions) => {
    const transportSecurityPolicy = vi.fn(() => true);
    const wsFactory = vi.fn<() => WebSocketLike>();

    await expect(connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      wsFactory,
      transportSecurityPolicy,
      ...timeoutOptions,
    })).rejects.toMatchObject({
      path: "tunnel",
      stage: "validate",
      code: "invalid_option",
    });

    expect(transportSecurityPolicy).not.toHaveBeenCalled();
    expect(wsFactory).not.toHaveBeenCalled();
  });

  test("uses one normalized channel_id for attach and handshake", async () => {
    const grant = makeGrant();
    grant.channel_id = "  endpoint-cancel-test  ";
    const websocket = new FakeWebSocket();
    const connecting = connectTunnel(grant, {
      origin: "http://127.0.0.1",
      wsFactory: () => websocket,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    });
    await waitFor(() => websocket.listenerCount() > 3);

    websocket.openThen(() => {});
    await waitFor(() => websocket.sent.length === 1);
    const attach = JSON.parse(String(websocket.sent[0])) as { channel_id?: string };
    expect(attach.channel_id).toBe("endpoint-cancel-test");
    websocket.close();
    await expect(connecting).rejects.toMatchObject({ path: "tunnel" });
  });

  test("does not create a websocket when already canceled", async () => {
    const controller = new AbortController();
    controller.abort();
    const wsFactory = vi.fn<() => WebSocketLike>();

    await expect(connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      signal: controller.signal,
      wsFactory,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    })).rejects.toMatchObject({
      path: "tunnel",
      stage: "connect",
      code: "canceled",
    });
    expect(wsFactory).not.toHaveBeenCalled();
  });

  test("does not send the attach token when canceled as the websocket opens", async () => {
    const controller = new AbortController();
    const websocket = new FakeWebSocket();
    const connecting = connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      signal: controller.signal,
      wsFactory: () => websocket,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    });
    await waitFor(() => websocket.listenerCount() > 3);

    websocket.openThen(() => controller.abort());

    await expect(connecting).rejects.toMatchObject({
      path: "tunnel",
      stage: "connect",
      code: "canceled",
    });
    expect(websocket.sent).toEqual([]);
    expect(websocket.closed).toBe(true);
  });

  test("reports cancellation during the post-attach handshake", async () => {
    const controller = new AbortController();
    const websocket = new FakeWebSocket();
    const connecting = connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      signal: controller.signal,
      wsFactory: () => websocket,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    });
    await waitFor(() => websocket.listenerCount() > 3);

    websocket.openThen(() => {});
    await waitFor(() => websocket.sent.length === 1);
    controller.abort();

    await expect(connecting).rejects.toMatchObject({
      path: "tunnel",
      stage: "handshake",
      code: "canceled",
    });
    expect(websocket.closed).toBe(true);
  });

  test("reports timeout during the post-attach handshake", async () => {
    const websocket = new FakeWebSocket();
    const connecting = connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      handshakeTimeoutMs: 10,
      wsFactory: () => websocket,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    });
    await waitFor(() => websocket.listenerCount() > 3);

    websocket.openThen(() => {});
    await waitFor(() => websocket.sent.length === 1);

    await expect(connecting).rejects.toMatchObject({
      path: "tunnel",
      stage: "handshake",
      code: "timeout",
    });
    expect(websocket.closed).toBe(true);
  });

  test("reports an unopened websocket as a connect timeout", async () => {
    const websocket = new FakeWebSocket();

    await expect(connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      connectTimeoutMs: 5,
      wsFactory: () => websocket,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    })).rejects.toMatchObject({
      path: "tunnel",
      stage: "connect",
      code: "timeout",
    });

    expect(websocket.sent).toEqual([]);
    expect(websocket.closed).toBe(true);
  });

  test("observes a closed state that occurs while open listeners are installed", async () => {
    const websocket = new FakeWebSocket();
    websocket.closeWhenOpenListenerIsAdded = true;

    await expect(connectTunnel(makeGrant(), {
      origin: "http://127.0.0.1",
      wsFactory: () => websocket,
      transportSecurityPolicy: AllowPlaintextForLoopback,
    })).rejects.toMatchObject({
      path: "tunnel",
      stage: "connect",
      code: "dial_failed",
    });
    expect(websocket.sent).toEqual([]);
    expect(websocket.closed).toBe(true);
  });
});

function makeGrant(): ChannelInitGrant {
  return {
    tunnel_url: "ws://127.0.0.1/flowersec",
    channel_id: "endpoint-cancel-test",
    channel_init_expire_at_unix_s: Math.floor(Date.now() / 1000) + 60,
    idle_timeout_seconds: 60,
    role: Role.Role_server,
    token: "one-time-secret-token",
    e2ee_psk_b64u: base64urlEncode(new Uint8Array(32).fill(7)),
    allowed_suites: [Suite.Suite_X25519_HKDF_SHA256_AES_256_GCM],
    default_suite: Suite.Suite_X25519_HKDF_SHA256_AES_256_GCM,
  };
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for endpoint connect state");
}
