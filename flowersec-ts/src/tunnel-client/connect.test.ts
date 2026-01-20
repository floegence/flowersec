import { beforeEach, describe, expect, test, vi } from "vitest";
import { base64urlEncode } from "../utils/base64url.js";
import { FlowersecError } from "../utils/errors.js";
import { E2EEHandshakeError } from "../e2ee/errors.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role, Suite } from "../gen/flowersec/controlplane/v1.gen.js";
import { WsCloseError } from "../ws-client/binaryTransport.js";

const mocks = vi.hoisted(() => {
  const clientHandshakeMock = vi.fn();
  const rpcClose = vi.fn();
  const muxClose = vi.fn();
  const openStream = vi.fn();

  class MockRpcClient {
    constructor(_readExactly: any, _write: any, _opts?: any) {}
    close() {
      rpcClose();
    }
  }

  class MockYamuxSession {
    constructor(_conn: any, _opts: any) {}
    async openStream() {
      return await openStream();
    }
    close() {
      muxClose();
    }
  }

  return {
    clientHandshakeMock,
    rpcClose,
    muxClose,
    openStream,
    MockRpcClient,
    MockYamuxSession
  };
});

const {
  clientHandshakeMock,
  rpcClose,
  muxClose,
  openStream
} = mocks;

vi.mock("../e2ee/handshake.js", () => ({
  clientHandshake: (...args: unknown[]) => mocks.clientHandshakeMock(...args)
}));

vi.mock("../rpc/client.js", () => ({ RpcClient: mocks.MockRpcClient }));

vi.mock("../yamux/session.js", () => ({ YamuxSession: mocks.MockYamuxSession }));

import { connectTunnel } from "./connect.js";

beforeEach(() => {
  vi.clearAllMocks();
});

class FakeWebSocket {
  binaryType = "arraybuffer";
  readyState = 1;
  closed = false;
  private readonly listeners = new Map<string, Set<(ev: any) => void>>();

  send(_data: string | ArrayBuffer | Uint8Array): void {}

  close(): void {
    this.closed = true;
    this.emit("close", {});
  }

  addEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void {
    const set = this.listeners.get(type) ?? new Set<(ev: any) => void>();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  emit(type: "open" | "message" | "error" | "close", ev: any): void {
    const set = this.listeners.get(type);
    if (set == null) return;
    for (const listener of set) listener(ev);
  }
}

function makeGrant(): ChannelInitGrant {
  const psk = base64urlEncode(new Uint8Array(32).fill(1));
  return {
    tunnel_url: "ws://example.invalid",
    channel_id: "ch_1",
    channel_init_expire_at_unix_s: Math.floor(Date.now() / 1000) + 120,
    idle_timeout_seconds: 60,
    role: Role.Role_client,
    token: "tok",
    e2ee_psk_b64u: psk,
    allowed_suites: [Suite.Suite_X25519_HKDF_SHA256_AES_256_GCM],
    default_suite: 1
  };
}

describe("connectTunnel", () => {
  test("wraps invalid grant payloads", async () => {
    const p = connectTunnel("bad" as any, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_input", path: "tunnel" });
  });

  test("rejects missing tunnel_url", async () => {
    const bad = makeGrant();
    bad.tunnel_url = "";
    const p = connectTunnel(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_tunnel_url", path: "tunnel" });
  });

  test("rejects missing channel_id", async () => {
    const bad = makeGrant();
    bad.channel_id = "";
    const p = connectTunnel(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_channel_id", path: "tunnel" });
  });

  test("rejects missing token", async () => {
    const bad = makeGrant();
    bad.token = "";
    const p = connectTunnel(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_token", path: "tunnel" });
  });

  test("rejects missing init exp", async () => {
    const bad = makeGrant();
    bad.channel_init_expire_at_unix_s = 0;
    const p = connectTunnel(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_init_exp", path: "tunnel" });
  });

  test("rejects invalid suite", async () => {
    const bad: any = makeGrant();
    bad.default_suite = 999;
    const p = connectTunnel(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_suite", path: "tunnel" });
  });

  test("rejects invalid psk length", async () => {
    const bad = makeGrant();
    bad.e2ee_psk_b64u = base64urlEncode(new Uint8Array(31).fill(1));
    const p = connectTunnel(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_psk", path: "tunnel" });
  });

  test("rejects invalid endpointInstanceId encoding", async () => {
    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      endpointInstanceId: "!!!"
    });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_endpoint_instance_id", path: "tunnel" });
  });

  test("rejects endpointInstanceId length out of range", async () => {
    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      endpointInstanceId: base64urlEncode(new Uint8Array(8).fill(1))
    });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_endpoint_instance_id", path: "tunnel" });
  });

  test("rejects non-client role grants", async () => {
    const bad = makeGrant();
    bad.role = Role.Role_server;
    const p = connectTunnel(bad, {
      origin: "https://app.redeven.com"
    });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "role_mismatch", path: "tunnel" });
  });

  test("rejects grant_server wrapper inputs with role mismatch", async () => {
    const bad = makeGrant();
    bad.role = Role.Role_server;
    const p = connectTunnel({ grant_server: bad } as any, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "role_mismatch", path: "tunnel" });
  });

  test("reports websocket error on connect", async () => {
    const ws = new FakeWebSocket();
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("error", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "connect", code: "dial_failed", path: "tunnel" });

    expect(observer.onConnect).toHaveBeenCalledWith("tunnel", "fail", "websocket_error", expect.any(Number));
  });

  test("maps tunnel attach rejection close reasons to stable attach codes", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockRejectedValueOnce(new WsCloseError(1008, "invalid_token"));
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "attach", code: "invalid_token", path: "tunnel" });
    expect(observer.onAttach).toHaveBeenCalledWith("fail", "invalid_token");
    expect(observer.onHandshake).not.toHaveBeenCalled();
  });

  test("does not lose tunnel attach close reasons when peer closes immediately after open", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockImplementationOnce(async (transport: any) => {
      await transport.readBinary();
      return {} as any;
    });
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      handshakeTimeoutMs: 30,
      observer
    });

    setTimeout(() => {
      ws.emit("open", {});
      ws.emit("close", { code: 1008, reason: "invalid_token" });
    }, 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "attach", code: "invalid_token", path: "tunnel" });
    expect(observer.onAttach).toHaveBeenCalledWith("fail", "invalid_token");
    expect(observer.onHandshake).not.toHaveBeenCalled();
  });

  test("reports connect timeout", async () => {
    const ws = new FakeWebSocket();
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      connectTimeoutMs: 30,
      observer
    });

    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "connect", code: "timeout", path: "tunnel" });
    expect(observer.onConnect).toHaveBeenCalledWith("tunnel", "fail", "timeout", expect.any(Number));
  });

  test("reports connect cancellation", async () => {
    const ws = new FakeWebSocket();
    const ac = new AbortController();
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      signal: ac.signal,
      observer
    });

    setTimeout(() => ac.abort(), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "connect", code: "canceled", path: "tunnel" });
    expect(observer.onConnect).toHaveBeenCalledWith("tunnel", "fail", "canceled", expect.any(Number));
  });

  test("reports attach send failures", async () => {
    const ws = new FakeWebSocket();
    ws.send = () => {
      throw new Error("send failed");
    };
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "attach", code: "attach_failed", path: "tunnel" });

    expect(observer.onAttach).toHaveBeenCalledWith("fail", "send_failed");
  });

  test("reports handshake failures", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockRejectedValueOnce(new Error("handshake failed"));
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "handshake", code: "handshake_failed", path: "tunnel" });

    expect(observer.onHandshake).toHaveBeenCalledWith("tunnel", "fail", "handshake_failed", expect.any(Number));
  });

  test("classifies handshake timestamp failures", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockRejectedValueOnce(new E2EEHandshakeError("timestamp_after_init_exp", "timestamp after init_exp"));
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "handshake", code: "timestamp_after_init_exp", path: "tunnel" });
    expect(observer.onHandshake).toHaveBeenCalledWith("tunnel", "fail", "timestamp_after_init_exp", expect.any(Number));
  });

  test("reports handshake timeout", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockImplementationOnce(() => new Promise(() => {}));
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      handshakeTimeoutMs: 30,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "handshake", code: "timeout", path: "tunnel" });
    expect(observer.onHandshake).toHaveBeenCalledWith("tunnel", "fail", "timeout", expect.any(Number));
  });

  test("close tears down rpc, mux, and secure resources", async () => {
    const ws = new FakeWebSocket();
    const secureClose = vi.fn();
    clientHandshakeMock.mockResolvedValueOnce({
      read: vi.fn(),
      write: vi.fn(),
      close: secureClose
    });
    openStream.mockResolvedValueOnce({
      read: vi.fn().mockResolvedValue(new Uint8Array()),
      write: vi.fn(),
      close: vi.fn()
    });

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any
    });

    setTimeout(() => ws.emit("open", {}), 0);
    const conn = await p;
    conn.close();

    expect(rpcClose).toHaveBeenCalledTimes(1);
    expect(muxClose).toHaveBeenCalledTimes(1);
    expect(secureClose).toHaveBeenCalledTimes(1);
  });

  test("ping wraps secure ping failures", async () => {
    const ws = new FakeWebSocket();
    const secureClose = vi.fn();
    const securePing = vi.fn().mockRejectedValueOnce(new Error("ping failed"));
    clientHandshakeMock.mockResolvedValueOnce({
      read: vi.fn(),
      write: vi.fn(),
      close: secureClose,
      sendPing: securePing
    });
    openStream.mockResolvedValueOnce({
      read: vi.fn().mockResolvedValue(new Uint8Array()),
      write: vi.fn(),
      close: vi.fn()
    });

    const p = connectTunnel(makeGrant(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any
    });

    setTimeout(() => ws.emit("open", {}), 0);
    const conn = await p;

    const pp = conn.ping();
    await expect(pp).rejects.toBeInstanceOf(FlowersecError);
    await expect(pp).rejects.toMatchObject({ stage: "secure", code: "ping_failed", path: "tunnel" });
    expect(securePing).toHaveBeenCalledTimes(1);

    conn.close();
  });
});
