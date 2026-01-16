import { beforeEach, describe, expect, test, vi } from "vitest";
import { base64urlEncode } from "../utils/base64url.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";

const mocks = vi.hoisted(() => {
  const clientHandshakeMock = vi.fn();
  const rpcClose = vi.fn();
  const rpcProxyAttach = vi.fn();
  const rpcProxyDetach = vi.fn();
  const muxClose = vi.fn();
  const openStream = vi.fn();

  class MockRpcClient {
    constructor(_readExactly: any, _write: any, _opts?: any) {}
    close() {
      rpcClose();
    }
  }

  class MockRpcProxy {
    attach() {
      rpcProxyAttach();
    }
    detach() {
      rpcProxyDetach();
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
    rpcProxyAttach,
    rpcProxyDetach,
    muxClose,
    openStream,
    MockRpcClient,
    MockRpcProxy,
    MockYamuxSession
  };
});

const {
  clientHandshakeMock,
  rpcClose,
  rpcProxyDetach,
  muxClose,
  openStream
} = mocks;

vi.mock("../e2ee/handshake.js", () => ({
  clientHandshake: (...args: unknown[]) => mocks.clientHandshakeMock(...args)
}));

vi.mock("../rpc/client.js", () => ({ RpcClient: mocks.MockRpcClient }));

vi.mock("../rpc-proxy/rpcProxy.js", () => ({ RpcProxy: mocks.MockRpcProxy }));

vi.mock("../yamux/session.js", () => ({ YamuxSession: mocks.MockYamuxSession }));

import { connectTunnelClientRpc } from "./connect.js";

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
    token: "tok",
    e2ee_psk_b64u: psk,
    default_suite: 1
  } as ChannelInitGrant;
}

describe("connectTunnelClientRpc", () => {
  test("reports websocket error on connect", async () => {
    const ws = new FakeWebSocket();
    const observer = {
      onTunnelConnect: vi.fn(),
      onTunnelAttach: vi.fn(),
      onTunnelHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnelClientRpc(makeGrant(), {
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("error", {}), 0);
    await expect(p).rejects.toThrow(/websocket error/);

    expect(observer.onTunnelConnect).toHaveBeenCalledWith("fail", "websocket_error", expect.any(Number));
  });

  test("reports attach send failures", async () => {
    const ws = new FakeWebSocket();
    ws.send = () => {
      throw new Error("send failed");
    };
    const observer = {
      onTunnelConnect: vi.fn(),
      onTunnelAttach: vi.fn(),
      onTunnelHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnelClientRpc(makeGrant(), {
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toThrow(/send failed/);

    expect(observer.onTunnelAttach).toHaveBeenCalledWith("fail", "send_failed");
  });

  test("reports handshake failures", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockRejectedValueOnce(new Error("handshake failed"));
    const observer = {
      onTunnelConnect: vi.fn(),
      onTunnelAttach: vi.fn(),
      onTunnelHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectTunnelClientRpc(makeGrant(), {
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toThrow(/handshake failed/);

    expect(observer.onTunnelHandshake).toHaveBeenCalledWith("fail", "handshake_error", expect.any(Number));
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

    const p = connectTunnelClientRpc(makeGrant(), {
      wsFactory: () => ws as any
    });

    setTimeout(() => ws.emit("open", {}), 0);
    const conn = await p;
    conn.close();

    expect(rpcProxyDetach).toHaveBeenCalledTimes(1);
    expect(rpcClose).toHaveBeenCalledTimes(1);
    expect(muxClose).toHaveBeenCalledTimes(1);
    expect(secureClose).toHaveBeenCalledTimes(1);
  });
});
