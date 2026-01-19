import { beforeEach, describe, expect, test, vi } from "vitest";
import { base64urlEncode } from "../utils/base64url.js";
import { FlowersecError } from "../utils/errors.js";
import { E2EEHandshakeError } from "../e2ee/errors.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

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

import { connectDirect } from "./connect.js";

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

function makeInfo(): DirectConnectInfo {
  const psk = base64urlEncode(new Uint8Array(32).fill(1));
  return {
    ws_url: "ws://example.invalid",
    channel_id: "ch_1",
    e2ee_psk_b64u: psk,
    channel_init_expire_at_unix_s: Math.floor(Date.now() / 1000) + 120,
    default_suite: 1
  };
}

describe("connectDirect", () => {
  test("wraps invalid connect info payloads", async () => {
    const p = connectDirect("bad" as any, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "invalid_connect_info", path: "direct" });
  });

  test("rejects missing ws_url", async () => {
    const bad = makeInfo();
    bad.ws_url = "";
    const p = connectDirect(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_ws_url", path: "direct" });
  });

  test("rejects missing init exp", async () => {
    const bad = makeInfo();
    bad.channel_init_expire_at_unix_s = 0;
    const p = connectDirect(bad, { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "missing_init_exp", path: "direct" });
  });

  test("requires wsFactory outside the browser", async () => {
    const p = connectDirect(makeInfo(), { origin: "https://app.redeven.com" });
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "validate", code: "ws_factory_required", path: "direct" });
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

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("error", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "connect", code: "websocket_error", path: "direct" });

    expect(observer.onConnect).toHaveBeenCalledWith("direct", "fail", "websocket_error", expect.any(Number));
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

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      connectTimeoutMs: 30,
      observer
    });

    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "connect", code: "timeout", path: "direct" });
    expect(observer.onConnect).toHaveBeenCalledWith("direct", "fail", "timeout", expect.any(Number));
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

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      signal: ac.signal,
      observer
    });

    setTimeout(() => ac.abort(), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "connect", code: "canceled", path: "direct" });
    expect(observer.onConnect).toHaveBeenCalledWith("direct", "fail", "canceled", expect.any(Number));
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

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "handshake", code: "handshake_failed", path: "direct" });

    expect(observer.onHandshake).toHaveBeenCalledWith("direct", "fail", "handshake_failed", expect.any(Number));
  });

  test("classifies handshake auth tag failures", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockRejectedValueOnce(new E2EEHandshakeError("auth_tag_mismatch", "auth tag mismatch"));
    const observer = {
      onConnect: vi.fn(),
      onAttach: vi.fn(),
      onHandshake: vi.fn(),
      onWsError: vi.fn(),
      onRpcCall: vi.fn(),
      onRpcNotify: vi.fn()
    };

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "handshake", code: "auth_tag_mismatch", path: "direct" });
    expect(observer.onHandshake).toHaveBeenCalledWith("direct", "fail", "auth_tag_mismatch", expect.any(Number));
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

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any,
      handshakeTimeoutMs: 30,
      observer
    });

    setTimeout(() => ws.emit("open", {}), 0);
    await expect(p).rejects.toBeInstanceOf(FlowersecError);
    await expect(p).rejects.toMatchObject({ stage: "handshake", code: "timeout", path: "direct" });
    expect(observer.onHandshake).toHaveBeenCalledWith("direct", "fail", "timeout", expect.any(Number));
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

    const p = connectDirect(makeInfo(), {
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

  test("openStream wraps yamux openStream errors", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockResolvedValueOnce({
      read: vi.fn(),
      write: vi.fn(),
      close: vi.fn()
    });
    openStream
      .mockResolvedValueOnce({
        read: vi.fn().mockResolvedValue(new Uint8Array()),
        write: vi.fn(),
        close: vi.fn()
      })
      .mockRejectedValueOnce(new Error("yamux open failed"));

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any
    });

    setTimeout(() => ws.emit("open", {}), 0);
    const conn = await p;
    await expect(conn.openStream("echo")).rejects.toMatchObject({ stage: "yamux", code: "open_stream_failed", path: "direct" });
    conn.close();
  });

  test("openStream validates stream kind", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockResolvedValueOnce({
      read: vi.fn(),
      write: vi.fn(),
      close: vi.fn()
    });
    openStream.mockResolvedValueOnce({
      read: vi.fn().mockResolvedValue(new Uint8Array()),
      write: vi.fn(),
      close: vi.fn()
    });

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any
    });

    setTimeout(() => ws.emit("open", {}), 0);
    const conn = await p;
    await expect(conn.openStream("")).rejects.toMatchObject({ stage: "validate", code: "missing_stream_kind", path: "direct" });
    conn.close();
  });

  test("openStream wraps StreamHello write errors and closes the stream", async () => {
    const ws = new FakeWebSocket();
    clientHandshakeMock.mockResolvedValueOnce({
      read: vi.fn(),
      write: vi.fn(),
      close: vi.fn()
    });
    const badStreamClose = vi.fn();
    openStream
      .mockResolvedValueOnce({
        read: vi.fn().mockResolvedValue(new Uint8Array()),
        write: vi.fn(),
        close: vi.fn()
      })
      .mockResolvedValueOnce({
        read: vi.fn(),
        write: vi.fn().mockRejectedValueOnce(new Error("write failed")),
        close: badStreamClose
      });

    const p = connectDirect(makeInfo(), {
      origin: "https://app.redeven.com",
      wsFactory: () => ws as any
    });

    setTimeout(() => ws.emit("open", {}), 0);
    const conn = await p;
    await expect(conn.openStream("echo")).rejects.toMatchObject({ stage: "rpc", code: "stream_hello_failed", path: "direct" });
    expect(badStreamClose).toHaveBeenCalledTimes(1);
    conn.close();
  });
});
