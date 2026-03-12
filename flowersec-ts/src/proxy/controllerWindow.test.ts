import { describe, expect, it, vi } from "vitest";

import { registerProxyControllerWindow } from "./controllerWindow.js";
import {
  PROXY_WINDOW_FETCH_MSG_TYPE,
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_MSG_TYPE,
} from "./windowBridgeProtocol.js";

class FakeWindow {
  private readonly listeners = new Map<string, Set<(event: MessageEvent) => void>>();

  addEventListener(type: string, listener: (event: MessageEvent) => void): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: (event: MessageEvent) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  emit(event: MessageEvent): void {
    for (const listener of this.listeners.get("message") ?? []) {
      listener(event);
    }
  }
}

class FakeMessagePort {
  onmessage: ((event: { data: unknown }) => void) | null = null;
  readonly messages: unknown[] = [];
  private peer: FakeMessagePort | null = null;
  closed = false;

  connect(peer: FakeMessagePort): void {
    this.peer = peer;
  }

  postMessage(message: unknown): void {
    if (this.closed) return;
    const peer = this.peer;
    if (!peer || peer.closed) return;
    queueMicrotask(() => {
      peer.messages.push(message);
      peer.onmessage?.({ data: message });
    });
  }

  close(): void {
    this.closed = true;
  }

  start(): void {}
}

function createFakeMessageChannel(): { port1: MessagePort; port2: MessagePort } {
  const port1 = new FakeMessagePort();
  const port2 = new FakeMessagePort();
  port1.connect(port2);
  port2.connect(port1);
  return {
    port1: port1 as unknown as MessagePort,
    port2: port2 as unknown as MessagePort,
  };
}

class FakeStream {
  readonly writes: Uint8Array[] = [];
  readonly resetCalls: string[] = [];
  closeCalls = 0;
  private readonly reads: Array<Uint8Array | null>;

  constructor(reads: Array<Uint8Array | null>) {
    this.reads = [...reads];
  }

  async read(): Promise<Uint8Array | null> {
    return this.reads.shift() ?? null;
  }

  async write(chunk: Uint8Array): Promise<void> {
    this.writes.push(chunk);
  }

  async close(): Promise<void> {
    this.closeCalls++;
  }

  reset(err: Error): void {
    this.resetCalls.push(err.message);
  }
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for async condition");
}

describe("registerProxyControllerWindow", () => {
  it("forwards fetch bridge messages to runtime.dispatchFetch", () => {
    const targetWindow = new FakeWindow();
    const runtime = {
      dispatchFetch: vi.fn(),
      openWebSocketStream: vi.fn(),
      limits: {},
      dispose: () => {},
    };

    const handle = registerProxyControllerWindow({
      runtime: runtime as any,
      allowedOrigins: ["https://app.example.test"],
      targetWindow: targetWindow as unknown as Window,
    });

    const channel = createFakeMessageChannel();
    const req = { id: "req-1", method: "GET", path: "/", headers: [] };
    targetWindow.emit({
      origin: "https://app.example.test",
      data: { type: PROXY_WINDOW_FETCH_MSG_TYPE, req },
      ports: [channel.port1],
      source: null,
    } as MessageEvent);

    expect(runtime.dispatchFetch).toHaveBeenCalledTimes(1);
    const [seenReq, seenPort] = runtime.dispatchFetch.mock.calls[0]!;
    expect(seenReq).toEqual(req);
    expect(seenPort).toBe(channel.port1);

    handle.dispose();
    targetWindow.emit({
      origin: "https://app.example.test",
      data: { type: PROXY_WINDOW_FETCH_MSG_TYPE, req },
      ports: [channel.port1],
      source: null,
    } as MessageEvent);
    expect(runtime.dispatchFetch).toHaveBeenCalledTimes(1);
  });

  it("bridges websocket traffic over MessagePort", async () => {
    const targetWindow = new FakeWindow();
    const stream = new FakeStream([new Uint8Array([1, 2, 3]), null]);
    const runtime = {
      dispatchFetch: vi.fn(),
      openWebSocketStream: vi.fn(async () => ({ stream: stream as any, protocol: "demo" })),
      limits: {},
      dispose: () => {},
    };

    registerProxyControllerWindow({
      runtime: runtime as any,
      allowedOrigins: ["https://app.example.test"],
      targetWindow: targetWindow as unknown as Window,
    });

    const channel = createFakeMessageChannel();
    (channel.port2 as unknown as FakeMessagePort).start();

    targetWindow.emit({
      origin: "https://app.example.test",
      data: { type: PROXY_WINDOW_WS_OPEN_MSG_TYPE, path: "/ws", protocols: ["demo"] },
      ports: [channel.port1],
      source: null,
    } as MessageEvent);

    await waitFor(() => runtime.openWebSocketStream.mock.calls.length === 1);
    expect(runtime.openWebSocketStream).toHaveBeenCalledWith(
      "/ws",
      expect.objectContaining({ protocols: ["demo"] }),
    );

    channel.port2.postMessage({
      type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
      data: new Uint8Array([9, 8]).buffer,
    });
    channel.port2.postMessage({ type: PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE });
    await waitFor(() => stream.writes.length === 1 && stream.closeCalls === 1);
    expect(stream.writes[0]).toEqual(new Uint8Array([9, 8]));
  });
});
