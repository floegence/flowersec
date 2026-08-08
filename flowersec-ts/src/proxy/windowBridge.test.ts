import { describe, expect, it } from "vitest";

import type { ByteStream } from "../public/contract.js";
import type { ProxyFetchRequest, ProxyRuntime } from "./types.js";
import {
  MessagePortByteStream,
  registerProxyAppWindow,
  registerProxyControllerWindow,
} from "./windowBridge.js";

class TestWindow extends EventTarget {
  opener: Window | null = null;
  parent: Window = this as unknown as Window;
}

class BridgeTarget {
  constructor(
    private readonly destination: TestWindow,
    private readonly origin: string,
    private readonly source: Window,
  ) {}
  postMessage(data: unknown, _targetOrigin: string, ports: Transferable[] = []): void {
    const event = new Event("message") as MessageEvent;
    Object.defineProperties(event, {
      data: { value: data },
      origin: { value: this.origin },
      source: { value: this.source },
      ports: { value: ports.filter((value): value is MessagePort => value instanceof MessagePort) },
    });
    queueMicrotask(() => this.destination.dispatchEvent(event));
  }
}

class DuplexStream implements ByteStream {
  readonly kind = "proxy";
  terminalError = undefined;
  readonly written: Uint8Array[] = [];
  closeWriteCalled = false;
  closed = false;
  private readonly incoming = [new Uint8Array([7]), null];
  async read(): Promise<Uint8Array | null> { return this.incoming.shift() ?? null; }
  async write(data: Uint8Array): Promise<number> { this.written.push(data.slice()); return data.length; }
  async closeWrite(): Promise<void> { this.closeWriteCalled = true; }
  async reset(): Promise<void> {}
  async close(): Promise<void> { this.closed = true; }
}

describe("proxy controller/app window bridge", () => {
  it("enforces origin and capability while bridging fetch and duplex WebSocket bytes", async () => {
    const controllerWindow = new TestWindow();
    const appWindow = new TestWindow();
    const controllerOrigin = "https://controller.example";
    const appOrigin = "https://app.example";
    const stream = new DuplexStream();
    let fetchRequest: ProxyFetchRequest | undefined;
    const runtime: ProxyRuntime = {
      limits: {
        maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1,
        maxWsFrameBytes: 1024, maxWsBufferedAmountBytes: 4096,
        maxConcurrentHttpStreams: 1, maxQueuedHttpRequests: 1, maxQueuedHttpBodyBytes: 1,
      },
      dispatchFetch(request, port) {
        fetchRequest = request;
        port.postMessage({ type: "flowersec-proxy:response_end" });
      },
      async openWebSocketStream(path, options) {
        expect(path).toBe("/socket");
        expect(options?.protocols).toEqual(["chat"]);
        return { stream, protocol: "chat" };
      },
      dispose() {},
    };
    const controller = registerProxyControllerWindow({
      runtime,
      targetWindow: controllerWindow as unknown as Window,
      expectedSource: appWindow as unknown as Window,
      allowedOrigins: [appOrigin],
      capabilityNonce: "capability",
    });
    const app = registerProxyAppWindow({
      controllerOrigin,
      controllerWindow: new BridgeTarget(
        controllerWindow,
        appOrigin,
        appWindow as unknown as Window,
      ) as unknown as Window,
      targetWindow: appWindow as unknown as Window,
      capabilityNonce: "capability",
    });

    const fetchChannel = new MessageChannel();
    const fetchDone = new Promise<void>((resolve) => {
      fetchChannel.port2.onmessage = (event) => {
        if (event.data?.type === "flowersec-proxy:response_end") resolve();
      };
    });
    app.runtime.dispatchFetch({ id: "request", method: "GET", path: "/api", headers: [] }, fetchChannel.port1);
    await fetchDone;
    expect(fetchRequest).toEqual({ id: "request", method: "GET", path: "/api", headers: [] });

    const opened = await app.runtime.openWebSocketStream("/socket", { protocols: ["chat"] });
    expect(opened.protocol).toBe("chat");
    expect(await opened.stream.read()).toEqual(new Uint8Array([7]));
    expect(await opened.stream.write(new Uint8Array([9, 8]))).toBe(2);
    await opened.stream.closeWrite();
    expect(await opened.stream.read()).toBeNull();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(stream.written).toEqual([new Uint8Array([9, 8])]);
    expect(stream.closeWriteCalled).toBe(true);

    app.dispose();
    controller.dispose();
  });

  it("fails closed when the inbound stream queue exceeds its byte budget", async () => {
    const channel = new MessageChannel();
    const stream = new MessagePortByteStream(channel.port1);
    for (let id = 1; id <= 5; id++) {
      const data = new Uint8Array(1024 * 1024).buffer;
      channel.port2.postMessage({ type: "chunk", id, data }, [data]);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    expect(stream.terminalError?.code).toBe("resource_exhausted");
    channel.port2.close();
  });
});
