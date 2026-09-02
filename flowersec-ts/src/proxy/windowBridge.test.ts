import { describe, expect, it } from "vitest";

import { SessionError, type ByteStream, type OperationOptions } from "../public/contract.js";
import type { ProxyFetchRequest, ProxyRuntime } from "./types.js";
import {
  MessagePortByteStream,
  registerProxyAppWindow,
  registerProxyAppWindowWithServiceWorkerRuntime,
  registerProxyControllerWindow,
} from "./windowBridge.js";

class TestWindow extends EventTarget {
  opener: Window | null = null;
  parent: Window = this as unknown as Window;
}

class TestServiceWorkerContainer extends EventTarget {}

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
  it("removes the abort waiter after an ACK wins the race", async () => {
    const channel = new MessageChannel();
    const stream = new MessagePortByteStream(channel.port1);
    channel.port2.start();
    const controller = new AbortController();
    const writing = stream.write(new Uint8Array([1, 2, 3]), { signal: controller.signal });
    const sent = await nextMessage(channel.port2);
    channel.port2.postMessage({ type: "ack", id: sent.id });
    await expect(within(writing)).resolves.toBe(3);
    controller.abort();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect((stream as unknown as { buffered: number }).buffered).toBe(0);
    await stream.close();
    channel.port2.close();
  });

  it("settles ACK waiters promptly on abort and ignores late ACK races", async () => {
    const channel = new MessageChannel();
    const stream = new MessagePortByteStream(channel.port1);
    channel.port2.start();
    const controller = new AbortController();
    const writing = stream.write(new Uint8Array([1, 2, 3]), { signal: controller.signal });
    const sent = await nextMessage(channel.port2);
    controller.abort();
    await expect(within(writing)).rejects.toMatchObject({ code: "canceled" });
    channel.port2.postMessage({ type: "ack", id: sent.id });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect((stream as unknown as { buffered: number }).buffered).toBe(0);
    channel.port2.close();
  });

  it("settles an ACK waiter once when the MessagePort fails", async () => {
    const channel = new MessageChannel();
    const stream = new MessagePortByteStream(channel.port1);
    channel.port2.start();
    const writing = stream.write(new Uint8Array([1, 2, 3]));
    const sent = await nextMessage(channel.port2);
    channel.port1.dispatchEvent(new MessageEvent("messageerror"));
    await expect(within(writing)).rejects.toMatchObject({ code: "operation_failed" });
    channel.port2.postMessage({ type: "ack", id: sent.id });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect((stream as unknown as { buffered: number }).buffered).toBe(0);
    channel.port2.close();
  });

  it("settles pending writes before ignoring ACKs that arrive after close or reset", async () => {
    for (const terminal of ["close", "reset"] as const) {
      const channel = new MessageChannel();
      const stream = new MessagePortByteStream(channel.port1);
      channel.port2.start();
      const writing = stream.write(new Uint8Array([1, 2, 3]));
      const sent = await nextMessage(channel.port2);
      if (terminal === "close") await stream.close();
      else await stream.reset();
      await expect(within(writing)).rejects.toMatchObject({
        code: terminal === "close" ? "closed" : "stream_reset",
      });
      channel.port2.postMessage({ type: "ack", id: sent.id });
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect((stream as unknown as { buffered: number }).buffered).toBe(0);
      channel.port2.close();
    }
  });

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

  it("composes the private Service Worker runtime bridge and disposes it idempotently", async () => {
    const appWindow = new TestWindow();
    const serviceWorker = new TestServiceWorkerContainer();
    Object.defineProperty(appWindow, "navigator", { value: { serviceWorker } });
    const forwarded: unknown[] = [];
    const controllerWindow = {
      postMessage(data: unknown): void { forwarded.push(data); },
    } as unknown as Window;
    const app = registerProxyAppWindowWithServiceWorkerRuntime({
      controllerOrigin: "https://controller.example",
      controllerWindow,
      targetWindow: appWindow as unknown as Window,
      capabilityNonce: "capability",
    });
    const channel = new MessageChannel();
    const event = new MessageEvent("message", {
      data: {
        type: "flowersec-proxy:fetch",
        req: {
          id: "request",
          method: "GET",
          path: "/api",
          headers: [],
          response_flow_control: "chunk_credit_v2",
        },
      },
      ports: [channel.port1],
    });
    serviceWorker.dispatchEvent(event);
    expect(forwarded).toHaveLength(1);

    app.dispose();
    app.dispose();
    serviceWorker.dispatchEvent(event);
    expect(forwarded).toHaveLength(1);
    channel.port2.close();
  });

  it("fails closed on malformed private Service Worker messages and rolls back partial setup", async () => {
    const appWindow = new TestWindow();
    const serviceWorker = new TestServiceWorkerContainer();
    Object.defineProperty(appWindow, "navigator", { value: { serviceWorker } });
    const app = registerProxyAppWindowWithServiceWorkerRuntime({
      controllerOrigin: "https://controller.example",
      controllerWindow: { postMessage() {} } as unknown as Window,
      targetWindow: appWindow as unknown as Window,
    });
    const channel = new MessageChannel();
    serviceWorker.dispatchEvent(new MessageEvent("message", {
      data: { type: "flowersec-proxy:fetch", req: { id: 7 } },
      ports: [channel.port1],
    }));
    await expect(within(nextMessage(channel.port2))).resolves.toMatchObject({
      type: "flowersec-proxy:response_error",
      status: 400,
      code: "invalid_request",
    });
    app.dispose();
    channel.port2.close();

    const failingWindow = new TestWindow();
    const failingWorker = {
      addEventListener(): never { throw new Error("listener rejected"); },
      removeEventListener() {},
    };
    Object.defineProperty(failingWindow, "navigator", { value: { serviceWorker: failingWorker } });
    expect(() => registerProxyAppWindowWithServiceWorkerRuntime({
      controllerOrigin: "https://controller.example",
      controllerWindow: { postMessage() {} } as unknown as Window,
      targetWindow: failingWindow as unknown as Window,
    })).toThrow("listener rejected");
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

  it("resets both bridge sides when either pump fails and when disposed", async () => {
    for (const mode of ["read_failure", "write_failure", "blocked"] as const) {
      const stream = new FailingDuplexStream(mode);
      const handles = bridgeHarness(stream);
      const opened = await handles.app.runtime.openWebSocketStream("/socket");
      if (mode === "write_failure") {
        await opened.stream.write(new Uint8Array([9]));
      } else if (mode === "blocked") {
        await stream.readStarted;
        handles.controller.dispose();
      }
      await waitFor(() => stream.resetCalled);
      await expect(within(opened.stream.read())).rejects.toBeInstanceOf(SessionError);
      handles.app.dispose();
      handles.controller.dispose();
    }
  });
});

class FailingDuplexStream implements ByteStream {
  readonly kind = "proxy";
  terminalError = undefined;
  resetCalled = false;
  private resolveReadStarted!: () => void;
  readonly readStarted = new Promise<void>((resolve) => { this.resolveReadStarted = resolve; });

  constructor(private readonly mode: "read_failure" | "write_failure" | "blocked") {}

  async read(options: OperationOptions = {}): Promise<Uint8Array | null> {
    this.resolveReadStarted();
    if (this.mode === "read_failure") throw new Error("runtime read failed");
    return await new Promise<never>((_resolve, reject) => {
      const abort = () => reject(new SessionError("canceled"));
      if (options.signal?.aborted === true) abort();
      else options.signal?.addEventListener("abort", abort, { once: true });
    });
  }

  async write(data: Uint8Array): Promise<number> {
    if (this.mode === "write_failure") throw new Error("runtime write failed");
    return data.length;
  }

  async closeWrite(): Promise<void> {}
  async reset(): Promise<void> { this.resetCalled = true; }
  async close(): Promise<void> {}
}

function bridgeHarness(stream: ByteStream): Readonly<{
  app: ReturnType<typeof registerProxyAppWindow>;
  controller: ReturnType<typeof registerProxyControllerWindow>;
}> {
  const controllerWindow = new TestWindow();
  const appWindow = new TestWindow();
  const controllerOrigin = "https://controller.example";
  const appOrigin = "https://app.example";
  const runtime = {
    limits: {
      maxJsonFrameBytes: 1, maxChunkBytes: 1, maxBodyBytes: 1,
      maxWsFrameBytes: 1024, maxWsBufferedAmountBytes: 4096,
      maxConcurrentHttpStreams: 1, maxQueuedHttpRequests: 1, maxQueuedHttpBodyBytes: 1,
    },
    dispatchFetch() {},
    async openWebSocketStream() { return { stream, protocol: "" }; },
    dispose() {},
  } satisfies ProxyRuntime;
  const controller = registerProxyControllerWindow({
    runtime,
    targetWindow: controllerWindow as unknown as Window,
    expectedSource: appWindow as unknown as Window,
    allowedOrigins: [appOrigin],
  });
  const app = registerProxyAppWindow({
    controllerOrigin,
    controllerWindow: new BridgeTarget(
      controllerWindow,
      appOrigin,
      appWindow as unknown as Window,
    ) as unknown as Window,
    targetWindow: appWindow as unknown as Window,
  });
  return { app, controller };
}

async function nextMessage(port: MessagePort): Promise<Record<string, unknown>> {
  return await new Promise((resolve) => {
    port.addEventListener("message", (event) => resolve(event.data as Record<string, unknown>), { once: true });
  });
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not reached");
}

async function within<T>(promise: Promise<T>): Promise<T> {
  return await Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("operation remained pending")), 200)),
  ]);
}
