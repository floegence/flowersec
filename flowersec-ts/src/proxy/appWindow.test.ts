import { describe, expect, it, vi } from "vitest";

import { registerProxyAppWindow } from "./appWindow.js";
import { PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE } from "./windowBridgeProtocol.js";

class FakeServiceWorker {
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

function createTargetWindow(serviceWorker: FakeServiceWorker, controllerWindow: Window): Window {
  return {
    top: controllerWindow,
    parent: controllerWindow,
    navigator: { serviceWorker },
  } as unknown as Window;
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for async condition");
}

describe("registerProxyAppWindow", () => {
  it("forwards service worker fetch bridge messages to the controller window", () => {
    const serviceWorker = new FakeServiceWorker();
    const controllerWindow = {
      postMessage: vi.fn(),
    } as unknown as Window;

    registerProxyAppWindow({
      controllerOrigin: "https://rt-demo.example.test",
      controllerWindow,
      targetWindow: createTargetWindow(serviceWorker, controllerWindow),
    });

    const channel = new MessageChannel();
    const req = { id: "req-1", method: "GET", path: "/", headers: [] };
    serviceWorker.emit({
      data: { type: PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE, req },
      ports: [channel.port1],
    } as MessageEvent);

    expect(controllerWindow.postMessage).toHaveBeenCalledWith(
      { type: "flowersec-proxy:fetch", req },
      "https://rt-demo.example.test",
      [channel.port1],
    );
  });

  it("creates a websocket runtime backed by controller postMessage", async () => {
    const serviceWorker = new FakeServiceWorker();
    const controllerPostMessage = vi.fn();
    const controllerWindow = {
      postMessage: controllerPostMessage,
    } as unknown as Window;

    const handle = registerProxyAppWindow({
      controllerOrigin: "https://rt-demo.example.test",
      controllerWindow,
      targetWindow: createTargetWindow(serviceWorker, controllerWindow),
      maxWsFrameBytes: 123,
    });

    const openPromise = handle.runtime.openWebSocketStream("/ws", { protocols: ["demo"] });
    expect(controllerPostMessage).toHaveBeenCalledTimes(1);
    const openCall = controllerPostMessage.mock.calls[0];
    expect(openCall[0]).toMatchObject({ type: "flowersec-proxy:ws_open", path: "/ws", protocols: ["demo"] });
    expect(openCall[1]).toBe("https://rt-demo.example.test");

    const controllerPort = openCall[2][0] as MessagePort;
    controllerPort.postMessage({ type: "flowersec-proxy:ws_open_ack", protocol: "demo" });

    const { stream, protocol } = await openPromise;
    expect(protocol).toBe("demo");
    expect(handle.runtime.limits).toEqual({ maxWsFrameBytes: 123 });

    const received: unknown[] = [];
    controllerPort.onmessage = (event) => {
      received.push(event.data);
    };
    controllerPort.start();

    await stream.write(new Uint8Array([7, 8]));
    await waitFor(() => received.length === 1);
    expect(received[0]).toMatchObject({ type: "flowersec-proxy:stream_chunk" });

    controllerPort.postMessage({ type: "flowersec-proxy:stream_chunk", data: new Uint8Array([1, 2]).buffer });
    expect(await stream.read()).toEqual(new Uint8Array([1, 2]));

    controllerPort.postMessage({ type: "flowersec-proxy:stream_end" });
    expect(await stream.read()).toBeNull();
  });
});
