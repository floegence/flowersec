import { afterEach, describe, expect, test, vi } from "vitest";

import { createBrowserConnectionController } from "./connectSession.js";
import { detectBrowserRuntimeCapabilityV2 } from "./runtimeCapability.js";
import { browserSessionRuntimeV2 } from "./sessionRuntime.js";
import { createBrowserWebTransportClientV2 } from "./webTransportClient.js";

afterEach(() => vi.unstubAllGlobals());

describe("browser runtime adapters", () => {
  test("detects only browser APIs that have their required surface", () => {
    expect(detectBrowserRuntimeCapabilityV2({}).unsupported).toEqual([
      { carrier: "raw_quic", reason: "browser_no_raw_udp" },
      { carrier: "websocket", reason: "browser_websocket_api_unavailable" },
      { carrier: "webtransport", reason: "browser_webtransport_api_unavailable" },
    ]);
    class Incomplete {}
    expect(detectBrowserRuntimeCapabilityV2({ WebTransport: Incomplete }).tuples).toHaveLength(0);
  });

  test("creates one native WebTransport from a URL and adapts its carrier", async () => {
    const transport = webTransportRuntime();
    vi.stubGlobal("WebTransport", transport.Constructor);
    const carrier = await createBrowserWebTransportClientV2(
      "https://example.test:443/flowersec/webtransport/v2/direct",
      { path: "direct", inboundBidirectionalStreamCapacity: 66 },
    );
    expect(transport.instances).toHaveLength(1);
    expect(transport.instances[0]!.url).toContain("/flowersec/webtransport/v2/direct");
    expect(carrier.kind).toBe("webtransport");
    carrier.abort({ code: 6, reason: "test" });
    expect(transport.instances[0]!.close).toHaveBeenCalledWith({ closeCode: 6, reason: "test" });
  });

  test.each([
    "not a URL",
    "http://example.test/flowersec/webtransport/v2/direct",
    "https://example.test/other",
    "https://user:pass@example.test/flowersec/webtransport/v2/direct",
    "https://example.test/flowersec/webtransport/v2/direct?x=1",
  ])("rejects an invalid WebTransport URL: %s", async (url) => {
    await expect(createBrowserWebTransportClientV2(url, {
      path: "direct",
      inboundBidirectionalStreamCapacity: 66,
    })).rejects.toMatchObject({ code: "runtime_start_failed" });
  });

  test("reports unavailable, aborted, and failed browser startup explicitly", async () => {
    vi.stubGlobal("WebTransport", undefined);
    await expect(createBrowserWebTransportClientV2(
      "https://example.test/flowersec/webtransport/v2/direct",
      { path: "direct", inboundBidirectionalStreamCapacity: 66 },
    )).rejects.toMatchObject({ code: "runtime_unsupported" });

    const controller = new AbortController();
    controller.abort(new Error("caller canceled"));
    vi.stubGlobal("WebTransport", webTransportRuntime().Constructor);
    await expect(createBrowserWebTransportClientV2(
      "https://example.test/flowersec/webtransport/v2/direct",
      { path: "direct", inboundBidirectionalStreamCapacity: 66, signal: controller.signal },
    )).rejects.toThrow("caller canceled");

    const failed = webTransportRuntime(new Error("network down"));
    vi.stubGlobal("WebTransport", failed.Constructor);
    await expect(createBrowserWebTransportClientV2(
      "https://example.test/flowersec/webtransport/v2/direct",
      { path: "direct", inboundBidirectionalStreamCapacity: 66 },
    )).rejects.toMatchObject({ code: "runtime_start_failed" });
    expect(failed.instances[0]!.close).toHaveBeenCalled();
  });

  test("closes a native WebTransport when cancellation wins the startup race", async () => {
    let settleReady!: () => void;
    const runtime = webTransportRuntime(undefined, new Promise<void>((resolve) => { settleReady = resolve; }));
    vi.stubGlobal("WebTransport", runtime.Constructor);
    const controller = new AbortController();
    const connecting = createBrowserWebTransportClientV2(
      "https://example.test/flowersec/webtransport/v2/tunnel",
      { path: "tunnel", inboundBidirectionalStreamCapacity: 66, signal: controller.signal },
    );
    controller.abort(new Error("caller canceled"));
    await expect(connecting).rejects.toMatchObject({ code: "runtime_start_failed" });
    expect(runtime.instances[0]!.close).toHaveBeenCalled();
    settleReady();
  });

  test("keeps browser session runtime independent from protocol session", () => {
    vi.stubGlobal("crypto", { getRandomValues: (bytes: Uint8Array) => { bytes.fill(7); return bytes; } });
    expect(browserSessionRuntimeV2.entropy(4)).toEqual(Uint8Array.of(7, 7, 7, 7));
    expect(browserSessionRuntimeV2.monotonicMilliseconds()).toBeTypeOf("number");
    expect(() => browserSessionRuntimeV2.entropy(0)).toThrow();
  });

  test("constructs the browser controller without starting an artifact attempt", () => {
    const acquire = vi.fn(async () => ({ kind: "failure" as const, code: "none", disposition: { kind: "terminal" as const } }));
    const controller = createBrowserConnectionController({ acquire }, { maxAttempts: 1 });
    expect(controller.state).toBe("idle");
    expect(acquire).not.toHaveBeenCalled();
  });

});

function webTransportRuntime(startFailure?: Error, pendingReady?: Promise<void>) {
  const instances: Array<Readonly<{ url: string; close: ReturnType<typeof vi.fn> }>> = [];
  class Constructor {
    readonly ready: Promise<void>;
    readonly closed: Promise<void>;
    readonly incomingBidirectionalStreams = new ReadableStream({ start() {} });
    readonly datagrams = {
      readable: new ReadableStream<Uint8Array>({ start() {} }),
      writable: new WritableStream<Uint8Array>({ write() {} }),
      maxDatagramSize: 1_200,
    };
    readonly close = vi.fn();
    constructor(readonly url: string) {
      this.ready = pendingReady ?? (startFailure === undefined ? Promise.resolve() : Promise.reject(startFailure));
      this.closed = new Promise(() => undefined);
      instances.push(this);
    }
    createBidirectionalStream(): Promise<never> { return new Promise(() => undefined); }
  }
  return { Constructor, instances };
}
