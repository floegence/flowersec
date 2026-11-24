import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchProxyPort, prepareProxyFetch } from "./fetch.js";
import { BodyIntake } from "./bodyIntake.js";

const NativeRequest = globalThis.Request;
afterEach(() => vi.unstubAllGlobals());

function bodyWithoutStreams(): void {
  // Firefox exposes Body.blob() while Request.body is absent. Keep native Body
  // consumption rather than faking serialized bytes or proxy transport.
  class RequestWithoutBodyStream extends NativeRequest {
    constructor(input: RequestInfo | URL, init?: RequestInit) {
      super(input, init);
      Object.defineProperty(this, "body", { value: undefined });
    }
  }
  vi.stubGlobal("Request", RequestWithoutBodyStream);
}

describe("portable proxy request bodies", () => {
  it("times out an unanswered controller dispatch", async () => {
    const { request, signal } = await prepareProxyFetch("/");
    let peer: MessagePort | undefined;
    vi.useFakeTimers();
    try {
      const response = fetchProxyPort((_, port) => { peer = port; }, request, signal);
      const rejected = expect(response).rejects.toMatchObject({ code: "timeout" });
      await vi.advanceTimersByTimeAsync(10_000);
      await rejected;
    } finally { peer?.close(); vi.useRealTimers(); }
  });
  it("bounds combined uploads before admission and releases canceled reservations", async () => {
    const intake = new BodyIntake(2, 4);
    const abort = new AbortController();
    let pulled!: () => void;
    const reading = new Promise<void>(resolve => { pulled = resolve; });
    const source = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(Uint8Array.of(1, 2, 3)); }, pull() { pulled(); } }, { highWaterMark: 0 });
    const init = { method: "POST", body: source, duplex: "half", signal: abort.signal };
    const first = prepareProxyFetch("/api", init, undefined, 4, intake);
    await reading;
    await expect(prepareProxyFetch("/api", { method: "POST", body: "12" }, undefined, 4, intake)).rejects.toMatchObject({ code: "resource_exhausted" });
    abort.abort();
    await expect(first).rejects.toBeDefined();
    await expect(prepareProxyFetch("/api", { method: "POST", body: "1234" }, undefined, 4, intake)).resolves.toBeDefined();
  });
  it("preserves POST bytes and headers when Request.body is unavailable", async () => {
    bodyWithoutStreams();
    const input = new Request("https://app.example/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"value":42}' });
    const { request } = await prepareProxyFetch(input, undefined, "https://app.example");
    expect(new TextDecoder().decode(request.body)).toBe('{"value":42}');
    expect(request.headers).toContainEqual({ name: "content-type", value: "application/json" });
    expect(request.method).toBe("POST");
  });

  it("admits overlapping small uploads without streams within one byte budget", async () => {
    bodyWithoutStreams();
    const intake = new BodyIntake(2, 4);
    const upload = () => prepareProxyFetch("/api", { method: "POST", body: "{}" }, undefined, 4, intake);
    const results = await Promise.all([upload(), upload()]);
    expect(results.map(result => result.request.body?.byteLength)).toEqual([2, 2]);
  });

  it("keeps empty GET requests bodyless without Request.body", async () => {
    bodyWithoutStreams();
    expect((await prepareProxyFetch("/api")).request.body).toBeUndefined();
  });

  it("enforces the request budget before copying a non-streaming body", async () => {
    bodyWithoutStreams();
    await expect(prepareProxyFetch("/api", { method: "POST", body: "oversized" }, undefined, 4)).rejects.toMatchObject({ code: "resource_exhausted" });
  });

  it("preserves cancellation on the non-streaming body path", async () => {
    bodyWithoutStreams();
    const abort = new AbortController(); abort.abort();
    await expect(prepareProxyFetch("/api", { method: "POST", body: "value", signal: abort.signal })).rejects.toBeDefined();
  });
});
