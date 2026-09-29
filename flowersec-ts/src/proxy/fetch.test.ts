import { afterEach, describe, expect, it, vi } from "vitest";
import { StreamAdmission } from "./admission.js";
import { prepareProxyFetch } from "./fetch.js";

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
  it("preserves POST bytes and headers when Request.body is unavailable", async () => {
    bodyWithoutStreams();
    const input = new Request("https://app.example/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"value":42}' });
    const { request } = await prepareProxyFetch(input, undefined, "https://app.example");
    expect(new TextDecoder().decode(request.body)).toBe('{"value":42}');
    expect(request.headers).toContainEqual({ name: "content-type", value: "application/json" });
    expect(request.method).toBe("POST");
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


describe("proxy body admission", () => {
  it("charges actual small uploads across one shared bounded owner", async () => {
    const admission = new StreamAdmission(2, 1, 8);
    const first = await admission.acquire(0, undefined, true);
    const second = await admission.acquire(0, undefined, true);
    try {
      const prepared = await prepareProxyFetch("/api", { method: "POST", body: "a" }, undefined, 64 * 1024 * 1024, first);
      expect(new TextDecoder().decode(prepared.request.body)).toBe("a");
      // A one-byte upload did not reserve the 64 MiB per-request ceiling.
      second.resizeBody(7);
      expect(() => second.resizeBody(8)).toThrow(/resource_exhausted/);
      first();
      expect(() => second.resizeBody(8)).not.toThrow();
    } finally { first(); second(); admission.close(); }
  });

  it("retains a canceled producer's slot until actual host cancellation settles", async () => {
    const admission = new StreamAdmission(1, 1, 8);
    const permit = await admission.acquire(0, undefined, true);
    let finishCancel!: () => void;
    let readStarted!: () => void;
    const reading = new Promise<void>(resolve => { readStarted = resolve; });
    const source = new ReadableStream<Uint8Array>({
      pull() { readStarted(); },
      cancel() { return new Promise<void>(resolve => { finishCancel = resolve; }); },
    }, { highWaterMark: 0 });
    const abort = new AbortController();
    const pending = prepareProxyFetch("/api", { method: "POST", body: source, signal: abort.signal, duplex: "half" } as RequestInit, undefined, 8, permit);
    await reading;
    abort.abort();
    await expect(pending).rejects.toMatchObject({ code: "canceled" });
    permit();
    await expect(admission.acquire(0, undefined, true)).rejects.toMatchObject({ code: "resource_exhausted" });
    finishCancel();
    await new Promise<void>(resolve => setImmediate(resolve));
    const next = await admission.acquire(0, undefined, true);
    next(); admission.close();
  });
});
