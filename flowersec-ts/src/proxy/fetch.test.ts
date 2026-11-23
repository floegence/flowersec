import { afterEach, describe, expect, it, vi } from "vitest";
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
