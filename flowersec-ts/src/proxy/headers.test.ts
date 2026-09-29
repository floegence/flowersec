import { describe, expect, it } from "vitest";
import { inspectProxyHeaders } from "./headers.js";

describe("original proxy HTTP fields", () => {
  it("keeps length assertions despite Connection and preserves repeated octets", () => {
    const facts = inspectProxyHeaders([
      { name: "Connection", value: "Content-Length, X-Tail" },
      { name: "Content-Length", value: "0005, 5" },
      { name: "content-length", value: "5" },
      { name: "x-visible", value: "é" },
      { name: "x-visible", value: "ÿ" },
    ]);
    expect(facts.contentLength).toBe(5n);
    expect(facts.connection).toEqual(new Set(["content-length", "x-tail"]));
    expect(facts.fields.slice(-2)).toEqual([{ name: "x-visible", value: "é" }, { name: "x-visible", value: "ÿ" }]);
    expect(inspectProxyHeaders([{ name: "content-length", value: "9223372036854775807" }]).contentLength).toBe(9223372036854775807n);
  });

  it.each([
    [{ name: "content-length", value: "1, 2" }],
    [{ name: "content-length", value: "+1" }],
    [{ name: "content-length", value: "9223372036854775808" }],
    [{ name: "content-length", value: "1" }, { name: "transfer-encoding", value: "chunked" }, { name: "connection", value: "content-length, transfer-encoding" }],
    [{ name: "connection", value: "x-tail," }],
    [{ name: "connection", value: "x-tail;abc" }],
    [{ name: "content-type", value: "text/plain" }, { name: "content-type", value: "application/json" }],
    [{ name: "x-ignore", value: "\u0100" }],
    [{ name: "x-ignore", value: "\r\nsecret" }],
    [{ name: "x-ignore ", value: "valid" }],
  ])("rejects malformed or conflicting fields before filtering: %j", (...headers) => {
    expect(() => inspectProxyHeaders(headers)).toThrow();
  });
});
