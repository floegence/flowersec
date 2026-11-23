import { describe, expect, test } from "vitest";
import { decodeHeader, encodeHeader, HEADER_LEN } from "./header.js";
import { TYPE_DATA, YAMUX_VERSION } from "./constants.js";

describe("yamux header", () => {
  test("encodeHeader/decodeHeader roundtrip", () => {
    const hdr = encodeHeader({ type: TYPE_DATA, flags: 0x1234, streamId: 99, length: 42 });
    expect(hdr.length).toBe(HEADER_LEN);
    const decoded = decodeHeader(hdr, 0);
    expect(decoded.version).toBe(YAMUX_VERSION);
    expect(decoded.type).toBe(TYPE_DATA);
    expect(decoded.flags).toBe(0x1234);
    expect(decoded.streamId).toBe(99);
    expect(decoded.length).toBe(42);
  });

  test("decodeHeader rejects short buffers", () => {
    const buf = new Uint8Array(HEADER_LEN - 1);
    expect(() => decodeHeader(buf, 0)).toThrow(/header too short/);
  });
});
