import { describe, expect, test } from "vitest";
import { base64urlDecode, base64urlEncode } from "./base64url.js";

describe("base64url", () => {
  test("encode/decode roundtrip", () => {
    const input = new Uint8Array([0, 1, 2, 250, 251, 252]);
    const enc = base64urlEncode(input);
    const dec = base64urlDecode(enc);
    expect(Array.from(dec)).toEqual(Array.from(input));
  });

  test("decode handles missing padding", () => {
    const input = new Uint8Array([255, 254, 253]);
    const enc = base64urlEncode(input);
    const trimmed = enc.replace(/=+$/, "");
    const dec = base64urlDecode(trimmed);
    expect(Array.from(dec)).toEqual(Array.from(input));
  });

  test("encode uses url-safe alphabet", () => {
    const input = new Uint8Array([251, 255]);
    const enc = base64urlEncode(input);
    expect(enc.includes("+")).toBe(false);
    expect(enc.includes("/")).toBe(false);
  });

  test("decode rejects invalid input", () => {
    expect(() => base64urlDecode("!!!!")).toThrow();
    expect(() => base64urlDecode("Zg=")).toThrow();
    expect(() => base64urlDecode("A")).toThrow(); // invalid length (1 mod 4)
  });
});
