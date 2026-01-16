import { describe, expect, test } from "vitest";
import { readU32be, readU64be, u16be, u32be, u64be } from "./bin.js";

describe("bin utils", () => {
  test("u16be and u32be encode big-endian", () => {
    expect(Array.from(u16be(0x1234))).toEqual([0x12, 0x34]);
    expect(Array.from(u32be(0x12345678))).toEqual([0x12, 0x34, 0x56, 0x78]);
  });

  test("u64be and readU64be roundtrip", () => {
    const v = 0x0102030405060708n;
    const buf = u64be(v);
    expect(readU64be(buf, 0)).toBe(v);
  });

  test("readU32be roundtrip", () => {
    const v = 0x90abcdef;
    const buf = u32be(v);
    expect(readU32be(buf, 0)).toBe(v >>> 0);
  });
});
