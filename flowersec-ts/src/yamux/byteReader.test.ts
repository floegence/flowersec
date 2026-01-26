import { describe, expect, test } from "vitest";
import { ByteReader } from "./byteReader.js";
import { StreamEOFError } from "./errors.js";

describe("ByteReader", () => {
  test("reads across multiple chunks", async () => {
    const chunks = [new Uint8Array([1, 2]), new Uint8Array([3, 4, 5])];
    const reader = new ByteReader(async () => chunks.shift() ?? null);
    await expect(reader.readExactly(4)).resolves.toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(reader.bufferedBytes()).toBe(1);
  });

  test("skips empty chunks", async () => {
    const chunks = [new Uint8Array(), new Uint8Array([9])];
    const reader = new ByteReader(async () => chunks.shift() ?? null);
    await expect(reader.readExactly(1)).resolves.toEqual(new Uint8Array([9]));
  });

  test("rejects on EOF", async () => {
    const reader = new ByteReader(async () => null);
    await expect(reader.readExactly(1)).rejects.toBeInstanceOf(StreamEOFError);
  });

  test("rejects negative length", async () => {
    const reader = new ByteReader(async () => null);
    await expect(reader.readExactly(-1)).rejects.toThrow(/invalid length/);
  });
});
