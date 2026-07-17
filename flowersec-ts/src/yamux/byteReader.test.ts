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
    await expect(reader.discardExactly(-1)).rejects.toThrow(/invalid length/);
  });

  test("releases fully discarded fragmented chunks", async () => {
    let remaining = 5_000;
    const reader = new ByteReader(async () => remaining-- > 0 ? new Uint8Array([1]) : null);

    await reader.discardExactly(5_000);

    expect(reader.bufferedBytes()).toBe(0);
    const state = reader as unknown as { chunks: Uint8Array[]; chunkHead: number; headOff: number };
    expect(state.chunks).toHaveLength(0);
    expect(state.chunkHead).toBe(0);
    expect(state.headOff).toBe(0);
  });

  test("preserves unread bytes across mixed discard and read operations", async () => {
    const chunks = [
      new Uint8Array([1, 2, 3]),
      new Uint8Array([4, 5]),
      new Uint8Array([6, 7, 8]),
    ];
    const reader = new ByteReader(async () => chunks.shift() ?? null);

    await reader.discardExactly(4);
    await expect(reader.readExactly(3)).resolves.toEqual(new Uint8Array([5, 6, 7]));
    await expect(reader.readExactly(1)).resolves.toEqual(new Uint8Array([8]));
    expect(reader.bufferedBytes()).toBe(0);
  });
});
