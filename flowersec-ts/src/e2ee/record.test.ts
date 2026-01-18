import { describe, expect, test } from "vitest";
import { decryptRecord, encryptRecord, maxPlaintextBytes, RecordError } from "./record.js";
import { RECORD_FLAG_APP } from "./constants.js";
import { u32be } from "../utils/bin.js";

function makeFrame(): { key: Uint8Array; noncePrefix: Uint8Array; frame: Uint8Array } {
  const key = new Uint8Array(32).fill(1);
  const noncePrefix = new Uint8Array(4).fill(2);
  const frame = encryptRecord(key, noncePrefix, RECORD_FLAG_APP, 1n, new Uint8Array([1, 2, 3]), 1 << 20);
  return { key, noncePrefix, frame };
}

describe("record", () => {
  test("encryptRecord validates key and nonce length", () => {
    const key = new Uint8Array(31);
    const nonce = new Uint8Array(4);
    expect(() => encryptRecord(key, nonce, RECORD_FLAG_APP, 1n, new Uint8Array(), 1 << 20)).toThrow(/key must be 32 bytes/);
    expect(() => encryptRecord(new Uint8Array(32), new Uint8Array(3), RECORD_FLAG_APP, 1n, new Uint8Array(), 1 << 20)).toThrow(/noncePrefix must be 4 bytes/);
  });

  test("encryptRecord enforces maxRecordBytes", () => {
    const key = new Uint8Array(32).fill(1);
    const nonce = new Uint8Array(4).fill(2);
    expect(() => encryptRecord(key, nonce, RECORD_FLAG_APP, 1n, new Uint8Array(10), 10)).toThrow(/record too large/);
  });

  test("decryptRecord validates key and nonce length", () => {
    const { frame } = makeFrame();
    expect(() => decryptRecord(new Uint8Array(31), new Uint8Array(4), frame, 1n, 1 << 20)).toThrow(/key must be 32 bytes/);
    expect(() => decryptRecord(new Uint8Array(32), new Uint8Array(3), frame, 1n, 1 << 20)).toThrow(/noncePrefix must be 4 bytes/);
  });

  test("decryptRecord validates header fields", () => {
    const { key, noncePrefix, frame } = makeFrame();

    const badMagic = frame.slice();
    badMagic[0] = 0x00;
    expect(() => decryptRecord(key, noncePrefix, badMagic, 1n, 1 << 20)).toThrow(/bad record magic/);

    const badVersion = frame.slice();
    badVersion[4] = 9;
    expect(() => decryptRecord(key, noncePrefix, badVersion, 1n, 1 << 20)).toThrow(/bad record version/);

    const badFlag = frame.slice();
    badFlag[5] = 9;
    expect(() => decryptRecord(key, noncePrefix, badFlag, 1n, 1 << 20)).toThrow(/bad record flag/);

    expect(() => decryptRecord(key, noncePrefix, frame, 2n, 1 << 20)).toThrow(/bad seq/);
  });

  test("decryptRecord validates length mismatch", () => {
    const { key, noncePrefix, frame } = makeFrame();
    const badLen = frame.slice();
    badLen.set(u32be(1), 14);
    expect(() => decryptRecord(key, noncePrefix, badLen, 1n, 1 << 20)).toThrow(/length mismatch/);
  });

  test("decryptRecord enforces maxRecordBytes", () => {
    const { key, noncePrefix, frame } = makeFrame();
    expect(() => decryptRecord(key, noncePrefix, frame, 1n, 10)).toThrow(RecordError);
  });

  test("maxPlaintextBytes returns capped size", () => {
    expect(maxPlaintextBytes(0)).toBe(0);
    expect(maxPlaintextBytes(4 + 1 + 1 + 8 + 4 + 16)).toBe(0);
    expect(maxPlaintextBytes(64)).toBe(64 - (4 + 1 + 1 + 8 + 4) - 16);
  });
});
