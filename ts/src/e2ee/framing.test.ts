import { describe, expect, test } from "vitest";
import { decodeHandshakeFrame, encodeHandshakeFrame, HANDSHAKE_HEADER_LEN, looksLikeRecordFrame, RECORD_HEADER_LEN, encodeU64beBigint, decodeU64beBigint } from "./framing.js";
import { HANDSHAKE_TYPE_INIT, HANDSHAKE_TYPE_RESP, PROTOCOL_VERSION, RECORD_MAGIC } from "./constants.js";
import { u32be } from "../utils/bin.js";

const te = new TextEncoder();

describe("e2ee framing", () => {
  test("decodeHandshakeFrame validates header", () => {
    const payload = te.encode("{}");
    const frame = encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, payload);

    const badMagic = frame.slice();
    badMagic[0] = 0x00;
    expect(() => decodeHandshakeFrame(badMagic, 1024)).toThrow(/bad handshake magic/);

    const badVersion = frame.slice();
    badVersion[4] = PROTOCOL_VERSION + 1;
    expect(() => decodeHandshakeFrame(badVersion, 1024)).toThrow(/bad handshake version/);

    const badLen = frame.slice();
    badLen.set(u32be(100), 6);
    expect(() => decodeHandshakeFrame(badLen, 1024)).toThrow(/handshake length mismatch/);
  });

  test("decodeHandshakeFrame enforces max payload", () => {
    const payload = new Uint8Array(10);
    const frame = encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, payload);
    expect(() => decodeHandshakeFrame(frame, 4)).toThrow(/handshake payload too large/);
  });

  test("looksLikeRecordFrame validates header shape", () => {
    const header = new Uint8Array(RECORD_HEADER_LEN);
    header.set(te.encode(RECORD_MAGIC), 0);
    header[4] = PROTOCOL_VERSION;
    header.set(u32be(0), 14);

    expect(looksLikeRecordFrame(header, 0)).toBe(true);
    expect(looksLikeRecordFrame(header, 1)).toBe(true);

    const bad = header.slice();
    bad[0] = 0x00;
    expect(looksLikeRecordFrame(bad, 0)).toBe(false);
  });

  test("encodeU64beBigint and decodeU64beBigint are inverse", () => {
    const v = 0x0102030405060708n;
    const buf = encodeU64beBigint(v);
    expect(buf.length).toBe(8);
    const out = decodeU64beBigint(buf, 0);
    expect(out).toBe(v);
  });

  test("handshake header length is stable", () => {
    const payload = new Uint8Array(0);
    const frame = encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, payload);
    expect(frame.length).toBe(HANDSHAKE_HEADER_LEN);
  });
});
