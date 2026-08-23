import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import type { CipherSuiteV3, DirectionV3 } from "./protocol.js";
import {
  deriveUnreliableMessageMaterialV3,
  encodeUnreliableMessageHeaderV3,
  sealUnreliableMessageDatagramV3,
} from "./unreliableMessage.js";

type DatagramVector = Readonly<{
  suite: 1 | 2;
  h3_b64u: string;
  direction: number;
  epoch: number;
  sequence: number;
  expires_at_unix_ms: number;
  plaintext_b64u: string;
  epoch_secret_b64u: string;
  unreliable_root_b64u: string;
  material_secret_b64u: string;
  record_key_b64u: string;
  nonce_prefix_b64u: string;
  nonce_b64u: string;
  header_hex: string;
  aad_b64u: string;
  ciphertext_b64u: string;
  wire_b64u: string;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/datagram_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ schema_version: number; vectors: readonly DatagramVector[] }>;
const b64u = (value: Uint8Array): string => Buffer.from(value).toString("base64url");

describe("transport v3 FSD3 unreliable messages", () => {
  test("matches every shared datagram vector", () => {
    expect(fixture.schema_version).toBe(3);
    for (const vector of fixture.vectors) {
      const sealed = sealUnreliableMessageDatagramV3({
        suite: vector.suite as CipherSuiteV3,
        epochSecret: base64urlDecode(vector.epoch_secret_b64u),
        h3: base64urlDecode(vector.h3_b64u),
        direction: vector.direction as DirectionV3,
        epoch: vector.epoch,
        sequence: BigInt(vector.sequence),
        expiresAtUnixMs: BigInt(vector.expires_at_unix_ms),
        plaintext: base64urlDecode(vector.plaintext_b64u),
      });
      expect(b64u(sealed.material.unreliableRoot)).toBe(vector.unreliable_root_b64u);
      expect(b64u(sealed.material.materialSecret)).toBe(vector.material_secret_b64u);
      expect(b64u(sealed.material.recordKey)).toBe(vector.record_key_b64u);
      expect(b64u(sealed.material.noncePrefix)).toBe(vector.nonce_prefix_b64u);
      expect(b64u(sealed.nonce)).toBe(vector.nonce_b64u);
      expect(Buffer.from(sealed.header).toString("hex")).toBe(vector.header_hex);
      expect(b64u(sealed.aad)).toBe(vector.aad_b64u);
      expect(b64u(sealed.ciphertext)).toBe(vector.ciphertext_b64u);
      expect(b64u(sealed.wire)).toBe(vector.wire_b64u);
    }
  });

  test("rejects a zero FSD3 expiry", () => {
    expect(() => encodeUnreliableMessageHeaderV3(0, 0n, 0n, 17)).toThrow("invalid FSD3 header");
  });

  test("rejects ciphertext lengths outside the FSD3 wire contract", () => {
    expect(() => encodeUnreliableMessageHeaderV3(0, 0n, 1n, 16)).toThrow("invalid FSD3 header");
    expect(() => encodeUnreliableMessageHeaderV3(0, 0n, 1n, 993)).toThrow("invalid FSD3 header");
  });

  test("rejects fixed-width integers instead of allowing DataView truncation", () => {
    const maxUint64 = (1n << 64n) - 1n;
    expect(() => encodeUnreliableMessageHeaderV3(-1, 0n, 1n, 17)).toThrow("invalid FSD3 header");
    expect(() => encodeUnreliableMessageHeaderV3(0x1_0000_0000, 0n, 1n, 17)).toThrow("invalid FSD3 header");
    expect(() => encodeUnreliableMessageHeaderV3(0, -1n, 1n, 17)).toThrow("invalid FSD3 header");
    expect(() => encodeUnreliableMessageHeaderV3(0, maxUint64 + 1n, 1n, 17)).toThrow("invalid FSD3 header");
    expect(() => encodeUnreliableMessageHeaderV3(0, 0n, maxUint64 + 1n, 17)).toThrow("invalid FSD3 header");

    const maximum = encodeUnreliableMessageHeaderV3(0xffff_ffff, maxUint64, maxUint64, 17);
    const view = new DataView(maximum.buffer, maximum.byteOffset, maximum.byteLength);
    expect(view.getUint32(8, false)).toBe(0xffff_ffff);
    expect(view.getBigUint64(12, false)).toBe(maxUint64);
    expect(view.getBigUint64(20, false)).toBe(maxUint64);

    expect(() => deriveUnreliableMessageMaterialV3(
      new Uint8Array(32),
      new Uint8Array(32),
      0 as DirectionV3,
      0x1_0000_0000,
    )).toThrow("invalid FSD3 uint32");
  });
});
