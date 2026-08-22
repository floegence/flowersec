import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import type { CipherSuiteV3, DirectionV3 } from "./protocol.js";
import {
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
    expect(() => encodeUnreliableMessageHeaderV3(0, 0n, 0n, 17)).toThrow("invalid FSD3 expiry");
  });
});
