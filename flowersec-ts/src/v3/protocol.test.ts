import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  CipherSuiteV3,
  ProtocolV3Error,
  buildDataInner,
  buildRecordAAD,
  computeFSS3HashV3,
  computeValidatedFSS3HashV3Internal,
  computeSetupMAC,
  decodeRecordHeader,
  decodeSetupPrefaceV3,
  deriveEpochZero,
  deriveStreamMaterial,
  encodeRecordHeader,
  encodeSetupPreface,
  openRecord,
  openRecordWithRawHeaderV3Internal,
  sealRecord,
  sealRecordWireV3Internal,
  type RecordHeaderV3,
  type DirectionV3,
  type SetupPrefaceV3,
} from "./protocol.js";

type CryptoVector = Readonly<{
  direction: number;
  epoch: number;
  logical_stream_id: number;
  sequence: number;
  session_prk_hex: string;
  h3_hex: string;
  epoch_secret_hex: string;
  control_root_hex: string;
  stream_root_hex: string;
  setup_root_hex: string;
  rekey_root_hex: string;
  stream_secret_hex: string;
  record_key_hex: string;
  nonce_prefix_hex: string;
  fss3_hex: string;
  fsr3_header_hex: string;
  inner_hex: string;
  aad_hex: string;
  chacha20_poly1305_ciphertext_hex: string;
  aes_256_gcm_ciphertext_hex: string;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/crypto_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ version: number; profile: string; vectors: readonly CryptoVector[] }>;
const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("transport v3 record protocol", () => {
  test("matches the shared roots, FSS3, FSR3, and AEAD vectors", () => {
    expect(fixture.version).toBe(3);
    expect(fixture.profile).toBe("flowersec/3");
    for (const vector of fixture.vectors) {
      const direction = vector.direction as DirectionV3;
      const h3 = fromHex(vector.h3_hex);
      const roots = deriveEpochZero(fromHex(vector.session_prk_hex), direction);
      expect(hex(roots.epochSecret)).toBe(vector.epoch_secret_hex);
      expect(hex(roots.controlRoot)).toBe(vector.control_root_hex);
      expect(hex(roots.streamRoot)).toBe(vector.stream_root_hex);
      expect(hex(roots.setupRoot)).toBe(vector.setup_root_hex);
      expect(hex(roots.rekeyRoot)).toBe(vector.rekey_root_hex);

      const material = deriveStreamMaterial(
        roots.streamRoot,
        h3,
        BigInt(vector.logical_stream_id),
        direction,
        vector.epoch,
      );
      expect(hex(material.secret)).toBe(vector.stream_secret_hex);
      expect(hex(material.recordKey)).toBe(vector.record_key_hex);
      expect(hex(material.noncePrefix)).toBe(vector.nonce_prefix_hex);

      const prefaceWithoutMAC: SetupPrefaceV3 = {
        openerRole: 1,
        logicalStreamID: BigInt(vector.logical_stream_id),
        initialSendEpoch: vector.epoch,
        setupMAC: new Uint8Array(32),
      };
      const setupMAC = computeSetupMAC(roots.setupRoot, h3, prefaceWithoutMAC);
      const rawPreface = encodeSetupPreface({ ...prefaceWithoutMAC, setupMAC });
      expect(hex(rawPreface)).toBe(vector.fss3_hex);
      expect(decodeSetupPrefaceV3(rawPreface).setupMAC).toEqual(setupMAC);
      expect(computeValidatedFSS3HashV3Internal(rawPreface)).toEqual(computeFSS3HashV3(rawPreface));

      const inner = buildDataInner(Uint8Array.from([0x61, 0x62, 0x63]));
      expect(hex(inner)).toBe(vector.inner_hex);
      const header: RecordHeaderV3 = {
        epoch: vector.epoch,
        sequence: BigInt(vector.sequence),
        ciphertextLength: inner.length + 16,
      };
      const rawHeader = encodeRecordHeader(header);
      expect(hex(rawHeader)).toBe(vector.fsr3_header_hex);
      expect(decodeRecordHeader(rawHeader)).toEqual(header);
      expect(hex(buildRecordAAD(h3, BigInt(vector.logical_stream_id), direction, rawHeader))).toBe(vector.aad_hex);

      for (const [suite, expected] of [
        [CipherSuiteV3.ChaCha20Poly1305, vector.chacha20_poly1305_ciphertext_hex],
        [CipherSuiteV3.AES256GCM, vector.aes_256_gcm_ciphertext_hex],
      ] as const) {
        const ciphertext = sealRecord(suite, material, h3, BigInt(vector.logical_stream_id), direction, header, inner);
        expect(hex(ciphertext)).toBe(expected);
        expect(openRecord(suite, material, h3, BigInt(vector.logical_stream_id), direction, header, ciphertext))
          .toEqual(inner);
        const sealed = sealRecordWireV3Internal(
          suite, material, h3, BigInt(vector.logical_stream_id), direction, header, inner,
        );
        expect(sealed.rawHeader).toEqual(rawHeader);
        expect(sealed.ciphertext).toEqual(ciphertext);
        expect(openRecordWithRawHeaderV3Internal(
          suite, material, h3, BigInt(vector.logical_stream_id), direction, header, rawHeader, ciphertext,
        )).toEqual(inner);
      }
    }
  });

  test("rejects v2 FSS2 and FSR2 frames before cryptographic processing", () => {
    const vector = fixture.vectors[0]!;
    for (const decode of [decodeSetupPrefaceV3, decodeRecordHeader]) {
      const source = fromHex(decode === decodeSetupPrefaceV3 ? vector.fss3_hex : vector.fsr3_header_hex);
      source[3] = 0x32;
      source[4] = 2;
      expect(() => decode(source)).toThrowError(ProtocolV3Error);
    }
  });

  test("public record helpers reject invalid AAD domain inputs", () => {
    const vector = fixture.vectors[0]!;
    const direction = vector.direction as DirectionV3;
    const h3 = fromHex(vector.h3_hex);
    const roots = deriveEpochZero(fromHex(vector.session_prk_hex), direction);
    const material = deriveStreamMaterial(
      roots.streamRoot,
      h3,
      BigInt(vector.logical_stream_id),
      direction,
      vector.epoch,
    );
    const inner = buildDataInner(Uint8Array.of(1));
    const header: RecordHeaderV3 = {
      epoch: vector.epoch,
      sequence: BigInt(vector.sequence),
      ciphertextLength: inner.length + 16,
    };
    const ciphertext = sealRecord(
      CipherSuiteV3.ChaCha20Poly1305,
      material,
      h3,
      BigInt(vector.logical_stream_id),
      direction,
      header,
      inner,
    );
    const badDirection = 3 as DirectionV3;
    for (const operation of [
      () => sealRecord(CipherSuiteV3.ChaCha20Poly1305, material, new Uint8Array(31), 1n, direction, header, inner),
      () => sealRecord(CipherSuiteV3.ChaCha20Poly1305, material, h3, 1n, badDirection, header, inner),
      () => openRecord(CipherSuiteV3.ChaCha20Poly1305, material, new Uint8Array(31), 1n, direction, header, ciphertext),
      () => openRecord(CipherSuiteV3.ChaCha20Poly1305, material, h3, 1n, badDirection, header, ciphertext),
    ]) {
      expect(operation).toThrowError(ProtocolV3Error);
    }
  });
});
