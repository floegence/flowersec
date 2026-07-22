import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CipherSuiteV2,
  DirectionV2,
  ProtocolV2Error,
  buildDataInner,
  buildRecordAAD,
  computeSetupMAC,
  decodeRecordHeader,
  deriveEpochZero,
  deriveStreamMaterial,
  encodeRecordHeader,
  encodeSetupPreface,
  openRecord,
  sealRecord,
  type RecordHeaderV2,
  type SetupPrefaceV2,
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
  fss2_hex: string;
  fsr2_header_hex: string;
  inner_hex: string;
  aad_hex: string;
  chacha20_poly1305_ciphertext_hex: string;
  aes_256_gcm_ciphertext_hex: string;
}>;

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/crypto_vectors.json", import.meta.url), "utf8")
) as { version: number; profile: string; vectors: CryptoVector[] };

const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("transport v2 shared crypto vectors", () => {
  it("derives exact roots, setup, record framing, and both AEAD suites", () => {
    expect(fixture.version).toBe(1);
    expect(fixture.profile).toBe("flowersec/2");
    const vector = fixture.vectors[0]!;
    const direction = vector.direction as DirectionV2;
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
      vector.epoch
    );
    expect(hex(material.secret)).toBe(vector.stream_secret_hex);
    expect(hex(material.recordKey)).toBe(vector.record_key_hex);
    expect(hex(material.noncePrefix)).toBe(vector.nonce_prefix_hex);

    const prefaceWithoutMAC: SetupPrefaceV2 = {
      openerRole: 1,
      logicalStreamID: BigInt(vector.logical_stream_id),
      initialSendEpoch: vector.epoch,
      setupMAC: new Uint8Array(32),
    };
    const setupMAC = computeSetupMAC(roots.setupRoot, h3, prefaceWithoutMAC);
    const preface = encodeSetupPreface({ ...prefaceWithoutMAC, setupMAC });
    expect(hex(preface)).toBe(vector.fss2_hex);

    const inner = buildDataInner(Uint8Array.from([0x61, 0x62, 0x63]));
    expect(hex(inner)).toBe(vector.inner_hex);
    const header: RecordHeaderV2 = {
      epoch: vector.epoch,
      sequence: BigInt(vector.sequence),
      ciphertextLength: inner.length + 16,
    };
    const rawHeader = encodeRecordHeader(header);
    expect(hex(rawHeader)).toBe(vector.fsr2_header_hex);
    expect(decodeRecordHeader(rawHeader)).toEqual(header);
    expect(hex(buildRecordAAD(h3, BigInt(vector.logical_stream_id), direction, rawHeader))).toBe(vector.aad_hex);

    const chacha = sealRecord(
      CipherSuiteV2.ChaCha20Poly1305,
      material,
      h3,
      BigInt(vector.logical_stream_id),
      direction,
      header,
      inner
    );
    expect(hex(chacha)).toBe(vector.chacha20_poly1305_ciphertext_hex);
    expect(
      openRecord(
        CipherSuiteV2.ChaCha20Poly1305,
        material,
        h3,
        BigInt(vector.logical_stream_id),
        direction,
        header,
        chacha
      )
    ).toEqual(inner);

    const aes = sealRecord(
      CipherSuiteV2.AES256GCM,
      material,
      h3,
      BigInt(vector.logical_stream_id),
      direction,
      header,
      inner
    );
    expect(hex(aes)).toBe(vector.aes_256_gcm_ciphertext_hex);
    expect(
      openRecord(
        CipherSuiteV2.AES256GCM,
        material,
        h3,
        BigInt(vector.logical_stream_id),
        direction,
        header,
        aes
      )
    ).toEqual(inner);
  });

  it("authenticates stream, direction, sequence/header, and ciphertext", () => {
    const vector = fixture.vectors[0]!;
    const direction = vector.direction as DirectionV2;
    const h3 = fromHex(vector.h3_hex);
    const roots = deriveEpochZero(fromHex(vector.session_prk_hex), direction);
    const material = deriveStreamMaterial(roots.streamRoot, h3, 1n, direction, 0);
    const header = decodeRecordHeader(fromHex(vector.fsr2_header_hex));
    const ciphertext = fromHex(vector.chacha20_poly1305_ciphertext_hex);
    const attempts = [
      () => openRecord(CipherSuiteV2.ChaCha20Poly1305, material, h3, 3n, direction, header, ciphertext),
      () => openRecord(CipherSuiteV2.ChaCha20Poly1305, material, h3, 1n, DirectionV2.ServerToClient, header, ciphertext),
      () => openRecord(CipherSuiteV2.ChaCha20Poly1305, material, h3, 1n, direction, { ...header, sequence: 1n }, ciphertext),
      () => {
        const changed = ciphertext.slice();
        changed[0] ^= 0x80;
        return openRecord(CipherSuiteV2.ChaCha20Poly1305, material, h3, 1n, direction, header, changed);
      },
    ];
    for (const attempt of attempts) expect(attempt).toThrow(ProtocolV2Error);
  });
});
