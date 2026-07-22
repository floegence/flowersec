import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  InnerTypeV2,
  computeOpenHashV2,
  decodeInnerRecordV2,
  decodeOpenACKV2,
  decodeOpenRejectV2,
  decodeSetupPrefaceV2,
  decodeStreamKeyUpdateACKV2,
  deriveControlMaterial,
  deriveEpochRoots,
  deriveEpochZero,
  deriveNextEpoch,
  encodeInnerRecordV2,
  encodeOpenPayload,
  encodeOpenACKV2,
  encodeOpenRejectV2,
  encodeStreamKeyUpdateACKV2,
  verifySetupMAC,
  type DirectionV2,
} from "./protocol.js";

type CryptoVector = Readonly<{
  session_prk_hex: string;
  h3_hex: string;
  direction: 1 | 2;
  epoch: number;
  fss2_hex: string;
}>;

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/crypto_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ vectors: readonly CryptoVector[] }>;
const sessionWireFixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/session_wire_vectors.json", import.meta.url), "utf8"),
) as Readonly<{
  stream_key_update_ack: readonly Readonly<{
    logical_id_hex: string;
    transition_id_hex: string;
    next_epoch_hex: string;
    payload_hex: string;
  }>[];
}>;
const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));

describe("transport v2 session wire", () => {
  test("decodes and authenticates FSS2 and derives control/next epoch material", () => {
    const vector = fixture.vectors[0]!;
    const roots = deriveEpochZero(fromHex(vector.session_prk_hex), vector.direction as DirectionV2);
    const preface = decodeSetupPrefaceV2(fromHex(vector.fss2_hex));
    expect(preface).toMatchObject({ openerRole: 1, logicalStreamID: 1n, initialSendEpoch: 0 });
    expect(verifySetupMAC(roots.setupRoot, fromHex(vector.h3_hex), preface)).toBe(true);

    const control = deriveControlMaterial(roots.controlRoot, fromHex(vector.h3_hex), vector.direction, 0);
    expect(control.recordKey).toHaveLength(32);
    expect(control.noncePrefix).toHaveLength(4);
    const nextSecret = deriveNextEpoch(roots.rekeyRoot, fromHex(vector.h3_hex), vector.direction, 1);
    const nextRoots = deriveEpochRoots(nextSecret);
    expect(nextRoots.epochSecret).toEqual(nextSecret);
    expect(nextRoots.controlRoot).not.toEqual(roots.controlRoot);
  });

  test("encodes every inner type with exact fixed-size validation", () => {
    const sizes = new Map<InnerTypeV2, number>([
      [InnerTypeV2.OpenACK, 32],
      [InnerTypeV2.OpenReject, 34],
      [InnerTypeV2.StreamKeyUpdate, 12],
      [InnerTypeV2.Ping, 8],
      [InnerTypeV2.Pong, 8],
      [InnerTypeV2.SessionKeyUpdate, 20],
      [InnerTypeV2.StreamReset, 10],
      [InnerTypeV2.GoAway, 10],
      [InnerTypeV2.SessionClose, 2],
      [InnerTypeV2.SessionKeyUpdateACK, 20],
      [InnerTypeV2.StreamKeyUpdateACK, 20],
    ]);
    for (const [type, size] of sizes) {
      const payload = new Uint8Array(size);
      const raw = encodeInnerRecordV2(type, payload);
      expect(decodeInnerRecordV2(raw)).toEqual({ type, payload });
      expect(() => encodeInnerRecordV2(type, new Uint8Array(size + 1))).toThrow();
    }
    for (const type of [InnerTypeV2.FIN, InnerTypeV2.SessionReady, InnerTypeV2.SessionReadyACK]) {
      expect(decodeInnerRecordV2(encodeInnerRecordV2(type, new Uint8Array()))).toEqual({
        type,
        payload: new Uint8Array(),
      });
    }
    expect(Buffer.from(encodeInnerRecordV2(InnerTypeV2.Data, new TextEncoder().encode("abc"))).toString("hex"))
      .toBe("0400000000000003616263");
    expect(() => encodeInnerRecordV2(InnerTypeV2.Data, new Uint8Array())).toThrow();
    expect(() => decodeInnerRecordV2(Uint8Array.of(255, 0, 0, 0, 0, 0, 0, 0))).toThrow();
  });

  test("binds OPEN ACK and REJECT to the exact OPEN bytes", () => {
    const open = encodeOpenPayload({
      logicalStreamID: 1n,
      fss2Hash: new Uint8Array(32),
      kind: "echo",
      metadata: new TextEncoder().encode("{}"),
    });
    const hash = computeOpenHashV2(open);
    expect(decodeOpenACKV2(encodeOpenACKV2(hash))).toEqual(hash);
    const reject = decodeOpenRejectV2(encodeOpenRejectV2(hash, 3));
    expect(reject).toEqual({ openHash: hash, reason: 3, knownReason: true });
    const unknown = new Uint8Array(34);
    unknown.set(hash);
    new DataView(unknown.buffer).setUint16(32, 99, false);
    expect(decodeOpenRejectV2(unknown)).toEqual({ openHash: hash, reason: 99, knownReason: false });
    expect(() => encodeOpenRejectV2(hash, 99)).toThrow();
  });

  test("matches the shared logical-id-first STREAM_KEY_UPDATE_ACK vector", () => {
    const vector = sessionWireFixture.stream_key_update_ack[0]!;
    const value = {
      logicalStreamID: BigInt(`0x${vector.logical_id_hex}`),
      transition: BigInt(`0x${vector.transition_id_hex}`),
      epoch: Number.parseInt(vector.next_epoch_hex, 16),
    } as const;
    const encoded = encodeStreamKeyUpdateACKV2(value);
    expect(Buffer.from(encoded).toString("hex")).toBe(vector.payload_hex);
    expect(decodeStreamKeyUpdateACKV2(fromHex(vector.payload_hex))).toEqual(value);
  });
});
