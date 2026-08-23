import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  ProtocolV3Error,
  computeOpenHashV3,
  computeValidatedOpenHashV3Internal,
  decodeOpenPayload,
  decodeStreamKeyUpdateACKV3,
  encodeOpenPayload,
  encodeOpenPayloadFromMetadataV3Internal,
  encodeStreamKeyUpdateACKV3,
} from "./protocol.js";

type OpenVector = Readonly<{
  id: string;
  kind?: string;
  kind_utf8_hex?: string;
  metadata_json?: string;
  metadata_hex?: string;
}>;

const openFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/open_unicode_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ unicode_version: string; positive: readonly OpenVector[]; negative: readonly OpenVector[] }>;
const wireFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/session_wire_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  version: number;
  profile: string;
  stream_key_update_ack: readonly Readonly<{
    logical_id_hex: string;
    transition_id_hex: string;
    next_epoch_hex: string;
    payload_hex: string;
  }>[];
  transition_boundary: Readonly<{
    maximum_transition_id_hex: string;
    next_after_maximum_hex: string;
    maximum_is_usable_once: boolean;
    exhaustion_error: string;
    exhaustion_goaway_reason: number;
    receive_after_maximum: string;
    goaway_delivery_failure: string;
  }>;
  epoch_boundary: Readonly<{
    maximum_epoch_hex: string;
    maximum_is_usable: boolean;
    rekey_after_maximum: string;
    exhaustion_goaway_reason: number;
    receive_after_maximum: string;
    goaway_delivery_failure: string;
  }>;
}>;
const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));

describe("transport v3 inherited session wire boundaries", () => {
  test("accepts every Unicode 15.1 OPEN vector", () => {
    expect(openFixture.unicode_version).toBe("15.1.0");
    for (const vector of openFixture.positive) {
      const encoded = encodeOpenPayload({
        logicalStreamID: 1n,
        fss3Hash: new Uint8Array(32),
        kind: vector.kind!,
        metadata: bytes(vector.metadata_json!),
      });
      const decoded = decodeOpenPayload(encoded);
      expect(decoded.kind, vector.id).toBe(vector.kind);
      expect(new TextDecoder().decode(decoded.metadata), vector.id).toBe(vector.metadata_json);
      const internal = encodeOpenPayloadFromMetadataV3Internal({
        logicalStreamID: 1n,
        fss3Hash: new Uint8Array(32),
        kind: vector.kind!,
        metadata: JSON.parse(vector.metadata_json!) as unknown,
      });
      expect(internal, vector.id).toEqual(encoded);
      expect(computeValidatedOpenHashV3Internal(internal), vector.id).toEqual(computeOpenHashV3(encoded));
    }
  });

  test("internal OPEN encoding preserves strict metadata validation", () => {
    const encode = (metadata: unknown) => encodeOpenPayloadFromMetadataV3Internal({
      logicalStreamID: 1n,
      fss3Hash: new Uint8Array(32),
      kind: "data",
      metadata,
    });
    expect(() => encode({ unsafe: Number.MAX_SAFE_INTEGER + 1 })).toThrowError(ProtocolV3Error);
    expect(() => encode({ negative_zero: -0 })).toThrowError(ProtocolV3Error);
    expect(() => encode({ "control\u0000": true })).toThrowError(ProtocolV3Error);

    let reads = 0;
    const changing = Object.defineProperty({}, "value", {
      enumerable: true,
      get() {
        reads++;
        return reads === 1 ? 1 : Number.MAX_SAFE_INTEGER + 1;
      },
    });
    const decoded = decodeOpenPayload(encode(changing));
    expect(new TextDecoder().decode(decoded.metadata)).toBe('{"value":1}');
    expect(reads).toBe(1);
  });

  test("rejects every invalid OPEN Unicode or canonical encoding", () => {
    for (const vector of openFixture.negative) {
      const metadata = vector.metadata_hex === undefined
        ? bytes(vector.metadata_json!)
        : fromHex(vector.metadata_hex);
      if (vector.kind_utf8_hex !== undefined) {
        const kind = fromHex(vector.kind_utf8_hex);
        const raw = new Uint8Array(46 + kind.length + metadata.length);
        new DataView(raw.buffer).setBigUint64(0, 1n, false);
        new DataView(raw.buffer).setUint16(40, kind.length, false);
        new DataView(raw.buffer).setUint32(42, metadata.length, false);
        raw.set(kind, 46);
        raw.set(metadata, 46 + kind.length);
        expect(() => decodeOpenPayload(raw), vector.id).toThrowError();
      } else {
        expect(() => encodeOpenPayload({
          logicalStreamID: 1n,
          fss3Hash: new Uint8Array(32),
          kind: vector.kind!,
          metadata,
        }), vector.id).toThrowError();
      }
    }
  });

  test("matches the STREAM_KEY_UPDATE_ACK wire vector", () => {
    expect(wireFixture.version).toBe(3);
    expect(wireFixture.profile).toBe("flowersec/3");
    for (const vector of wireFixture.stream_key_update_ack) {
      const value = {
        logicalStreamID: BigInt(`0x${vector.logical_id_hex}`),
        transition: BigInt(`0x${vector.transition_id_hex}`),
        epoch: Number.parseInt(vector.next_epoch_hex, 16),
      };
      expect(Buffer.from(encodeStreamKeyUpdateACKV3(value)).toString("hex")).toBe(vector.payload_hex);
      expect(decodeStreamKeyUpdateACKV3(fromHex(vector.payload_hex))).toEqual(value);
    }

    expect(wireFixture.transition_boundary).toEqual({
      maximum_transition_id_hex: "ffffffffffffffff",
      next_after_maximum_hex: "0000000000000000",
      maximum_is_usable_once: true,
      exhaustion_error: "resource_exhausted",
      exhaustion_goaway_reason: 5,
      receive_after_maximum: "protocol_failure",
      goaway_delivery_failure: "session_failure",
    });
    expect(wireFixture.epoch_boundary).toEqual({
      maximum_epoch_hex: "ffffffff",
      maximum_is_usable: true,
      rekey_after_maximum: "resource_exhausted",
      exhaustion_goaway_reason: 5,
      receive_after_maximum: "protocol_failure",
      goaway_delivery_failure: "session_failure",
    });
  });
});
