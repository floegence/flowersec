import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { assertRpcEnvelope } from "../rpc/validate.js";
import { decodeFSB2RequestV2 } from "./artifact.js";
import { decodeClientInitV2 } from "./handshake.js";
import { decodeInnerRecordV2, decodeOpenPayload, decodeRecordHeader, decodeSetupPrefaceV2 } from "./protocol.js";
import { decodeFSA2ResponseV2 } from "./artifact.js";
import { parseArtifact } from "./opaqueArtifact.js";

type SecurityVector = { id: string; kind: string; value: string };
const fixture = JSON.parse(readFileSync(new URL("../../../testdata/transport_v2/security_negative_vectors.json", import.meta.url), "utf8")) as {
  version: number; profile: string; vectors: SecurityVector[];
};
const artifacts = JSON.parse(readFileSync(new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url), "utf8")) as {
  positive: Array<{ artifact_json: string; winners: Array<{ fsb2_hex: string }> }>;
  fsa2: Array<{ frame_hex: string }>;
};
const crypto = JSON.parse(readFileSync(new URL("../../../testdata/transport_v2/crypto_vectors.json", import.meta.url), "utf8")) as {
  vectors: Array<{ fss2_hex: string; fsr2_header_hex: string; inner_hex: string }>;
};
const handshakes = JSON.parse(readFileSync(new URL("../../../testdata/transport_v2/handshake_vectors.json", import.meta.url), "utf8")) as {
  vectors: Array<{ client_init_hex: string }>;
};

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (part) => Number.parseInt(part, 16));
}

describe("shared security negative vectors", () => {
  test("rejects every malformed parser input", () => {
    expect(fixture.version).toBe(1);
    expect(fixture.profile).toBe("flowersec/2");
    for (const vector of fixture.vectors) {
      expect(() => {
        switch (vector.kind) {
          case "artifact_json": parseArtifact(vector.value); break;
          case "fsa2_hex": decodeFSA2ResponseV2(hex(vector.value)); break;
          case "fsr2_hex": decodeRecordHeader(hex(vector.value)); break;
          case "open_hex": decodeOpenPayload(hex(vector.value)); break;
          case "fsc2_hex": decodeSetupPrefaceV2(hex(vector.value)); break;
          case "inner_hex": decodeInnerRecordV2(hex(vector.value)); break;
          default: throw new Error(`unknown security vector ${vector.kind}`);
        }
      }, vector.id).toThrow();
    }
  });

  test("bounded shared-vector mutations fail closed", () => {
    const seeds = [
      ["FSB2", hex(artifacts.positive[0]!.winners[0]!.fsb2_hex), decodeFSB2RequestV2],
      ["FSA2", hex(artifacts.fsa2[0]!.frame_hex), decodeFSA2ResponseV2],
      ["FSS2", hex(crypto.vectors[0]!.fss2_hex), decodeSetupPrefaceV2],
      ["FSR2", hex(crypto.vectors[0]!.fsr2_header_hex), decodeRecordHeader],
      ["inner", hex(crypto.vectors[0]!.inner_hex), decodeInnerRecordV2],
      ["FSH2", hex(handshakes.vectors[0]!.client_init_hex), decodeClientInitV2],
    ] as const;
    for (const [name, seed, decode] of seeds) {
      expect(() => decode(seed), `${name}/valid`).not.toThrow();
      for (const [mutation, raw] of boundedMutations(seed)) {
        expect(() => decode(raw), `${name}/${mutation}`).toThrow();
      }
    }

    const artifact = artifacts.positive[0]!.artifact_json;
    expect(() => parseArtifact(artifact)).not.toThrow();
    for (const [mutation, raw] of boundedTextMutations(artifact)) {
      expect(() => parseArtifact(raw), `artifact/${mutation}`).toThrow();
    }

    const validEnvelope = { type_id: 1, request_id: 1, response_to: 0, payload: {} };
    expect(assertRpcEnvelope(validEnvelope)).toEqual(validEnvelope);
    for (const invalid of [
      { ...validEnvelope, type_id: -1 },
      { ...validEnvelope, request_id: 9_007_199_254_740_992 },
      { ...validEnvelope, response_to: 1.5 },
      { ...validEnvelope, error: { code: 1, message: 2 } },
    ]) {
      expect(() => assertRpcEnvelope(invalid)).toThrow();
    }
  });
});

function boundedMutations(seed: Uint8Array): Array<readonly [string, Uint8Array]> {
  const points = [...new Set([0, 1, 4, 8, 12, Math.floor(seed.length / 2), seed.length - 1])]
    .filter((point) => point >= 0 && point < seed.length);
  const mutations: Array<readonly [string, Uint8Array]> = points.map((point) => [
    `truncate-${point}`,
    seed.slice(0, point),
  ]);
  const trailing = new Uint8Array(seed.length + 1);
  trailing.set(seed);
  trailing[seed.length] = 0;
  mutations.push(["trailing-byte", trailing]);
  return mutations;
}

function boundedTextMutations(seed: string): Array<readonly [string, string]> {
  const points = [...new Set([0, 1, Math.floor(seed.length / 2), seed.length - 1])]
    .filter((point) => point >= 0 && point < seed.length);
  return [
    ...points.map((point) => [`truncate-${point}`, seed.slice(0, point)] as const),
    ["trailing-json", `${seed}{}`] as const,
    ["duplicate-version", seed.replace('"v":2', '"v":2,"v":2')] as const,
    ["unsafe-integer", seed.replace('"max_inbound_streams":64', '"max_inbound_streams":9007199254740992')] as const,
  ];
}
