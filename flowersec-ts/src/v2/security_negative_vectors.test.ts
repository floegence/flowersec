import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { decodeInnerRecordV2, decodeOpenPayload, decodeRecordHeader, decodeSetupPrefaceV2 } from "./protocol.js";
import { decodeFSA2ResponseV2 } from "./artifact.js";
import { parseArtifact } from "./opaqueArtifact.js";

type SecurityVector = { id: string; kind: string; value: string };
const fixture = JSON.parse(readFileSync(new URL("../../../testdata/transport_v2/security_negative_vectors.json", import.meta.url), "utf8")) as {
  version: number; profile: string; vectors: SecurityVector[];
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
});
