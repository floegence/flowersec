import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { transportV4DH as dh, transportV4Registry } from "../generated/transportV4Registry.js";
import { profileDHReference, profileDHPublicReference } from "./profileDHReference.js";

type Vector = { id: string; profile: string; private_hex: string; public_hex: string | null; shared_hex: string | null; accept: boolean };
const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/profile_dh.json", import.meta.url), "utf8")) as {
  schema_sha256: string; policy_revision: number; vectors: Vector[]; keys: Vector[];
};
const bytes = (hex: string | null) => Uint8Array.from(Buffer.from(hex ?? "", "hex"));

describe("v4.profile_dh.ts_reference", () => {
  it("binds the generated policy and rejects unknown profiles", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    expect(corpus.policy_revision).toBe((JSON.parse(dh.PolicyJSON) as { revision: number }).revision);
    expect(corpus.vectors.length).toBeGreaterThan(0);
    expect(corpus.keys.length).toBeGreaterThan(0);
    expect(() => profileDHReference("unregistered", new Uint8Array(32), new Uint8Array(32))).toThrow(dh.Failure);
  });
  for (const [kind, vectors] of [["dh", corpus.vectors], ["key", corpus.keys]] as const) {
    for (const v of vectors) it(v.id, () => {
      const privateKey = bytes(v.private_hex), publicKey = bytes(v.public_hex);
      const beforePrivate = privateKey.slice(), beforePublic = publicKey.slice();
      const invoke = () => kind === "dh" ? profileDHReference(v.profile, privateKey, publicKey)
        : profileDHPublicReference(v.profile, privateKey);
      if (v.accept) expect(invoke()).toEqual(bytes(kind === "dh" ? v.shared_hex : v.public_hex));
      else expect(invoke).toThrow(dh.Failure);
      expect(privateKey).toEqual(beforePrivate);
      expect(publicKey).toEqual(beforePublic);
    });
  }
});
