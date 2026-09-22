import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import { transportV4Domains, transportV4Registry } from "../generated/transportV4Registry.js";

// Independent primitive consumption of public fixtures; no runtime trust grant.
type Vector = {
  id: string;
  domain: string | null;
  message_hex: string;
  public_key_hex: string;
  signature_hex: string;
  accept: boolean;
};
const corpus = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v4/signatures.json", import.meta.url), "utf8"),
) as { schema_sha256: string; signing_seed_hex: string; vectors: Vector[] };
const hex = (value: string): Uint8Array => {
  if (!/^(?:[0-9a-f]{2})*$/u.test(value)) throw new Error("invalid fixture hex");
  return Uint8Array.from(Buffer.from(value, "hex"));
};

describe("v4 signature vectors", () => {
  it("binds every Ed25519 domain and an external known answer to the schema", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    const covered = new Set(corpus.vectors.filter((v) => v.accept).map((v) => v.domain));
    expect(covered.has(null)).toBe(true);
    for (const domain of transportV4Domains) {
      if (domain.operation === "ed25519") expect(covered.has(domain.name)).toBe(true);
    }
  });
  for (const vector of corpus.vectors) {
    it(vector.id, () => {
      const message = hex(vector.message_hex), key = hex(vector.public_key_hex), signature = hex(vector.signature_hex);
      const valid = key.length === 32 && signature.length === 64
        && ed25519.verify(signature, message, key, { zip215: false });
      expect(valid).toBe(vector.accept);
      if (vector.accept) {
        const seed = hex(corpus.signing_seed_hex);
        expect(ed25519.getPublicKey(seed)).toEqual(key);
        expect(ed25519.sign(message, seed)).toEqual(signature);
      }
    });
  }
});
