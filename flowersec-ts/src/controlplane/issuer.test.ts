import { ed25519 } from "@noble/curves/ed25519";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { IssuerKeyset } from "./issuer.js";
import { verifyToken, type TokenPayload } from "./token.js";

const payload: Omit<TokenPayload, "kid"> = {
  aud: "flowersec-tunnel",
  channel_id: "channel-test",
  role: 1,
  token_id: "token-test",
  init_exp: 2_000,
  idle_timeout_seconds: 60,
  iat: 1_000,
  exp: 1_500,
};

describe("IssuerKeyset", () => {
  test("matches the shared issuer rotation vectors", () => {
    const vectors = JSON.parse(readFileSync(new URL("../../../testdata/issuer_rotation_vectors.json", import.meta.url), "utf8")) as {
      keys: Array<{ kid: string; seed_b64u: string; public_key_b64u: string }>;
      stages: Array<{ name: string; active_kid: string; verification_kids: string[] }>;
    };
    const [first, second] = vectors.keys;
    if (first == null || second == null) throw new Error("issuer rotation vectors require two keys");
    const issuer = new IssuerKeyset(first.kid, base64urlDecode(first.seed_b64u));
    const assertStage = (index: number) => {
      const stage = vectors.stages[index]!;
      expect(issuer.currentKID(), stage.name).toBe(stage.active_kid);
      expect([...issuer.publicKeys().keys()], stage.name).toEqual(stage.verification_kids);
    };

    assertStage(0);
    issuer.addVerificationKey(second.kid, base64urlDecode(second.public_key_b64u));
    assertStage(1);
    issuer.rotate(second.kid, base64urlDecode(second.seed_b64u));
    assertStage(2);
    issuer.retireVerificationKey(first.kid);
    assertStage(3);
  });

  test("requires prepublication and preserves verification overlap during rotation", () => {
    const firstSeed = new Uint8Array(32).fill(1);
    const secondSeed = new Uint8Array(32).fill(2);
    const firstPublic = ed25519.getPublicKey(firstSeed);
    const secondPublic = ed25519.getPublicKey(secondSeed);
    const issuer = new IssuerKeyset("z-key", firstSeed);

    expect(() => issuer.rotate("a-key", secondSeed)).toThrow(/prepublished/);
    expect(issuer.currentKID()).toBe("z-key");

    issuer.addVerificationKey("a-key", secondPublic);
    issuer.addVerificationKey("a-key", secondPublic);
    issuer.rotate("a-key", secondSeed);

    expect(issuer.currentKID()).toBe("a-key");
    expect([...issuer.publicKeys().keys()]).toEqual(["a-key", "z-key"]);
    expect(verifyToken(issuer.sign(payload), issuer.publicKeys(), { nowUnixS: 1_200 }).kid).toBe("a-key");

    expect(JSON.parse(new TextDecoder().decode(issuer.exportTunnelKeyset()))).toEqual({
      keys: [
        { kid: "a-key", pubkey_b64u: base64urlEncode(secondPublic) },
        { kid: "z-key", pubkey_b64u: base64urlEncode(firstPublic) },
      ],
    });

    issuer.retireVerificationKey("z-key");
    expect([...issuer.publicKeys().keys()]).toEqual(["a-key"]);
    expect(() => issuer.retireVerificationKey("a-key")).toThrow(/active/);
    expect(() => issuer.retireVerificationKey("missing-key")).toThrow(/not published/);

    const exported = new TextDecoder().decode(issuer.exportTunnelKeyset());
    expect(JSON.parse(exported)).toEqual({
      keys: [{ kid: "a-key", pubkey_b64u: base64urlEncode(secondPublic) }],
    });
  });

  test("rejects conflicting keys and keeps rotation atomic", () => {
    const firstSeed = new Uint8Array(32).fill(3);
    const secondSeed = new Uint8Array(32).fill(4);
    const otherSeed = new Uint8Array(32).fill(5);
    const issuer = new IssuerKeyset("first", firstSeed);

    issuer.addVerificationKey("second", ed25519.getPublicKey(secondSeed));
    expect(() => issuer.addVerificationKey("second", ed25519.getPublicKey(otherSeed))).toThrow(/different public key/);
    expect(() => issuer.rotate("second", otherSeed)).toThrow(/different public key/);
    expect(issuer.currentKID()).toBe("first");
    expect(verifyToken(issuer.sign(payload), issuer.publicKeys(), { nowUnixS: 1_200 }).kid).toBe("first");
  });

  test("copies mutable key inputs and returned public keys", () => {
    const seed = new Uint8Array(32).fill(6);
    const expectedPublic = ed25519.getPublicKey(seed);
    const issuer = new IssuerKeyset("copy", seed);
    seed.fill(0);

    const returned = issuer.publicKeys().get("copy")!;
    returned.fill(0);
    expect(issuer.publicKeys().get("copy")).toEqual(expectedPublic);
    expect(verifyToken(issuer.sign(payload), issuer.publicKeys(), { nowUnixS: 1_200 }).kid).toBe("copy");
  });

  test("fails closed after idempotent disposal", () => {
    const issuer = new IssuerKeyset("disposed", new Uint8Array(32).fill(7));
    issuer.dispose();
    expect(() => issuer.dispose()).not.toThrow();

    const operations = [
      () => issuer.currentKID(),
      () => issuer.publicKeys(),
      () => issuer.sign(payload),
      () => issuer.addVerificationKey("next", new Uint8Array(32)),
      () => issuer.rotate("next", new Uint8Array(32)),
      () => issuer.retireVerificationKey("next"),
      () => issuer.exportTunnelKeyset(),
    ];
    for (const operation of operations) expect(operation).toThrow(/disposed/);
  });
});
