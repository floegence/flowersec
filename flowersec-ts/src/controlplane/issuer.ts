import { ed25519 } from "@noble/curves/ed25519";

import { base64urlEncode } from "../utils/base64url.js";
import { signToken, type TokenPayload } from "./token.js";

export class IssuerKeyset {
  private active: Readonly<{ kid: string; signingSeed: Uint8Array }> | undefined;
  private readonly verificationKeys = new Map<string, Uint8Array>();

  constructor(kid: string, signingSeed: Uint8Array) {
    const normalizedKID = normalizeKid(kid);
    const retainedSeed = copySigningSeed(signingSeed);
    this.active = { kid: normalizedKID, signingSeed: retainedSeed };
    this.verificationKeys.set(normalizedKID, ed25519.getPublicKey(retainedSeed));
  }

  static random(kid: string): IssuerKeyset {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    try {
      return new IssuerKeyset(kid, seed);
    } finally {
      seed.fill(0);
    }
  }

  currentKID(): string {
    return this.requireActive().kid;
  }

  publicKeys(): ReadonlyMap<string, Uint8Array> {
    this.requireActive();
    return new Map(
      [...this.verificationKeys.entries()]
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([kid, publicKey]) => [kid, publicKey.slice()]),
    );
  }

  sign(payload: Omit<TokenPayload, "kid"> & Readonly<{ kid?: string }>): string {
    const active = this.requireActive();
    return signToken(active.signingSeed, { ...payload, kid: active.kid });
  }

  addVerificationKey(kid: string, publicKey: Uint8Array): void {
    this.requireActive();
    const normalizedKID = normalizeKid(kid);
    const retainedKey = copyPublicKey(publicKey);
    const existing = this.verificationKeys.get(normalizedKID);
    if (existing != null) {
      if (!equalBytes(existing, retainedKey)) throw new Error(`key ID ${normalizedKID} is already bound to a different public key`);
      return;
    }
    this.verificationKeys.set(normalizedKID, retainedKey);
  }

  rotate(kid: string, signingSeed: Uint8Array): void {
    const active = this.requireActive();
    const nextKID = normalizeKid(kid);
    const nextSeed = copySigningSeed(signingSeed);
    const nextPublicKey = ed25519.getPublicKey(nextSeed);
    const prepublishedKey = this.verificationKeys.get(nextKID);
    if (prepublishedKey == null) {
      nextSeed.fill(0);
      throw new Error(`key ID ${nextKID} must be prepublished before rotation`);
    }
    if (!equalBytes(prepublishedKey, nextPublicKey)) {
      nextSeed.fill(0);
      throw new Error(`key ID ${nextKID} is bound to a different public key`);
    }
    this.active = { kid: nextKID, signingSeed: nextSeed };
    active.signingSeed.fill(0);
  }

  retireVerificationKey(kid: string): void {
    const active = this.requireActive();
    const normalizedKID = normalizeKid(kid);
    if (normalizedKID === active.kid) throw new Error("the active signing key cannot be retired");
    if (!this.verificationKeys.delete(normalizedKID)) throw new Error(`key ID ${normalizedKID} is not published`);
  }

  exportTunnelKeyset(): Uint8Array {
    const keys = [...this.publicKeys()].map(([kid, publicKey]) => ({ kid, pubkey_b64u: base64urlEncode(publicKey) }));
    return new TextEncoder().encode(JSON.stringify({ keys }, null, 2));
  }

  dispose(): void {
    const active = this.active;
    if (active == null) return;
    active.signingSeed.fill(0);
    this.active = undefined;
    this.verificationKeys.clear();
  }

  private requireActive(): Readonly<{ kid: string; signingSeed: Uint8Array }> {
    if (this.active == null) throw new Error("issuer keyset is disposed");
    return this.active;
  }
}

function copySigningSeed(signingSeed: Uint8Array): Uint8Array {
  if (signingSeed.length !== 32) throw new TypeError("Ed25519 signing seed must be 32 bytes");
  return signingSeed.slice();
}

function copyPublicKey(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32) throw new TypeError("Ed25519 public key must be 32 bytes");
  return publicKey.slice();
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index++) diff |= left[index]! ^ right[index]!;
  return diff === 0;
}

function normalizeKid(kid: string): string {
  const value = kid.trim();
  if (value === "") throw new TypeError("key ID is required");
  return value;
}
