import { ed25519 } from "@noble/curves/ed25519";

import { base64urlEncode } from "../utils/base64url.js";
import { signToken, type TokenPayload } from "./token.js";

export class IssuerKeyset {
  private kid: string;
  private signingSeed: Uint8Array;

  constructor(kid: string, signingSeed: Uint8Array) {
    this.kid = normalizeKid(kid);
    if (signingSeed.length !== 32) throw new TypeError("Ed25519 signing seed must be 32 bytes");
    this.signingSeed = signingSeed.slice();
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
    return this.kid;
  }

  publicKeys(): ReadonlyMap<string, Uint8Array> {
    return new Map([[this.kid, ed25519.getPublicKey(this.signingSeed)]]);
  }

  sign(payload: Omit<TokenPayload, "kid"> & Readonly<{ kid?: string }>): string {
    return signToken(this.signingSeed, { ...payload, kid: this.kid });
  }

  rotate(kid: string, signingSeed: Uint8Array): void {
    const nextKID = normalizeKid(kid);
    if (signingSeed.length !== 32) throw new TypeError("Ed25519 signing seed must be 32 bytes");
    const nextSeed = signingSeed.slice();
    this.signingSeed.fill(0);
    this.kid = nextKID;
    this.signingSeed = nextSeed;
  }

  exportTunnelKeyset(): Uint8Array {
    const keys = [...this.publicKeys()].map(([kid, publicKey]) => ({ kid, pubkey_b64u: base64urlEncode(publicKey) }));
    return new TextEncoder().encode(JSON.stringify({ keys }, null, 2));
  }

  dispose(): void {
    this.signingSeed.fill(0);
  }
}

function normalizeKid(kid: string): string {
  const value = kid.trim();
  if (value === "") throw new TypeError("key ID is required");
  return value;
}
