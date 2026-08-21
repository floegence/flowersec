import { createHash } from "node:crypto";

import type { DecodedFSB3RequestV3 } from "../v3/artifact.js";

/** Opaque, secret-free authorization lookup for one observed FSB3 request. */
export class RuntimeAuthorizationRequestV3 {
  readonly #lookupKey: string;

  private constructor(lookupKey: string) {
    this.#lookupKey = lookupKey;
  }

  /** Returns the non-secret credential digest used to locate authorization state. */
  lookupKey(): string { return this.#lookupKey; }

  toString(): string { return "Flowersec.RuntimeAuthorizationRequestV3"; }

  toJSON(): Readonly<Record<string, never>> { return Object.freeze({}); }

  /** @internal */
  static fromDecoded(decoded: DecodedFSB3RequestV3): RuntimeAuthorizationRequestV3 {
    const credential = decoded.request.pathKind === "direct"
      ? decoded.request.routing_token
      : decoded.request.attach_token;
    const request = new RuntimeAuthorizationRequestV3(
      createHash("sha256").update(credential, "utf8").digest("base64url"),
    );
    Object.freeze(request);
    return request;
  }
}

/** @internal */
export function runtimeAuthorizationRequestV3FromDecoded(
  decoded: DecodedFSB3RequestV3,
): RuntimeAuthorizationRequestV3 {
  return RuntimeAuthorizationRequestV3.fromDecoded(decoded);
}
