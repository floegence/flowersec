import { p256 } from "@noble/curves/nist.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

/** A qualified host CSPRNG is synchronous, bounded and does not retain bytes. */
export type RandomFill = (destination: Uint8Array<ArrayBuffer>) => void;
export function randomCharge(runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new Error("configuration_capacity");
  return new ResourceVector([runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export class TrustedRandom {
  #fill: RandomFill | undefined;
  #reservation: ResourceReference | undefined;
  #busy = false;
  #closed = false;
  constructor(fill: RandomFill, runtimeBytes: bigint, reference: ResourceReference, private readonly failed: () => void) {
    if (typeof fill !== "function") throw new Error("configuration_capacity");
    this.#fill = fill; this.#reservation = reference.take(randomCharge(runtimeBytes)); Object.freeze(this);
  }
  fill(destination: Uint8Array<ArrayBuffer>): void {
    if (this.#closed || this.#busy || destination.length < 1 || destination.length > 65536) throw new Error("random_unavailable");
    this.#busy = true;
    try {
      this.#reservation!.check();
      if (this.#fill!(destination) !== undefined || this.#closed) throw new Error("random_unavailable");
      this.#reservation!.check();
    } catch {
      destination.fill(0); this.#closed = true; this.failed(); throw new Error("random_unavailable");
    } finally { this.#busy = false; this.#cleanup(); }
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#busy) return;
    this.#fill = undefined; this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#reservation === undefined; }
}
/** Bounded rejection sampling; invalid entropy never becomes a fallback key. */
export function randomDH(x: boolean, fill: RandomFill): Uint8Array<ArrayBuffer> {
  const secret = new Uint8Array(32);
  try {
    for (let attempt = 0; attempt < 32; attempt++) {
      fill(secret);
      if (x || p256.utils.isValidSecretKey(secret)) return secret;
    }
    throw new Error("random_unavailable");
  } catch (error) { secret.fill(0); throw error; }
}
export const hostRandomFill: RandomFill = destination => { globalThis.crypto.getRandomValues(destination); };
Object.freeze(TrustedRandom.prototype); Object.freeze(TrustedRandom);
