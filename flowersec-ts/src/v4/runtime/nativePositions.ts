import { nativeFrameCharge, nativeOpeningCharge } from "./nativeFrame.js";
import { ResourceError, ResourceVector, type ResourceReference, type ResourceRoot, type ProtectedResourceReservation } from "./resources.js";

export function nativeOutputCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([runtimeBytes + 128n, 0n, 0n, 1n, 1n, 2n, 0n, 0n, 0n, 0n, 0n]);
}
export function nativeAssociationCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([runtimeBytes + 768n, 0n, 0n, 1n, 2n, 2n, 2n, 0n, 0n, 0n, 0n]);
}
export function nativeOutputBodyCharge(): ResourceVector {
  return new ResourceVector([128n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function nativePositionCharges(runtimeBytes: bigint): readonly ResourceVector[] {
  return [nativeFrameCharge(runtimeBytes, 128), nativeOutputCharge(runtimeBytes), nativeAssociationCharge(runtimeBytes), nativeOutputBodyCharge()];
}
export function nativePositionPoolCharge(positions: number, openings: number, runtimeBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(positions) || positions < 1 || positions > 4096 || !Number.isSafeInteger(openings) || openings < 1 || openings > 4096 || runtimeBytes <= 0n) {
    throw new Error("configuration_capacity");
  }
  return new ResourceVector([BigInt(positions * 256 + openings * 64) + runtimeBytes, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export interface NativeProtocolPosition {
  readonly references: readonly ResourceReference[];
  readonly output: ProtectedResourceReservation;
  readonly renewal?: Readonly<{ available(): boolean; checkout(): NativeProtocolPosition }>;
}
/** Protocol descriptors are protected separately from the provider's native
 * positions. OPEN backing is shared only by original pending/unbound owners;
 * bound DATA keeps H_DATA, without retaining an OPEN-sized buffer per scope. */
export class NativeProtocolPositions {
  #reference: ResourceReference | undefined;
  readonly #positions: ProtectedResourceReservation[][] = [];
  readonly #openings: ProtectedResourceReservation[] = [];
  readonly #dedicated = new Set<number>();
  readonly #dedicatedOpenings = new Set<number>();
  #next = 0;
  #nextOpening = 0;
  #closed = false;
  constructor(root: ResourceRoot, positions: number, openings: number, runtimeBytes: bigint, original: ResourceReference,
    descriptors: readonly ResourceReference[], staging: readonly ResourceReference[]) {
    const charge = nativePositionPoolCharge(positions, openings, runtimeBytes);
    const costs = nativePositionCharges(runtimeBytes);
    if (descriptors.length !== positions * costs.length || staging.length !== openings) throw new Error("configuration_capacity");
    this.#reference = original.take(charge);
    try {
      for (let n = 0; n < positions; n++) {
        const slots: ProtectedResourceReservation[] = []; this.#positions.push(slots);
        for (let k = 0; k < costs.length; k++) {
          const reference = descriptors[n * costs.length + k]!, cost = costs[k]!;
          slots.push(k === 3 ? root.protectBytes(reference, cost) : root.protect(reference, cost));
        }
      }
      for (const reference of staging) this.#openings.push(root.protect(reference, nativeOpeningCharge()));
    } catch (error) { this.close(); throw error; }
  }
  checkout(dedicated = false): NativeProtocolPosition {
    if (this.#closed) throw new Error("closed");
    this.#reference!.check();
    let selected = -1, staging = -1;
    for (let n = 0; n < this.#positions.length; n++) {
      const index = (this.#next + n) % this.#positions.length;
      if (!this.#dedicated.has(index) && this.#positions[index]!.every(slot => slot.available())) { selected = index; break; }
    }
    for (let n = 0; n < this.#openings.length; n++) {
      const index = (this.#nextOpening + n) % this.#openings.length;
      if (!this.#dedicatedOpenings.has(index) && this.#openings[index]!.available()) { staging = index; break; }
    }
    // No checkout/release churn when the entire tuple is unavailable. The
    // original capacity waiter wakes on a real owner release, not this attempt.
    if (selected < 0 || staging < 0) throw new ResourceError("resource_exhausted");
    let renewal: NativeProtocolPosition["renewal"];
    if (dedicated) {
      this.#dedicated.add(selected); this.#dedicatedOpenings.add(staging);
      renewal = Object.freeze({ available: () => !this.#closed && this.#positions[selected]!.every(slot => slot.available()) && this.#openings[staging]!.available(),
        checkout: () => this.#checkout(selected, staging, renewal) });
    }
    return this.#checkout(selected, staging, renewal);
  }
  #checkout(selected: number, staging: number, renewal?: NativeProtocolPosition["renewal"]): NativeProtocolPosition {
    if (this.#closed) throw new Error("closed"); this.#reference!.check();
    if (!this.#positions[selected]!.every(slot => slot.available()) || !this.#openings[staging]!.available()) throw new ResourceError("resource_exhausted");
    const refs: ResourceReference[] = [];
    try {
      const slots = this.#positions[selected]!;
      for (let n = 0; n < 3; n++) refs.push(slots[n]!.checkout());
      refs.push(this.#openings[staging]!.checkout());
      this.#next = (selected + 1) % this.#positions.length;
      this.#nextOpening = (staging + 1) % this.#openings.length;
      return { references: refs, output: slots[3]!, ...(renewal === undefined ? {} : { renewal }) };
    } catch (error) { for (const reference of refs) reference.release(); throw error; }
  }
  close(): void {
    if (!this.#closed) {
      this.#closed = true;
      for (const slots of this.#positions) for (const slot of slots) slot.closeAfterUse();
      for (const slot of this.#openings) slot.closeAfterUse();
    }
    this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#positions.some(slots => slots.some(slot => !slot.cleanupComplete())) || this.#openings.some(slot => !slot.cleanupComplete())) return;
    this.#reference?.release(); this.#reference = undefined; this.#positions.length = this.#openings.length = 0;
    this.#dedicated.clear(); this.#dedicatedOpenings.clear();
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
