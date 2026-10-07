import { recordCipherCharge, recordEpochCharge, type RecordCipherConfig } from "./recordCrypto.js";
import type { CryptoKeyPositions, CryptoUsageLedger } from "./cryptoUsage.js";
import { rekeyDecoderCharge, rekeyRoundCharge, type RekeyStorageConfig } from "./rekey.js";
import { ResourceError, ResourceVector, type ResourceRoot, type ResourceReference, type ProtectedResourceReservation } from "./resources.js";

export function directionKeyCharge(config: RecordCipherConfig): ResourceVector {
  return recordCipherCharge(config).add(new ResourceVector([128n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
}

/** A stream prepays both generations before its first key is installed. A
 * rekey uses the spare original position; it never acquires a new root slot. */
export class DirectionKeyPositions {
  readonly usage: CryptoKeyPositions;
  readonly #slots: ProtectedResourceReservation[] = [];
  #closed = false;
  #next = 0;
  #borrowed = false;
  constructor(root: ResourceRoot, config: RecordCipherConfig, references: readonly ResourceReference[], ledger: CryptoUsageLedger, scope: bigint, direction: 0 | 1, protectedSlots?: readonly ProtectedResourceReservation[], preparedUsage?: CryptoKeyPositions) {
    if (references.length !== 2) throw new Error("configuration_capacity");
    this.usage = preparedUsage === undefined ? ledger.reserveKeyPositions(scope, direction, references[0]!)
      : ledger.bindKeyPositions(preparedUsage, scope, direction, references[0]!);
    try {
      if (protectedSlots === undefined) for (const reference of references) this.#slots.push(root.protect(reference, directionKeyCharge(config)));
      else {
        if (protectedSlots.length !== 2 || !protectedSlots.every((slot, index) => slot.sameEnvironment(references[index]!))) throw new Error("configuration_capacity");
        this.#borrowed = true; this.#slots.push(...protectedSlots);
        for (const reference of references) reference.release();
      }
    }
    catch (error) { this.close(); throw error; }
  }
  checkout(): ResourceReference {
    if (this.#closed) throw new ResourceError("admission_closed");
    for (let n = 0; n < this.#slots.length; n++) {
      const index = (this.#next + n) % this.#slots.length, slot = this.#slots[index]!;
      if (!slot.available()) continue;
      const reference = slot.checkout(); this.#next = (index + 1) % this.#slots.length; return reference;
    }
    throw new ResourceError("resource_exhausted");
  }
  cleanupComplete(): boolean { return this.#closed && this.#slots.every(slot => slot.cleanupComplete()); }
  /** The authenticated management OPEN transfers its original protected key
   * positions permanently; an ordinary refused contender only borrowed them. */
  adoptProtection(): void { if (this.#closed) throw new Error("configuration_capacity"); this.#borrowed = false; }
  close(): void {
    if (!this.#closed) { this.#closed = true; this.usage.close(); if (!this.#borrowed) for (const slot of this.#slots) slot.closeAfterUse(); }
    if (this.#slots.every(slot => slot.cleanupComplete())) this.#slots.length = 0;
  }
}

export function maintenancePositionCharges(config: RekeyStorageConfig): readonly ResourceVector[] {
  return [new ResourceVector([config.runtimeBytes + 1024n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]),
    rekeyRoundCharge(config), rekeyDecoderCharge(config), recordEpochCharge(config.runtimeBytes), recordCipherCharge(config), recordCipherCharge(config)];
}

/** Scope-zero progress never competes with future application allocation for
 * the original rekey round, parser or old/new epoch and key positions. */
export class MaintenancePositions {
  #reference: ResourceReference | undefined;
  readonly #round: ProtectedResourceReservation[] = [];
  readonly #epochs: ProtectedResourceReservation[][] = [];
  #closed = false;
  #next = 0;
  constructor(root: ResourceRoot, config: RekeyStorageConfig, original: ResourceReference,
    round: readonly ResourceReference[], epochs: readonly ResourceReference[]) {
    const costs = maintenancePositionCharges(config);
    if (round.length !== 2 || epochs.length !== 6) throw new Error("configuration_capacity");
    this.#reference = original.take(costs[0]!);
    try {
      for (let n = 0; n < 2; n++) this.#round.push(root.protect(round[n]!, costs[n + 1]!));
      for (let n = 0; n < 2; n++) {
        const slots: ProtectedResourceReservation[] = []; this.#epochs.push(slots);
        for (let k = 0; k < 3; k++) slots.push(root.protect(epochs[n * 3 + k]!, costs[k + 3]!));
      }
    } catch (error) { this.close(); throw error; }
  }
  #checkout(slots: readonly ProtectedResourceReservation[]): ResourceReference[] {
    if (this.#closed) throw new ResourceError("admission_closed");
    this.#reference!.check();
    if (!slots.every(slot => slot.available())) throw new ResourceError("resource_exhausted");
    const references: ResourceReference[] = [];
    try { for (const slot of slots) references.push(slot.checkout()); return references; }
    catch (error) { for (const reference of references) reference.release(); throw error; }
  }
  round(): ResourceReference[] { return this.#checkout(this.#round); }
  epoch(): ResourceReference[] {
    if (this.#closed) throw new ResourceError("admission_closed");
    this.#reference!.check();
    for (let n = 0; n < this.#epochs.length; n++) {
      const index = (this.#next + n) % this.#epochs.length, slots = this.#epochs[index]!;
      if (!slots.every(slot => slot.available())) continue;
      const result = this.#checkout(slots); this.#next = (index + 1) % this.#epochs.length; return result;
    }
    throw new ResourceError("resource_exhausted");
  }
  close(): void {
    if (!this.#closed) {
      this.#closed = true;
      for (const slot of this.#round) slot.closeAfterUse();
      for (const slots of this.#epochs) for (const slot of slots) slot.closeAfterUse();
    }
    this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#round.some(slot => !slot.cleanupComplete()) || this.#epochs.some(slots => slots.some(slot => !slot.cleanupComplete()))) return;
    this.#reference?.release(); this.#reference = undefined; this.#round.length = this.#epochs.length = 0;
  }
  cleanupComplete(): boolean { this.#collect(); return this.#reference === undefined; }
}
