import { ResourceError, ResourceVector, type ProtectedResourceReservation } from "../v4/runtime/resources.js";

export function browserNativeStreamCharge(maximum: number, runtimeBytes: bigint, providerBytes: bigint): ResourceVector {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || runtimeBytes <= 0n || providerBytes <= 0n) throw new Error("configuration_capacity");
  // BYOB backing is fixed before a read. Reader/writer closed observations,
  // create/read/write/FIN/cancel tasks and both native handles coexist here.
  return new ResourceVector([BigInt(Math.min(16384, maximum)) + runtimeBytes + 256n, providerBytes, 0n, 8n, 4n, 8n, 0n, 0n, 0n, 0n, 2n]);
}
export interface BrowserNativeStreamPosition { check(): void; release(): void }

/** One position is exclusively maintenance; all other positions include local
 * creation, peer acceptance, unbound/live streams and actual closing tails.
 * Logical cancellation never puts a held position back on the free list. */
export class BrowserWebTransportPositions {
  readonly #positions: ProtectedResourceReservation[];
  readonly #free: number[] = [];
  #maintenance = false;
  #held = 0;
  #closed = false;
  constructor(positions: readonly ProtectedResourceReservation[]) {
    if (positions.length < 2 || positions.length > 4097) throw new Error("configuration_capacity");
    this.#positions = [...positions];
    for (let i = positions.length - 1; i >= 1; i--) this.#free.push(i);
  }
  acquire(maintenance: boolean): BrowserNativeStreamPosition {
    if (this.#closed) throw new Error("closed");
    if (maintenance && this.#maintenance) throw new Error("busy");
    const index = maintenance ? 0 : this.#free.pop();
    if (index === undefined) throw new ResourceError("resource_exhausted");
    let reference;
    try { reference = this.#positions[index]!.checkout(); }
    catch (error) { if (!maintenance) this.#free.push(index); throw error; }
    this.#held++; if (maintenance) this.#maintenance = true;
    let released = false;
    return Object.freeze({
      check: (): void => { if (released || this.#closed) throw new Error("closed"); reference.check(); },
      release: (): void => {
        if (released) return; released = true;
        reference.release(); this.#held--;
        if (maintenance) this.#maintenance = false; else if (!this.#closed) this.#free.push(index);
        this.#collect();
      },
    });
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#free.length = 0;
    for (const position of this.#positions) position.closeAfterUse(); this.#collect();
  }
  #collect(): void { if (this.#closed && this.#held === 0) this.#positions.length = 0; }
  cleanupComplete(): boolean { return this.#closed && this.#held === 0; }
}
