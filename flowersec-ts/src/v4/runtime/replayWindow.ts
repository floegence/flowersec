import { cryptoFailure } from "./cryptoUsage.js";
import { wire } from "./wireRegistry.js";

const maximum = (1n << 64n) - 1n;
const width = wire.resource_caps.record_replay_window_bits;
if (width !== 256) throw new Error("wire_registry");

// The original receive key owns this fixed backing. Precheck grants only one
// bounded authentication attempt; commit belongs after AEAD, protocol checks
// and the original Session/epoch/queue gate. No unauthenticated value shifts it.
export class ReplayWindow {
  readonly #bits = new Uint32Array(width / 32);
  #empty = true;
  #highest = 0n;
  allows(sequence: bigint): boolean {
    if (typeof sequence !== "bigint" || sequence < 0n || sequence > maximum) cryptoFailure("record_sequence");
    if (this.#empty || sequence > this.#highest) return true;
    const delta = this.#highest - sequence;
    if (delta >= BigInt(width)) return false;
    const at = Number(delta);
    return (this.#bits[Math.floor(at / 32)]! & (1 << (at % 32))) === 0;
  }
  commit(sequence: bigint): void {
    if (!this.allows(sequence)) cryptoFailure("record_replay");
    if (this.#empty) { this.#empty = false; this.#highest = sequence; this.#bits[0] = 1; return; }
    if (sequence > this.#highest) {
      const delta = sequence - this.#highest;
      if (delta >= BigInt(width)) this.#bits.fill(0);
      else {
        const shift = Number(delta), words = Math.floor(shift / 32), bits = shift % 32;
        for (let i = this.#bits.length - 1; i >= 0; i--) {
          const from = i - words;
          let value = from >= 0 ? this.#bits[from]! << bits : 0;
          if (bits !== 0 && from > 0) value |= this.#bits[from - 1]! >>> (32 - bits);
          this.#bits[i] = value >>> 0;
        }
      }
      this.#highest = sequence; this.#bits[0] = this.#bits[0]! | 1;
    } else {
      const at = Number(this.#highest - sequence), word = Math.floor(at / 32);
      this.#bits[word] = this.#bits[word]! | (1 << (at % 32));
    }
  }
  clear(): void { this.#bits.fill(0); this.#empty = true; this.#highest = 0n; }
}
Object.freeze(ReplayWindow.prototype); Object.freeze(ReplayWindow);
