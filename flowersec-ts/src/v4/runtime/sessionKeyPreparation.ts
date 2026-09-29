import type { CryptoKeyPositions, CryptoKeyReservation, CryptoUsageLedger } from "./cryptoUsage.js";
import type { ResourceReference } from "./resources.js";

type Channel = "bootstrap" | "notify_0" | "notify_1" | "management";
type Direction = "receive" | "send";

/** Fixed internal channels own their counter pairs before acquisition. The
 * ordinary OPEN path cannot spend these positions; rebuilds reuse only after
 * the prior direction and both of its key generations have actually exited. */
export class SessionKeyPreparation {
  readonly #positions = new Map<string, CryptoKeyReservation>();
  #closed = false;
  constructor(ledger: CryptoUsageLedger, profile: "transport" | "services" | "execution", original: ResourceReference) {
    const channels: Channel[] = profile === "transport" ? [] : ["bootstrap", "notify_0", "notify_1"];
    if (profile === "execution") channels.push("management");
    try {
      for (const channel of channels) for (const direction of ["receive", "send"] as const) this.#positions.set(`${channel}_${direction}`,
        ledger.reserveReusableKeyPositions(direction === "send" ? ledger.sendDirection : ledger.sendDirection === 0 ? 1 : 0, original));
    } catch (error) { this.close(); throw error; }
  }
  available(channel: Channel, direction: Direction): boolean { return !this.#closed && this.#positions.get(`${channel}_${direction}`)?.available() === true; }
  checkout(channel: Channel, direction: Direction): CryptoKeyPositions {
    if (!this.available(channel, direction)) throw new Error("crypto_busy"); return this.#positions.get(`${channel}_${direction}`)!.checkout();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const position of this.#positions.values()) position.close(); this.#positions.clear();
  }
}
