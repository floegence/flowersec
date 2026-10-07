import type { CryptoKeyPositions, CryptoKeyReservation, CryptoUsageLedger } from "./cryptoUsage.js";
import type { ResourceReference } from "./resources.js";

type Channel = "bootstrap" | `rpc_${number}` | "notify_0" | "notify_1" | "management";
type Direction = "receive" | "send";

/** Fixed internal channels own their counter pairs before acquisition. The
 * ordinary OPEN path cannot spend these positions; rebuilds reuse only after
 * the prior direction and both of its key generations have actually exited. */
export class SessionKeyPreparation {
  readonly #positions = new Map<string, CryptoKeyReservation>();
  #closed = false;
  constructor(ledger: CryptoUsageLedger, profile: "transport" | "services" | "execution", original: ResourceReference) {
    const channels: Channel[] = profile === "transport" ? [] : ["bootstrap", "notify_0", "notify_1"];
    if (profile !== "transport") for (let position = 1; position < 8; position++) channels.push(`rpc_${position}`);
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
  /** Authenticated OPEN classification can exchange equal prepaid receive
   * floors. The original live key pair moves with its exact reservation;
   * neither key derivation nor scope/nonce state is recreated. */
  exchangeReceive(from: Channel, to: Channel): void {
    if (from === to) return;
    const original = this.#positions.get(`${from}_receive`), replacement = this.#positions.get(`${to}_receive`);
    if (this.#closed || original === undefined || replacement === undefined || !replacement.available()) throw new Error("crypto_busy");
    this.#positions.set(`${from}_receive`, replacement); this.#positions.set(`${to}_receive`, original);
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const position of this.#positions.values()) position.close(); this.#positions.clear();
  }
}
