import type { CryptoKeyPositions, CryptoUsageLedger } from "./cryptoUsage.js";
import type { ResourceAccount, ResourceOwner, ResourceReference, ResourceRoot, ResourceVector } from "./resources.js";

export interface PreparedPeerOpen {
  readonly references: readonly ResourceReference[];
  readonly usage: CryptoKeyPositions;
}

/** OPEN must authenticate before its kind can select a registration. These
 * initial ingress positions belong to the candidate Session, never a claimed
 * remote kind. Binding a real scope is the first cryptographic use. */
export class PeerOpenPreparation {
  readonly #entries: PreparedPeerOpen[] = [];
  #closed = false;
  #capacity = 0;
  constructor(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, ledger: CryptoUsageLedger,
    count: number, keyCharges: readonly ResourceVector[]) {
    if (!Number.isSafeInteger(count) || count < 1 || count > 4096 || keyCharges.length !== 2) throw new Error("configuration_capacity");
    this.#capacity = count;
    try {
      for (let index = 0; index < count; index++) {
        const references = root.reserveBatch(keyCharges.map((charge, part) => ({ accounts, charge, owner: { ...owner, kind: `initial_peer_key_${index}_${part}` } })));
        try { this.#entries.push({ references, usage: ledger.prepareKeyPositions(ledger.sendDirection === 0 ? 1 : 0, references[0]!) }); }
        catch (error) { for (const reference of references) reference.release(); throw error; }
      }
    } catch (error) { this.close(); throw error; }
  }
  /** Additional Controller declarations join the same original candidate
   * ingress owner before acquisition; failure leaves its existing pool intact. */
  extend(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, ledger: CryptoUsageLedger,
    count: number, keyCharges: readonly ResourceVector[]): void {
    if (this.#closed) throw new Error("owner_unavailable");
    if (!Number.isSafeInteger(count) || count < 1 || this.#capacity + count > 4096) throw new Error("configuration_capacity");
    const additional = new PeerOpenPreparation(root, accounts, owner, ledger, count, keyCharges);
    this.#entries.push(...additional.#entries); additional.#entries.length = 0; additional.close(); this.#capacity += count;
  }
  take(reference: ResourceReference): PreparedPeerOpen | undefined {
    if (this.#closed) throw new Error("owner_unavailable");
    if (this.#entries[0]?.references.some(part => !part.sameEnvironment(reference))) throw new Error("owner_unavailable");
    return this.#entries.shift();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const entry of this.#entries) { entry.usage.close(); for (const reference of entry.references) reference.release(); }
    this.#entries.length = 0;
  }
}
