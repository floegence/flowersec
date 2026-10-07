import type { ResourceReference } from "../v4/runtime/resources.js";
import { equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { isOriginalGrantIssuance, type OriginalGrantIssuance } from "./grantIssuerCurrent.js";
import { admissionLeaseKey, encodeParentWinner } from "./admissionRecord.js";
import { clearRelayFields } from "./relayRecord.js";
import type { SQLiteAdmissionStore } from "./sqliteAdmission.js";

const original = Symbol("original registered publication winner continuation");
export interface RegisteredWinnerPublication {
  readonly continuation: Uint8Array;
  readonly lease: Uint8Array;
  readonly projection: Uint8Array;
}
/** The original issuance fixes this continuation's only possible ledger match.
 * Its publication belongs to B's original registration; it cannot be recovered
 * from durable rows, received Grants, or a later control registration. */
export class OriginalRegisteredWinnerContinuation {
  readonly #lease: Uint8Array; readonly #projection: Uint8Array; readonly #nonce: Uint8Array;
  readonly #reference: ResourceReference; readonly #store: SQLiteAdmissionStore;
  #published = false; #acknowledged = false; #consumed = false; #closed = false;
  constructor(token: symbol, lease: Uint8Array, projection: Uint8Array, nonce: Uint8Array, reference: ResourceReference, store: SQLiteAdmissionStore) {
    requireCredential(token === original); this.#lease = lease; this.#projection = projection; this.#nonce = nonce; this.#reference = reference.borrow(); this.#store = store; Object.freeze(this);
  }
  #check(): void { requireCredential(!this.#closed, "credential_closed"); this.#reference.check(); }
  publication(): RegisteredWinnerPublication {
    this.#check(); requireCredential(!this.#published); this.#published = true;
    return Object.freeze({ continuation: this.#nonce, lease: this.#lease, projection: this.#projection });
  }
  acknowledge(nonce: Uint8Array): void {
    this.#check(); requireCredential(this.#published && !this.#acknowledged && equalCredential(nonce, this.#nonce), "credential_binding"); this.#acknowledged = true;
  }
  async continue(nonce: Uint8Array, reference: ResourceReference, operation: Readonly<{ signal: AbortSignal; check(): void; remainingMS(): bigint }>): Promise<void> {
    this.#check(); requireCredential(this.#acknowledged && !this.#consumed && this.#reference.sameEnvironment(reference) && equalCredential(nonce, this.#nonce), "credential_binding");
    // Failure or interruption terminates this original continuation. A retry
    // cannot acquire a fresh authorization or completion capability.
    this.#consumed = true;
    try { await this.#store.matchOriginalParentWinner(this.#store.authorityID(), this.#lease, this.#projection, reference, operation.check, operation.signal, operation.remainingMS); operation.check(); }
    finally { this.close(); }
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#lease.fill(0); this.#projection.fill(0); this.#nonce.fill(0); this.#reference.release(); }
}
/** Called while the original branded issuance still owns its verified closure.
 * The caller's publication reservation pays for this bounded retained evidence. */
export function captureOriginalRegisteredWinner(issuance: OriginalGrantIssuance, reference: ResourceReference, store: SQLiteAdmissionStore, fillRandom: (nonce: Uint8Array) => void): OriginalRegisteredWinnerContinuation {
  requireCredential(isOriginalGrantIssuance(issuance)); issuance.check(reference);
  const fields = issuance.original(reference).closure.parentSelectionFields(reference), buffer = new Uint8Array(8192);
  let lease: Uint8Array | undefined, projection: Uint8Array | undefined, nonce: Uint8Array | undefined;
  try {
    requireCredential(fields.source === "preauthorized_pool" && fields.winnerAuthority === store.authorityID(), "credential_binding");
    lease = admissionLeaseKey(fields); projection = new Uint8Array(encodeParentWinner(buffer, fields)); nonce = new Uint8Array(32); fillRandom(nonce);
    requireCredential(nonce.some(value => value !== 0));
    return new OriginalRegisteredWinnerContinuation(original, lease, projection, nonce, reference, store);
  } catch (error) { lease?.fill(0); projection?.fill(0); nonce?.fill(0); throw error; }
  finally { clearRelayFields(fields); buffer.fill(0); }
}
