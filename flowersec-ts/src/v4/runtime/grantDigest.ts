import { CredentialWork, credentialOwner, credentialWorkCharge, type CredentialResources } from "./credentialSupport.js";

/** Original control owners reserve the parser before issuance. Grant digests
 * cover the registered unsigned projection, including for an ACK comparison. */
export class PreparedGrantDigest {
  readonly #work: CredentialWork;
  constructor(resources: CredentialResources) {
    const reference = resources.root.reserve({ owner: credentialOwner(resources, "grant_digest"), accounts: resources.accounts, charge: credentialWorkCharge(65536, resources.runtimeBytes) });
    let work: CredentialWork | undefined;
    try {
      this.#work = work = new CredentialWork(resources, 65536, reference);
      work.prepayParsers(65536, 16384, 1);
    } catch (error) { work?.close(); throw error; }
    finally { reference.release(); }
  }
  digest(encoded: Uint8Array): Uint8Array {
    const grant = this.#work.parse(encoded, "Grant", 65536);
    try { return this.#work.digest(grant, "grant_digest"); }
    finally { grant.close(); }
  }
  close(): void { this.#work.close(); }
}
