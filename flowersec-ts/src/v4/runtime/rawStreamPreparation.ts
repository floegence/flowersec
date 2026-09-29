import type { CryptoUsageLedger } from "./cryptoUsage.js";
import type { V4RawStreamHandler, V4StreamOpenAuthorizer } from "../streamHandlers.js";
import { applicationGroup, type ApplicationGroup, type ApplicationStartPosition } from "./applicationExecutor.js";
import type { captureRegistration} from "./streamRegistration.js";
import { streamRegistrationCharge, streamHandlerCharge } from "./streamRegistration.js";
import { StreamOpenPreparation } from "./streamOpenPreparation.js";
import type { ResourceAccount, ResourceOwner, ResourceReference, ResourceRoot, ResourceVector, ProtectedResourceAccounts } from "./resources.js";

export interface CapturedRawStreamDeclaration {
  readonly kind: string;
  readonly authorize?: V4StreamOpenAuthorizer;
  readonly handler: V4RawStreamHandler;
  readonly options: ReturnType<typeof captureRegistration>;
}
export interface PreparedRawInvocation {
  readonly work: ResourceReference;
  readonly open: StreamOpenPreparation;
  readonly authorize: ApplicationStartPosition | undefined;
  readonly handler: ApplicationStartPosition;
  close(): void;
}

/** Initial declared work uses the same registration, callback and OPEN owners
 * as ordinary raw streams. No scope, key or protocol association is invented
 * during preparation. Later work replenishes through normal Session admission. */
export class PreparedRawRegistration {
  #reference: ResourceReference | undefined;
  #declaration: CapturedRawStreamDeclaration | undefined;
  readonly options: CapturedRawStreamDeclaration["options"];
  readonly #invocations: PreparedRawInvocation[] = [];
  #closed = false;
  constructor(declaration: CapturedRawStreamDeclaration, root: ResourceRoot, accounts: readonly ResourceAccount[],
    owner: ResourceOwner, runtimeBytes: bigint, group: ApplicationGroup, openCharges: readonly ResourceVector[], sendAccounts: ProtectedResourceAccounts, ledger: CryptoUsageLedger) {
    const options = this.options = declaration.options; this.#declaration = declaration;
    try {
      this.#reference = root.reserve({ accounts, owner: { ...owner, kind: `${owner.kind}_registration` }, charge: streamRegistrationCharge(options, runtimeBytes) });
      for (let index = 0; index < options.maxActive; index++) {
        const costs = [streamHandlerCharge(options, runtimeBytes), ...openCharges];
        const references = root.reserveBatch(costs.map((charge, part) => ({ accounts, owner: { ...owner, kind: `${owner.kind}_${index}_${part}` }, charge })));
        let open: StreamOpenPreparation | undefined, account: ResourceAccount | undefined;
        let authorize: ApplicationStartPosition | undefined, handler: ApplicationStartPosition | undefined;
        try {
          account = sendAccounts.checkout();
          open = new StreamOpenPreparation(root, openCharges, references.slice(1), account);
          open.prepareSendKeys(ledger);
          handler = group.reserveStart(options.workClass);
          if (declaration.authorize !== undefined) authorize = group.reserveStart("short");
          const work = references[0]!.take(costs[0]!), preparedOpen = open, preparedHandler = handler, preparedAuthorize = authorize;
          let closed = false;
          this.#invocations.push({ work, open: preparedOpen, handler: preparedHandler, authorize: preparedAuthorize,
            close() { if (closed) return; closed = true; work.release(); preparedOpen.close(); preparedHandler.close(); preparedAuthorize?.close(); } });
        } catch (error) { open?.close(); if (open === undefined) account?.close(); handler?.close(); authorize?.close(); throw error; }
        finally { for (const reference of references) reference.release(); }
      }
    } catch (error) { this.close(); throw error; }
  }
  takeDeclaration(): CapturedRawStreamDeclaration {
    if (this.#closed || this.#declaration === undefined) throw new Error("owner_unavailable");
    const declaration = this.#declaration; this.#declaration = undefined; return declaration;
  }
  takeReference(reference: ResourceReference, runtimeBytes: bigint): ResourceReference {
    if (this.#closed || this.#reference === undefined || !this.#reference.sameEnvironment(reference)) throw new Error("owner_unavailable");
    const result = this.#reference.take(streamRegistrationCharge(this.options, runtimeBytes)); this.#reference = undefined; return result;
  }
  takeInvocation(): PreparedRawInvocation | undefined {
    if (this.#closed) throw new Error("owner_unavailable"); return this.#invocations.shift();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#declaration = undefined; this.#reference?.release(); this.#reference = undefined;
    for (const invocation of this.#invocations) invocation.close(); this.#invocations.length = 0;
  }
}

/** Candidate-only ownership. Successful installation moves each part to the
 * original Session; failure returns only parts not already transferred. */
export class RawStreamPreparation {
  #group: ApplicationGroup | undefined;
  readonly #registrations: PreparedRawRegistration[] = [];
  #closed = false;
  constructor(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint,
    declarations: readonly CapturedRawStreamDeclaration[], openCharges: readonly ResourceVector[], sendAccounts: ProtectedResourceAccounts, ledger: CryptoUsageLedger) {
    try {
      this.#group = applicationGroup(root, accounts, { ...owner, kind: "raw_initial_application" }, runtimeBytes, false);
      for (const [index, declaration] of declarations.entries()) this.#registrations.push(new PreparedRawRegistration(declaration,
        root, accounts, { ...owner, kind: `raw_initial_${index}` }, runtimeBytes,
        this.#group, openCharges, sendAccounts, ledger));
    } catch (error) { this.close(); throw error; }
  }
  takeGroup(reference: ResourceReference): ApplicationGroup {
    if (this.#closed || this.#group === undefined || !this.#group.sameEnvironment(reference)) throw new Error("owner_unavailable");
    const group = this.#group; this.#group = undefined; return group;
  }
  takeRegistration(): PreparedRawRegistration | undefined {
    if (this.#closed) throw new Error("owner_unavailable"); return this.#registrations.shift();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const registration of this.#registrations) registration.close(); this.#registrations.length = 0;
    this.#group?.close(); this.#group = undefined;
  }
}
