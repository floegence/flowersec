import type { CryptoUsageLedger } from "./cryptoUsage.js";
import { StreamOpenPreparation } from "./streamOpenPreparation.js";
import type { NativeProtocolPositions, NativeProtocolPosition } from "./nativePositions.js";
import { applicationGroup, type ApplicationGroup } from "./applicationExecutor.js";
import type { InitializerMethodTarget } from "./initializerWorkload.js";
import { sameServiceBindingTarget } from "./serviceBindingConfig.js";
import { rpcPreacceptedStreamsCharge } from "./rpcPreacceptedStreams.js";
import { rpcStreamMessagesCharges } from "./rpcStreamMessages.js";
import { rpcStreamingErrorCharge } from "./rpcStreamingExchange.js";
import type { ResourceAccount, ResourceOwner, ResourceReference, ResourceRoot, ResourceVector, ProtectedResourceAccounts } from "./resources.js";

export interface PreparedRPCStreamMessages {
  readonly references: readonly ResourceReference[];
  readonly group: ApplicationGroup;
  readonly open: StreamOpenPreparation;
}
interface Entry extends PreparedRPCStreamMessages {
  readonly namespace: string;
  readonly authority: string;
  readonly kind: string;
  readonly metadata: Uint8Array;
}

/** The first accepted entry for each declared required target uses these
 * original message resources. No Stream ID, OPEN or remote contract is created
 * by this resource-only admission. Subsequent replenishment has its own owner. */
export class RPCStreamPreparation {
  #pool: ResourceReference | undefined;
  readonly #entries: Entry[] = [];
  #closed = false;
  constructor(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint,
    targets: readonly InitializerMethodTarget[], openCharges: readonly ResourceVector[], sendAccounts: ProtectedResourceAccounts, nativePositions?: NativeProtocolPositions, ledger?: CryptoUsageLedger) {
    const selected: InitializerMethodTarget[] = [];
    for (const target of targets) {
      if (!target.method.required || target.method.facts.shape !== "server_streaming") continue;
      // Compatible dependency aliases point at the same binding target and
      // method. They must share one preaccepted Stream slot; charging a second
      // slot would consume the bounded pool without creating another demand.
      if (!selected.some(existing => existing.method.method === target.method.method &&
          existing.namespace === target.namespace && sameServiceBindingTarget(existing.target, target.target))) selected.push(target);
    }
    if (selected.length < 1 || selected.length > 8) throw new Error("configuration_capacity");
    try {
      this.#pool = root.reserve({ accounts, owner: { ...owner, kind: "rpc_preaccepted_streams" }, charge: rpcPreacceptedStreamsCharge(runtimeBytes) });
      const charges = [...rpcStreamMessagesCharges(runtimeBytes), rpcStreamingErrorCharge(runtimeBytes)];
      for (const [index, target] of selected.entries()) {
        if (target.method.streamKind === undefined) throw new Error("configuration_capacity");
        const references = root.reserveBatch(charges.map((charge, part) => ({ accounts, owner: { ...owner, kind: `rpc_initial_stream_${index}_${part}` }, charge })));
        let group: ApplicationGroup | undefined, open: StreamOpenPreparation | undefined, account: ResourceAccount | undefined, native: NativeProtocolPosition | undefined;
        let openReferences: ResourceReference[] = [];
        try {
          group = applicationGroup(root, accounts, { ...owner, kind: `rpc_initial_stream_group_${index}` }, runtimeBytes, false, references[5]!);
          openReferences = root.reserveBatch(openCharges.map((charge, part) => ({ accounts, owner: { ...owner, kind: `rpc_initial_open_${index}_${part}` }, charge })));
          account = sendAccounts.checkout(); native = nativePositions?.checkout();
          open = new StreamOpenPreparation(root, openCharges, openReferences, account, native);
          if (ledger !== undefined) { open.prepareReceiveKeys(ledger); open.prepareSendKeys(ledger); }
          for (const reference of openReferences) reference.release(); openReferences = [];
          this.#entries.push({ namespace: target.namespace, authority: target.target.authority, kind: target.method.streamKind,
            metadata: new Uint8Array(target.method.streamMetadata ?? []), references, group, open });
        } catch (error) { if (open !== undefined) open.close(); else { account?.close(); for (const ref of native?.references ?? []) ref.release(); for (const ref of openReferences) ref.release(); } group?.close(); for (const reference of references) reference.release(); throw error; }
      }
    } catch (error) { this.close(); throw error; }
  }
  takePool(): ResourceReference | undefined {
    if (this.#closed) throw new Error("owner_unavailable");
    const pool = this.#pool; this.#pool = undefined; return pool;
  }
  take(namespace: string, authority: string, kind: string, metadata: Uint8Array): PreparedRPCStreamMessages | undefined {
    if (this.#closed) throw new Error("owner_unavailable");
    const index = this.#entries.findIndex(entry => entry.namespace === namespace && entry.authority === authority && entry.kind === kind &&
      entry.metadata.length === metadata.length && entry.metadata.every((value, at) => value === metadata[at]));
    if (index < 0) return;
    const [entry] = this.#entries.splice(index, 1); entry!.metadata.fill(0); return { references: entry!.references, group: entry!.group, open: entry!.open };
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#pool?.release(); this.#pool = undefined;
    for (const entry of this.#entries) { entry.metadata.fill(0); entry.open.close(); entry.group.close(); for (const reference of entry.references) reference.release(); }
    this.#entries.length = 0;
  }
}
Object.freeze(RPCStreamPreparation.prototype); Object.freeze(RPCStreamPreparation);
