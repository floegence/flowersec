import type { V4TransportEnvironment } from "./public.js";
import { serviceDefinition, type V4ServiceDefinition, type V4ServiceMethods } from "./serviceDefinition.js";
import type { V4AuthenticatedContext } from "./streamHandlers.js";
import { CBORDecoder, cborDecoderCharge } from "./runtime/cbor.js";
import { originalEnvironment, type EnvironmentDependency, type V4EnvironmentRuntime } from "./runtime/environment.js";
import { RPCProtocolError } from "./runtime/rpcFragment.js";
import { ResourceVector, type ProtectedResourceReservation, type ResourceReference } from "./runtime/resources.js";
import { AdmissionOffer, ServiceContractSnapshot, serviceContractCharge, serviceContractDecoderCharge } from "./runtime/serviceContract.js";
import { captureServiceBindingTarget, checkServiceBindingTarget, type ServiceBindingTarget } from "./runtime/serviceBindingConfig.js";

export interface V4StaticServiceContractInput {
  readonly method: object;
  readonly contract: Uint8Array;
  readonly offer?: Uint8Array;
}
export interface V4StaticServiceContractOptions {
  readonly target: ServiceBindingTarget;
  readonly maximumOfferWindowMS: bigint;
}
interface Entry { readonly method: object; readonly contract: ServiceContractSnapshot; readonly offer: AdmissionOffer | undefined }
const capability = Symbol("trusted static service contracts"), owners = new WeakMap<V4StaticServiceContracts, StaticContractsOwner>();
const offerConfig = (runtimeBytes: bigint) => ({ bytes: 256, nodes: 16, textBytes: 0, arrayItems: 8, runtimeBytes });

/** Trusted immutable local snapshots for one exact service definition. Close
 * seals new bindings; already captured bindings and operations retain their
 * original charged contract bodies until their actual owners exit. */
export class V4StaticServiceContracts {
  constructor(token: symbol, owner: StaticContractsOwner) {
    if (token !== capability) throw new RPCProtocolError("service_contract_owner"); owners.set(this, owner);
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  close(): void { owners.get(this)!.close(); }
  toJSON(): object { return {}; }
}
class StaticContractsOwner {
  #dependency: EnvironmentDependency | undefined;
  #positions: readonly ProtectedResourceReservation[];
  #entries: Entry[] = [];
  #definition: object | undefined;
  #target: ServiceBindingTarget | undefined;
  #unobserve: (() => void) | undefined;
  #closed = false;
  #busy = true;
  constructor(environment: V4EnvironmentRuntime, definition: object, input: readonly V4StaticServiceContractInput[], target: ServiceBindingTarget,
    maximumOfferWindowMS: bigint, dependency: EnvironmentDependency, positions: readonly ProtectedResourceReservation[]) {
    this.#definition = definition; this.#target = target; this.#dependency = dependency; this.#positions = positions;
    let decoder: CBORDecoder | undefined, contractDecoder: ProtectedResourceReservation | undefined;
    const resources = environment.resources, scratch: ResourceReference[] = [];
    try {
      dependency.onClose(() => this.close());
      const costs = [serviceContractDecoderCharge(resources.runtimeBytes), cborDecoderCharge(offerConfig(resources.runtimeBytes))];
      scratch.push(...resources.root.reserveBatch(costs.map((charge, index) => ({ accounts: resources.accounts, owner: { ...resources.owner, kind: `static_contract_decode_${index}` }, charge }))));
      contractDecoder = resources.root.protect(scratch[0]!, costs[0]!);
      decoder = new CBORDecoder(offerConfig(resources.runtimeBytes), scratch[1]!);
      const declared = serviceDefinition(definition);
      for (let index = 0; index < input.length; index++) {
        dependency.check();
        const item = input[index]!, reference = positions[index]!.checkout();
        let contract: ServiceContractSnapshot | undefined;
        const parse = contractDecoder.checkout();
        try {
          contract = new ServiceContractSnapshot(item.contract, resources.runtimeBytes, reference, parse);
          contract.checkMethod(declared.namespace, declared.entries.find(entry => entry.method === item.method)!.facts);
          let offer: AdmissionOffer | undefined;
          if (item.offer !== undefined) {
            const doc = decoder.decodeMap(item.offer, "AdmissionOffer");
            try { offer = new AdmissionOffer(doc, contract, maximumOfferWindowMS, new Uint8Array(32)); } finally { doc.release(); }
          }
          if ((contract.semantics === "execution") !== (offer !== undefined)) throw new RPCProtocolError("admission_offer_unavailable");
          dependency.check(); this.#entries.push(Object.freeze({ method: item.method, contract, offer })); contract = undefined;
        } finally { contract?.release(); reference.release(); parse.release(); }
      }
      this.#unobserve = resources.root.observeAvailability(dependency.reference, () => this.#collect()); dependency.check();
    } catch (error) { this.close(); throw error; }
    finally { decoder?.close(); contractDecoder?.closeAfterUse(); for (const reference of scratch) reference.release(); this.#busy = false; this.#collect(); }
  }
  capture(definition: object, target: ServiceBindingTarget, authentication: V4AuthenticatedContext, reference: ResourceReference): readonly Entry[] {
    if (this.#closed || this.#definition !== definition) throw new RPCProtocolError("service_contract_owner");
    this.#dependency!.check();
    if (!reference.sameEnvironment(this.#dependency!.reference) || target.authority !== this.#target!.authority || target.tenant !== this.#target!.tenant ||
        target.audience !== this.#target!.audience || target.localSubject !== this.#target!.localSubject) throw new RPCProtocolError("service_target_mismatch");
    checkServiceBindingTarget(this.#target!, authentication); return this.#entries;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.#definition = this.#target = undefined;
    for (const entry of this.#entries) entry.contract.release(); this.#entries = [];
    for (const position of this.#positions) position.closeAfterUse(); this.#collect();
  }
  #collect(): void {
    if (this.#busy || !this.#closed || this.#dependency === undefined || this.#positions.some(position => !position.cleanupComplete())) return;
    this.#positions = []; this.#unobserve?.(); this.#unobserve = undefined;
    const dependency = this.#dependency; this.#dependency = undefined; dependency.release();
  }
}
/** Borrowed only during the binding's synchronous capture gate. The binding
 * must retain each accepted body before another host call or returning. */
export function staticServiceContracts(source: V4StaticServiceContracts, definition: object, target: ServiceBindingTarget,
  authentication: V4AuthenticatedContext, reference: ResourceReference): readonly Entry[] {
  const owner = owners.get(source); if (owner === undefined) throw new RPCProtocolError("service_contract_owner");
  return owner.capture(definition, target, authentication, reference);
}
export function createV4StaticServiceContracts<Methods extends V4ServiceMethods>(environment: V4TransportEnvironment, definition: V4ServiceDefinition<Methods>,
  inputs: readonly V4StaticServiceContractInput[], options: V4StaticServiceContractOptions): V4StaticServiceContracts {
  return createStaticServiceContracts(originalEnvironment(environment), definition, inputs, options);
}
/** Original Environment assembler; inputs are synchronously copied/validated
 * after complete reservation, never retained as application buffer aliases. */
export function createStaticServiceContracts(environment: V4EnvironmentRuntime, definition: object, inputs: readonly V4StaticServiceContractInput[],
  options: V4StaticServiceContractOptions): V4StaticServiceContracts {
  const declared = serviceDefinition(definition), { target, maximumOfferWindowMS } = options;
  if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > declared.entries.length || typeof maximumOfferWindowMS !== "bigint" ||
      maximumOfferWindowMS < 1n || maximumOfferWindowMS >= 1n << 64n) throw new RPCProtocolError("configuration_capacity");
  const captured = inputs.map(({ method, contract, offer }) => ({ method, contract, offer }));
  if (new Set(captured.map(entry => entry.method)).size !== captured.length || captured.some(entry => !declared.entries.some(method => method.method === entry.method))) throw new RPCProtocolError("service_selector_invalid");
  const destination = captureServiceBindingTarget(target), runtimeBytes = environment.resources.runtimeBytes;
  const charge = new ResourceVector([16384n + BigInt(captured.length) * 512n + runtimeBytes, 0n, 0n, BigInt(captured.length * 2 + 4), 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const { dependency, positions } = environment.admitDependencyPositions("static_service_contracts", charge, serviceContractCharge(runtimeBytes), captured.length);
  try { return new V4StaticServiceContracts(capability, new StaticContractsOwner(environment, definition, captured, destination, maximumOfferWindowMS, dependency, positions)); }
  catch (error) { for (const position of positions) position.closeAfterUse(); dependency.release(); throw error; }
}
Object.freeze(V4StaticServiceContracts.prototype); Object.freeze(V4StaticServiceContracts);
