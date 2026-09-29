import type { V4StreamingImplementation } from "../serviceHandlers.js";
import { serviceDefinition, type CapturedMethodDefinition } from "../serviceDefinition.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";
import { AdmissionOffer } from "./serviceContract.js";
import type { ContractQueryTargets } from "./contractQuery.js";
import type { ContractSnapshotChoice } from "./contractSnapshotWriter.js";
import type { TrustedClock } from "./clock.js";
import type { RPCUnaryRegistration, RPCUnaryHandlerCapture } from "./rpcUnaryRegistration.js";
import type { NotificationRegistration } from "./notifyDispatch.js";

interface Registration {
  readonly contract: ServiceContractSnapshot;
  readonly offers: readonly AdmissionOffer[];
  readonly maxOfferWindowMS: bigint | undefined;
  readonly advertised: boolean;
}

interface MethodRoute {
  readonly namespace: string; readonly method: object; readonly facts: CapturedMethodDefinition;
  entries: readonly Registration[]; registered: boolean; generation: bigint;
  handler: RPCUnaryRegistration | undefined;
  notification?: NotificationRegistration;
  streaming?: RPCUnaryRegistration<V4StreamingImplementation<unknown, unknown>>;
}
function declarations(definitions: readonly object[], maxMethods: number) {
  if (!Array.isArray(definitions) || !Number.isSafeInteger(maxMethods) || maxMethods < 1 || maxMethods > 4096 || definitions.length > maxMethods) throw new RPCProtocolError("configuration_capacity");
  const entries: MethodRoute[] = [], keys = new Set<string>();
  for (const definition of definitions) {
    const captured = serviceDefinition(definition);
    for (const entry of captured.entries) {
      const key = `${captured.namespace}\0${entry.facts.typeID}`;
      if (keys.has(key)) throw new RPCProtocolError("service_definition_duplicate"); keys.add(key);
      entries.push({ namespace: captured.namespace, method: entry.method, facts: entry.facts, entries: [], registered: false, generation: 0n, handler: undefined });
    }
    if (entries.length > maxMethods) throw new RPCProtocolError("configuration_capacity");
  }
  return entries;
}
export function contractRoutesCharge(definitions: readonly object[], maxMethods: number, runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const methods = declarations(definitions, maxMethods); let bytes = 256n + runtimeBytes;
  for (const { namespace, facts } of methods) {
    bytes += 1024n + 8n * 8n * 128n + runtimeBytes + BigInt(2 * (namespace.length + facts.request.revision.length + facts.responseRevision.length));
    for (const error of facts.errors) bytes += 160n + BigInt(error.codec.revision.length * 2);
  }
  // Complete contract bodies carry their own original snapshot reservations.
  return new ResourceVector([bytes, 0n, 0n, BigInt(methods.length + 1), 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
const capability = Symbol("captured original contract route");
/** An accepted input retains exactly this method/generation/contract even when
 * later registration changes. It grants no authorization or handler permit. */
export class CapturedContractRoute {
  readonly namespace: string;
  readonly method: object;
  readonly definition: CapturedMethodDefinition;
  readonly contract: ServiceContractSnapshot;
  readonly generation: bigint;
  readonly registered: boolean;
  readonly handler: RPCUnaryHandlerCapture | undefined;
  readonly notification: NotificationRegistration | undefined;
  readonly streaming: RPCUnaryHandlerCapture<V4StreamingImplementation<unknown, unknown>> | undefined;
  #reference: ResourceReference | undefined;
  constructor(token: symbol, route: MethodRoute, contract: ServiceContractSnapshot, reference: ResourceReference) {
    if (token !== capability) throw new RPCProtocolError("rpc_route_owner");
    this.namespace = route.namespace; this.method = route.method; this.definition = route.facts;
    this.generation = route.generation; this.registered = route.registered; this.contract = contract.retain(); this.notification = route.notification;
    try { this.handler = route.registered ? route.handler?.capture() : undefined; this.streaming = route.registered ? route.streaming?.capture() : undefined; }
    catch (error) { this.contract.release(); throw error; }
    this.#reference = reference; Object.freeze(this);
  }
  check(): void { if (this.#reference === undefined) throw new RPCProtocolError("rpc_route_closed"); this.#reference.checkRetained(); }
  close(): void {
    if (this.#reference === undefined) return; this.handler?.close(); this.streaming?.close(); this.contract.release(); this.#reference.release(); this.#reference = undefined;
  }
  toJSON(): object { return {}; }
}

/** Finite route set fixed before READY. Updates replace only the registered
 * contracts/availability of a declared method; they never add a method, change
 * its shape, select another namespace by type alone or change the Session. */
export class ContractRoutes {
  #reference: ResourceReference | undefined;
  readonly #methods: MethodRoute[];
  readonly #scratch = new Uint8Array(256);
  readonly #lookup = new Map<string, MethodRoute>();
  readonly #clock: TrustedClock | undefined;
  #generation = 0n;
  constructor(definitions: readonly object[], maxMethods: number, runtimeBytes: bigint, reference: ResourceReference, clock?: TrustedClock) {
    const charge = contractRoutesCharge(definitions, maxMethods, runtimeBytes);
    this.#reference = reference.take(charge); this.#clock = clock;
    try {
      this.#methods = declarations(definitions, maxMethods);
      for (const method of this.#methods) this.#lookup.set(`${method.namespace}\0${method.facts.typeID}`, method);
    }
    catch (error) { this.#reference.release(); this.#reference = undefined; throw error; }
  }
  #check(): void { if (this.#reference === undefined) throw new RPCProtocolError("rpc_routes_closed"); this.#reference.check(); }
  #method(namespace: string, method: object): MethodRoute {
    this.#check(); const route = this.#methods.find(entry => entry.namespace === namespace && entry.method === method);
    if (route === undefined) throw new RPCProtocolError("rpc_route_not_declared"); return route;
  }
  #now(): { lowerMS: bigint; upperMS: bigint } {
    const generation = this.#generation;
    if (this.#clock === undefined) throw new RPCProtocolError("admission_offer_unavailable");
    const now = this.#clock.sample().requireInterval(); this.#check();
    if (this.#generation !== generation) throw new RPCProtocolError("rpc_registration_changed");
    return now;
  }
  installHandler(namespace: string, method: object, handler: RPCUnaryRegistration): void {
    const route = this.#method(namespace, method);
    if (handler.method !== method || handler.definition !== route.facts || !handler.sameEnvironment(this.#reference!) ||
        this.#generation === (1n << 64n) - 1n) throw new RPCProtocolError("rpc_handler_binding");
    if (route.handler === handler) return;
    const old = route.handler; route.handler = handler; route.generation = ++this.#generation; old?.close();
  }
  installStreamingHandler(namespace: string, method: object, handler: RPCUnaryRegistration<V4StreamingImplementation<unknown, unknown>>): void {
    const route = this.#method(namespace, method);
    if (route.facts.shape !== "server_streaming" || handler.method !== method || !handler.sameEnvironment(this.#reference!) ||
        this.#generation === (1n << 64n) - 1n) throw new RPCProtocolError("rpc_handler_binding");
    if (route.streaming === handler) return;
    const old = route.streaming; route.streaming = handler; route.generation = ++this.#generation; old?.close();
  }
  installNotificationHandler(namespace: string, method: object, handler: NotificationRegistration): void {
    const route = this.#method(namespace, method);
    if (route.facts.shape !== "notify" || route.facts.semantics !== "execution" || !handler.sameEnvironment(this.#reference!) ||
        this.#generation === (1n << 64n) - 1n) throw new RPCProtocolError("rpc_handler_binding");
    if (route.notification === handler) return;
    const old = route.notification; route.notification = handler; route.generation = ++this.#generation; old?.close();
  }
  install(namespace: string, method: object, contracts: readonly ServiceContractSnapshot[]): void {
    const route = this.#method(namespace, method);
    if (!Array.isArray(contracts) || contracts.length < 1 || contracts.length > 8 || this.#generation === (1n << 64n) - 1n) throw new RPCProtocolError("configuration_capacity");
    // The service authority's lower time bound is the only expiry evidence.
    // Updates cannot remove a still-published execution admission obligation.
    const now = route.entries.some(entry => entry.offers.length !== 0) ? this.#now() : undefined;
    const captured: Registration[] = [];
    try {
      for (const contract of contracts) {
        if (!contract.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_route_owner");
        contract.checkMethod(namespace, route.facts);
        const digest = this.#scratch.subarray(0, 32); contract.copyDigest(digest);
        if (captured.some(other => other.contract.hasDigest(digest))) throw new RPCProtocolError("service_contract_duplicate");
        const old = route.entries.find(entry => entry.contract.hasDigest(digest));
        captured.push({ contract: contract.retain(), offers: Object.freeze(old?.offers.filter(offer => now === undefined || now.lowerMS < offer.notAfterMS) ?? []),
          maxOfferWindowMS: old?.maxOfferWindowMS, advertised: old?.advertised ?? false });
      }
      for (const old of route.entries) {
        old.contract.copyDigest(this.#scratch.subarray(0, 32));
        if (!captured.some(entry => entry.contract.hasDigest(this.#scratch.subarray(0, 32))) &&
            old.offers.some(offer => now === undefined || now.lowerMS < offer.notAfterMS)) throw new RPCProtocolError("service_contract_obligation");
      }
    } catch (error) { for (const entry of captured) entry.contract.release(); throw error; }
    finally { this.#scratch.fill(0); }
    const previous = route.entries; route.entries = Object.freeze(captured); route.registered = true; route.generation = ++this.#generation;
    for (const entry of previous) entry.contract.release();
  }
  /** Publish one explicitly selected registered body and one exact Offer.
   * Overlapping windows remain distinct; normal updates never evict promises. */
  advertise(namespace: string, method: object, digest: Uint8Array, offer?: AdmissionOffer, maxOfferWindowMS?: bigint): void {
    const route = this.#method(namespace, method), selected = route.entries.find(entry => entry.contract.hasDigest(digest));
    if (!route.registered || selected === undefined || this.#generation === (1n << 64n) - 1n) throw new RPCProtocolError("service_contract_mismatch");
    let offers: readonly AdmissionOffer[] = [];
    if (selected.contract.semantics === "execution") {
      if (!(offer instanceof AdmissionOffer) || maxOfferWindowMS === undefined || selected.maxOfferWindowMS !== undefined && selected.maxOfferWindowMS !== maxOfferWindowMS) throw new RPCProtocolError("admission_offer_unavailable");
      try { offer.copyEncoded(selected.contract, maxOfferWindowMS, this.#scratch); }
      finally { this.#scratch.fill(0); }
      const now = this.#now();
      if (now.lowerMS >= offer.notAfterMS) throw new RPCProtocolError("admission_offer_unavailable");
      offers = selected.offers.filter(value => now.lowerMS < value.notAfterMS);
      if (!offers.some(value => value.notBeforeMS === offer.notBeforeMS && value.notAfterMS === offer.notAfterMS)) {
        if (offers.length === 8) throw new RPCProtocolError("resource_exhausted"); offers = [...offers, offer];
      }
    } else if (offer !== undefined || maxOfferWindowMS !== undefined) throw new RPCProtocolError("query_offer_presence");
    route.entries = Object.freeze(route.entries.map(entry => ({ ...entry, advertised: entry === selected,
      ...(entry === selected ? { offers: Object.freeze(offers), maxOfferWindowMS } : {}) })));
    route.generation = ++this.#generation;
  }
  disable(namespace: string, method: object): void {
    const route = this.#method(namespace, method);
    if (this.#generation === (1n << 64n) - 1n) throw new RPCProtocolError("configuration_capacity");
    if (route.entries.some(entry => entry.offers.length !== 0)) {
      const now = this.#now();
      if (route.entries.some(entry => entry.offers.some(offer => now.lowerMS < offer.notAfterMS))) throw new RPCProtocolError("service_contract_obligation");
    }
    route.registered = false; route.generation = ++this.#generation;
  }
  /** Called only after the original Session's per-target permission gate.
   * Known selects body elision, never a registration or the current revision. */
  query(request: ContractQueryTargets, index: number): ContractQuerySelection | undefined {
    this.#check(); if (!request.sameEnvironment(this.#reference!)) throw new RPCProtocolError("rpc_route_owner");
    const identity = request.identity(index), route = this.#lookup.get(`${identity.namespace}\0${identity.typeID}`);
    if (route === undefined || !route.registered) return;
    let selected: Registration | undefined;
    try {
      const wanted = this.#scratch.subarray(0, 32), exact = request.copyDigest(index, "wanted", wanted);
      selected = route.entries.find(entry => exact ? entry.contract.hasDigest(wanted) : entry.advertised);
    } finally { this.#scratch.fill(0); }
    if (selected === undefined) return;
    const contract = selected.contract.retain(), generation = route.generation;
    try {
      let offer: AdmissionOffer | undefined;
      if (contract.semantics === "execution") {
        const now = this.#now();
        offer = selected.offers.find(value => now.lowerMS >= value.notBeforeMS && now.upperMS < value.notAfterMS);
        if (offer === undefined) return;
      }
      this.#check(); if (!route.registered || route.generation !== generation) return;
      const choice: ContractSnapshotChoice = { status: request.matchesKnown(index, contract) ? "available_unchanged" : "available_full", contract,
        ...(offer === undefined ? {} : { offer, maxOfferWindowMS: selected.maxOfferWindowMS! }) };
      return new ContractQuerySelection(capability, this, route, generation, choice);
    } finally { contract.release(); }
  }
  queryCurrent(selection: ContractQuerySelection): boolean {
    const state = querySelections.get(selection);
    return this.#reference !== undefined && state?.routes === this && state.route.registered && state.route.generation === state.generation;
  }
  checkQueryPublication(selections: readonly ContractQuerySelection[]): void {
    this.#check();
    if (selections.length > 8) throw new RPCProtocolError("configuration_capacity");
    const now = selections.some(selection => selection.choice.offer !== undefined) ? this.#now() : undefined;
    for (const selection of selections) {
      if (!this.queryCurrent(selection)) throw new RPCProtocolError("rpc_registration_changed");
      const offer = selection.choice.offer;
      if (offer !== undefined && (now === undefined || now.lowerMS < offer.notBeforeMS || now.upperMS >= offer.notAfterMS)) throw new RPCProtocolError("admission_offer_unavailable");
    }
  }
  /** Synchronous known-body lookup for the prepaid rejection hasher. This
   * borrow cannot escape the current SDK input-admission turn. */
  known(header: ApplicationHeader): ServiceContractSnapshot | undefined {
    this.#check(); header.copyBytes(6, this.#scratch);
    try { for (const route of this.#methods) for (const { contract } of route.entries) if (contract.hasDigest(this.#scratch.subarray(0, 32))) return contract; }
    finally { this.#scratch.fill(0); }
    return undefined;
  }
  capture(header: ApplicationHeader): CapturedContractRoute | undefined {
    this.#check(); header.copyBytes(6, this.#scratch);
    try {
      for (const route of this.#methods) for (const { contract } of route.entries) {
        if (!contract.hasDigest(this.#scratch.subarray(0, 32))) continue;
        const reference = this.#reference!.borrow();
        try { return new CapturedContractRoute(capability, route, contract, reference); }
        catch (error) { reference.release(); throw error; }
      }
    } finally { this.#scratch.fill(0); }
    return undefined;
  }
  /** The original first-registration gate. Existing execution joins deliberately
   * do not consult a current Offer or reapply a newer method horizon. */
  checkExecutionAdmission(captured: CapturedContractRoute, cutoff: bigint, now: Readonly<{ lowerMS: bigint; upperMS: bigint }>): void {
    this.#check(); const route = this.#method(captured.namespace, captured.method);
    if (!route.registered || route.generation !== captured.generation ||
        !(captured.definition.shape === "notify" ? captured.notification?.current() : captured.definition.shape === "server_streaming"
          ? captured.streaming?.current() : captured.handler?.current())) throw new RPCProtocolError("service_unavailable");
    const entry = route.entries.find(value => value.contract === captured.contract);
    if (entry === undefined || entry.contract.semantics !== "execution") throw new RPCProtocolError("service_contract_mismatch");
    if (!entry.offers.some(offer => offer.notBeforeMS <= now.lowerMS && now.upperMS < cutoff && cutoff <= offer.notAfterMS)) throw new RPCProtocolError("deadline_exceeded");
  }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  close(): void {
    if (this.#reference === undefined) return;
    for (const method of this.#methods) for (const { contract } of method.entries) contract.release();
    for (const method of this.#methods) { method.handler?.close(); method.streaming?.close(); method.notification?.close(); }
    this.#methods.length = 0; this.#lookup.clear(); this.#scratch.fill(0); this.#reference.release(); this.#reference = undefined;
  }
}

interface QuerySelectionState { readonly routes: ContractRoutes; readonly route: MethodRoute; readonly generation: bigint }
const querySelections = new WeakMap<ContractQuerySelection, QuerySelectionState>();
/** One complete registered body pinned by the original fixed query read. */
export class ContractQuerySelection {
  readonly choice: ContractSnapshotChoice;
  constructor(token: symbol, routes: ContractRoutes, route: MethodRoute, generation: bigint, choice: ContractSnapshotChoice) {
    if (token !== capability || choice.contract === undefined) throw new RPCProtocolError("rpc_route_owner");
    this.choice = Object.freeze({ ...choice, contract: choice.contract.retain() });
    querySelections.set(this, { routes, route, generation }); Object.freeze(this);
  }
  current(): boolean { const state = querySelections.get(this); return state !== undefined && state.routes.queryCurrent(this); }
  close(): void { if (!querySelections.delete(this)) return; this.choice.contract?.release(); }
}
Object.freeze(ContractQuerySelection.prototype); Object.freeze(ContractQuerySelection);
