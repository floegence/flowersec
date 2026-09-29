import type { V4EnvironmentRuntime } from "./runtime/environment.js";
import type { ServiceBindingReservation } from "./runtime/serviceBindingPool.js";
import type { ClientSessionAdmission } from "./runtime/sessionAdmission.js";
import type { ContractQueryPreparation } from "./runtime/queryRenewalPosition.js";
import type { InitializerWorkload, InitializerMethodTarget } from "./runtime/initializerWorkload.js";
import { serviceDefinition, type V4MethodDefinition, type V4ServiceDefinition, type V4ServiceMethods } from "./serviceDefinition.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { V4UnaryOptions, V4UnaryResult } from "./unaryOperation.js";
import type { V4NotifyOptions, V4NotifyStatus } from "./notificationOperation.js";
import type { V4StreamingOptions, V4StreamingOperation, V4ExecutionStreamingOperation } from "./streamingOperation.js";
import { serviceClient, type V4ServiceClient } from "./serviceClient.js";
import { captureServiceBinding, type ServiceBindingOptions, type CapturedServiceBinding } from "./runtime/serviceBindingConfig.js";
import type { ServiceBinding } from "./runtime/serviceBinding.js";
import type { V4AuthenticatedSessionRuntime } from "./runtime/session.js";
import type { TrustedDeadline } from "./runtime/deadline.js";
import { applicationHasPermit } from "./runtime/applicationExecutor.js";

export type V4DispatchRequirement = "required_for_dispatch" | "on_use";
declare const selectionType: unique symbol;
/** A captured local declaration. It owns no connection and has no lifecycle. */
export interface V4ServiceDependency<Methods extends V4ServiceMethods = V4ServiceMethods> { readonly [selectionType]: Methods }
export type V4ServiceDependencies = Readonly<Record<string, V4ServiceDependency<any>>>;
type ChildOptions<T> = Omit<T, "context" | "admission"> & { readonly admission?: "try_now" };
type MethodView<M> = M extends V4MethodDefinition<infer Request, infer Value, infer Shape, infer Semantics>
  ? Shape extends "notify" ? (value: Request, options?: ChildOptions<V4NotifyOptions>) => Promise<V4NotifyStatus>
    : Shape extends "server_streaming" ? (value: Request, options?: ChildOptions<V4StreamingOptions>) => Promise<Semantics extends "execution" ? V4ExecutionStreamingOperation<Value> : V4StreamingOperation<Value>>
    : (value: Request, options?: ChildOptions<V4UnaryOptions>) => Promise<V4UnaryResult<Value>> : never;
export type V4InvocationServices<Dependencies extends V4ServiceDependencies> = {
  readonly [Alias in keyof Dependencies]: Dependencies[Alias] extends V4ServiceDependency<infer Methods>
    ? { readonly [Method in keyof Methods]: MethodView<Methods[Method]> } : never;
};
interface Declaration {
  readonly definition: V4ServiceDefinition<any>;
  readonly binding: CapturedServiceBinding;
  readonly options: ServiceBindingOptions;
  readonly methods: readonly Readonly<{ name: string; method: object; requirement: V4DispatchRequirement; shape: string }>[];
}
const declarations = new WeakMap<object, Declaration>();
function alias(value: string): void {
  if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(value) || ["then", "constructor", "prototype"].includes(value)) throw new Error("configuration_capacity");
}
/** Select only the methods visible to an invocation. Binding configuration is
 * captured now; the original candidate Bind owner performs later preparation. */
export function v4ServiceDependency<Methods extends V4ServiceMethods, Selected extends Record<string, Methods[keyof Methods]>>(
  definition: V4ServiceDefinition<Methods>, options: Readonly<{
    binding: Omit<ServiceBindingOptions, "initialMethods">;
    methods: Selected;
    dispatchRequirements?: Partial<Record<keyof Selected, V4DispatchRequirement>>;
  }>,
): V4ServiceDependency<Selected> {
  const entries = Object.entries(options.methods), modes: Partial<Record<keyof Selected, V4DispatchRequirement>> = options.dispatchRequirements ?? {};
  if (entries.length < 1 || entries.length > 128 || new Set(entries.map(([, method]) => method)).size !== entries.length ||
      Object.keys(modes).some(key => !Object.hasOwn(options.methods, key))) throw new Error("configuration_capacity");
  const known = serviceDefinition(definition).entries;
  const methods = entries.map(([name, method]) => {
    alias(name); const facts = known.find(entry => entry.method === method)?.facts;
    const requirement = modes[name as keyof Selected] ?? "required_for_dispatch";
    if (facts === undefined || requirement !== "required_for_dispatch" && requirement !== "on_use") throw new Error("configuration_capacity");
    return Object.freeze({ name, method, requirement, shape: facts.shape });
  });
  const required = methods.filter(method => method.requirement === "required_for_dispatch");
  const configured = options.binding.methods ?? [];
  const bindingOptions: ServiceBindingOptions = { ...options.binding, initialMethods: required.map(entry => entry.method),
    methods: known.map(entry => {
      const original = configured.find(config => config.method === entry.method), selected = methods.find(method => method.method === entry.method);
      if (selected?.requirement !== "required_for_dispatch" && (original?.preacceptStream || original?.requiredForDispatch)) throw new Error("configuration_capacity");
      return { ...original, method: entry.method, requiredForDispatch: selected?.requirement === "required_for_dispatch" };
    }) };
  // Validate caller options before rebuilding the immutable method projection.
  if (configured.some(entry => !known.some(method => method.method === entry.method)) || new Set(configured.map(entry => entry.method)).size !== configured.length) throw new Error("configuration_capacity");
  const binding = captureServiceBinding(definition, bindingOptions, true);
  const capturedOptions = Object.freeze({ target: binding.target, maximumOfferWindowMS: binding.maximumOfferWindowMS,
    ...(options.binding.contractSource === undefined ? {} : { contractSource: options.binding.contractSource }) });
  const declaration = Object.freeze({ definition, binding, options: capturedOptions, methods: Object.freeze(methods) });
  const view = Object.freeze(Object.create(null)) as V4ServiceDependency<Selected>; declarations.set(view, declaration); return view;
}
export interface CapturedServiceDependency { readonly name: string; readonly declaration: Declaration }
export function captureServiceDependencies(input: V4ServiceDependencies | undefined): readonly CapturedServiceDependency[] {
  const entries = Object.entries(input ?? {});
  if (entries.length > 64) throw new Error("configuration_capacity");
  let count = 0;
  return Object.freeze(entries.map(([name, dependency]) => {
    alias(name); const declaration = declarations.get(dependency); if (declaration === undefined) throw new Error("configuration_capacity");
    count += declaration.methods.length; if (count > 128) throw new Error("configuration_capacity");
    return Object.freeze({ name, declaration });
  }));
}
interface BoundDependency { readonly declaration: Declaration; readonly binding: ServiceBinding; readonly client: V4ServiceClient<any> }
interface InvocationState { current: { readonly context: V4ApplicationContext; readonly bindings: ReadonlyMap<string, BoundDependency>; readonly deadline: TrustedDeadline; readonly check: () => void } | undefined }
/** Revocable invocation projection. Escaped functions capture only this cell
 * and local alias strings, never a Session/client/contract/executor graph. */
function invoke(state: InvocationState, aliasName: string, methodName: string, value: unknown, options: V4UnaryOptions = {}): Promise<unknown> {
  try {
    const current = state.current; if (current === undefined || !applicationHasPermit(current.context)) throw new Error("invocation_closed");
    current.check(); current.deadline.check();
    if (current.context.signal.aborted || options.signal?.aborted) throw new Error("canceled");
    if (options.context !== undefined || options.admission !== undefined && options.admission !== "try_now") throw new Error("admission_mode_incompatible");
    const bound = current.bindings.get(aliasName)!, method = bound.declaration.methods.find(method => method.name === methodName)!;
    bound.binding.checkDependency(method.method);
    const deadlineAtMS = options.deadlineAtMS === undefined || options.deadlineAtMS > current.deadline.cap ? current.deadline.cap : options.deadlineAtMS;
    const captured = { ...options, deadlineAtMS, context: current.context, admission: "try_now" as const };
    current.check(); if (state.current !== current) throw new Error("invocation_closed");
    if (method.shape === "notify") return bound.client.notify(method.method as any, value, captured);
    if (method.shape === "server_streaming") return bound.client.stream(method.method as any, value, captured);
    return bound.client.call(method.method as any, value, captured);
  } catch (error) { return Promise.reject(error); }
}
function methodView(state: InvocationState, aliasName: string, methodName: string): (value: unknown, options?: V4UnaryOptions) => Promise<unknown> {
  return (value, options) => invoke(state, aliasName, methodName, value, options);
}
function sameBinding(a: Declaration, b: Declaration): boolean {
  const x = a.binding, y = b.binding;
  if (a.definition !== b.definition || a.options.contractSource !== b.options.contractSource || x.offerRefresh !== y.offerRefresh ||
      x.maximumOfferWindowMS !== y.maximumOfferWindowMS || x.contractCheckIntervalMS !== y.contractCheckIntervalMS) return false;
  for (const key of ["authority", "tenant", "audience", "localSubject"] as const) if (x.target[key] !== y.target[key]) return false;
  if (x.target.peers.length !== y.target.peers.length || x.target.peers.some((peer, index) => peer.subject !== y.target.peers[index]!.subject || peer.identityDigest !== y.target.peers[index]!.identityDigest)) return false;
  for (const key of ["batchMS", "suspendMS", "joinMS", "timeErrorMS"] as const) if (x.offerTiming[key] !== y.offerTiming[key]) return false;
  return x.methods.length === y.methods.length && x.methods.every((method, index) => {
    const other = y.methods[index]!;
    if (method.method !== other.method || method.resumeKind !== other.resumeKind || method.streamKind !== other.streamKind ||
        method.defaultResponseLimitBytes !== other.defaultResponseLimitBytes || method.workClass !== other.workClass || method.acceptance.mode !== other.acceptance.mode) return false;
    if (method.streamMetadata?.length !== other.streamMetadata?.length || method.streamMetadata?.some((byte, index) => byte !== other.streamMetadata![index])) return false;
    if (method.acceptance.mode === "bounded") {
      if (other.acceptance.mode !== "bounded") return false;
      const ranges = other.acceptance.ranges;
      if (method.acceptance.ranges.length !== ranges.length || method.acceptance.ranges.some(range => !ranges.some(other => range.field === other.field && range.lower === other.lower && range.upper === other.upper))) return false;
    }
    return true;
  });
}
interface DependencyGroup { readonly members: CapturedServiceDependency[]; readonly binding: CapturedServiceBinding }
export class CandidateServiceDependencies {
  readonly #bindings = new Map<string, BoundDependency>();
  readonly #groups: readonly DependencyGroup[];
  readonly #reservations = new Map<DependencyGroup, ServiceBindingReservation>();
  #queries: ContractQueryPreparation | undefined;
  #reserved = false;
  #closed = false;
  #session: object | undefined;
  constructor(readonly declarations: readonly CapturedServiceDependency[]) {
    const groups: { members: CapturedServiceDependency[] }[] = [];
    for (const item of declarations) {
      const group = groups.find(group => sameBinding(group.members[0]!.declaration, item.declaration));
      if (group === undefined) groups.push({ members: [item] }); else group.members.push(item);
    }
    let streams = 0;
    this.#groups = groups.map(group => {
      const original = group.members[0]!.declaration.binding;
      const methods = original.methods.map((method, index) => {
        const required = group.members.some(item => item.declaration.binding.methods[index]!.required);
        return Object.freeze({ ...method, required, initial: required, preacceptStream: required && method.facts.shape === "server_streaming" });
      });
      const count = methods.filter(method => method.preacceptStream).length;
      streams += count; if (count > 2 || streams > 8) throw new Error("configuration_capacity");
      return { members: group.members, binding: Object.freeze({ ...original, methods: Object.freeze(methods) }) };
    });
  }
  reserve(environment: V4EnvironmentRuntime, admission?: ClientSessionAdmission, additionalTargets: readonly InitializerMethodTarget[] = []): void {
    this.#check(); if (this.#reserved) throw new Error("owner_unavailable"); this.#reserved = true;
    try {
      for (const group of this.#groups) this.#reservations.set(group, environment.reserveServiceBinding(group.binding));
      const targets = [...this.workloadTargets(), ...additionalTargets];
      if (targets.some(target => target.method.required && target.method.facts.shape === "server_streaming")) {
        if (admission === undefined) throw new Error("configuration_capacity"); environment.reserveDependencyStreams(admission, targets);
      }
      if (this.#groups.some(group => group.members[0]!.declaration.options.contractSource === undefined && group.binding.methods.some(method => method.required))) {
        if (admission === undefined) throw new Error("configuration_capacity");
        this.#queries = environment.reserveDependencyQueries(admission);
      }
    }
    catch (error) { this.close(); throw error; }
  }
  workloadTargets(): readonly InitializerMethodTarget[] {
    this.#check();
    return this.#groups.flatMap(group => group.binding.methods.filter(method =>
      group.members.some(member => member.declaration.methods.some(selected => selected.method === method.method)))
      .map(method => ({ method, namespace: group.binding.namespace, target: group.binding.target })));
  }
  async prepare(candidate: V4AuthenticatedSessionRuntime, deadline: TrustedDeadline, signal: AbortSignal, check: () => void): Promise<void> {
    if (this.declarations.length === 0) { this.checkRequired(); check(); return; }
    this.#session = candidate.rpcApplication();
    for (const group of this.#groups) {
      this.#check(); check(); const original = group.members[0]!.declaration;
      const reservation = this.#reservations.get(group);
      if (reservation === undefined) throw new Error("dependency_unavailable");
      const binding = await candidate.bindServiceDependency(original.definition, original.options, group.binding, deadline, signal, reservation, this.#queries);
      this.#reservations.delete(group);
      if (this.#closed || signal.aborted) { binding.close(); throw new Error("canceled"); }
      const client = serviceClient(original.definition, binding);
      for (const { name, declaration } of group.members) this.#bindings.set(name, { declaration, binding, client });
    }
    this.checkRequired(); check(); this.#queries?.close(); this.#queries = undefined;
  }
  #check(): void { if (this.#closed) throw new Error("dependency_unavailable"); }
  checkRequired(): void {
    this.#check(); if (this.#bindings.size !== this.declarations.length) throw new Error("dependency_unavailable");
    for (const bound of this.#bindings.values()) for (const method of bound.declaration.methods) {
      if (method.requirement === "required_for_dispatch") bound.binding.checkDependency(method.method);
    }
  }
  view(deadline: TrustedDeadline, check: () => void, workload?: InitializerWorkload): { services: object; enter(context: V4ApplicationContext): void; revoke(): void } {
    this.checkRequired(); const state: InvocationState = { current: undefined }, services: Record<string, object> = Object.create(null);
    for (const { name, declaration } of this.declarations) {
      const methods: Record<string, unknown> = Object.create(null);
      for (const method of declaration.methods) methods[method.name] = methodView(state, name, method.name);
      services[name] = Object.freeze(methods);
    }
    Object.freeze(services); let releaseWorkload: (() => void) | undefined;
    return { services, enter: context => {
      this.checkRequired(); releaseWorkload = workload?.enter(context, this.#session!); state.current = { context, bindings: this.#bindings, deadline, check };
    }, revoke: () => { releaseWorkload?.(); releaseWorkload = undefined; state.current = undefined; } };
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#queries?.close(); this.#queries = undefined; for (const reservation of this.#reservations.values()) reservation.close(); this.#reservations.clear(); for (const bound of this.#bindings.values()) bound.binding.close(); this.#bindings.clear(); this.#session = undefined; }
}
