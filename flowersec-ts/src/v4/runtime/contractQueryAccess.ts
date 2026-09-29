import { serviceDefinition } from "../serviceDefinition.js";
import type { ContractTargetIdentity } from "./contractQuery.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { ResourceVector, type ResourceReference } from "./resources.js";

export type ContractQueryPermission = "unavailable" | "denied" | "allowed";
function methods(definitions: readonly object[], maximum: number): readonly string[] {
  if (!Array.isArray(definitions) || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4096 || definitions.length > maximum) throw new RPCProtocolError("configuration_capacity");
  const keys: string[] = [];
  for (const definition of definitions) {
    const service = serviceDefinition(definition);
    for (const entry of service.entries) {
      const key = `${service.namespace}\0${entry.facts.typeID}`;
      if (keys.includes(key) || keys.length === maximum) throw new RPCProtocolError("configuration_capacity"); keys.push(key);
    }
  }
  return keys;
}
export function contractQueryAccessCharge(definitions: readonly object[], maximum: number, runtimeBytes: bigint): ResourceVector {
  if (runtimeBytes <= 0n) throw new RPCProtocolError("configuration_capacity");
  const keys = methods(definitions, maximum);
  return new ResourceVector([keys.reduce((sum, key) => sum + 128n + BigInt(key.length * 2), runtimeBytes), 0n, 0n, BigInt(keys.length + 2), 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

/** Original authenticated Session permission view. A trusted host updates only
 * predeclared methods from its authorization lifecycle. The fixed worker reads
 * these scalar decisions; it never calls a user authorizer, performs store I/O,
 * or infers access from namespace/known/wanted/refresh request fields. */
export class ContractQueryAccess {
  #reference: ResourceReference | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  readonly #methods = new Map<string, ContractQueryPermission>();
  #epoch = 1n;
  #closed = false;
  #working = false;
  #changed: (() => void) | undefined;
  constructor(definitions: readonly object[], maximum: number, delivery: ReceiveDeliveryGate, runtimeBytes: bigint, reference: ResourceReference) {
    this.#reference = reference.take(contractQueryAccessCharge(definitions, maximum, runtimeBytes));
    try {
      for (const key of methods(definitions, maximum)) this.#methods.set(key, "unavailable");
      this.#lease = delivery.retain(this.#reference, () => this.close()); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  #check(): void {
    if (this.#closed) throw new RPCProtocolError("query_authorization_closed");
    if (this.#working) throw new RPCProtocolError("query_busy");
    this.#reference!.check(); this.#working = true;
    try { this.#lease!.check(); }
    finally { this.#working = false; if (this.#closed) this.#cleanup(); }
    if (this.#closed) throw new RPCProtocolError("query_authorization_closed");
  }
  set(namespace: string, typeID: number, permission: ContractQueryPermission): void {
    if (typeof namespace !== "string" || namespace.length > 128 || !Number.isSafeInteger(typeID) || typeID < 1 || typeID > 0xffffffff) throw new RPCProtocolError("query_authorization_target");
    this.#check(); const key = `${namespace}\0${typeID}`;
    if (permission !== "unavailable" && permission !== "denied" && permission !== "allowed" || !this.#methods.has(key)) throw new RPCProtocolError("query_authorization_target");
    if (this.#methods.get(key) === permission) return;
    if (this.#epoch === (1n << 64n) - 1n) { this.close(); throw new RPCProtocolError("query_authorization_closed"); }
    this.#methods.set(key, permission); this.#epoch++; this.#changed?.();
  }
  observe(reference: ResourceReference, changed: () => void): () => void {
    this.#check();
    if (this.#changed !== undefined || !this.#reference!.sameEnvironment(reference)) throw new RPCProtocolError("rpc_query_consumer");
    this.#changed = changed;
    return () => { if (this.#changed === changed) this.#changed = undefined; };
  }
  checkActive(): void { this.#check(); }
  read(target: ContractTargetIdentity): Readonly<{ permission: ContractQueryPermission; epoch: bigint }> {
    const namespace = target.namespace, typeID = target.typeID;
    this.#check(); return { permission: this.#methods.get(`${namespace}\0${typeID}`) ?? "denied", epoch: this.#epoch };
  }
  check(epoch: bigint): void { this.#check(); if (!this.current(epoch)) throw new RPCProtocolError("query_authorization_changed"); }
  current(epoch: bigint): boolean { return !this.#closed && epoch !== 0n && epoch === this.#epoch; }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  close(): void { if (this.#closed) return; this.#closed = true; this.#changed?.(); if (!this.#working) this.#cleanup(); }
  #cleanup(): void {
    this.#lease?.release(); this.#lease = undefined; this.#methods.clear(); this.#changed = undefined; this.#reference?.release(); this.#reference = undefined;
  }
  cleanupComplete(): boolean { return this.#reference === undefined; }
}
Object.freeze(ContractQueryAccess.prototype); Object.freeze(ContractQueryAccess);
