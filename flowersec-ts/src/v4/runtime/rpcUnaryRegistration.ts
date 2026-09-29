import { byteEventSource } from "../eventSource.js";
import type { VolatileExecutions } from "./volatileExecutions.js";
import type { V4UnaryHandler, V4UnaryHandlerOptions } from "../serviceHandlers.js";
import { methodDefinition, type CapturedMethodDefinition } from "../serviceDefinition.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { RPCProtocolError } from "./rpcFragment.js";

export function captureUnaryHandler<Options extends V4UnaryHandlerOptions>(options: Options): Omit<V4UnaryHandlerOptions, "authorization"> & Pick<Options, "authorization"> {
  const { workClass, maxConcurrentCalls, applicationBytes, authorization } = options;
  if (workClass !== "short" && workClass !== "resident" || !Number.isSafeInteger(maxConcurrentCalls) || maxConcurrentCalls < 1 || maxConcurrentCalls > 1024 ||
      typeof applicationBytes !== "bigint" || applicationBytes < 1n || applicationBytes > (1n << 63n) - 1n ||
      authorization !== "authenticated" && typeof authorization !== "function") throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ workClass, maxConcurrentCalls, applicationBytes, authorization: authorization as Options["authorization"] });
}
export function rpcUnaryRegistrationCharge(options: V4UnaryHandlerOptions, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([2048n + runtimeBytes + options.applicationBytes, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
/** One declared method generation. Closure stops future captures; already
 * captured requests retain its exact callback, policy and actual allowance. */
export class RPCUnaryRegistration<Handler = V4UnaryHandler<unknown, unknown>> {
  readonly definition: CapturedMethodDefinition;
  #reference: ResourceReference | undefined;
  #handler: Handler | undefined;
  #options: V4UnaryHandlerOptions | undefined;
  #closed = false;
  #captures = 0;
  #active = 0;
  #permission: "allowed" | "denied" | "unavailable" = "allowed";
  constructor(readonly method: object, handler: Handler, options: V4UnaryHandlerOptions,
    runtimeBytes: bigint, reference: ResourceReference, readonly execution?: VolatileExecutions, shape: "unary" | "server_streaming" = "unary") {
    this.definition = methodDefinition(method);
    if (this.definition.shape !== shape || typeof handler !== "function" && (shape !== "server_streaming" || byteEventSource(handler) === undefined)) throw new RPCProtocolError("rpc_handler_binding");
    this.#reference = reference.take(rpcUnaryRegistrationCharge(options, runtimeBytes));
    this.#handler = handler; this.#options = options; Object.freeze(this);
  }
  sameEnvironment(reference: ResourceReference): boolean {
    if (this.#closed) throw new RPCProtocolError("rpc_handler_closed"); return this.#reference!.sameEnvironment(reference);
  }
  capture(): RPCUnaryHandlerCapture<Handler> | undefined {
    if (this.#closed) return; this.#reference!.check();
    if (this.#captures >= 4096) throw new RPCProtocolError("resource_exhausted"); this.#captures++;
    return new RPCUnaryHandlerCapture(this, this.#handler!, this.#options!, this.execution);
  }
  permission(): "allowed" | "denied" | "unavailable" { return this.#permission; }
  setPermission(permission: "allowed" | "denied" | "unavailable"): void {
    if (!["allowed", "denied", "unavailable"].includes(permission)) throw new RPCProtocolError("rpc_handler_binding"); this.#permission = permission;
  }
  admit(): void {
    this.#reference!.checkRetained();
    if (this.#permission !== "allowed") throw new RPCProtocolError(this.#permission === "denied" ? "permission_denied" : "service_unavailable");
    if (this.#active >= this.#options!.maxConcurrentCalls) throw new RPCProtocolError("resource_exhausted"); this.#active++;
  }
  release(active: boolean): void { if (active) this.#active--; this.#captures--; this.#collect(); }
  close(): void { this.#closed = true; this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#captures !== 0) return;
    this.#handler = undefined; this.#options = undefined; this.#reference?.release(); this.#reference = undefined;
  }
}
export class RPCUnaryHandlerCapture<Handler = V4UnaryHandler<unknown, unknown>> {
  #registration: RPCUnaryRegistration<Handler> | undefined;
  #active = false;
  constructor(registration: RPCUnaryRegistration<Handler>, readonly handler: Handler, readonly options: V4UnaryHandlerOptions, readonly execution?: VolatileExecutions) {
    this.#registration = registration; Object.freeze(this);
  }
  check(): void {
    if (this.#registration === undefined) throw new RPCProtocolError("rpc_handler_closed");
    const permission = this.#registration.permission();
    if (permission !== "allowed") throw new RPCProtocolError(permission === "denied" ? "permission_denied" : "service_unavailable");
  }
  current(): boolean { return this.#registration?.permission() === "allowed"; }
  admit(): void {
    this.check(); if (this.#active) throw new RPCProtocolError("rpc_handler_owner"); this.#registration!.admit(); this.#active = true;
  }
  close(): void { const original = this.#registration; this.#registration = undefined; original?.release(this.#active); }
}
for (const constructor of [RPCUnaryRegistration, RPCUnaryHandlerCapture]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }
