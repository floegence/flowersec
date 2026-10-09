import type { ConnectionFacts } from "./connectionFacts.js";
import type { CredentialInput, LiveAuthorizationRequest, VerifiedCredentialClosure } from "./credentialVerifier.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "./environment.js";
import type { ClientAdmissionExchange } from "./clientAdmission.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { timerChunk } from "./deadline.js";
import { credentialOwner } from "./credentialSupport.js";

export type V4LiveAuthorizationRequest = LiveAuthorizationRequest;
/** Independently authenticated bounded control transport. One invocation is
 * one physical request, without retries, detached borrows or pool fallback.
 * Invoke check immediately before publication, including after TLS work, and
 * return the complete signed response byte count. Tunnel responses contain
 * ["live-tunnel-material-1", activation_bytes, local_grant_bytes]. */
export type V4LiveAuthorizationProvider = (request: V4LiveAuthorizationRequest, destination: Uint8Array,
  options: Readonly<{ signal: AbortSignal; check(): void }>) => Promise<number>;
export interface V4LiveAuthorizationConfig {
  readonly requestAuthorization: V4LiveAuthorizationProvider;
  readonly maxConcurrentRequests: number;
  readonly runtimeBytes: bigint;
  readonly providerBytes: bigint;
}

/** Private custody follows the acquired material, including failures before TxA. */
export interface OriginalLiveAuthorizationCustody { withdraw(): void; handoff(): void; }
type AcquireOriginalMaterial = (input: CredentialInput, reference: ResourceReference) => OriginalLiveAuthorizationCustody;
const custodyOwners = new WeakMap<V4LiveAuthorizationProvider, AcquireOriginalMaterial>();
const acquisitionWithdrawals = new WeakMap<V4LiveAuthorizationProvider, () => void>();
const owners = new WeakMap<V4LiveAuthorizationProvider, V4EnvironmentRuntime>();
const responseObservers = new WeakMap<object, (proof: Uint8Array) => void>();
/** Private built-in transport continuation, never part of provider or package exports. */
export function observeOriginalLiveSpend(options: object, proof: Uint8Array): void { responseObservers.get(options)?.(proof); }
/** Built-in transports retain their original Environment admission. */
export function bindLiveAuthorizationConfig(environment: V4EnvironmentRuntime, config: V4LiveAuthorizationConfig, acquireOriginalMaterial?: AcquireOriginalMaterial, withdrawUnboundAcquisition?: () => void): V4LiveAuthorizationConfig {
  owners.set(config.requestAuthorization, environment); if (acquireOriginalMaterial !== undefined) custodyOwners.set(config.requestAuthorization, acquireOriginalMaterial);
  if (withdrawUnboundAcquisition !== undefined) acquisitionWithdrawals.set(config.requestAuthorization, withdrawUnboundAcquisition); return config;
}

/** The live control dependency belongs to the original Environment. */
export class LiveAuthorizationClient {
  readonly #dependency: EnvironmentDependency;
  readonly #active = new Set<AbortController>();
  readonly #maximum: number;
  readonly #charge: ResourceVector;
  #provider: V4LiveAuthorizationProvider | undefined;
  #closed = false;
  constructor(private readonly environment: V4EnvironmentRuntime, config: V4LiveAuthorizationConfig) {
    if (owners.has(config.requestAuthorization) && owners.get(config.requestAuthorization) !== environment) throw new Error("credential_binding");
    if (typeof config.requestAuthorization !== "function" || !Number.isSafeInteger(config.maxConcurrentRequests) || config.maxConcurrentRequests < 1 || config.maxConcurrentRequests > 65536 ||
        typeof config.runtimeBytes !== "bigint" || config.runtimeBytes < 1n || typeof config.providerBytes !== "bigint" || config.providerBytes < 1n) throw new Error("configuration_capacity");
    this.#maximum = config.maxConcurrentRequests; this.#provider = config.requestAuthorization;
    this.#charge = new ResourceVector([81920n + config.runtimeBytes, config.providerBytes, 0n, 4n, 1n, 1n, 1n, 1n, 1n, 0n, 0n]);
    this.#dependency = environment.admitDependency("live_authorization", new ResourceVector([environment.resources.runtimeBytes + 512n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
    this.#dependency.onClose(() => { this.#closed = true; for (const abort of this.#active) abort.abort(); this.#cleanup(); });
  }
  acquireOriginalMaterial(input: CredentialInput, reference: ResourceReference): OriginalLiveAuthorizationCustody | undefined {
    this.#dependency.check();
    if (input.source !== "live_authority" || this.#provider === undefined) return undefined;
    return custodyOwners.get(this.#provider)?.(input, reference);
  }
  withdrawUnboundAcquisition(): void { if (this.#provider !== undefined) acquisitionWithdrawals.get(this.#provider)?.(); }
  close(): void { this.#dependency.close(); }
  #cleanup(): void { if (this.#closed && this.#active.size === 0) { this.#provider = undefined; this.#dependency.release(); } }
  async authorize(closure: VerifiedCredentialClosure, exchange: ClientAdmissionExchange, admission: ResourceReference,
    check: () => void, signal: AbortSignal, connectionFacts?: ConnectionFacts): Promise<void> {
    this.#dependency.check(); check();
    if (signal.aborted || this.#closed) throw new Error("closed");
    if (this.#active.size >= this.#maximum) throw new Error("resource_exhausted");
    const r = this.environment.resources, reservation = r.root.reserve({ owner: credentialOwner(r, "live_authorization_request"), accounts: r.accounts, charge: this.#charge });
    const abort = new AbortController(); this.#active.add(abort);
    let request: LiveAuthorizationRequest | undefined, output: Uint8Array | undefined, timer: ReturnType<typeof setTimeout> | undefined;
    let invocation: Readonly<{ signal: AbortSignal; check(): void }> | undefined;
    const canceled = (): void => { abort.abort(); };
    try {
      if (!reservation.sameEnvironment(admission)) throw new Error("credential_binding");
      const deadline = exchange.fields.preparationDeadline;
      const guard = (): void => {
        this.#dependency.check(); reservation.check(); check(); deadline.check();
        if (abort.signal.aborted || signal.aborted) throw new Error("canceled");
        closure.checkPreparation(admission);
      };
      const tick = (): void => {
        try { guard(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
        catch { abort.abort(); }
      };
      output = new Uint8Array(exchange.fields.pathKind === 1 ? 73728 : 4096); request = closure.liveAuthorizationRequest(admission);
      signal.addEventListener("abort", canceled, { once: true }); tick(); guard();
      // Retain real request/output borrowing through provider return even when
      // cancellation leaves the remote durable transaction outcome unknown.
      connectionFacts?.spendDispatched();
      invocation = Object.freeze({ signal: abort.signal, check: guard });
      if (connectionFacts !== undefined) responseObservers.set(invocation, proof => {
        closure.observeLiveSpend(proof, admission); connectionFacts.spent();
      });
      const count = await this.#provider!(request, output, invocation);
      guard();
      if (!Number.isSafeInteger(count) || count < 1 || count > output.length) throw new Error("control_response_invalid");
      exchange.installLiveAuthorization(output.subarray(0, count)); connectionFacts?.spent(); guard();
    } catch {
      // Provider exceptions can retain response bodies or its private client
      // graph. Public failure preserves uncertainty without exporting them.
      throw new Error(abort.signal.aborted || signal.aborted ? "canceled" : "live_authorization_failed");
    } finally {
      if (invocation !== undefined) responseObservers.delete(invocation);
      if (timer !== undefined) clearTimeout(timer); signal.removeEventListener("abort", canceled);
      output?.fill(0);
      if (request !== undefined) for (const value of Object.values(request)) if (value instanceof Uint8Array) value.fill(0);
      reservation.release(); this.#active.delete(abort); this.#cleanup();
    }
  }
}
