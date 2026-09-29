import type { LiveAuthorizationRequest, VerifiedCredentialClosure } from "./credentialVerifier.js";
import type { V4EnvironmentRuntime, EnvironmentDependency } from "./environment.js";
import type { ClientAdmissionExchange } from "./clientAdmission.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { timerChunk } from "./deadline.js";

export type V4LiveAuthorizationRequest = LiveAuthorizationRequest;
/** Independently authenticated bounded control transport. One invocation is
 * one physical request, without retries, detached borrows or pool fallback.
 * Invoke check immediately before publication, including after TLS work, and
 * return the full signed activation proof's byte count. */
export type V4LiveAuthorizationProvider = (request: V4LiveAuthorizationRequest, destination: Uint8Array,
  options: Readonly<{ signal: AbortSignal; check(): void }>) => Promise<number>;
export interface V4LiveAuthorizationConfig {
  readonly requestAuthorization: V4LiveAuthorizationProvider;
  readonly maxConcurrentRequests: number;
  readonly runtimeBytes: bigint;
  readonly providerBytes: bigint;
}

const owners = new WeakMap<V4LiveAuthorizationProvider, V4EnvironmentRuntime>();
/** Built-in transports retain their original Environment admission. */
export function bindLiveAuthorizationConfig(environment: V4EnvironmentRuntime, config: V4LiveAuthorizationConfig): V4LiveAuthorizationConfig {
  owners.set(config.requestAuthorization, environment); return config;
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
    this.#charge = new ResourceVector([8192n + config.runtimeBytes, config.providerBytes, 0n, 4n, 1n, 1n, 1n, 1n, 1n, 0n, 0n]);
    this.#dependency = environment.admitDependency("live_authorization", new ResourceVector([environment.resources.runtimeBytes + 512n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
    this.#dependency.onClose(() => { this.#closed = true; for (const abort of this.#active) abort.abort(); this.#cleanup(); });
  }
  close(): void { this.#dependency.close(); }
  #cleanup(): void { if (this.#closed && this.#active.size === 0) { this.#provider = undefined; this.#dependency.release(); } }
  async authorize(closure: VerifiedCredentialClosure, exchange: ClientAdmissionExchange, admission: ResourceReference,
    check: () => void, signal: AbortSignal): Promise<void> {
    this.#dependency.check(); check();
    if (signal.aborted || this.#closed) throw new Error("closed");
    if (this.#active.size >= this.#maximum) throw new Error("resource_exhausted");
    const r = this.environment.resources, reservation = r.root.reserve({ owner: { ...r.owner, kind: "live_authorization_request" }, accounts: r.accounts, charge: this.#charge });
    const abort = new AbortController(); this.#active.add(abort);
    let request: LiveAuthorizationRequest | undefined, output: Uint8Array | undefined, timer: ReturnType<typeof setTimeout> | undefined;
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
      output = new Uint8Array(4096); request = closure.liveAuthorizationRequest(admission);
      signal.addEventListener("abort", canceled, { once: true }); tick(); guard();
      // Retain real request/output borrowing through provider return even when
      // cancellation leaves the remote durable transaction outcome unknown.
      const count = await this.#provider!(request, output, Object.freeze({ signal: abort.signal, check: guard }));
      guard();
      if (!Number.isSafeInteger(count) || count < 1 || count > output.length) throw new Error("control_response_invalid");
      exchange.installLiveAuthorization(output.subarray(0, count)); guard();
    } catch {
      // Provider exceptions can retain response bodies or its private client
      // graph. Public failure preserves uncertainty without exporting them.
      throw new Error(abort.signal.aborted || signal.aborted ? "canceled" : "live_authorization_failed");
    } finally {
      if (timer !== undefined) clearTimeout(timer); signal.removeEventListener("abort", canceled);
      output?.fill(0);
      if (request !== undefined) for (const value of Object.values(request)) if (value instanceof Uint8Array) value.fill(0);
      reservation.release(); this.#active.delete(abort); this.#cleanup();
    }
  }
}
