import type { PreparedRawRegistration } from "./rawStreamPreparation.js";
import { methodDefinition } from "../serviceDefinition.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { V4StreamOpenAuthorizer, V4RawStreamHandler, V4MessageStreamHandler, V4StreamRegistrationOptions, V4StreamRegistrationOwner, V4ApplicationContext, V4ApplicationWaitOptions } from "../streamHandlers.js";
import { applicationDependsOn } from "./applicationExecutor.js";
import { captureMessageOptions } from "../messageStream.js";
import { fieldPattern } from "./schemaRegistry.js";
import { ResourceVector, type ResourceReference, type ResourceRoot, type ResourceAccount, type ResourceOwner } from "./resources.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import type { TrustedClock } from "./clock.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import { captureRawStreamMetadataContract } from "../../public/streamMetadata.js";

const complete: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
export type RegisteredHandler = V4RawStreamHandler | V4MessageStreamHandler<unknown, unknown>;
export function captureRegistration(options: V4StreamRegistrationOptions) {
  const maxActive = options.maxConcurrentStreams ?? 8, maxAuthorizing = options.maxAuthorizing ?? Math.min(maxActive, 4), timeout = options.applicationTimeoutMS ?? 30000n;
  const workClass = options.workClass ?? "resident";
  if (!Number.isSafeInteger(maxActive) || maxActive < 1 || maxActive > 128 || !Number.isSafeInteger(maxAuthorizing) || maxAuthorizing < 1 || maxAuthorizing > 128 ||
      workClass !== "short" && workClass !== "resident" || typeof options.applicationBytes !== "bigint" || options.applicationBytes < 1n || options.applicationBytes > (1n << 64n) - 1n || typeof timeout !== "bigint" || timeout < 1n || timeout > 86400000n) throw new Error("configuration_capacity");
  const recovery = options.resume;
  const resume = recovery === undefined ? undefined : Object.freeze({ namespace: recovery.namespace, method: recovery.method });
  if (resume !== undefined) {
    const method = methodDefinition(resume.method);
    if (typeof resume.namespace !== "string" || resume.namespace.length < 1 || resume.namespace.length > 256 || method.shape !== "unary" ||
        method.semantics !== "execution" || method.request.implementation !== "bytes" || method.response?.implementation !== "bytes") throw new Error("resume_binding");
  }
  const namespaces = options.metadataNamespaces ?? [];
  if (namespaces.length > 64) throw new Error("configuration_capacity");
  const captured = namespaces.map(({ namespace, version }) => {
    if (typeof namespace !== "string" || fieldPattern("metadata_namespace")!.exec(namespace)?.[0] !== namespace || namespace.startsWith("flowersec/") ||
        !Number.isSafeInteger(version) || version < 0 || version > 65535) throw new Error("configuration_capacity");
    return Object.freeze({ namespace, version });
  });
  if (new Set(captured.map(v => `${v.namespace}\0${v.version}`)).size !== captured.length) throw new Error("configuration_capacity");
  let metadataContract;
  try { metadataContract = captureRawStreamMetadataContract(options.metadataContract); }
  catch { throw new Error("configuration_capacity"); }
  if (metadataContract !== undefined && !captured.some(value => value.namespace === metadataContract!.namespace && value.version === metadataContract!.version)) {
    if (captured.length >= 64) throw new Error("configuration_capacity");
    captured.push(Object.freeze({ namespace: metadataContract.namespace, version: metadataContract.version }));
  }
  return Object.freeze({ ...captureMessageOptions(options), resume, maxActive, maxAuthorizing, workClass, applicationBytes: options.applicationBytes,
    applicationTimeoutMS: timeout, namespaces: Object.freeze(captured), ...(metadataContract === undefined ? {} : { metadataContract }) });
}
export function streamRegistrationCharge(options: ReturnType<typeof captureRegistration>, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([options.applicationBytes + runtimeBytes + 16384n, 0n, 0n, 2n, 0n, 1n, 1n, 0n, 0n, 0n, 0n]);
}
export function streamHandlerCharge(options: ReturnType<typeof captureRegistration>, runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([options.applicationBytes + 3n * runtimeBytes + 8448n, 0n, 0n, 4n, 1n, 3n, 1n, 0n, 0n, 0n, 0n]);
}
export function checkRawStreamKind(kind: string): void {
  if (typeof kind !== "string" || kind.length === 0 || kind.length > 128 || kind.startsWith("flowersec/") ||
      kind === "flowersec.rpc.v4" || kind.normalize("NFC") !== kind || new TextEncoder().encode(kind).length > 128) throw new Error("invalid_handler");
}
/** Wait admission is independent of Session I/O. Close clears both mutable
 * notification links before an uncooperative application can retain them. */
export class RegistrationHost {
  #counter = 0n;
  #closed: (() => void) | undefined;
  #changed: (() => void) | undefined;
  constructor(readonly clock: TrustedClock, readonly runtimeBytes: bigint, private readonly root: ResourceRoot,
    private readonly accounts: readonly ResourceAccount[], private readonly owner: ResourceOwner, private readonly id: bigint) {}
  attach(closed: () => void, changed: () => void): void { this.#closed = closed; this.#changed = changed; }
  detach(): void { this.#closed = this.#changed = undefined; }
  reserve(charge: ResourceVector): ResourceReference {
    if (this.#counter === (1n << 64n) - 1n) throw new Error("configuration_capacity");
    return this.root.reserve({ accounts: this.accounts, owner: { ...this.owner, kind: `v4_registration_wait_${this.id.toString(16)}_${(++this.#counter).toString(16)}` }, charge });
  }
  closed(): void { this.#closed?.(); }
  changed(): void { this.#changed?.(); }
}
/** SDK workflow exit and actual callback exit are separate facts. This job
 * owns the original parameter budget and never stores a Session continuation. */
export class RegisteredStreamJob {
  readonly abort = new AbortController();
  accepted = false;
  context: V4ApplicationContext | undefined;
  #workflow = true;
  #running = false;
  #finished = false;
  #work: ResourceReference | undefined;
  constructor(private readonly registration: StreamRegistrationState, private readonly cleanup: SessionCleanup) {
    cleanup.startJob(); registration.jobs.add(this);
  }
  own(reference: ResourceReference): void { this.#work = reference; }
  check(): void { this.#work!.check(); }
  accept(): void { this.accepted = true; this.registration.authorizing--; this.registration.active++; }
  async invoke<T, A extends unknown[]>(invocation: Readonly<{ context: V4ApplicationContext; release(): void }>, callback: (...args: A) => T | Promise<T>, args: A): Promise<T> {
    this.#running = true; this.context = invocation.context; this.cleanup.enterCallback();
    try { return await callback(...args); }
    finally {
      invocation.release(); this.context = undefined; this.#running = false; this.cleanup.exitCallback(); this.#collect();
    }
  }
  finishWorkflow(): void { this.#workflow = false; this.#collect(); }
  #collect(): void {
    if (this.#workflow || this.#running || this.#finished) return; this.#finished = true;
    if (this.accepted) this.registration.active--; else this.registration.authorizing--;
    this.registration.jobs.delete(this);
    this.#work?.release(); this.#work = undefined;
    this.registration.cleanup(); this.cleanup.finishJob();
  }
}
/** One entry in the original Session kind table. Public close never touches
 * another registration, the borrowed Environment, or accepted handler work. */
export class StreamRegistrationState implements V4StreamRegistrationOwner {
  definition: object | undefined;
  authorize: V4StreamOpenAuthorizer | undefined;
  handler: RegisteredHandler | undefined;
  host: RegistrationHost | undefined;
  readonly jobs = new Set<RegisteredStreamJob>();
  authorizing = 0;
  active = 0;
  closed = false;
  #reference: ResourceReference | undefined;
  #deadline: TrustedWindow | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #incomplete = false;
  #waits = 0;
  readonly #changed = new Set<() => void>();
  constructor(readonly kind: string, readonly options: ReturnType<typeof captureRegistration>, reference: ResourceReference,
    host: RegistrationHost, definition: object | undefined, authorize: V4StreamOpenAuthorizer | undefined, handler: RegisteredHandler, readonly preparation?: PreparedRawRegistration) {
    this.#reference = reference; this.host = host; this.definition = definition; this.authorize = authorize; this.handler = handler;
  }
  close(): void {
    if (this.closed) return; this.closed = true; this.preparation?.close(); this.host?.closed();
    // Dispatch captures the generation before its first wait. The public
    // registration need not retain any other application closures after close.
    this.authorize = undefined; this.handler = undefined; this.definition = undefined;
    for (const job of this.jobs) if (!job.accepted) job.abort.abort();
    try { this.#deadline = new TrustedWindow(this.host!.clock, this.options.cleanupTimeoutMS); }
    catch { this.#incomplete = true; }
    const tick = (): void => {
      if (this.#reference === undefined) return;
      try { this.#deadline!.check(); this.#timer = setTimeout(tick, timerChunk(this.#deadline!.remainingMS())); }
      catch { this.#timer = undefined; this.#incomplete = true; this.notify(); }
    };
    if (this.#deadline !== undefined) tick(); this.cleanup();
  }
  cleanup(): void {
    if (this.closed && this.jobs.size === 0 && this.#reference !== undefined) {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#deadline = undefined;
      this.authorize = undefined; this.handler = undefined; this.definition = undefined;
      this.#reference.release(); this.#reference = undefined; const host = this.host; this.host = undefined; host?.changed(); host?.detach();
    }
    this.host?.changed();
    this.notify();
  }
  notify(): void { for (const notify of this.#changed) notify(); }
  cleanupStatus(): V4CleanupStatus {
    if (this.#reference === undefined) return complete;
    return Object.freeze({ status: this.#incomplete ? "cleanup_incomplete" : "pending", core_cleanup: this.closed ? "complete" : "pending", pending_callbacks: BigInt(this.jobs.size) });
  }
  waitCleanup(options?: V4ApplicationWaitOptions): Promise<V4CleanupStatus> {
    const status = this.cleanupStatus(); if (status.status !== "pending") return Promise.resolve(status);
    try { if ([...this.jobs].some(job => applicationDependsOn(options?.context, job.context))) return Promise.reject(new Error("dependency_unavailable")); }
    catch { return Promise.reject(new Error("dependency_unavailable")); }
    if (options?.signal?.aborted) return Promise.reject(new Error("canceled"));
    if (this.#waits >= 32) return Promise.reject(new Error("resource_exhausted"));
    const host = this.host!;
    const ref = host.reserve(new ResourceVector([host.runtimeBytes + 256n, 0n, 0n, 1n, 0n, 1n, 1n, 0n, 0n, 0n, 0n])); this.#waits++;
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined, done = false;
      const finish = (canceled = false): void => {
        if (done) return; done = true;
        this.#changed.delete(wake); if (timer !== undefined) clearTimeout(timer); options?.signal?.removeEventListener("abort", cancel);
        this.#waits--; ref.release(); if (canceled) reject(new Error("canceled")); else resolve(this.cleanupStatus());
      };
      const cancel = (): void => finish(true), wake = (): void => { if (this.cleanupStatus().status !== "pending") finish(); };
      this.#changed.add(wake); options?.signal?.addEventListener("abort", cancel, { once: true });
      try {
        const window = new TrustedWindow(host.clock, this.options.cleanupTimeoutMS);
        const tick = (): void => { try { window.check(); timer = setTimeout(tick, timerChunk(window.remainingMS())); } catch { finish(); } };
        if (options?.signal?.aborted) cancel(); else { wake(); if (!done) tick(); }
      } catch { finish(); }
    });
  }
}
