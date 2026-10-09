import type { ResumeTargetFacts, ResumeOutcome } from "./resumeCodec.js";
import type { V4Checkpoint, V4CheckpointIssuanceOptions } from "../checkpoint.js";
import { captureCheckpoint, type CheckpointSessionPolicy } from "./checkpointToken.js";
import { executionStorage, executionMode, type ExecutionStorage, type ExecutionRecordFacts, type ExecutionResultReceipt } from "./executionStorage.js";
import { captureExecutionTarget, type ExecutionTarget, type ExecutionObservation, type ExecutionManagementResult } from "./executionManagementCodec.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { V4AuthenticatedContext } from "../streamHandlers.js";
import { credentialOwner, type CredentialResources } from "./credentialSupport.js";
import type { TrustedClock } from "./clock.js";
import type { ContractRoutes, CapturedContractRoute } from "./contractRoutes.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { RPCRequestInput } from "./rpcInput.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import { RPCProtocolError } from "./rpcFragment.js";
import { ResourceVector, type ResourceAccount, type ResourceReference } from "./resources.js";
import { timeAdd } from "./timeArithmetic.js";
/** Trusted mapping of this exact authenticated peer into a stable principal.
 * The fingerprint selects the current certificate; only authority + subject
 * belong to the execution key, so certificate rotation preserves history. */
export interface RPCExecutionIdentity {
  readonly authority: string;
  readonly subject: string;
  readonly identityDigest: string;
}
export interface VolatileExecutionConfig {
  readonly tenant: string;
  readonly audience: string;
  readonly namespace: string;
  readonly callerAuthorities: readonly string[];
  readonly maxRecords: number;
  readonly maxActive: number;
  readonly resultBytes: bigint;
}
function securityText(value: string): boolean { return typeof value === "string" && /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(value); }
function digestText(value: string): boolean { return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value) && !/^0+$/u.test(value); }
export function executionResultReadCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([2048n + runtimeBytes, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function captureExecutionIdentity(input: RPCExecutionIdentity | undefined): RPCExecutionIdentity | undefined {
  if (input === undefined) return;
  const { authority, subject, identityDigest } = input;
  if (!digestText(authority) || !securityText(subject) || !digestText(identityDigest)) throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ authority, subject, identityDigest });
}
export function captureVolatileExecution(input: VolatileExecutionConfig): VolatileExecutionConfig {
  if (executionStorage(input) !== undefined) return input;
  const { tenant, audience, namespace, callerAuthorities, maxRecords, maxActive, resultBytes } = input;
  if (![tenant, audience, namespace].every(securityText) || !Array.isArray(callerAuthorities) || callerAuthorities.length < 1 || callerAuthorities.length > 16 ||
    callerAuthorities.some(value => !digestText(value)) || new Set(callerAuthorities).size !== callerAuthorities.length ||
    !Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 8192 || !Number.isSafeInteger(maxActive) || maxActive < 1 || maxActive > Math.min(1024, maxRecords) ||
    typeof resultBytes !== "bigint" || resultBytes < 1n || resultBytes > 16777216n) throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ tenant, audience, namespace, callerAuthorities: Object.freeze([...callerAuthorities].sort()), maxRecords, maxActive, resultBytes });
}
export function executionServiceKey(config: Pick<VolatileExecutionConfig, "tenant" | "audience" | "namespace">): string {
  return `${config.tenant}\0${config.audience}\0${config.namespace}`;
}
export function volatileExecutionCharge(config: VolatileExecutionConfig, runtimeBytes: bigint): ResourceVector {
  // All compact records, keys, floors, finite observer indices and GC cursor
  // precede the first Session. Full result payloads are admitted per operation.
  const bytes = 8192n + BigInt(config.maxRecords) * 1536n + BigInt(config.callerAuthorities.length) * 256n + BigInt(config.maxActive * 3 + 8) * 512n + runtimeBytes;
  if (runtimeBytes <= 0n || bytes > 5242880n) throw new RPCProtocolError("configuration_capacity");
  return new ResourceVector([bytes, 0n, 0n, BigInt(config.maxRecords * 3 + 8), BigInt(config.maxActive * 3 + 8), BigInt(config.maxActive * 3 + 9), 1n, 0n, 0n, 0n, 0n]);
}
type State = "accepted" | "executing" | "completed" | "failed" | "unknown";
interface RecordState {
  readonly notification: boolean;
  readonly streaming: boolean;
  metadataFinished: boolean;
  readonly key: string;
  readonly domain: string;
  readonly request: string;
  readonly contract: string;
  readonly cutoff: bigint;
  readonly historyUntil: bigint;
  readonly retention: bigint;
  readonly limit: number;
  readonly cancelMode: boolean;
  cancelRequested: boolean;
  resultDigest: string;
  state: State;
  active: boolean;
  dispatched: boolean;
  result: RPCPayload | undefined;
  resultBytes: number;
  resultCode: number | undefined;
  resultUntil: bigint | undefined;
  error: RPCSDKError | undefined;
  holders: number;
  transitions: number;
  transitionTail: Promise<void>;
  deferredFailure: RPCSDKError | undefined;
  exitRequested: boolean;
  stop: (() => void) | undefined;
  readonly waiters: Set<() => void>;
}
const capability = Symbol("original volatile execution attempt"), NativePromise = Promise;
const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;
const addListener = EventTarget.prototype.addEventListener, removeListener = EventTarget.prototype.removeEventListener;
const aborted = (signal: AbortSignal): boolean => signalAborted.call(signal) as boolean;
const hex = (bytes: Uint8Array): string => Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
/** One continuous logical service history shared by every original Session.
 * Absence is not cross-owner proof. No Session, certificate, method or contract
 * digest is added to the key, and no pressure/LRU deletion grants a new Start. */
export class VolatileExecutions {
  readonly config: VolatileExecutionConfig;
  readonly configuration: string;
  readonly #resources: CredentialResources;
  readonly #clock: TrustedClock;
  readonly #storage: ExecutionStorage | undefined;
  #storageBound = false;
  #pendingStorage = 0;
  #pendingRecordWork = 0;
  async #storageWork<T>(action: () => T | Promise<T>): Promise<T> {
    if (this.#pendingStorage >= this.config.maxActive * 3 + 8)
      throw new RPCProtocolError("resource_exhausted");
    this.#pendingStorage++;
    try {
      return await action();
    }
    finally {
      this.#pendingStorage--;
      this.#collectClosed();
    }
  }
  async #recordWork<T>(record: RecordState, action: () => T | Promise<T>): Promise<T> {
    if (record.transitions >= 64 || this.#pendingRecordWork >= this.config.maxActive * 3 + 8 || this.#pendingStorage >= this.config.maxActive * 3 + 8) throw new RPCProtocolError("resource_exhausted");
    const previous = record.transitionTail;
    let release!: () => void;
    record.transitionTail = new Promise<void>(resolve => { release = resolve; });
    record.transitions++;
    this.#pendingRecordWork++;
    try {
      return await this.#storageWork(async () => { await previous; return await action(); });
    } finally {
      record.transitions--;
      this.#pendingRecordWork--;
      // Custody extends through applying the real receipt, including payloads.
      // Failure and exit persist the final facts after all admitted transitions.
      if (record.transitions === 0) {
        const failure = record.deferredFailure;
        record.deferredFailure = undefined;
        if (failure !== undefined) this.fail(record, failure);
        if (record.exitRequested) this.exit(record);
      }
      release();
      this.#collectClosed();
    }
  }
  async #updateReceipt(facts: ExecutionRecordFacts, payload: Uint8Array | undefined, guard: (() => void) | undefined, apply: () => void): Promise<void> {
    if (this.#storage === undefined) { guard?.(); apply(); return; }
    let delivered = false;
    await this.#storage.update(facts, payload, guard, () => {
      if (delivered) throw new RPCProtocolError("service_failed");
      delivered = true;
      apply();
    });
    if (!delivered) throw new RPCProtocolError("service_failed");
  }
  #applyResultReceipt(record: RecordState, receipt: ExecutionResultReceipt): void {
    // The admitted transition retains the original result allocation through
    // COMMIT. Custody settlement does not recheck a now-closed publication gate.
    record.result!.write(0, receipt.payload);
    record.result!.seal();
    record.resultDigest = receipt.facts.resultDigest;
    record.resultBytes = receipt.facts.resultBytes;
    record.resultCode = receipt.facts.resultCode;
    record.resultUntil = receipt.facts.resultUntil;
    record.state = receipt.facts.state;
    this.#notify(record);
  }
  #reference: ResourceReference | undefined;
  #resultAccount: ResourceAccount | undefined;
  readonly #records = new Map<string, RecordState>();
  readonly #slots: (RecordState | undefined)[];
  readonly #floors = new Map<string, bigint>();
  #active = 0;
  #next = 0n;
  #cursor = 0;
  #closed = false;
  #busy = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  constructor(resources: CredentialResources, clock: TrustedClock, config: VolatileExecutionConfig) {
    this.#storage = executionStorage(config);
    this.config = captureVolatileExecution(config); this.configuration = JSON.stringify(this.config, (_key, value) => typeof value === "bigint" ? value.toString() : value);
    this.#resources = Object.freeze({ ...resources, accounts: Object.freeze([...resources.accounts]), owner: Object.freeze({ ...resources.owner }) }); this.#clock = clock;
    const charge = volatileExecutionCharge(this.config, resources.runtimeBytes);
    const id = hex(sha256(new TextEncoder().encode(JSON.stringify([resources.owner.tenant, resources.owner.environment, "execution_results", executionServiceKey(this.config)])))).slice(0, 32);
    this.#reference = resources.root.reserve({ accounts: resources.accounts, owner: { ...resources.owner, kind: `execution_history_${id}` }, charge });
    this.#slots = new Array(this.config.maxRecords);
    try {
      const values = [...resources.root.snapshot().limit.values()]; values[0] = config.resultBytes;
      this.#resultAccount = resources.root.account("pool", id, new ResourceVector(values));
      for (const authority of this.config.callerAuthorities) this.#floors.set(authority, 0n);
      if (this.#storage !== undefined) {
        this.#storage.bind(this.#reference); this.#storageBound = true;
        for (const [authority, floor] of this.#storage.floors()) this.#floors.set(authority, floor);
        for (const saved of this.#storage.records()) {
          const facts = saved.facts;
          if (this.#records.size >= this.config.maxRecords || facts.active || this.#records.has(facts.key)) throw new RPCProtocolError("service_unavailable");
          let result: RPCPayload | undefined;
          if (saved.payload !== undefined) {
            const reference = resources.root.reserve({
              accounts: [...resources.accounts, this.#resultAccount!],
              owner: credentialOwner(resources, `execution_result_${++this.#next}`), charge: rpcPayloadCharge(facts.limit, resources.runtimeBytes)
            });
            try { result = new RPCPayload(facts.limit, resources.runtimeBytes, reference); result.write(0, saved.payload); result.seal(); }
            finally { reference.release(); saved.payload.fill(0); }
          }
          const record: RecordState = { ...facts, result, holders: 0, transitions: 0, transitionTail: Promise.resolve(), deferredFailure: undefined, exitRequested: false, stop: undefined, waiters: new Set() };
          this.#slots[this.#records.size] = record; this.#records.set(record.key, record);
        }
      }
      this.#timer = setTimeout(this.#tick, 1000); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  sameEnvironment(reference: ResourceReference): boolean { this.#check(); return this.#reference!.sameEnvironment(reference); }
  #check(): void { if (this.#closed) throw new RPCProtocolError("service_unavailable"); this.#reference!.check(); this.#storage?.check(); }
  async admit(input: RPCRequestInput, route: CapturedContractRoute, routes: ContractRoutes, authentication: V4AuthenticatedContext, identity: RPCExecutionIdentity, access: RPCPublicationGuard, stop: () => void): Promise<VolatileExecutionAttempt> {
    this.#check();
    if (this.#busy) throw new RPCProtocolError("service_unavailable");
    this.#busy = true;
    let result: RPCPayload | undefined, committedRecord: RecordState | undefined;
    try {
      const header = input.header, contract = route.contract, config = this.config;
      const notification = header.kind === "execution_notify", streaming = header.kind === "execution_stream_request";
      if (input.state !== "complete" || !notification && !streaming && header.kind !== "execution_unary_request" && header.kind !== "resume_request" || contract.optionalUint(13) !== executionMode(config) ||
        contract.shape !== (notification ? "notify" : streaming ? "server_streaming" : "unary") || authentication.tenant !== config.tenant || authentication.audience !== config.audience ||
        route.namespace !== config.namespace || identity.subject !== authentication.peerSubject || identity.identityDigest !== authentication.peerIdentityDigest ||
        !this.#floors.has(identity.authority) || !input.sameEnvironment(this.#reference!)) throw new RPCProtocolError("permission_denied");
      const operation = new Uint8Array(32), request = new Uint8Array(32), digest = new Uint8Array(32);
      header.copyBytes(1, operation);
      header.copyBytes(4, request);
      header.copyBytes(6, digest);
      const key = `${identity.authority}\0${identity.subject}\0${hex(operation)}`, requestID = hex(request), contractID = hex(digest);
      let cutoff = 0n;
      for (let i = 0; i < 8; i++) cutoff = (cutoff << 8n) | BigInt(operation[i]!);
      operation.fill(0);
      request.fill(0);
      digest.fill(0);
      access.check();
      this.#check();
      const existing = this.#records.get(key);
      if (existing !== undefined) {
        if (existing.request !== requestID || existing.contract !== contractID) throw new RPCProtocolError("operation_conflict");
        if (existing.holders >= 64) throw new RPCProtocolError("resource_exhausted");
        existing.holders++; return new VolatileExecutionAttempt(capability, this, existing, false);
      }
      const sample = this.#clock.sample(), now = sample.requireInterval();
      access.check();
      this.#check();
      if (cutoff <= this.#floors.get(identity.authority)! || now.upperMS >= cutoff || cutoff > timeAdd(now.lowerMS, contract.uint(16)) ||
        now.upperMS >= header.uint(5) || header.uint(5) > timeAdd(now.lowerMS, contract.uint(17))) throw new RPCProtocolError("deadline_exceeded");
      routes.checkExecutionAdmission(route, cutoff, now);
      if (this.#active >= config.maxActive || this.#records.size >= config.maxRecords || this.#next === (1n << 64n) - 1n) throw new RPCProtocolError("resource_exhausted");
      const historyUntil = timeAdd(header.uint(5), contract.uint(14)), retention = contract.optionalUint(15) ?? 0n, limit = Number(header.uint(8));
      // Check the complete future retention arithmetic before registration.
      timeAdd(header.uint(5), retention);
      if (!notification && !streaming) {
        const r = this.#resources, reference = r.root.reserve({
          accounts: [...r.accounts, this.#resultAccount!],
          owner: credentialOwner(r, `execution_result_${++this.#next}`), charge: rpcPayloadCharge(limit, r.runtimeBytes)
        });
        try { result = new RPCPayload(limit, r.runtimeBytes, reference); } finally { reference.release(); }
      }
      access.check();
      this.#check();
      const finalTime = this.#clock.sample().requireInterval();
      this.#check();
      if (!access.current() || finalTime.upperMS >= cutoff || finalTime.upperMS >= header.uint(5) ||
        cutoff > timeAdd(finalTime.lowerMS, contract.uint(16)) || header.uint(5) > timeAdd(finalTime.lowerMS, contract.uint(17))) throw new RPCProtocolError("deadline_exceeded");
      routes.checkExecutionAdmission(route, cutoff, finalTime);
      const index = this.#slots.findIndex(value => value === undefined);
      if (index < 0) throw new RPCProtocolError("resource_exhausted");
      const record: RecordState = {
        notification, streaming, metadataFinished: false, key, domain: identity.authority, request: requestID, contract: contractID, cutoff, historyUntil, retention, limit,
        state: "accepted", active: true, dispatched: false, cancelMode: contract.optionalUint(19) === 1n, cancelRequested: false, resultDigest: "0".repeat(64), result, resultBytes: 0, resultCode: undefined, resultUntil: undefined, error: undefined,
        holders: 1, transitions: 0, transitionTail: Promise.resolve(), deferredFailure: undefined, exitRequested: false, stop, waiters: new Set()
      };
      let registered = false;
      const receipt = (): void => {
        if (registered) throw new RPCProtocolError("service_failed");
        registered = true;
        committedRecord = record;
        this.#records.set(key, record);
        this.#slots[index] = record;
        this.#active++;
        result = undefined;
      };
      await this.#storageWork(() => {
        if (this.#storage === undefined) { receipt(); return; }
        return this.#storage.register(record, contract, header.uint(5), () => { access.check(); this.#check(); routes.checkExecutionAdmission(route, cutoff, this.#clock.sample().requireInterval()); }, receipt);
      });
      if (!registered) throw new RPCProtocolError("service_failed");
      return new VolatileExecutionAttempt(capability, this, record, true);
    }
    catch (error) {
      if (committedRecord !== undefined) {
        // A receipt may have settled registration before a later SDK failure.
        // No public attempt owns its one holder, but history cannot be erased.
        this.fail(committedRecord, "service_unavailable");
        this.exit(committedRecord);
        this.release(committedRecord);
      }
      throw error;
    }
    finally { result?.close(); this.#busy = false; this.#collectClosed(); }
  }
  async enter(record: RecordState, guard?: () => void): Promise<void> {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (!record.active || record.dispatched || record.state !== "accepted") throw new RPCProtocolError("service_unavailable");
      await this.#updateReceipt({ ...record, dispatched: true, state: "executing" }, undefined, () => { this.#check(); guard?.(); }, () => {
        record.dispatched = true;
        record.state = "executing";
      });
      this.#check(); guard?.();
    });
  }
  async finish(record: RecordState, bytes: Uint8Array, code: number | undefined, executionCap: bigint): Promise<void> {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (!record.active || !record.dispatched || record.resultUntil !== undefined || record.error !== undefined || bytes.length > record.limit) throw new RPCProtocolError("service_failed");
      const now = this.#clock.sample().requireInterval(), until = timeAdd(now.upperMS, record.retention);
      this.#check();
      if (record.error !== undefined || !record.active || record.resultUntil !== undefined || now.upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded");
      const resultDigest = hex(sha256(bytes)), state = code === undefined ? "completed" : "failed";
      const completed: ExecutionRecordFacts = { ...record, resultDigest, resultBytes: bytes.length, resultCode: code, resultUntil: until, state };
      await this.#updateReceipt(completed, bytes, () => { this.#check(); if (this.#clock.sample().requireInterval().upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded"); }, () => {
        this.#applyResultReceipt(record, { facts: completed, payload: bytes });
      });
      this.#check();
    });
  }
  async saveContent(record: RecordState, position: Uint8Array, payload: Uint8Array, executionCap: bigint, guard: () => void) {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (this.#storage === undefined || !record.streaming || !record.active || !record.dispatched || record.state !== "executing") throw new RPCProtocolError("service_unavailable");
      return (await this.#storage!.saveContent(record, position, payload, executionCap, () => { this.#check(); guard(); }));
    });
  }
  async readContent(record: RecordState, target: ExecutionTarget, position: Uint8Array, destination: Uint8Array, readerType: number, guard: () => void) {
    return await this.#recordWork(record, async () => {
      this.#check();
      const captured = captureExecutionTarget(target), [authority, subject] = record.key.split("\0");
      if (this.#storage === undefined || !record.active || !record.dispatched || record.state !== "executing" || record.streaming || record.notification ||
        captured.authority !== authority || captured.subject !== subject || captured.tenant !== this.config.tenant || captured.audience !== this.config.audience || captured.namespace !== this.config.namespace) throw new RPCProtocolError("permission_denied");
      return (await this.#storage!.readContent(record, captured, position, destination, readerType, () => { this.#check(); guard(); }));
    });
  }
  async issueCheckpoint(record: RecordState, original: ExecutionTarget, checkpoint: V4Checkpoint, options: V4CheckpointIssuanceOptions, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void): Promise<void> {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (this.#storage === undefined || record.notification || record.streaming || !record.active || !record.dispatched || record.state !== "executing" || record.resultUntil !== undefined || record.error !== undefined) throw new RPCProtocolError("service_unavailable");
      const captured = captureCheckpoint(original, checkpoint, options), target = captured.target;
      const [authority, subject, operation] = record.key.split("\0");
      if (target.tenant !== this.config.tenant || target.audience !== this.config.audience || target.namespace !== this.config.namespace ||
        target.authority !== authority || target.subject !== subject || target.operation === operation) throw new RPCProtocolError("permission_denied");
      const check = (): void => { this.#check(); guard(); };
      try {
        const result = await this.#storage!.issueCheckpoint(record, target, captured.checkpoint, captured.options, policy, executionCap, check,
          receipt => this.#applyResultReceipt(record, receipt));
        result.payload.fill(0);
      }
      finally { captured.checkpoint.position.fill(0); }
    });
  }
  async finishResume(record: RecordState, request: Uint8Array, target: ResumeTargetFacts, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void): Promise<ResumeOutcome> {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (this.#storage === undefined || record.notification || record.streaming || !record.active || !record.dispatched || record.resultUntil !== undefined || record.error !== undefined) throw new RPCProtocolError("service_unavailable");
      const result = await this.#storage!.finishResume(record, request, target, policy, executionCap, () => { this.#check(); guard(); },
        receipt => this.#applyResultReceipt(record, receipt));
      try { return result.outcome; } finally { result.payload.fill(0); }
    });
  }
  async finishNotification(record: RecordState, executionCap: bigint): Promise<void> {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (!record.notification || !record.active || !record.dispatched || record.error !== undefined || record.state !== "executing") throw new RPCProtocolError("service_failed");
      const now = this.#clock.sample().requireInterval();
      this.#check();
      if (now.upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded");
      await this.#updateReceipt({ ...record, state: "completed" }, undefined, () => { this.#check(); if (this.#clock.sample().requireInterval().upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded"); }, () => {
        record.state = "completed";
        this.#notify(record);
      });
      this.#check();
    });
  }
  async finishStreaming(record: RecordState, executionCap: bigint, applicationError?: number): Promise<void> {
    return await this.#recordWork(record, async () => {
      this.#check();
      if (!record.streaming || !record.active || !record.dispatched || record.metadataFinished || record.error !== undefined) throw new RPCProtocolError("service_failed");
      const now = this.#clock.sample().requireInterval();
      this.#check();
      if (now.upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded");
      // The stable stream contract promises execution metadata, not saved
      // items. Never turn the final item or an empty body into a unary result.
      const state = applicationError === undefined ? "completed" : "failed";
      await this.#updateReceipt({ ...record, metadataFinished: true, resultCode: applicationError, state }, undefined, () => { this.#check(); if (this.#clock.sample().requireInterval().upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded"); }, () => {
        record.metadataFinished = true;
        record.resultCode = applicationError;
        record.state = state;
        this.#notify(record);
      });
      this.#check();
    });
  }
  fail(record: RecordState, code: RPCSDKError): void {
    if (record.transitions !== 0) { record.deferredFailure ??= code; return; }
    if (record.metadataFinished || record.state === "completed" || record.resultUntil !== undefined || record.error !== undefined) return;
    record.error = code;
    record.state = record.dispatched ? "unknown" : "failed";
    // An uncertain persistent write fences the store. Keep the actual local
    // task and let explicit reopen recover its original persisted facts.
    try {
      void this.#recordWork(record, () => this.#storage?.update({ ...record })).catch(() => undefined);
    }
    catch { /* No publication authority. */ }
    this.#notify(record);
  }
  exit(record: RecordState): void {
    if (!record.active) return;
    if (record.transitions !== 0) { record.exitRequested = true; return; }
    record.exitRequested = false;
    if (!record.metadataFinished && record.state !== "completed" && record.resultUntil === undefined && record.error === undefined) this.fail(record, "service_failed");
    record.active = false;
    record.stop = undefined;
    try {
      void this.#recordWork(record, () => this.#storage?.update({ ...record })).catch(() => undefined);
    }
    catch { /* Reopen settles persisted active facts. */ }
    this.#active--;
    this.#collectClosed();
  }
  release(record: RecordState): void { record.holders--; this.#collectClosed(); }
  #notify(record: RecordState): void { for (const wake of [...record.waiters]) wake(); }
  async wait(record: RecordState, signal: AbortSignal): Promise<void> {
    this.#check();
    if (record.metadataFinished || record.state === "completed" || record.resultUntil !== undefined || record.error !== undefined) return;
    if (record.waiters.size >= 64 || aborted(signal)) throw new RPCProtocolError("service_unavailable");
    await new NativePromise<void>((resolve, reject) => {
      const clean = (): void => { record.waiters.delete(wake); removeListener.call(signal, "abort", cancel); };
      const wake = (): void => { clean(); resolve(); }, cancel = (): void => { clean(); reject(new RPCProtocolError("service_unavailable")); };
      record.waiters.add(wake); addListener.call(signal, "abort", cancel, { once: true });
      if (aborted(signal)) cancel();
    });
  }
  copyResult(record: RecordState, destination: RPCPayload): Readonly<{ bytes: number; applicationError?: number; sdkError?: RPCSDKError }> {
    this.#check();
    if (record.error !== undefined) return { bytes: 0, sdkError: record.error };
    const now = this.#clock.sample().requireInterval(); this.#check();
    if (record.resultUntil === undefined) throw new RPCProtocolError("service_unavailable");
    if (record.result === undefined || now.lowerMS >= record.resultUntil) return { bytes: 0, sdkError: "result_expired" };
    if (now.upperMS >= record.resultUntil) return { bytes: 0, sdkError: "service_unavailable" };
    const borrow = record.result.borrowShared(record.resultBytes);
    try { destination.write(0, borrow.bytes); } finally { borrow.release(); }
    return { bytes: record.resultBytes, ...(record.resultCode === undefined ? {} : { applicationError: record.resultCode }) };
  }
  /** A read pins only the original immutable backing. Its charged metadata
   * and the pin follow the publisher through the actual last fragment tail. */
  captureResult(target: ExecutionTarget, access: RPCPublicationGuard, reference: ResourceReference, runtimeBytes: bigint):
    Readonly<{ payload: RPCPayloadBorrow; guard: RPCPublicationGuard }> {
    this.#check(); if (this.#busy) throw new RPCProtocolError("service_unavailable"); this.#busy = true;
    let metadata: ResourceReference | undefined, borrow: RPCPayloadBorrow | undefined;
    try {
      access.check(); this.#check();
      if (!access.current() || !reference.sameEnvironment(this.#reference!) || target.tenant !== this.config.tenant ||
        target.audience !== this.config.audience || target.namespace !== this.config.namespace || !this.#floors.has(target.authority)) throw new RPCProtocolError("permission_denied");
      const record = this.#records.get(`${target.authority}\0${target.subject}\0${target.operation}`);
      // The fixed RPC error catalog has no absent-history assertion. The
      // separate bounded QueryOperation supplies that observation when needed.
      if (record === undefined) throw new RPCProtocolError("service_unavailable");
      if (record.request !== target.requestDigest || record.contract !== target.contractDigest) throw new RPCProtocolError("operation_conflict");
      const check = (): void => {
        access.check(); this.#check();
        const now = this.#clock.sample().requireInterval(); access.check(); this.#check();
        if (!access.current() || record.resultUntil === undefined) throw new RPCProtocolError("service_unavailable");
        if (record.result === undefined || now.lowerMS >= record.resultUntil) throw new RPCProtocolError("result_expired");
        if (now.upperMS >= record.resultUntil) throw new RPCProtocolError("service_unavailable");
      };
      check(); if (record.holders >= 64) throw new RPCProtocolError("resource_exhausted");
      metadata = reference.take(executionResultReadCharge(runtimeBytes));
      borrow = record.result!.borrowShared(record.resultBytes);
      const original = borrow, owned = metadata; let held = true;
      const result = Object.freeze({
        payload: Object.freeze({
          bytes: original.bytes, retainSend: original.retainSend, release: () => {
            if (!held) return; held = false; original.release(); owned.release(); this.release(record);
          }
        }), guard: Object.freeze({
          check: () => {
            if (!held) throw new RPCProtocolError("service_unavailable"); owned.check(); check();
            if (!held) throw new RPCProtocolError("service_unavailable");
          }, current: () => held && !this.#closed && access.current()
        })
      });
      record.holders++; borrow = undefined; metadata = undefined; return result;
    } finally { borrow?.release(); metadata?.release(); this.#busy = false; this.#collectClosed(); }
  }
  /** Current Session authority must be checked before lookup. A remote target
   * does not prove continuity of an absent RAM record. Cancellation changes
   * the original record before any cooperative application signal is emitted. */
  async manage(target: ExecutionTarget, cancel: boolean, access: RPCPublicationGuard): Promise<ExecutionManagementResult> {
    this.#check();
    if (this.#busy) return { status: "unavailable" };
    this.#busy = true;
    let notify: (() => void) | undefined;
    try {
      access.check();
      this.#check();
      const now = this.#clock.sample().requireInterval();
      access.check();
      this.#check();
      if (!access.current() || target.tenant !== this.config.tenant || target.audience !== this.config.audience || target.namespace !== this.config.namespace ||
        !this.#floors.has(target.authority)) throw new RPCProtocolError("permission_denied");
      const record = this.#records.get(`${target.authority}\0${target.subject}\0${target.operation}`);
      if (record === undefined) {
        const key = `${target.authority}\0${target.subject}\0${target.operation}`, cutoff = BigInt("0x" + target.operation.slice(0, 16));
        const reason = (await this.#storageWork(() => this.#storage?.absence(key, target.authority, cutoff, () => { access.check(); this.#check(); }))) ?? "history_unknown";
        return Object.freeze({
          status: cancel ? "ok" : reason === "not_registered" ? "not_found" : "history_unknown",
          observation: Object.freeze({ found: false, reason }), ...(cancel ? { cancelResult: reason } : {})
        });
      }
      if (record.request !== target.requestDigest || record.contract !== target.contractDigest) throw new RPCProtocolError("operation_conflict");
      if (cancel && !record.cancelMode) return { status: "unsupported" };
      let cancelResult: "requested" | "terminal" = "terminal";
      if (cancel) await this.#recordWork(record, async () => {
        access.check(); this.#check();
        if (["accepted", "executing", "unknown"].includes(record.state)) {
          const state = record.dispatched ? record.state : "failed", error = record.dispatched ? record.error : "service_unavailable";
          await this.#updateReceipt({ ...record, cancelRequested: true, state, error }, undefined, () => { access.check(); this.#check(); }, () => {
            // A failed or uncertain durable write cannot publish a cancellation
            // fact or dispatch a cooperative signal as though it were confirmed.
            if (!record.cancelRequested) notify = record.stop;
            record.cancelRequested = true;
            record.state = state;
            record.error = error;
            cancelResult = "requested";
          });
        }
      });
      const formed = record.resultUntil !== undefined, deleted = formed && (record.result === undefined || now.lowerMS >= record.resultUntil!);
      const observation: ExecutionObservation = Object.freeze({
        found: true,
        reason: record.error === undefined ? "none" : record.cancelRequested && !record.dispatched ? "cancelled" : record.error === "deadline_exceeded" ? "deadline_exceeded" : record.dispatched ? "work_outcome_unknown" : "dispatch_unavailable",
        state: record.state, cancelRequested: record.cancelRequested, dispatched: record.dispatched, workActive: record.active,
        historyNotBeforeGCMS: record.historyUntil, resultNotAfterMS: record.resultUntil ?? 0n,
        resultAvailable: formed && record.result !== undefined && now.upperMS < record.resultUntil!, resultDeleted: deleted,
        resultBytes: record.resultBytes, applicationErrorCode: record.resultCode ?? 0, resultDigest: record.resultDigest
      });
      return Object.freeze({ status: cancel ? "ok" : deleted ? "result_expired" : "ok", observation, ...(cancel ? { cancelResult } : {}) });
    }
    finally {
      this.#busy = false;
      // AbortSignal dispatch can enter application listeners. Leave the finite
      // history gate first; the signal never supplies work-exit evidence.
      if (notify !== undefined) queueMicrotask(notify);
      this.#collectClosed();
    }
  }
  readonly #tick = async (): Promise<void> => {
    this.#timer = undefined;
    if (this.#closed) return;
    if (this.#busy) {
      this.#timer = setTimeout(this.#tick, 1000);
      return;
    }
    this.#busy = true;
    try {
      const now = this.#clock.sample().requireInterval();
      this.#check();
      for (let count = 0; count < Math.min(8, this.#slots.length); count++) {
        const index = this.#cursor;
        this.#cursor = (index + 1) % this.#slots.length;
        const record = this.#slots[index];
        if (record === undefined || record.transitions !== 0) continue;
        if (!record.active && record.holders === 0 && record.result !== undefined && (record.resultUntil === undefined || now.lowerMS >= record.resultUntil)) {
          (await this.#storageWork(() => this.#storage?.expireResult(record.key)));
          record.result.close();
          record.result = undefined;
        }
        if (record.active || record.holders !== 0 || record.result !== undefined || now.lowerMS < record.historyUntil || now.lowerMS < record.cutoff) continue;
        // Install the original domain's floor before deleting any key detail.
        const floor = record.cutoff > this.#floors.get(record.domain)! ? record.cutoff : this.#floors.get(record.domain)!;
        (await this.#storageWork(() => this.#storage?.remove(record.key, record.domain, floor)));
        this.#floors.set(record.domain, floor);
        this.#records.delete(record.key);
        this.#slots[index] = undefined;
      }
    }
    catch { /* Unavailable trusted time cannot delete history or advance a floor. */ }
    finally {
      this.#busy = false;
      this.#collectClosed();
    }
    if (!this.#closed)
      this.#timer = setTimeout(this.#tick, 1000);
  };
  close(): void {
    if (this.#closed) return; this.#closed = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    for (const record of this.#records.values()) { this.fail(record, "service_unavailable"); record.stop?.(); }
    this.#collectClosed();
  }
  #collectClosed(): void {
    if (!this.#closed || this.#busy || this.#pendingStorage !== 0 || this.#pendingRecordWork !== 0 || this.#active !== 0 || [...this.#records.values()].some(record => record.holders !== 0 || record.transitions !== 0))
      return;
    for (const record of this.#records.values()) record.result?.close();
    this.#records.clear();
    this.#slots.fill(undefined);
    this.#floors.clear();
    if (this.#storageBound) { this.#storageBound = false; this.#storage!.release(); }
    this.#resultAccount?.close();
    this.#resultAccount = undefined;
    this.#reference?.release();
    this.#reference = undefined;
  }
  cleanupComplete(): boolean { this.#collectClosed(); return this.#reference === undefined; }
}
/** A duplicate has observation rights only. Only the first complete input
 * receives the original one-use execution work capability. */
export class VolatileExecutionAttempt {
  #owner: VolatileExecutions | undefined;
  #exited = false;
  readonly #record: RecordState;
  constructor(token: symbol, owner: VolatileExecutions, record: RecordState, readonly created: boolean) {
    if (token !== capability) throw new RPCProtocolError("rpc_owner"); this.#owner = owner; this.#record = record; Object.freeze(this);
  }
  async enter(guard?: () => void): Promise<void> {
    if (!this.created) throw new RPCProtocolError("rpc_owner");
    (await this.#owner!.enter(this.#record, guard));
  }
  async finish(bytes: Uint8Array, code: number | undefined, executionCap: bigint): Promise<void> {
    if (!this.created) throw new RPCProtocolError("rpc_owner");
    (await this.#owner!.finish(this.#record, bytes, code, executionCap));
  }
  async saveContent(position: Uint8Array, payload: Uint8Array, executionCap: bigint, guard: () => void) {
    if (!this.created || this.#exited) throw new RPCProtocolError("rpc_owner");
    return (await this.#owner!.saveContent(this.#record, position, payload, executionCap, guard));
  }
  async readContent(target: ExecutionTarget, position: Uint8Array, destination: Uint8Array, readerType: number, guard: () => void) {
    if (!this.created || this.#exited) throw new RPCProtocolError("rpc_owner");
    return (await this.#owner!.readContent(this.#record, target, position, destination, readerType, guard));
  }
  async issueCheckpoint(original: ExecutionTarget, checkpoint: V4Checkpoint, options: V4CheckpointIssuanceOptions, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void): Promise<void> {
    if (!this.created || this.#exited) throw new RPCProtocolError("rpc_owner");
    (await this.#owner!.issueCheckpoint(this.#record, original, checkpoint, options, policy, executionCap, guard));
  }
  async finishResume(request: Uint8Array, target: ResumeTargetFacts, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void): Promise<ResumeOutcome> {
    if (!this.created || this.#exited) throw new RPCProtocolError("rpc_owner");
    return (await this.#owner!.finishResume(this.#record, request, target, policy, executionCap, guard));
  }
  async finishNotification(executionCap: bigint): Promise<void> {
    if (!this.created) throw new RPCProtocolError("rpc_owner");
    (await this.#owner!.finishNotification(this.#record, executionCap));
  }
  async finishStreaming(executionCap: bigint, applicationError?: number): Promise<void> {
    if (!this.created) throw new RPCProtocolError("rpc_owner");
    (await this.#owner!.finishStreaming(this.#record, executionCap, applicationError));
  }
  fail(code: RPCSDKError): void { if (this.created) this.#owner?.fail(this.#record, code); }
  exit(): void { if (this.#exited || !this.created) return; this.#exited = true; this.#owner?.exit(this.#record); }
  wait(signal: AbortSignal): Promise<void> { return this.#owner!.wait(this.#record, signal); }
  copyResult(destination: RPCPayload): ReturnType<VolatileExecutions["copyResult"]> { return this.#owner!.copyResult(this.#record, destination); }
  release(): void { this.exit(); const owner = this.#owner; this.#owner = undefined; owner?.release(this.#record); }
}
for (const owner of [VolatileExecutions, VolatileExecutionAttempt]) { Object.freeze(owner.prototype); Object.freeze(owner); }
