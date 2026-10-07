import type { V4ContentObservation } from "../streamContent.js";
import type { ResumeTargetFacts, ResumeOutcome } from "./resumeCodec.js";
import type { V4Checkpoint, V4CheckpointIssuanceOptions } from "../checkpoint.js";
import type { ExecutionTarget } from "./executionManagementCodec.js";
import type { CheckpointSessionPolicy } from "./checkpointToken.js";
import type { VolatileExecutionConfig } from "./volatileExecutions.js";
import type { ResourceReference } from "./resources.js";
import type { ServiceContractSnapshot, AdmissionOffer } from "./serviceContract.js";
import type { RPCSDKError } from "./rpcCompletion.js";

/** Persisted facts contain no callback, Session, payload borrow or dispatch
 * capability. Only the original successful register transaction grants work. */
export interface ExecutionRecordFacts {
  readonly notification: boolean;
  readonly streaming: boolean;
  readonly metadataFinished: boolean;
  readonly key: string;
  readonly domain: string;
  readonly request: string;
  readonly contract: string;
  readonly cutoff: bigint;
  readonly historyUntil: bigint;
  readonly retention: bigint;
  readonly limit: number;
  readonly cancelMode: boolean;
  readonly cancelRequested: boolean;
  readonly resultDigest: string;
  readonly state: "accepted" | "executing" | "completed" | "failed" | "unknown";
  readonly active: boolean;
  readonly dispatched: boolean;
  readonly resultBytes: number;
  readonly resultCode: number | undefined;
  readonly resultUntil: bigint | undefined;
  readonly error: RPCSDKError | undefined;
}
type StorageResult<T> = T | Promise<T>;
export type ExecutionResultReceipt = Readonly<{ facts: ExecutionRecordFacts; payload: Uint8Array }>;
/** Invoked synchronously by the SDK adapter after the real COMMIT receipt and
 * before releasing the original transaction position and payload custody.
 * It records durable facts; it never grants fresh publication authority. */
export type ExecutionCommitReceipt<T = void> = (result: T) => void;
export interface ExecutionStorage {
  bind(reference: ResourceReference): void;
  release(): void;
  check(): void;
  floors(): ReadonlyMap<string, bigint>;
  records(): Iterable<Readonly<{ facts: ExecutionRecordFacts; payload?: Uint8Array }>>;
  checkContract(contract: ServiceContractSnapshot, offer: AdmissionOffer, maximumWindowMS: bigint): void;
  register(facts: ExecutionRecordFacts, contract: ServiceContractSnapshot, deadline: bigint, guard: () => void, receipt?: ExecutionCommitReceipt): StorageResult<void>;
  update(facts: ExecutionRecordFacts, payload?: Uint8Array, guard?: () => void, receipt?: ExecutionCommitReceipt): StorageResult<void>;
  issueCheckpoint(facts: ExecutionRecordFacts, original: ExecutionTarget, checkpoint: V4Checkpoint,
    options: V4CheckpointIssuanceOptions, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void, receipt?: ExecutionCommitReceipt<ExecutionResultReceipt>): StorageResult<ExecutionResultReceipt>;
  finishResume(facts: ExecutionRecordFacts, request: Uint8Array, target: ResumeTargetFacts, policy: CheckpointSessionPolicy,
    executionCap: bigint, guard: () => void, receipt?: ExecutionCommitReceipt<ExecutionResultReceipt & Readonly<{ outcome: ResumeOutcome }>>): StorageResult<ExecutionResultReceipt & Readonly<{ outcome: ResumeOutcome }>>;
  saveContent(facts: ExecutionRecordFacts, position: Uint8Array, payload: Uint8Array, executionCap: bigint, guard: () => void): StorageResult<V4ContentObservation>;
  readContent(facts: ExecutionRecordFacts, target: ExecutionTarget, position: Uint8Array, destination: Uint8Array, readerType: number, guard: () => void): StorageResult<V4ContentObservation>;
  absence(key: string, authority: string, cutoff: bigint, guard: () => void): StorageResult<"not_registered" | "history_unknown">;
  expireResult(key: string): StorageResult<void>;
  remove(key: string, authority: string, floor: bigint): StorageResult<void>;
}

// Only SDK-owned persistent adapters install these associations. Copying a
// configuration or returning an application "committed" boolean cannot do so.
const stores = new WeakMap<VolatileExecutionConfig, ExecutionStorage>();
export function registerExecutionStorage(config: VolatileExecutionConfig, store: ExecutionStorage): void {
  if (!Object.isFrozen(config) || stores.has(config)) throw new Error("execution_storage_owner");
  stores.set(config, store);
}
export function executionStorage(config: VolatileExecutionConfig): ExecutionStorage | undefined { return stores.get(config); }
export function executionMode(config: VolatileExecutionConfig): bigint { return stores.has(config) ? 1n : 0n; }
