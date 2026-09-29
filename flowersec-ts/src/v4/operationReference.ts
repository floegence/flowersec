import { FixedCBORWriter } from "./runtime/cborWriter.js";
import { writeExecutionTarget, captureExecutionTarget, type ExecutionTarget } from "./runtime/executionManagementCodec.js";
export type { ExecutionObservation as V4ExecutionObservation, ExecutionManagementResult as V4ExecutionManagementResult } from "./runtime/executionManagementCodec.js";
import { checkServiceBindingTarget, type ServiceBindingTarget } from "./runtime/serviceBindingConfig.js";
import type { V4AuthenticatedContext } from "./streamHandlers.js";
export interface OperationReferenceState { readonly domain: string; readonly shape: 0 | 1 | 2; readonly target: ExecutionTarget; readonly destination?: ServiceBindingTarget; readonly deadlineAtMS: bigint; readonly mode: 0 | 1; readonly cancel: 0 | 1; readonly resultLimit: number }
const capability = Symbol("original execution reference"), references = new WeakMap<V4OperationReference, OperationReferenceState>();
/** Compact original identity only. It owns no Session, request bytes, Start,
 * replay or resume capability. A chosen current Session must authorize use. */
export class V4OperationReference {
  constructor(token: symbol, state: OperationReferenceState) {
    if (token !== capability) throw new Error("operation_reference_owner"); const target = captureExecutionTarget(state.target), destination = state.destination;
    const cutoff = BigInt(`0x${target.operation.slice(0, 16)}`);
    if (!/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(state.domain) || ![0, 1, 2].includes(state.shape) || ![0, 1].includes(state.mode) || ![0, 1].includes(state.cancel) ||
        cutoff === 0n || cutoff > state.deadlineAtMS || state.deadlineAtMS >= 1n << 64n ||
        [target.authority, target.operation, target.requestDigest, target.contractDigest].some(value => /^0+$/u.test(value)) ||
        destination !== undefined && (destination.authority !== state.domain || destination.tenant !== target.tenant || destination.audience !== target.audience || destination.localSubject !== target.subject) ||
        !Number.isSafeInteger(state.resultLimit) || state.resultLimit < 0 || state.resultLimit > 1048576) throw new Error("operation_reference_binding");
    references.set(this, Object.freeze({ ...state, target }));
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  toJSON(): object { return {}; }
}
export function operationReference(target: ExecutionTarget, destination: ServiceBindingTarget, deadlineAtMS: bigint, mode: 0 | 1, cancel: 0 | 1, resultLimit: number, shape: 0 | 1 | 2 = 0): V4OperationReference { return new V4OperationReference(capability, { domain: destination.authority, shape, target, destination, deadlineAtMS, mode, cancel, resultLimit }); }
export function importOperationReference(state: Omit<OperationReferenceState, "destination" | "resultLimit">): V4OperationReference {
  // The persistence schema deliberately omits response limits. Reserve the
  // entire protocol result maximum for an imported unary reference.
  return new V4OperationReference(capability, { ...state, resultLimit: 1048576 });
}
export function operationReferenceState(reference: V4OperationReference): OperationReferenceState {
  const state = references.get(reference); if (state === undefined) throw new Error("operation_reference_owner"); return state;
}
/** Shared fixed canonical persistence encoding for export and store handoff. */
export function encodeOperationReference(reference: V4OperationReference, destination: Uint8Array): Uint8Array {
  const state = operationReferenceState(reference), writer = new FixedCBORWriter(destination);
  writer.map(7).uint(0).uint(1).uint(1).data(new TextEncoder().encode(state.domain), true).uint(2);
  return writeExecutionTarget(writer, state.target).uint(3).uint(state.shape).uint(4).uint(state.mode).uint(5).uint(state.deadlineAtMS).uint(6).uint(state.cancel).result();
}
/** Original local result bound, or the full legal maximum after import. */
export function operationResultLimit(reference: V4OperationReference): number {
  const state = operationReferenceState(reference); if (state.shape !== 0) throw new Error("operation_reference_shape"); return state.resultLimit;
}
export function operationTarget(reference: V4OperationReference, authentication: V4AuthenticatedContext, targets: readonly ServiceBindingTarget[] = []): ExecutionTarget {
  const state = references.get(reference); if (state === undefined) throw new Error("operation_reference_owner");
  const destination = targets.find(target => target.authority === state.domain) ?? state.destination;
  if (destination === undefined || destination.tenant !== state.target.tenant || destination.audience !== state.target.audience) throw new Error("operation_reference_domain");
  checkServiceBindingTarget(destination, authentication); return state.target;
}
Object.freeze(V4OperationReference.prototype); Object.freeze(V4OperationReference);
