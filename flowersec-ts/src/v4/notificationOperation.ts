import type { V4OperationReference } from "./operationReference.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { NotifyPreparation, NotifyPreparationOptions, NotifyProgress, NotifyStartResult } from "./runtime/notifyPreparation.js";

export interface V4NotifyOptions extends NotifyPreparationOptions { readonly context?: V4ApplicationContext; readonly signal?: AbortSignal; }
export type V4NotifyStatus = Readonly<NotifyProgress>;
export type V4NotifyStartResult = NotifyStartResult;
const capability = Symbol("original notification");

/** A local submission view. Submitted means only that the complete message was
 * accepted locally; it makes no claim about remote delivery or handler success. */
export class V4ObservationNotifyOperation {
  readonly #operation: NotifyPreparation;
  constructor(token: symbol, operation: NotifyPreparation) {
    if (token !== capability) throw new Error("notify_owner"); this.#operation = operation;
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  start(options: Pick<V4NotifyOptions, "context" | "signal"> = {}): V4NotifyStartResult { return this.#operation.start(options.context, options.signal); }
  status(): V4NotifyStatus { return this.#operation.status(); }
  waitSubmission(options: Pick<V4NotifyOptions, "signal"> = {}): Promise<Readonly<NotifyProgress & { wait?: "canceled" }>> { return this.#operation.waitSubmission(options.signal); }
  close(): void { this.#operation.close(); }
  cleanupStatus(): V4CleanupStatus { return this.#operation.cleanupStatus(); }
  toJSON(): object { return {}; }
}
export class V4ExecutionNotifyOperation extends V4ObservationNotifyOperation {
  readonly #reference: V4OperationReference;
  constructor(token: symbol, operation: NotifyPreparation) { super(token, operation); this.#reference = operation.reference(); }
  reference(): V4OperationReference { return this.#reference; }
}
export function notifyOperation(operation: NotifyPreparation): V4ObservationNotifyOperation | V4ExecutionNotifyOperation {
  return operation.execution ? new V4ExecutionNotifyOperation(capability, operation) : new V4ObservationNotifyOperation(capability, operation);
}
for (const view of [V4ObservationNotifyOperation, V4ExecutionNotifyOperation]) { Object.freeze(view.prototype); Object.freeze(view); }
