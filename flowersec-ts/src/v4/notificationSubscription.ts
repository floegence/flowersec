import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4MethodDefinition } from "./serviceDefinition.js";
import type { V4NotificationHandler, V4NotificationHandlerOptions } from "./serviceHandlers.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import type { NotificationRegistration } from "./runtime/notifyDispatch.js";

export interface V4NotificationSubscriptionOptions<Input, Value = Input> extends V4NotificationHandlerOptions {
  /** Select latest_pending only when each value replaces the entire token's
   * observation domain. Filtering inside the callback does not narrow it. */
  readonly pendingPolicy?: "drop_newest" | "latest_pending";
  readonly project?: (context: V4ApplicationContext, value: Input) => Value | Promise<Value>;
}
export type V4NotificationGap = "dropped_budget" | "coalesced_pending" | "decode_error" | "projection_error" | "handler_error" |
  "permission_denied" | "deadline_exceeded" | "source_closed" | "subscription_closed";
export interface V4ObservationStatus {
  readonly closed: boolean;
  readonly pending: number;
  readonly running: 0 | 1;
  readonly knownDropped: bigint;
  readonly lastGap?: V4NotificationGap;
  readonly cleanupStatus: V4CleanupStatus;
}
export interface V4NotificationWaitOptions {
  readonly timeoutMS?: bigint;
  readonly context?: V4ApplicationContext;
  readonly signal?: AbortSignal;
}
export interface V4NotificationClosedResult {
  readonly closed: boolean;
  readonly cleanupStatus: V4CleanupStatus;
  readonly wait: "complete" | "canceled" | "deadline_exceeded" | "dependency_unavailable";
}
const capability = Symbol("original notification subscription");

/** Local registration only. Close never sends a frame, starts a replacement
 * callback or waits for an application invocation to return. */
export class V4NotificationSubscription<Value> {
  declare private readonly valueType: Value;
  readonly #owner: NotificationRegistration;
  constructor(token: symbol, owner: NotificationRegistration) {
    if (token !== capability) throw new Error("notification_owner"); this.#owner = owner;
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  close(): void { this.#owner.close(); }
  unsubscribe(): void { this.close(); }
  observationStatus(): V4ObservationStatus { return this.#owner.status(); }
  cleanupStatus(): V4CleanupStatus { return this.#owner.cleanupStatus(); }
  waitClosed(options?: V4NotificationWaitOptions): Promise<V4NotificationClosedResult> { return this.#owner.waitClosed(options); }
  toJSON(): object { return {}; }
}
export interface V4Notifications {
  subscribe<Input, Value = Input>(method: V4MethodDefinition<Input, any, "notify">, handler: V4NotificationHandler<Value>,
    options: V4NotificationSubscriptionOptions<Input, Value>): V4NotificationSubscription<Value>;
}
export function notificationSubscription<Value>(owner: NotificationRegistration): V4NotificationSubscription<Value> {
  return new V4NotificationSubscription(capability, owner);
}
Object.freeze(V4NotificationSubscription.prototype); Object.freeze(V4NotificationSubscription);
