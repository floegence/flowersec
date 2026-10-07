import type { OperationOptions } from "../public/contract.js";

export type V4UnreliableSendResult = "accepted" | "dropped_expired" | "dropped_budget" | "dropped_carrier";
export interface V4UnreliableSendOptions extends OperationOptions { readonly expiresAtMS: bigint }
export type V4UnreliableMessage = Uint8Array;
export interface V4UnreliableReceiveStatus {
  readonly state: "available" | "temporarily_blocked" | "receive_disabled";
  readonly retryAfterMS: bigint | null;
}
/** A local submission bound, never a delivery promise or peer receive quota. */
export interface V4UnreliableMessages {
  maxMessageBytes(): Readonly<{ bytes: bigint; scope: "local_submission" }>;
  send(message: Uint8Array, options: V4UnreliableSendOptions): Promise<V4UnreliableSendResult>;
  receive(options?: OperationOptions): Promise<V4UnreliableMessage>;
  receiveStatus(): V4UnreliableReceiveStatus;
}
export type V4UnreliableMessageErrorCode = "unavailable" | "closed" | "canceled" | "invalid_message" | "too_large" | "operation_failed" | "temporarily_blocked" | "receive_disabled";
export class V4UnreliableMessageError extends Error {
  constructor(readonly code: V4UnreliableMessageErrorCode,
    readonly retryAfterMS: bigint | null = null) { super(code); this.name = "UnreliableMessageError"; }
}
