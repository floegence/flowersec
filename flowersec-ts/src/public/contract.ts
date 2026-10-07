export type JsonPrimitive = null | boolean | number | string;

export type JsonValue = JsonPrimitive | JsonObject | readonly JsonValue[];

export type JsonObject = Readonly<{ [key: string]: JsonValue }>;

export type OperationOptions = Readonly<{
  signal?: AbortSignal;
}>;

export type SessionErrorCode =
  | "canceled"
  | "timeout"
  | "closed"
  | "going_away"
  | "resource_exhausted"
  | "stream_rejected"
  | "stream_reset"
  | "rekey_failed"
  | "liveness_failed"
  | "operation_failed";

/** A closed, carrier-neutral session failure with no internal cause or peer detail. */
export class SessionError extends Error {
  constructor(readonly code: SessionErrorCode) {
    super(`Flowersec session failed (code=${code})`);
    this.name = "SessionError";
  }
}
