export class TimeoutError extends Error {
  constructor(message = "timeout") {
    super(message);
    this.name = "TimeoutError";
  }
}

export class AbortError extends Error {
  constructor(message = "aborted") {
    super(message);
    this.name = "AbortError";
  }
}

export type FlowersecPath = "tunnel" | "direct";

export type FlowersecStage = "validate" | "connect" | "attach" | "handshake" | "yamux" | "rpc" | "close";

export class FlowersecError extends Error {
  readonly code: string;
  readonly stage: FlowersecStage;
  readonly path?: FlowersecPath;
  override readonly cause?: unknown;

  constructor(args: Readonly<{ code: string; stage: FlowersecStage; message?: string; path?: FlowersecPath; cause?: unknown }>) {
    super(args.message ?? `${args.stage} failed`, args.cause !== undefined ? { cause: args.cause } : undefined);
    this.name = "FlowersecError";
    this.code = args.code;
    this.stage = args.stage;
    if (args.path !== undefined) this.path = args.path;
    if (args.cause !== undefined) this.cause = args.cause;
  }
}

export function isTimeoutError(e: unknown): e is TimeoutError {
  return e instanceof TimeoutError;
}

export function isAbortError(e: unknown): e is AbortError {
  return e instanceof AbortError;
}

export function isFlowersecError(e: unknown): e is FlowersecError {
  return e instanceof FlowersecError;
}

export function throwIfAborted(signal?: AbortSignal, message?: string): void {
  if (signal?.aborted) throw new AbortError(message);
}
