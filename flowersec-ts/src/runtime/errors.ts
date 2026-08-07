export type RuntimeErrorCode =
  | "runtime_unsupported"
  | "runtime_start_failed"
  | "runtime_crashed";

export class RuntimeError extends Error {
  constructor(
    readonly code: RuntimeErrorCode,
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = "RuntimeError";
  }
}
