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

/** @internal */
export function throwIfAborted(signal?: AbortSignal, message?: string): void {
  if (signal?.aborted) throw new AbortError(message);
}
