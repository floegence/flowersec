// StreamEOFError marks end-of-stream for yamux reads.
export class StreamEOFError extends Error {
  constructor(message = "eof") {
    super(message);
    this.name = "StreamEOFError";
  }
}

export function isStreamEOFError(e: unknown): e is StreamEOFError {
  return e instanceof StreamEOFError;
}

export class YamuxResourceExhaustedError extends Error {
  readonly resource: string;
  readonly current: number;
  readonly limit: number;

  constructor(resource: string, current: number, limit: number) {
    super(`yamux ${resource} limit reached (${current}/${limit})`);
    this.name = "YamuxResourceExhaustedError";
    this.resource = resource;
    this.current = current;
    this.limit = limit;
  }
}

export function isYamuxResourceExhaustedError(error: unknown): error is YamuxResourceExhaustedError {
  return error instanceof YamuxResourceExhaustedError;
}
