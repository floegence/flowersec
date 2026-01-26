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

