/// The structured retry decision used by ``ConnectionController``.
///
/// Retry deadlines use exact Unix milliseconds on every platform so the
/// contract does not depend on `Date` precision or rounding.
public enum RetryDisposition: Equatable, Sendable {
  case terminal
  case retryable
  case retryAfter(UInt64)
}

extension SessionError {
  public var retryDisposition: RetryDisposition {
    switch self {
    case .canceled, .streamRejected, .operationFailed:
      return .terminal
    case .timeout, .closed, .goingAway, .resourceExhausted, .streamReset, .rekeyFailed,
      .livenessFailed:
      return .retryable
    }
  }
}
