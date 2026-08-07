import Foundation

/// The structured decision used by ``ConnectionController`` after a failed
/// artifact acquisition, connection attempt, or established session.
public enum RetryDisposition: Equatable, Sendable {
  /// The failure is authoritative and ends the connection lifecycle.
  case terminal
  /// A fresh artifact and a new one-shot session may be attempted after backoff.
  case retryable
  /// A fresh attempt may start no earlier than the supplied absolute deadline.
  case retryAfter(Date)
}

extension ConnectError {
  public var retryDisposition: RetryDisposition {
    switch self {
    case .invalidOptions, .runtimeUnsupported, .canceled:
      return .terminal
    case .expiredArtifact, .timeout, .connectionFailed:
      return .retryable
    }
  }
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
