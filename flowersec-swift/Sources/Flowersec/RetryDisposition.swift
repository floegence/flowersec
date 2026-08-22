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

extension ConnectErrorV2 {
  public var retryDisposition: RetryDisposition {
    switch self {
    case .invalidOptions, .artifactInvalid, .runtimeUnsupported,
      .transportSecurityUnsupported, .transportSecurityFailed, .canceled:
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

/// The v3 retry decision uses an exact Unix-millisecond deadline on every
/// platform. The bounded integer avoids Date precision and rounding differences.
public enum RetryDispositionV3: Equatable, Sendable {
  case terminal
  case retryable
  case retryAfter(UInt64)
}

extension SessionError {
  public var retryDispositionV3: RetryDispositionV3 {
    switch self {
    case .canceled, .streamRejected, .operationFailed:
      return .terminal
    case .timeout, .closed, .goingAway, .resourceExhausted, .streamReset, .rekeyFailed,
      .livenessFailed:
      return .retryable
    }
  }
}
