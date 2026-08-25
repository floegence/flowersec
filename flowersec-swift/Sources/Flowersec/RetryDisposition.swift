import Foundation

/// The structured decision used by ``ConnectionController`` after a failed
/// artifact acquisition, connection attempt, or established session.
public enum RetryDispositionV2: Equatable, Sendable {
  /// The failure is authoritative and ends the connection lifecycle.
  case terminal
  /// A fresh artifact and a new one-shot session may be attempted after backoff.
  case retryable
  /// A fresh attempt may start no earlier than the supplied absolute deadline.
  case retryAfter(Date)
}

@available(*, deprecated, renamed: "RetryDispositionV2")
public typealias RetryDisposition = RetryDispositionV2

extension ConnectErrorV2 {
  public var retryDispositionV2: RetryDispositionV2 {
    switch self {
    case .invalidOptions, .artifactInvalid, .runtimeUnsupported,
      .transportSecurityUnsupported, .transportSecurityFailed, .canceled:
      return .terminal
    case .expiredArtifact, .timeout, .connectionFailed:
      return .retryable
    }
  }

  @available(*, deprecated, renamed: "retryDispositionV2")
  public var retryDisposition: RetryDispositionV2 { retryDispositionV2 }
}

extension SessionError {
  public var retryDispositionV2: RetryDispositionV2 {
    switch self {
    case .canceled, .streamRejected, .operationFailed:
      return .terminal
    case .timeout, .closed, .goingAway, .resourceExhausted, .streamReset, .rekeyFailed,
      .livenessFailed:
      return .retryable
    }
  }

  @available(*, deprecated, renamed: "retryDispositionV2")
  public var retryDisposition: RetryDispositionV2 { retryDispositionV2 }
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
