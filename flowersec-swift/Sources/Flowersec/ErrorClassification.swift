public enum RetryAction: String, Equatable, Sendable {
  case retry
  case refreshArtifact = "refresh_artifact"
  case stop
}

public struct ErrorRetryClassification: Equatable, Sendable {
  public let action: RetryAction
  public let callerCanceled: Bool
  public let sessionClosed: Bool

  fileprivate init(
    action: RetryAction,
    callerCanceled: Bool = false,
    sessionClosed: Bool = false
  ) {
    self.action = action
    self.callerCanceled = callerCanceled
    self.sessionClosed = sessionClosed
  }
}

public func classifyConnectError(
  _ error: ConnectError
) -> ErrorRetryClassification {
  switch error {
  case .invalidOptions:
    return ErrorRetryClassification(action: .stop)
  case .canceled:
    return ErrorRetryClassification(action: .stop, callerCanceled: true)
  case .expiredArtifact, .timeout, .connectionFailed:
    return ErrorRetryClassification(action: .refreshArtifact)
  }
}

public func classifySessionError(
  _ error: SessionError
) -> ErrorRetryClassification {
  switch error {
  case .canceled:
    return ErrorRetryClassification(action: .stop, callerCanceled: true)
  case .closed, .goingAway:
    return ErrorRetryClassification(action: .refreshArtifact, sessionClosed: true)
  case .timeout, .resourceExhausted, .streamReset, .rekeyFailed, .livenessFailed:
    return ErrorRetryClassification(action: .retry)
  case .streamRejected, .operationFailed:
    return ErrorRetryClassification(action: .stop)
  }
}
