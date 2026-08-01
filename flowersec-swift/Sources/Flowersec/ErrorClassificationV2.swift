public enum FlowersecRetryActionV2: String, Equatable, Sendable {
  case retry
  case refreshArtifact = "refresh_artifact"
  case stop
}

public struct FlowersecErrorRetryClassificationV2: Equatable, Sendable {
  public let action: FlowersecRetryActionV2
  public let retryable: Bool
  public let refreshArtifact: Bool
  public let callerCanceled: Bool
  public let sessionClosed: Bool

  fileprivate init(
    action: FlowersecRetryActionV2,
    callerCanceled: Bool = false,
    sessionClosed: Bool = false
  ) {
    self.action = action
    self.retryable = action != .stop
    self.refreshArtifact = action == .refreshArtifact
    self.callerCanceled = callerCanceled
    self.sessionClosed = sessionClosed
  }
}

public func classifyConnectErrorV2(
  _ error: ConnectErrorV2
) -> FlowersecErrorRetryClassificationV2 {
  switch error {
  case .invalidOptions:
    return FlowersecErrorRetryClassificationV2(action: .stop)
  case .canceled:
    return FlowersecErrorRetryClassificationV2(action: .stop, callerCanceled: true)
  case .expiredArtifact, .timeout, .connectionFailed:
    return FlowersecErrorRetryClassificationV2(action: .refreshArtifact)
  }
}

public func classifySessionErrorV2(
  _ error: SessionErrorV2
) -> FlowersecErrorRetryClassificationV2 {
  switch error {
  case .canceled:
    return FlowersecErrorRetryClassificationV2(action: .stop, callerCanceled: true)
  case .closed, .goingAway:
    return FlowersecErrorRetryClassificationV2(action: .refreshArtifact, sessionClosed: true)
  case .timeout, .resourceExhausted, .streamReset, .rekeyFailed, .livenessFailed:
    return FlowersecErrorRetryClassificationV2(action: .retry)
  case .streamRejected, .operationFailed:
    return FlowersecErrorRetryClassificationV2(action: .stop)
  }
}
