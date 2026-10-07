import Foundation

/// Stable current connection failure codes.
public enum ConnectErrorCode: String, CaseIterable, Equatable, Sendable {
  case invalidMaterial = "invalid_material"
  case expired = "expired"
  case unsupported = "unsupported"
  case securityFailed = "security_failed"
  case connectionFailed = "connection_failed"
}

/// A stable, redacted connection failure and its local retry disposition.
public struct ConnectError: Error, Equatable, Sendable {
  public let code: ConnectErrorCode
  public let retryDisposition: RetryDisposition
  public let connection: ConnectionAttemptFacts
  public let cleanup: CleanupStatus
  public var localReport: LocalReport { LocalReport(code: code.rawValue, connection: connection, cleanup: cleanup) }

  public static let invalidMaterial = ConnectError(.invalidMaterial, .terminal)
  public static let expired = ConnectError(.expired, .retryable)
  public static let unsupported = ConnectError(
    .unsupported, .terminal)
  public static let securityFailed = ConnectError(.securityFailed, .terminal)
  public static let connectionFailed = ConnectError(.connectionFailed, .retryable)

  func terminalized() -> ConnectError { ConnectError(code, .terminal, connection: connection, cleanup: cleanup) }

  internal static let canceled = ConnectError(.connectionFailed, .terminal)

  init(_ code: ConnectErrorCode, _ retryDisposition: RetryDisposition,
    connection: ConnectionAttemptFacts = ConnectionAttemptFacts(spendState: .unspent, admissionState: .notStarted,
      networkReady: .notStarted, applicationPublish: .notStarted, sourceProfile: nil, queryAvailability: .unavailable),
    cleanup: CleanupStatus = CleanupStatus(complete: true)) {
    self.code = code; self.connection = connection; self.cleanup = cleanup
    self.retryDisposition = connection.permitsAutomaticRetry ? retryDisposition : .terminal
  }
  func withFacts(_ facts: ConnectionAttemptFacts, cleanup: CleanupStatus) -> ConnectError {
    ConnectError(code, retryDisposition, connection: facts, cleanup: cleanup)
  }
  static func capture(_ error: any Error, connection: ConnectionAttemptFacts, cleanup: CleanupStatus) -> ConnectError {
    if let value = error as? ConnectError {
      // Nested failure boundaries observe overlapping original cleanup owners.
      // A later complete observation cannot erase an unfinished earlier tail.
      return value.withFacts(connection, cleanup: value.cleanup.preserving(cleanup))
    }
    if error is CancellationError { return canceled.withFacts(connection, cleanup: cleanup) }
    if let value = error as? SessionError {
      switch value {
      case .canceled, .closed: return canceled.withFacts(connection, cleanup: cleanup)
      default: break
      }
    }
    #if os(macOS) || os(iOS)
    if let value = error as? TransportControlError {
      switch value {
      case .canceled, .closed: return canceled.withFacts(connection, cleanup: cleanup)
      default: break
      }
    }
    if let value = error as? TransportConnectError {
      let failure: ConnectError
      switch value {
      case .invalidMaterial: failure = .invalidMaterial
      case .unsupported: failure = .unsupported
      case .securityFailed, .futureTimestamp: failure = .securityFailed
      case .expired: failure = .expired
      case .canceled, .closed: failure = .canceled
      case .connectionFailed, .admissionRejected, .timePending, .timeNotProven,
        .bootstrapDeadline, .timeUnavailable: failure = .connectionFailed
      }
      return failure.withFacts(connection, cleanup: cleanup)
    }
    if error is V4TimeFailure { return expired.withFacts(connection, cleanup: cleanup) }
    if error is V4NamespaceFailure || error is V4CryptoFailure { return securityFailed.withFacts(connection, cleanup: cleanup) }
    #endif
    return connectionFailed.withFacts(connection, cleanup: cleanup)
  }
}

/// Establishes a current Session through the configured TransportEnvironment and its
/// original independently spendable connection material source.
public func connect(environment: TransportEnvironment, source: ConnectionMaterialSource,
  requirements: ConnectionRequirements = ConnectionRequirements()) async throws -> any Session {
  try await environment.connect(source: source, requirements: requirements)
}
public func connect(environment: TransportEnvironment, material: ConnectionMaterial,
  requirements: ConnectionRequirements = ConnectionRequirements()) async throws -> any Session {
  try await environment.connectMaterial(material, requirements: requirements)
}

#if os(macOS) || os(iOS)
// This projection lives only inside the original charged connect operation.
// Delivery refreshes its actual owners after that operation's tail exits and
// returns a detached ConnectError, without retaining the Environment aggregate.
struct V4ConnectFailureProjection: Error, Sendable {
  let failure: ConnectError
  let observeCleanup: @Sendable () async -> CleanupStatus

  func delivered() async -> ConnectError {
    failure.withFacts(failure.connection, cleanup: await observeCleanup())
  }
}

func v4FailureProjection(
  _ error: any Error,
  connection: ConnectionAttemptFacts,
  cleanup: @escaping @Sendable () -> CleanupStatus
) -> V4ConnectFailureProjection {
  let initial = cleanup()
  let failure = ConnectError.capture(error, connection: connection, cleanup: initial)
  return V4ConnectFailureProjection(failure: failure, observeCleanup: {
    initial.preserving(cleanup())
  })
}
#endif
