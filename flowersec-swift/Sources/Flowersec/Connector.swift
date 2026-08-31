import Foundation

public struct ConnectorOptions: Sendable {
  public var origin: String?
  public var connectTimeout: Duration
  public var trustRootsPEM: [Data]

  public init(
    origin: String? = nil,
    connectTimeout: Duration = .seconds(10),
    trustRootsPEM: [Data] = []
  ) {
    self.origin = origin
    self.connectTimeout = connectTimeout
    self.trustRootsPEM = trustRootsPEM
  }
}

/// The complete public Transport v3 connection error code set.
public enum ConnectErrorCode: String, CaseIterable, Equatable, Sendable {
  case artifactInvalid = "artifact_invalid"
  case expiredArtifact = "expired_artifact"
  case transportSecurityUnsupported = "transport_security_unsupported"
  case transportSecurityFailed = "transport_security_failed"
  case connectionFailed = "connection_failed"
}

/// A stable, redacted Transport v3 connection failure.
public struct ConnectError: Error, Equatable, Sendable {
  public let code: ConnectErrorCode
  public let retryDisposition: RetryDisposition

  public static let artifactInvalid = ConnectError(.artifactInvalid, .terminal)
  public static let expiredArtifact = ConnectError(.expiredArtifact, .retryable)
  public static let transportSecurityUnsupported = ConnectError(
    .transportSecurityUnsupported, .terminal)
  public static let transportSecurityFailed = ConnectError(.transportSecurityFailed, .terminal)
  public static let connectionFailed = ConnectError(.connectionFailed, .retryable)

  func terminalized() -> ConnectError { ConnectError(code, .terminal) }

  internal static let invalidOptions = artifactInvalid
  internal static let runtimeUnsupported = transportSecurityUnsupported
  internal static let canceled = ConnectError(.connectionFailed, .terminal)
  internal static let timeout = connectionFailed
  internal static let terminalConnectionFailed = ConnectError(.connectionFailed, .terminal)

  private init(_ code: ConnectErrorCode, _ retryDisposition: RetryDisposition) {
    self.code = code
    self.retryDisposition = retryDisposition
  }
}

/// Establishes a carrier-neutral Transport v3 session from a strict v3 lease.
///
/// Candidate capability filtering and TLS verification happen before the
/// single-use lease is spent. No downgrade path is available.
public func connect(
  lease: ArtifactLease,
  options: ConnectorOptions = ConnectorOptions()
) async throws -> any Session {
  try await connectOneShotV3(lease: lease, options: options)
}

private func connectOneShotV3(
  lease: ArtifactLease,
  options: ConnectorOptions
) async throws -> any Session {
  #if os(macOS) || os(iOS)
    return try await SessionConnectorV3(
      lease: lease,
      options: options,
      runtime: AppleWebSocketRuntimeAdapterV3()
    ).connect()
  #else
    _ = options
    let claimed: ClaimedArtifactLeaseV3
    do {
      claimed = try await lease.claim()
    } catch is ArtifactLeaseError {
      throw ConnectError.artifactInvalid
    }
    try? await claimed.retire()
    throw ConnectError.transportSecurityUnsupported
  #endif
}

func connectV3ForController(
  lease: ArtifactLease,
  options: ConnectorOptions = ConnectorOptions()
) async throws -> any Session {
  #if os(macOS) || os(iOS)
    return try await SessionConnectorV3(
      lease: lease,
      options: options,
      runtime: AppleWebSocketRuntimeAdapterV3()
    ).connectForController()
  #else
    _ = options
    throw ControllerConnectFailureV3.connection(
      .transportSecurityUnsupported, .terminal, policyTriggerIDs: [],
      opaquePolicyTriggerIDs: [], failedIDs: [])
  #endif
}
