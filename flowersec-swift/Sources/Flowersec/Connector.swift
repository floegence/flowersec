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

/// Explicit legacy Transport v2 connection errors.
public enum ConnectErrorV2: String, Error, Equatable, Sendable {
  case invalidOptions = "invalid_options"
  case artifactInvalid = "artifact_invalid"
  case runtimeUnsupported = "runtime_unsupported"
  case transportSecurityUnsupported = "transport_security_unsupported"
  case transportSecurityFailed = "transport_security_failed"
  case expiredArtifact = "expired_artifact"
  case canceled = "canceled"
  case timeout
  case connectionFailed = "connection_failed"
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
  public let retryDisposition: RetryDispositionV3

  public static let artifactInvalid = ConnectError(.artifactInvalid, .terminal)
  public static let expiredArtifact = ConnectError(.expiredArtifact, .retryable)
  public static let transportSecurityUnsupported = ConnectError(
    .transportSecurityUnsupported, .terminal)
  public static let transportSecurityFailed = ConnectError(.transportSecurityFailed, .terminal)
  public static let connectionFailed = ConnectError(.connectionFailed, .retryable)

  public var retryDispositionV3: RetryDispositionV3 { retryDisposition }

  func terminalized() -> ConnectError { ConnectError(code, .terminal) }

  internal static let invalidOptions = artifactInvalid
  internal static let runtimeUnsupported = transportSecurityUnsupported
  internal static let canceled = ConnectError(.connectionFailed, .terminal)
  internal static let timeout = connectionFailed
  internal static let terminalConnectionFailed = ConnectError(.connectionFailed, .terminal)

  private init(_ code: ConnectErrorCode, _ retryDisposition: RetryDispositionV3) {
    self.code = code
    self.retryDisposition = retryDisposition
  }
}

public typealias ConnectErrorV3 = ConnectError

/// Establishes an explicit legacy Transport v2 session.
public func connectV2(
  lease: ArtifactLeaseV2,
  options: ConnectorOptions = ConnectorOptions()
) async throws -> any Session {
  #if os(macOS) || os(iOS)
    try await SessionConnectorV2(
      lease: lease,
      options: options,
      runtime: AppleWebSocketRuntimeAdapterV2()
    ).connect()
  #else
    throw ConnectErrorV2.runtimeUnsupported
  #endif
}

/// Establishes a carrier-neutral Transport v3 session from a strict v3 lease.
///
/// Candidate capability filtering and TLS verification happen before the
/// single-use lease is spent. This path never invokes the v2 connector.
public func connect(
  lease: ArtifactLease,
  options: ConnectorOptions = ConnectorOptions()
) async throws -> any Session {
  try await connectV3(lease: lease, options: options)
}

public func connectV3(
  lease: ArtifactLeaseV3,
  options: ConnectorOptions = ConnectorOptions()
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
    } catch is ArtifactLeaseErrorV3 {
      throw ConnectError.artifactInvalid
    }
    try? await claimed.retire()
    throw ConnectError.transportSecurityUnsupported
  #endif
}

func connectV3ForController(
  lease: ArtifactLeaseV3,
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
