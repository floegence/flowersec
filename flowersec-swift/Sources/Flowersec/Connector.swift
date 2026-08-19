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

public enum ConnectError: String, Error, Equatable, Sendable {
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
    throw ConnectError.runtimeUnsupported
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
