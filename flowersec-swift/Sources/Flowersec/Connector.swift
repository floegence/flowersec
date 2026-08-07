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
  case runtimeUnsupported = "runtime_unsupported"
  case expiredArtifact = "expired_artifact"
  case canceled = "canceled"
  case timeout
  case connectionFailed = "connection_failed"
}

/// Establishes a carrier-neutral Transport v2 session on supported Apple runtimes.
/// Swift on other platforms reports `runtime_unsupported` explicitly.
public func connect(
  lease: ArtifactLease,
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
