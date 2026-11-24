import Foundation

/// Local limits on the encoded JSON envelope, excluding its four-byte length prefix.
/// Configure both peers explicitly for larger messages; these limits are not negotiated.
public struct RPCFrameLimits: Equatable, Sendable {
  public let send: Int
  public let receive: Int
  public static let standard = RPCFrameLimits()

  private init() {
    send = FlowersecWire.jsonFrameMaxBytes
    receive = FlowersecWire.jsonFrameMaxBytes
  }

  public init(send: Int, receive: Int) throws {
    guard send > 0, receive > 0, UInt32(exactly: send) != nil, UInt32(exactly: receive) != nil
    else { throw ConnectError.invalidOptions }
    self.send = send
    self.receive = receive
  }

  func inboundBudget(queueSize: Int) -> Int {
    let (standardBudget, overflow) = Self.standard.receive.multipliedReportingOverflow(by: queueSize)
    return overflow ? Int.max : max(receive, standardBudget)
  }
}

/// An application-owned snapshot installed before either peer may make its first call.
public struct RPCHandlers: Sendable {
  struct Method: Sendable {
    let acceptsNotifications: Bool
    let invoke: @Sendable ((any Sendable)?, Data) async throws -> Data
  }
  var methods: [UInt32: Method] = [:]
  var notifications: [UInt32: @Sendable (Data) async throws -> Void] = [:]
  var context: (any Sendable)?
  public init() {}

  /// Bind per-session application state while sharing the immutable method table.
  public func bound(to context: any Sendable) -> Self {
    var snapshot = self; snapshot.context = context; return snapshot
  }

  public mutating func register<Context: Sendable, Request: Decodable & Sendable, Response: Encodable & Sendable>(
    _ typeID: UInt32, context: Context.Type, acceptsNotifications: Bool = true,
    handler: @escaping @Sendable (Context, Request) async throws -> Response
  ) throws {
    try install(typeID, acceptsNotifications: acceptsNotifications) { value, request in
      guard let state = value as? Context else { throw RPCError(code: 503, message: "handler unavailable") }
      return try await handler(state, request)
    }
  }

  public mutating func register<Request: Decodable & Sendable, Response: Encodable & Sendable>(
    _ typeID: UInt32, acceptsNotifications: Bool = true, handler: @escaping @Sendable (Request) async throws -> Response
  ) throws {
    try install(typeID, acceptsNotifications: acceptsNotifications) { _, request in try await handler(request) }
  }

  public mutating func registerNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32, handler: @escaping @Sendable (Payload) async throws -> Void
  ) throws {
    guard canRegister(typeID) else { throw ConnectError.invalidOptions }
    notifications[typeID] = { data in
      try await handler(JSONDecoder.flowersecRPC.decode(Payload.self, from: data))
    }
  }

  func canRegister(_ typeID: UInt32) -> Bool {
    typeID != 0 && methods[typeID] == nil && notifications[typeID] == nil
  }

  private mutating func install<Request: Decodable & Sendable, Response: Encodable & Sendable>(
    _ typeID: UInt32, acceptsNotifications: Bool,
    handler: @escaping @Sendable ((any Sendable)?, Request) async throws -> Response
  ) throws {
    guard canRegister(typeID) else { throw ConnectError.invalidOptions }
    methods[typeID] = Method(acceptsNotifications: acceptsNotifications) { context, data in
      let request = try JSONDecoder.flowersecRPC.decode(Request.self, from: data)
      do { return try JSONEncoder.flowersecRPC.encode(try await handler(context, request)) }
      catch let error as RPCError { throw FlowersecRPCError(code: error.code, message: error.message) }
    }
  }
}

public struct ConnectorOptions: Sendable {
  public var origin: String
  public var connectTimeout: Duration
  public var trustRootsPEM: [Data]
  public var rpcFrameLimits: RPCFrameLimits
  public var rpcHandlers: RPCHandlers
  /// Local tunnel entry, matched using the issuer's v5 URL rules. Required for multiple entries.
  public var tunnelIngress: String?
  public var maxConcurrentRPCRequests: Int

  public init(
    origin: String,
    connectTimeout: Duration = .seconds(10),
    trustRootsPEM: [Data] = [], rpcFrameLimits: RPCFrameLimits = .standard,
    rpcHandlers: RPCHandlers = RPCHandlers(), tunnelIngress: String? = nil,
    maxConcurrentRPCRequests: Int = 32
  ) {
    self.origin = origin
    self.connectTimeout = connectTimeout
    self.trustRootsPEM = trustRootsPEM
    self.rpcFrameLimits = rpcFrameLimits
    self.rpcHandlers = rpcHandlers
    self.tunnelIngress = tunnelIngress
    self.maxConcurrentRPCRequests = maxConcurrentRPCRequests
  }

  func ingressCandidates(_ artifact: Artifact) throws -> [CanonicalCandidateV3] {
    let candidates = artifact.canonicalCandidates
    guard artifact.value.path.kind == "tunnel" else {
      guard tunnelIngress == nil else { throw ConnectError.invalidOptions }
      return candidates
    }
    guard let tunnelIngress else {
      guard Set(candidates.map(\.normalizedURL)).count == 1 else { throw ConnectError.invalidOptions }
      return candidates
    }
    let selected = candidates.filter { candidate in
      (try? ArtifactCodecV3.normalizeURL(tunnelIngress, carrier: candidate.carrier, kind: "tunnel"))
        == candidate.normalizedURL
    }
    guard !selected.isEmpty else { throw ConnectError.invalidOptions }
    return selected
  }
}

/// The complete public Transport v5 connection error code set.
public enum ConnectErrorCode: String, CaseIterable, Equatable, Sendable {
  case artifactInvalid = "artifact_invalid"
  case expiredArtifact = "expired_artifact"
  case transportSecurityUnsupported = "transport_security_unsupported"
  case transportSecurityFailed = "transport_security_failed"
  case connectionFailed = "connection_failed"
}

/// A stable, redacted Transport v5 connection failure.
public struct ConnectError: Error, Equatable, Sendable {
  public let code: ConnectErrorCode
  public let retryDisposition: RetryDisposition
  public let leaseReleaseFailed: Bool

  public static let artifactInvalid = ConnectError(.artifactInvalid, .terminal)
  public static let expiredArtifact = ConnectError(.expiredArtifact, .retryable)
  public static let transportSecurityUnsupported = ConnectError(
    .transportSecurityUnsupported, .terminal)
  public static let transportSecurityFailed = ConnectError(.transportSecurityFailed, .terminal)
  public static let connectionFailed = ConnectError(.connectionFailed, .retryable)

  func terminalized() -> ConnectError { ConnectError(code, .terminal, leaseReleaseFailed: leaseReleaseFailed) }

  internal static let invalidOptions = artifactInvalid
  internal static let runtimeUnsupported = transportSecurityUnsupported
  internal static let canceled = ConnectError(.connectionFailed, .terminal)
  internal static let timeout = connectionFailed
  internal static let terminalConnectionFailed = ConnectError(.connectionFailed, .terminal)
  internal static let releaseFailure = ConnectError(.connectionFailed, .terminal, leaseReleaseFailed: true)

  private init(_ code: ConnectErrorCode, _ retryDisposition: RetryDisposition, leaseReleaseFailed: Bool = false) {
    self.code = code
    self.retryDisposition = retryDisposition
    self.leaseReleaseFailed = leaseReleaseFailed
  }
}

/// Establishes a carrier-neutral Transport v5 session from a strict v5 lease.
///
/// Candidate capability filtering and TLS verification happen before the
/// single-use lease is spent. No downgrade path is available.
public func connect(
  lease: ArtifactLease,
  options: ConnectorOptions
) async throws -> any Session {
  try await connectOneShotV3(lease: lease, options: options)
}

private func connectOneShotV3(
  lease: ArtifactLease,
  options: ConnectorOptions
) async throws -> any Session {
  _ = try options.ingressCandidates(lease.artifact)
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

/// Establishes TLS inside application-owned streams without direct-network fallback.
/// Artifact TLS policy, admission, and single-use lease semantics remain unchanged.
public func connect(
  lease: ArtifactLease, options: ConnectorOptions, channelProvider: TLSChannelProvider
) async throws -> any Session {
  _ = try options.ingressCandidates(lease.artifact)
  #if os(macOS) || os(iOS)
    return try await SessionConnectorV3(
      lease: lease, options: options,
      runtime: AppleWebSocketRuntimeAdapterV3(tlsChannelProvider: channelProvider)
    ).connect()
  #else
    let claimed: ClaimedArtifactLeaseV3
    do { claimed = try await lease.claim() } catch { throw ConnectError.artifactInvalid }
    try? await claimed.retire()
    throw ConnectError.transportSecurityUnsupported
  #endif
}

func connectV3ForController(
  lease: ArtifactLease,
  options: ConnectorOptions
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
