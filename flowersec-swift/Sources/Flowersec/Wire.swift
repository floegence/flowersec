import Foundation

public enum FlowersecPath: String, Codable, Equatable, Sendable {
  case auto
  case tunnel
  case direct
}

public enum FlowersecStage: String, Codable, Equatable, Sendable {
  case validate
  case scope
  case connect
  case transport
  case attach
  case handshake
  case secure
  case yamux
  case rpc
  case reconnect
  case close
}

public enum DiagnosticCodeDomain: String, Codable, Equatable, Sendable {
  case error
  case event
}

public enum DiagnosticResult: String, Codable, Equatable, Sendable {
  case ok
  case fail
  case retry
  case skip
}

public struct DiagnosticEvent: Codable, Equatable, Sendable {
  public var v: Int
  public var namespace: String
  public var path: FlowersecPath
  public var stage: FlowersecStage
  public var codeDomain: DiagnosticCodeDomain
  public var code: String
  public var result: DiagnosticResult
  public var elapsedMS: Double
  public var attemptSeq: Int
  public var traceID: String?
  public var sessionID: String?
  public var resource: String?
  public var current: Int?
  public var limit: Int?

  public init(
    v: Int = 1,
    namespace: String = "connect",
    path: FlowersecPath,
    stage: FlowersecStage,
    codeDomain: DiagnosticCodeDomain,
    code: String,
    result: DiagnosticResult,
    elapsedMS: Double = 0,
    attemptSeq: Int = 1,
    traceID: String? = nil,
    sessionID: String? = nil,
    resource: String? = nil,
    current: Int? = nil,
    limit: Int? = nil
  ) {
    self.v = v
    self.namespace = namespace
    self.path = path
    self.stage = stage
    self.codeDomain = codeDomain
    self.code = code
    self.result = result
    self.elapsedMS = elapsedMS
    self.attemptSeq = attemptSeq
    self.traceID = traceID
    self.sessionID = sessionID
    self.resource = resource
    self.current = current
    self.limit = limit
  }

  private enum CodingKeys: String, CodingKey {
    case v
    case namespace
    case path
    case stage
    case codeDomain = "code_domain"
    case code
    case result
    case elapsedMS = "elapsed_ms"
    case attemptSeq = "attempt_seq"
    case traceID = "trace_id"
    case sessionID = "session_id"
    case resource
    case current
    case limit
  }
}

public enum FlowersecCode: String, Codable, CaseIterable, Equatable, Sendable {
  case invalidInput = "invalid_input"
  case invalidOption = "invalid_option"
  case missingGrant = "missing_grant"
  case missingConnectInfo = "missing_connect_info"
  case missingConn = "missing_conn"
  case roleMismatch = "role_mismatch"
  case missingTunnelURL = "missing_tunnel_url"
  case missingWSURL = "missing_ws_url"
  case missingOrigin = "missing_origin"
  case missingChannelID = "missing_channel_id"
  case missingToken = "missing_token"
  case missingInitExp = "missing_init_exp"
  case invalidPSK = "invalid_psk"
  case invalidSuite = "invalid_suite"
  case invalidVersion = "invalid_version"
  case invalidEndpointInstanceID = "invalid_endpoint_instance_id"
  case resolveFailed = "resolve_failed"
  case transportPolicyDenied = "transport_policy_denied"
  case credentialCommitFailed = "credential_commit_failed"
  case randomFailed = "random_failed"
  case dialFailed = "dial_failed"
  case attachFailed = "attach_failed"
  case upgradeFailed = "upgrade_failed"
  case tooManyConnections = "too_many_connections"
  case expectedAttach = "expected_attach"
  case invalidAttach = "invalid_attach"
  case invalidToken = "invalid_token"
  case channelMismatch = "channel_mismatch"
  case initExpMismatch = "init_exp_mismatch"
  case idleTimeoutMismatch = "idle_timeout_mismatch"
  case tokenReplay = "token_replay"
  case tenantMismatch = "tenant_mismatch"
  case policyDenied = "policy_denied"
  case policyError = "policy_error"
  case replaceRateLimited = "replace_rate_limited"
  case timeout
  case canceled
  case handshakeFailed = "handshake_failed"
  case timestampAfterInitExp = "timestamp_after_init_exp"
  case timestampOutOfSkew = "timestamp_out_of_skew"
  case authTagMismatch = "auth_tag_mismatch"
  case openStreamFailed = "open_stream_failed"
  case acceptStreamFailed = "accept_stream_failed"
  case muxFailed = "mux_failed"
  case streamHelloFailed = "stream_hello_failed"
  case rpcFailed = "rpc_failed"
  case missingStreamKind = "missing_stream_kind"
  case missingHandler = "missing_handler"
  case pingFailed = "ping_failed"
  case rekeyFailed = "rekey_failed"
  case notConnected = "not_connected"
  case resourceExhausted = "resource_exhausted"
}

public enum Suite: Int, Codable, Equatable, Sendable {
  case x25519HKDFSHA256AES256GCM = 1
  case p256HKDFSHA256AES256GCM = 2
}

public struct DirectConnectInfo: Codable, Equatable, Sendable {
  public var wsURL: URL
  public var channelID: String
  public var psk: Data
  public var channelInitExpiresAtUnixS: Int64
  public var defaultSuite: Suite
  private var encodedPSK: String

  public init(
    wsURL: URL,
    channelID: String,
    psk: Data,
    channelInitExpiresAtUnixS: Int64,
    defaultSuite: Suite
  ) {
    self.wsURL = wsURL
    self.channelID = channelID
    self.psk = psk
    self.channelInitExpiresAtUnixS = channelInitExpiresAtUnixS
    self.defaultSuite = defaultSuite
    self.encodedPSK = psk.base64URLEncodedString()
  }

  private init(
    wsURL: URL,
    channelID: String,
    psk: Data,
    encodedPSK: String,
    channelInitExpiresAtUnixS: Int64,
    defaultSuite: Suite
  ) {
    self.wsURL = wsURL
    self.channelID = channelID
    self.psk = psk
    self.encodedPSK = encodedPSK
    self.channelInitExpiresAtUnixS = channelInitExpiresAtUnixS
    self.defaultSuite = defaultSuite
  }

  private enum CodingKeys: String, CodingKey {
    case wsURL = "ws_url"
    case channelID = "channel_id"
    case psk = "e2ee_psk_b64u"
    case channelInitExpiresAtUnixS = "channel_init_expire_at_unix_s"
    case defaultSuite = "default_suite"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let rawURL = try container.decode(String.self, forKey: .wsURL)
    guard let wsURL = URL(string: rawURL) else {
      throw DecodingError.dataCorruptedError(
        forKey: .wsURL,
        in: container,
        debugDescription: "Invalid ws_url"
      )
    }
    let rawPSK = try container.decode(String.self, forKey: .psk)
    guard let psk = Data(base64URLEncoded: rawPSK) else {
      throw DecodingError.dataCorruptedError(
        forKey: .psk,
        in: container,
        debugDescription: "Invalid e2ee_psk_b64u"
      )
    }
    self.init(
      wsURL: wsURL,
      channelID: try container.decode(String.self, forKey: .channelID),
      psk: psk,
      encodedPSK: rawPSK,
      channelInitExpiresAtUnixS: try container.decode(
        Int64.self, forKey: .channelInitExpiresAtUnixS),
      defaultSuite: try container.decode(Suite.self, forKey: .defaultSuite)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(wsURL.absoluteString, forKey: .wsURL)
    try container.encode(channelID, forKey: .channelID)
    try container.encode(encodedPSK, forKey: .psk)
    try container.encode(channelInitExpiresAtUnixS, forKey: .channelInitExpiresAtUnixS)
    try container.encode(defaultSuite, forKey: .defaultSuite)
  }

  public static func == (lhs: DirectConnectInfo, rhs: DirectConnectInfo) -> Bool {
    lhs.wsURL == rhs.wsURL
      && lhs.channelID == rhs.channelID
      && lhs.psk == rhs.psk
      && lhs.channelInitExpiresAtUnixS == rhs.channelInitExpiresAtUnixS
      && lhs.defaultSuite == rhs.defaultSuite
  }
}

public struct ChannelInitGrant: Codable, Equatable, Sendable {
  public var tunnelURL: URL
  public var channelID: String
  public var channelInitExpiresAtUnixS: Int64
  public var idleTimeoutSeconds: Int32
  public var role: UInt8
  public var token: String
  public var psk: Data
  public var allowedSuites: [Suite]
  public var defaultSuite: Suite
  private var encodedPSK: String

  public init(
    tunnelURL: URL,
    channelID: String,
    channelInitExpiresAtUnixS: Int64,
    idleTimeoutSeconds: Int32,
    role: UInt8,
    token: String,
    psk: Data,
    allowedSuites: [Suite],
    defaultSuite: Suite
  ) {
    self.tunnelURL = tunnelURL
    self.channelID = channelID
    self.channelInitExpiresAtUnixS = channelInitExpiresAtUnixS
    self.idleTimeoutSeconds = idleTimeoutSeconds
    self.role = role
    self.token = token
    self.psk = psk
    self.allowedSuites = allowedSuites
    self.defaultSuite = defaultSuite
    self.encodedPSK = psk.base64URLEncodedString()
  }

  private init(
    tunnelURL: URL,
    channelID: String,
    channelInitExpiresAtUnixS: Int64,
    idleTimeoutSeconds: Int32,
    role: UInt8,
    token: String,
    psk: Data,
    encodedPSK: String,
    allowedSuites: [Suite],
    defaultSuite: Suite
  ) {
    self.tunnelURL = tunnelURL
    self.channelID = channelID
    self.channelInitExpiresAtUnixS = channelInitExpiresAtUnixS
    self.idleTimeoutSeconds = idleTimeoutSeconds
    self.role = role
    self.token = token
    self.psk = psk
    self.encodedPSK = encodedPSK
    self.allowedSuites = allowedSuites
    self.defaultSuite = defaultSuite
  }

  private enum CodingKeys: String, CodingKey {
    case tunnelURL = "tunnel_url"
    case channelID = "channel_id"
    case channelInitExpiresAtUnixS = "channel_init_expire_at_unix_s"
    case idleTimeoutSeconds = "idle_timeout_seconds"
    case role
    case token
    case psk = "e2ee_psk_b64u"
    case allowedSuites = "allowed_suites"
    case defaultSuite = "default_suite"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let rawURL = try container.decode(String.self, forKey: .tunnelURL)
    guard let tunnelURL = URL(string: rawURL) else {
      throw DecodingError.dataCorruptedError(
        forKey: .tunnelURL,
        in: container,
        debugDescription: "Invalid tunnel_url"
      )
    }
    let rawPSK = try container.decode(String.self, forKey: .psk)
    guard let psk = Data(base64URLEncoded: rawPSK) else {
      throw DecodingError.dataCorruptedError(
        forKey: .psk,
        in: container,
        debugDescription: "Invalid e2ee_psk_b64u"
      )
    }
    self.init(
      tunnelURL: tunnelURL,
      channelID: try container.decode(String.self, forKey: .channelID),
      channelInitExpiresAtUnixS: try container.decode(
        Int64.self, forKey: .channelInitExpiresAtUnixS),
      idleTimeoutSeconds: try container.decode(Int32.self, forKey: .idleTimeoutSeconds),
      role: try container.decode(UInt8.self, forKey: .role),
      token: try container.decode(String.self, forKey: .token),
      psk: psk,
      encodedPSK: rawPSK,
      allowedSuites: try container.decode([Suite].self, forKey: .allowedSuites),
      defaultSuite: try container.decode(Suite.self, forKey: .defaultSuite)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(tunnelURL.absoluteString, forKey: .tunnelURL)
    try container.encode(channelID, forKey: .channelID)
    try container.encode(channelInitExpiresAtUnixS, forKey: .channelInitExpiresAtUnixS)
    try container.encode(idleTimeoutSeconds, forKey: .idleTimeoutSeconds)
    try container.encode(role, forKey: .role)
    try container.encode(token, forKey: .token)
    try container.encode(encodedPSK, forKey: .psk)
    try container.encode(allowedSuites, forKey: .allowedSuites)
    try container.encode(defaultSuite, forKey: .defaultSuite)
  }

  public static func == (lhs: ChannelInitGrant, rhs: ChannelInitGrant) -> Bool {
    lhs.tunnelURL == rhs.tunnelURL
      && lhs.channelID == rhs.channelID
      && lhs.channelInitExpiresAtUnixS == rhs.channelInitExpiresAtUnixS
      && lhs.idleTimeoutSeconds == rhs.idleTimeoutSeconds
      && lhs.role == rhs.role
      && lhs.token == rhs.token
      && lhs.psk == rhs.psk
      && lhs.allowedSuites == rhs.allowedSuites
      && lhs.defaultSuite == rhs.defaultSuite
  }
}

public struct ConnectArtifactMetadata: Equatable, Sendable {
  public static let empty = ConnectArtifactMetadata(uncheckedScoped: [], correlation: nil)

  public let scoped: [ScopeMetadataEntry]
  public let correlation: CorrelationContext?

  public init(
    scoped: [ScopeMetadataEntry] = [],
    correlation: CorrelationContext? = nil
  ) throws {
    try Self.validate(scoped: scoped)
    self.scoped = scoped
    self.correlation = correlation
  }

  private init(uncheckedScoped scoped: [ScopeMetadataEntry], correlation: CorrelationContext?) {
    self.scoped = scoped
    self.correlation = correlation
  }

  static func decoded(scoped: [ScopeMetadataEntry], correlation: CorrelationContext?) throws
    -> ConnectArtifactMetadata
  {
    try Self.validate(scoped: scoped)
    return ConnectArtifactMetadata(uncheckedScoped: scoped, correlation: correlation)
  }

  private static func validate(scoped: [ScopeMetadataEntry]) throws {
    guard scoped.count <= 8 else {
      throw FlowersecError.invalidConnectInfo("ConnectArtifact.scoped has too many entries.")
    }
    var seen = Set<String>()
    for entry in scoped {
      guard seen.insert(entry.scope).inserted else {
        throw FlowersecError.invalidConnectInfo("ConnectArtifact.scoped contains duplicate scopes.")
      }
    }
  }
}

public struct ScopeMetadataEntry: Codable, Equatable, Sendable {
  public let scope: String
  public let scopeVersion: Int
  public let critical: Bool
  public let payload: ScopePayload

  public init(
    scope: String,
    scopeVersion: Int,
    critical: Bool,
    payload: ScopePayload
  ) throws {
    try Self.validate(scope: scope, scopeVersion: scopeVersion)
    self.scope = scope
    self.scopeVersion = scopeVersion
    self.critical = critical
    self.payload = payload
  }

  private init(
    uncheckedScope scope: String,
    scopeVersion: Int,
    critical: Bool,
    payload: ScopePayload
  ) {
    self.scope = scope
    self.scopeVersion = scopeVersion
    self.critical = critical
    self.payload = payload
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case scope
    case scopeVersion = "scope_version"
    case critical
    case payload
  }

  public init(from decoder: Decoder) throws {
    let raw = try decoder.container(keyedBy: AnyCodingKey.self)
    try rejectUnknownFields(raw, allowed: CodingKeys.allowedKeys, kind: "ScopeMetadataEntry")
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let scope = try container.decode(String.self, forKey: .scope)
    let scopeVersion = try container.decode(Int.self, forKey: .scopeVersion)
    try Self.validate(scope: scope, scopeVersion: scopeVersion)
    self.init(
      uncheckedScope: scope,
      scopeVersion: scopeVersion,
      critical: try container.decode(Bool.self, forKey: .critical),
      payload: try container.decode(ScopePayload.self, forKey: .payload)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(scope, forKey: .scope)
    try container.encode(scopeVersion, forKey: .scopeVersion)
    try container.encode(critical, forKey: .critical)
    try container.encode(payload, forKey: .payload)
  }

  private static func validate(scope: String, scopeVersion: Int) throws {
    guard ConnectArtifactConstraints.matches(scope, pattern: .scopeName) else {
      throw FlowersecError.invalidConnectInfo("ScopeMetadataEntry.scope is invalid.")
    }
    guard (1...65_535).contains(scopeVersion) else {
      throw FlowersecError.invalidConnectInfo("ScopeMetadataEntry.scope_version is invalid.")
    }
  }
}

public struct ScopePayload: Codable, Equatable, Sendable {
  public let object: [String: ScopePayloadValue]

  public init(_ object: [String: ScopePayloadValue]) throws {
    self.object = object
    try validate()
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: AnyCodingKey.self)
    var object: [String: ScopePayloadValue] = [:]
    for key in container.allKeys {
      object[key.stringValue] = try container.decode(ScopePayloadValue.self, forKey: key)
    }
    self.object = object
    try validate()
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: AnyCodingKey.self)
    for key in object.keys.sorted() {
      guard let codingKey = AnyCodingKey(stringValue: key) else { continue }
      try container.encode(object[key], forKey: codingKey)
    }
  }

  private func validate() throws {
    guard try normalizedBytes().count <= 8_192 else {
      throw FlowersecError.invalidConnectInfo("ScopeMetadataEntry.payload is too large.")
    }
    guard containerDepth <= 8 else {
      throw FlowersecError.invalidConnectInfo("ScopeMetadataEntry.payload is too deep.")
    }
  }

  private var containerDepth: Int {
    var best = 1
    for value in object.values {
      best = max(best, 1 + value.containerDepth)
    }
    return best
  }

  private func normalizedBytes() throws -> Data {
    try JSONSerialization.data(withJSONObject: jsonObject, options: [.sortedKeys])
  }

  private var jsonObject: [String: Any] {
    object.mapValues(\.jsonObject)
  }
}

public enum ScopePayloadValue: Codable, Equatable, Sendable {
  case null
  case bool(Bool)
  case string(String)
  case number(Double)
  case array([ScopePayloadValue])
  case object([String: ScopePayloadValue])

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .bool(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode(Int64.self) {
      self = .number(Double(value))
    } else if let value = try? container.decode(UInt64.self) {
      self = .number(Double(value))
    } else if let value = try? container.decode(Double.self), value.isFinite {
      self = .number(value)
    } else if let value = try? container.decode([ScopePayloadValue].self) {
      self = .array(value)
    } else if let value = try? container.decode([String: ScopePayloadValue].self) {
      self = .object(value)
    } else {
      throw DecodingError.dataCorruptedError(
        in: container,
        debugDescription: "Unsupported JSON payload value"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .null:
      try container.encodeNil()
    case .bool(let value):
      try container.encode(value)
    case .string(let value):
      try container.encode(value)
    case .number(let value):
      guard value.isFinite else {
        throw EncodingError.invalidValue(
          value,
          EncodingError.Context(
            codingPath: encoder.codingPath,
            debugDescription: "ScopePayloadValue.number must be finite."
          )
        )
      }
      try container.encode(value)
    case .array(let value):
      try container.encode(value)
    case .object(let value):
      try container.encode(value)
    }
  }

  fileprivate var containerDepth: Int {
    switch self {
    case .array(let values):
      var best = 1
      for value in values {
        best = max(best, 1 + value.containerDepth)
      }
      return best
    case .object(let values):
      var best = 1
      for value in values.values {
        best = max(best, 1 + value.containerDepth)
      }
      return best
    case .null, .bool, .string, .number:
      return 0
    }
  }

  fileprivate var jsonObject: Any {
    switch self {
    case .null:
      return NSNull()
    case .bool(let value):
      return value
    case .string(let value):
      return value
    case .number(let value):
      return NSNumber(value: value)
    case .array(let values):
      return values.map(\.jsonObject)
    case .object(let values):
      return values.mapValues(\.jsonObject)
    }
  }
}

public struct CorrelationKV: Codable, Equatable, Sendable {
  public let key: String
  public let value: String

  public init(key: String, value: String) throws {
    try Self.validate(key: key, value: value)
    self.key = key
    self.value = value
  }

  private init(uncheckedKey key: String, value: String) {
    self.key = key
    self.value = value
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case key
    case value
  }

  public init(from decoder: Decoder) throws {
    let raw = try decoder.container(keyedBy: AnyCodingKey.self)
    try rejectUnknownFields(raw, allowed: CodingKeys.allowedKeys, kind: "CorrelationKV")
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let key = try container.decode(String.self, forKey: .key)
    let value = try container.decode(String.self, forKey: .value)
    try Self.validate(key: key, value: value)
    self.init(uncheckedKey: key, value: value)
  }

  private static func validate(key: String, value: String) throws {
    guard ConnectArtifactConstraints.matches(key, pattern: .tagKey), key.utf8.count <= 32 else {
      throw FlowersecError.invalidConnectInfo("CorrelationKV.key is invalid.")
    }
    guard value.utf8.count <= 128 else {
      throw FlowersecError.invalidConnectInfo("CorrelationKV.value is too long.")
    }
  }
}

public struct CorrelationContext: Codable, Equatable, Sendable {
  public let traceID: String?
  public let sessionID: String?
  public let tags: [CorrelationKV]

  public init(
    traceID: String? = nil,
    sessionID: String? = nil,
    tags: [CorrelationKV] = []
  ) throws {
    try Self.validate(tags: tags)
    self.traceID = Self.sanitizedID(traceID)
    self.sessionID = Self.sanitizedID(sessionID)
    self.tags = tags
  }

  private init(
    uncheckedTraceID traceID: String?,
    sessionID: String?,
    tags: [CorrelationKV]
  ) {
    self.traceID = traceID
    self.sessionID = sessionID
    self.tags = tags
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case v
    case traceID = "trace_id"
    case sessionID = "session_id"
    case tags
  }

  public init(from decoder: Decoder) throws {
    let raw = try decoder.container(keyedBy: AnyCodingKey.self)
    try rejectUnknownFields(raw, allowed: CodingKeys.allowedKeys, kind: "CorrelationContext")
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let version = try container.decode(Int.self, forKey: .v)
    guard version == 1 else {
      throw DecodingError.dataCorruptedError(
        forKey: .v,
        in: container,
        debugDescription: "bad CorrelationContext.v"
      )
    }
    let tags: [CorrelationKV]
    if container.contains(.tags) {
      tags = try container.decode([CorrelationKV].self, forKey: .tags)
    } else {
      tags = []
    }
    try Self.validate(tags: tags)
    self.init(
      uncheckedTraceID: Self.sanitizedID(
        try container.decodeIfPresent(String.self, forKey: .traceID)),
      sessionID: Self.sanitizedID(try container.decodeIfPresent(String.self, forKey: .sessionID)),
      tags: tags
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(1, forKey: .v)
    try container.encodeIfPresent(traceID, forKey: .traceID)
    try container.encodeIfPresent(sessionID, forKey: .sessionID)
    try container.encode(tags, forKey: .tags)
  }

  private static func validate(tags: [CorrelationKV]) throws {
    guard tags.count <= 8 else {
      throw FlowersecError.invalidConnectInfo("CorrelationContext.tags has too many entries.")
    }
    var seen = Set<String>()
    for tag in tags {
      guard seen.insert(tag.key).inserted else {
        throw FlowersecError.invalidConnectInfo("CorrelationContext.tags contains duplicate keys.")
      }
    }
  }

  private static func sanitizedID(_ value: String?) -> String? {
    guard let value else { return nil }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard ConnectArtifactConstraints.matches(trimmed, pattern: .correlationID) else {
      return nil
    }
    return trimmed
  }
}

public enum ConnectArtifact: Codable, Equatable, Sendable {
  case direct(DirectConnectInfo, metadata: ConnectArtifactMetadata)
  case tunnel(ChannelInitGrant, metadata: ConnectArtifactMetadata)

  public var metadata: ConnectArtifactMetadata {
    switch self {
    case .direct(_, let metadata),
      .tunnel(_, let metadata):
      return metadata
    }
  }

  public var directInfo: DirectConnectInfo? {
    guard case .direct(let info, metadata: _) = self else { return nil }
    return info
  }

  public var tunnelGrant: ChannelInitGrant? {
    guard case .tunnel(let grant, metadata: _) = self else { return nil }
    return grant
  }

  private enum CodingKeys: String, CodingKey, CaseIterable {
    case v
    case transport
    case directInfo = "direct_info"
    case tunnelGrant = "tunnel_grant"
    case scoped
    case correlation
  }

  public init(from decoder: Decoder) throws {
    let raw = try decoder.container(keyedBy: AnyCodingKey.self)
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let version = try container.decode(Int.self, forKey: .v)
    guard version == 1 else {
      throw DecodingError.dataCorruptedError(
        forKey: .v,
        in: container,
        debugDescription: "Unsupported ConnectArtifact version"
      )
    }
    let transport = try container.decode(String.self, forKey: .transport)
    let scoped: [ScopeMetadataEntry]
    if container.contains(.scoped) {
      scoped = try container.decode([ScopeMetadataEntry].self, forKey: .scoped)
    } else {
      scoped = []
    }
    let correlation: CorrelationContext?
    if container.contains(.correlation) {
      correlation = try container.decode(CorrelationContext.self, forKey: .correlation)
    } else {
      correlation = nil
    }
    let metadata = try ConnectArtifactMetadata.decoded(scoped: scoped, correlation: correlation)
    switch transport {
    case "direct":
      try rejectUnknownFields(
        raw,
        allowed: ["v", "transport", "direct_info", "scoped", "correlation"],
        kind: "DirectClientConnectArtifact"
      )
      self = .direct(
        try container.decode(DirectConnectInfo.self, forKey: .directInfo),
        metadata: metadata
      )
    case "tunnel":
      try rejectUnknownFields(
        raw,
        allowed: ["v", "transport", "tunnel_grant", "scoped", "correlation"],
        kind: "TunnelClientConnectArtifact"
      )
      let grant = try container.decode(ChannelInitGrant.self, forKey: .tunnelGrant)
      guard grant.role == 1 else {
        throw DecodingError.dataCorruptedError(
          forKey: .tunnelGrant,
          in: container,
          debugDescription: "bad TunnelClientConnectArtifact.tunnel_grant.role"
        )
      }
      self = .tunnel(grant, metadata: metadata)
    default:
      throw DecodingError.dataCorruptedError(
        forKey: .transport,
        in: container,
        debugDescription: "Unsupported ConnectArtifact transport"
      )
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(1, forKey: .v)
    switch self {
    case .direct(let info, let metadata):
      try container.encode("direct", forKey: .transport)
      try container.encode(info, forKey: .directInfo)
      try encode(metadata, to: &container)
    case .tunnel(let grant, let metadata):
      try container.encode("tunnel", forKey: .transport)
      try container.encode(grant, forKey: .tunnelGrant)
      try encode(metadata, to: &container)
    }
  }

  private func encode(
    _ metadata: ConnectArtifactMetadata,
    to container: inout KeyedEncodingContainer<CodingKeys>
  ) throws {
    if !metadata.scoped.isEmpty {
      try container.encode(metadata.scoped, forKey: .scoped)
    }
    try container.encodeIfPresent(metadata.correlation, forKey: .correlation)
  }
}

private enum ConnectArtifactConstraintPattern {
  case scopeName
  case tagKey
  case correlationID
}

private enum ConnectArtifactConstraints {
  private static let scopeName = try! NSRegularExpression(pattern: #"^[a-z][a-z0-9._-]{0,63}$"#)
  private static let tagKey = try! NSRegularExpression(pattern: #"^[a-z][a-z0-9._-]{0,31}$"#)
  private static let correlationID = try! NSRegularExpression(pattern: #"^[A-Za-z0-9._~-]{8,128}$"#)

  static func matches(_ value: String, pattern: ConnectArtifactConstraintPattern) -> Bool {
    let regex: NSRegularExpression
    switch pattern {
    case .scopeName:
      regex = scopeName
    case .tagKey:
      regex = tagKey
    case .correlationID:
      regex = correlationID
    }
    let range = NSRange(value.startIndex..<value.endIndex, in: value)
    guard let match = regex.firstMatch(in: value, range: range) else { return false }
    return match.range == range
  }
}

private func rejectUnknownFields(
  _ container: KeyedDecodingContainer<AnyCodingKey>,
  allowed: Set<String>,
  kind: String
) throws {
  for key in container.allKeys where !allowed.contains(key.stringValue) {
    throw DecodingError.dataCorruptedError(
      forKey: key,
      in: container,
      debugDescription: "bad \(kind).\(key.stringValue)"
    )
  }
}

extension CaseIterable where Self: CodingKey {
  fileprivate static var allowedKeys: Set<String> {
    Set(allCases.map(\.stringValue))
  }
}

private struct AnyCodingKey: CodingKey {
  var stringValue: String
  var intValue: Int?

  init?(stringValue: String) {
    self.stringValue = stringValue
    self.intValue = nil
  }

  init?(intValue: Int) {
    self.stringValue = "\(intValue)"
    self.intValue = intValue
  }
}

public typealias ConnectScopeResolver = @Sendable (ScopeMetadataEntry) async throws -> Void

public typealias ConnectScopeResolverMap = [String: ConnectScopeResolver]

public struct ConnectOptions: Sendable {
  public var origin: String?
  public var connectTimeout: Duration
  public var handshakeTimeout: Duration
  public var transportSecurityPolicy: TransportSecurityPolicy
  public var onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)?
  public var onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
  public var outboundRecordChunkBytes: Int
  public var maxOutboundBufferedBytes: Int
  public var yamuxLimits: YamuxLimits
  public var liveness: LivenessOptions
  public var scopeResolvers: ConnectScopeResolverMap
  public var relaxedOptionalScopeValidation: Bool

  public init(
    origin: String? = nil,
    connectTimeout: Duration = FlowersecSDKDefaults.Transport.connectTimeout,
    transportSecurityPolicy: TransportSecurityPolicy = .requireTLS,
    onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)? = nil,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    yamuxLimits: YamuxLimits = YamuxLimits(),
    liveness: LivenessOptions = .pathDefault
  ) {
    self.init(
      origin: origin,
      connectTimeout: connectTimeout,
      handshakeTimeout: FlowersecSDKDefaults.Transport.handshakeTimeout,
      transportSecurityPolicy: transportSecurityPolicy,
      onTransportSecurityDiagnostic: onTransportSecurityDiagnostic,
      onDiagnosticEvent: onDiagnosticEvent,
      outboundRecordChunkBytes: outboundRecordChunkBytes,
      maxOutboundBufferedBytes: FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes,
      yamuxLimits: yamuxLimits,
      liveness: liveness
    )
  }

  public init(
    origin: String? = nil,
    connectTimeout: Duration = FlowersecSDKDefaults.Transport.connectTimeout,
    handshakeTimeout: Duration,
    transportSecurityPolicy: TransportSecurityPolicy = .requireTLS,
    onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)? = nil,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    maxOutboundBufferedBytes: Int = FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes,
    yamuxLimits: YamuxLimits = YamuxLimits(),
    liveness: LivenessOptions = .pathDefault
  ) {
    self.origin = origin
    self.connectTimeout = connectTimeout
    self.handshakeTimeout = handshakeTimeout
    self.transportSecurityPolicy = transportSecurityPolicy
    self.onTransportSecurityDiagnostic = onTransportSecurityDiagnostic
    self.onDiagnosticEvent = onDiagnosticEvent
    self.outboundRecordChunkBytes = outboundRecordChunkBytes
    self.maxOutboundBufferedBytes = maxOutboundBufferedBytes
    self.yamuxLimits = yamuxLimits
    self.liveness = liveness
    self.scopeResolvers = [:]
    self.relaxedOptionalScopeValidation = false
  }

  public init(
    origin: String? = nil,
    connectTimeout: Duration = FlowersecSDKDefaults.Transport.connectTimeout,
    transportSecurityPolicy: TransportSecurityPolicy = .requireTLS,
    onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)? = nil,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    maxOutboundBufferedBytes: Int,
    yamuxLimits: YamuxLimits = YamuxLimits(),
    liveness: LivenessOptions = .pathDefault
  ) {
    self.init(
      origin: origin,
      connectTimeout: connectTimeout,
      handshakeTimeout: FlowersecSDKDefaults.Transport.handshakeTimeout,
      transportSecurityPolicy: transportSecurityPolicy,
      onTransportSecurityDiagnostic: onTransportSecurityDiagnostic,
      onDiagnosticEvent: onDiagnosticEvent,
      outboundRecordChunkBytes: outboundRecordChunkBytes,
      maxOutboundBufferedBytes: maxOutboundBufferedBytes,
      yamuxLimits: yamuxLimits,
      liveness: liveness
    )
  }

  public init(
    origin: String? = nil,
    connectTimeout: Duration = FlowersecSDKDefaults.Transport.connectTimeout,
    handshakeTimeout: Duration = FlowersecSDKDefaults.Transport.handshakeTimeout,
    transportSecurityPolicy: TransportSecurityPolicy = .requireTLS,
    onTransportSecurityDiagnostic: (@Sendable (TransportSecurityDiagnostic) -> Void)? = nil,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    maxOutboundBufferedBytes: Int = FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes,
    yamuxLimits: YamuxLimits = YamuxLimits(),
    liveness: LivenessOptions = .pathDefault,
    scopeResolvers: ConnectScopeResolverMap,
    relaxedOptionalScopeValidation: Bool = false
  ) {
    self.init(
      origin: origin,
      connectTimeout: connectTimeout,
      handshakeTimeout: handshakeTimeout,
      transportSecurityPolicy: transportSecurityPolicy,
      onTransportSecurityDiagnostic: onTransportSecurityDiagnostic,
      onDiagnosticEvent: onDiagnosticEvent,
      outboundRecordChunkBytes: outboundRecordChunkBytes,
      maxOutboundBufferedBytes: maxOutboundBufferedBytes,
      yamuxLimits: yamuxLimits,
      liveness: liveness
    )
    self.scopeResolvers = scopeResolvers
    self.relaxedOptionalScopeValidation = relaxedOptionalScopeValidation
  }
}

public typealias DirectConnectOptions = ConnectOptions
public typealias TunnelConnectOptions = ConnectOptions

public struct FlowersecError: LocalizedError, Equatable, Sendable {
  public var path: FlowersecPath
  public var stage: FlowersecStage
  public var code: FlowersecCode
  public var message: String

  public init(
    path: FlowersecPath,
    stage: FlowersecStage,
    code: FlowersecCode,
    message: String
  ) {
    self.path = path
    self.stage = stage
    self.code = code
    self.message = message
  }

  public var errorDescription: String? { message }
}

extension FlowersecError {
  public static func invalidConnectInfo(
    _ message: String,
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .validate, code: .invalidInput, message: message)
  }

  public static func invalidHandshake(
    _ message: String,
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .handshake, code: .handshakeFailed, message: message)
  }

  public static func invalidRecord(
    _ message: String,
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .secure, code: .invalidInput, message: message)
  }

  public static func invalidYamux(
    _ message: String,
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .yamux, code: .muxFailed, message: message)
  }

  public static func resourceExhausted(
    path: FlowersecPath = .direct,
    stage: FlowersecStage,
    _ message: String
  ) -> FlowersecError {
    FlowersecError(path: path, stage: stage, code: .resourceExhausted, message: message)
  }

  public static func livenessTimeout(
    _ message: String = "The yamux liveness probe timed out.",
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .yamux, code: .timeout, message: message)
  }

  public static func invalidRPC(
    _ message: String,
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .rpc, code: .rpcFailed, message: message)
  }

  static func missingStreamKind(path: FlowersecPath) -> FlowersecError {
    FlowersecError(
      path: path,
      stage: .rpc,
      code: .missingStreamKind,
      message: "Stream kind is empty."
    )
  }

  public static func webSocket(
    _ message: String,
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .connect, code: .dialFailed, message: message)
  }

  public static let closed = FlowersecError(
    path: .direct,
    stage: .close,
    code: .notConnected,
    message: "The Flowersec session closed."
  )

  public static let timeout = FlowersecError(
    path: .direct,
    stage: .connect,
    code: .timeout,
    message: "The Flowersec request timed out."
  )

  public static func closed(path: FlowersecPath = .direct) -> FlowersecError {
    FlowersecError(
      path: path,
      stage: .close,
      code: .notConnected,
      message: "The Flowersec session closed."
    )
  }

  public static func timeout(
    path: FlowersecPath = .direct,
    stage: FlowersecStage = .connect,
    message: String = "The Flowersec request timed out."
  ) -> FlowersecError {
    FlowersecError(path: path, stage: stage, code: .timeout, message: message)
  }

  func withPath(_ path: FlowersecPath) -> FlowersecError {
    var error = self
    error.path = path
    return error
  }
}

enum FlowersecWire {
  static let handshakeMagic = Data("FSEH".utf8)
  static let recordMagic = Data("FSEC".utf8)
  static let protocolVersion: UInt8 = 1
  static let handshakeTypeInit: UInt8 = 1
  static let handshakeTypeResp: UInt8 = 2
  static let handshakeTypeAck: UInt8 = 3
  static let suiteX25519HKDFAES256GCM = 1
  static let suiteP256HKDFAES256GCM = 2
  static let maxHandshakePayloadBytes = FlowersecSDKDefaults.E2EE.maxHandshakePayloadBytes
  static let maxRecordBytes = FlowersecSDKDefaults.E2EE.maxRecordBytes
  static let jsonFrameMaxBytes = FlowersecSDKDefaults.RPC.maxJSONFrameBytes
}

struct FlowersecSessionKeys: Sendable {
  var c2sKey: Data
  var s2cKey: Data
  var c2sNoncePrefix: Data
  var s2cNoncePrefix: Data
  var rekeyBase: Data
  var transcript: Data
}

struct FlowersecRecordKeyState: Sendable {
  var sendKey: Data
  var recvKey: Data
  var sendNoncePrefix: Data
  var recvNoncePrefix: Data
  var rekeyBase: Data
  var transcript: Data
  var sendDirection: UInt8
  var recvDirection: UInt8
  var sendSeq: UInt64
  var recvSeq: UInt64
}
