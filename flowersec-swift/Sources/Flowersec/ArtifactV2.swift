import Crypto
import Foundation

public enum ArtifactCodecErrorV2: Error, Equatable, Sendable {
  case artifactTooLarge
  case invalidArtifact
  case invalidCandidate
}

/// An opaque, validated Flowersec Transport v2 artifact.
///
/// Wire credentials are intentionally unavailable to application code. Pass this
/// handle to Flowersec session APIs instead of inspecting or serializing it.
public final class ArtifactV2: @unchecked Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  fileprivate let value: ArtifactWireV2

  fileprivate init(value: ArtifactWireV2) { self.value = value }

  public var description: String { "Flowersec.ArtifactV2(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

/// Parses and fully validates a Transport v2 artifact without exposing its wire fields.
public func parseArtifactV2(_ data: Data) throws -> ArtifactV2 {
  try ArtifactCodecV2.decode(data)
}

public enum ArtifactLeaseErrorV2: Error, Equatable, Sendable {
  case alreadyCommitted
}

/// Binds an artifact to the caller-owned durable single-use record.
///
/// `commitSpend` must durably publish SPENT before it returns successfully. A
/// connector must call it before writing the first credential-bearing byte.
public struct ArtifactLeaseV2: Sendable {
  public let artifact: ArtifactV2
  private let state: ArtifactLeaseStateV2

  public init(artifact: ArtifactV2, commitSpend: @escaping @Sendable () async throws -> Void) {
    self.artifact = artifact
    self.state = ArtifactLeaseStateV2(spend: commitSpend)
  }

  public func commitSpend() async throws { try await state.commit() }
}

private actor ArtifactLeaseStateV2 {
  private enum State {
    case idle
    case committing(UInt64, Task<Void, Error>)
    case committed
  }

  private let spend: @Sendable () async throws -> Void
  private var state: State = .idle
  private var nextAttempt: UInt64 = 0

  init(spend: @escaping @Sendable () async throws -> Void) { self.spend = spend }

  func commit() async throws {
    let attempt: UInt64
    let task: Task<Void, Error>
    switch state {
    case .committed:
      throw ArtifactLeaseErrorV2.alreadyCommitted
    case .committing(let existingAttempt, let existingTask):
      attempt = existingAttempt
      task = existingTask
    case .idle:
      nextAttempt &+= 1
      attempt = nextAttempt
      task = Task { try await spend() }
      state = .committing(attempt, task)
    }

    do {
      try await task.value
      finish(attempt: attempt, succeeded: true)
    } catch {
      finish(attempt: attempt, succeeded: false)
      throw error
    }
  }

  private func finish(attempt: UInt64, succeeded: Bool) {
    guard case .committing(let activeAttempt, _) = state, activeAttempt == attempt else { return }
    state = succeeded ? .committed : .idle
  }
}

private enum ArtifactCodecV2 {
  static let maxBytes = 65_536

  static func decode(_ data: Data) throws -> ArtifactV2 {
    guard data.count <= maxBytes else { throw ArtifactCodecErrorV2.artifactTooLarge }
    do {
      try JSONDuplicateKeyScannerV2.validate(data)
      guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw ArtifactCodecErrorV2.invalidArtifact
      }
      try exact(root, ["v", "profile", "session", "path", "scoped", "correlation"])
      try validateShapes(root)
      let value = try JSONDecoder().decode(ArtifactWireV2.self, from: data)
      try validate(value)
      return ArtifactV2(value: value)
    } catch let error as ArtifactCodecErrorV2 {
      throw error
    } catch {
      throw ArtifactCodecErrorV2.invalidArtifact
    }
  }

  private static func validateShapes(_ root: [String: Any]) throws {
    guard
      let session = root["session"] as? [String: Any],
      let path = root["path"] as? [String: Any],
      let scopes = root["scoped"] as? [[String: Any]],
      let correlation = root["correlation"] as? [String: Any],
      let candidates = path["candidates"] as? [[String: Any]],
      let tags = correlation["tags"] as? [[String: Any]]
    else { throw ArtifactCodecErrorV2.invalidArtifact }
    try exact(session, [
      "channel_id", "init_expire_at_unix_s", "idle_timeout_seconds",
      "establish_timeout_seconds", "rekey_prepare_timeout_seconds",
      "rekey_completion_timeout_seconds", "max_inbound_streams", "e2ee_psk_b64u",
      "allowed_suites", "default_suite", "selected_features", "contract_hash_b64u",
    ])
    guard let kind = path["kind"] as? String else { throw ArtifactCodecErrorV2.invalidArtifact }
    if kind == "direct" {
      try exact(path, ["kind", "rendezvous_group_id", "listener_audience", "routing_token", "candidates"])
    } else if kind == "tunnel" {
      try exact(path, [
        "kind", "rendezvous_group_id", "listener_audience", "role",
        "local_endpoint_instance_id", "expected_peer_endpoint_instance_id", "token", "candidates",
      ])
    } else { throw ArtifactCodecErrorV2.invalidArtifact }
    for candidate in candidates { try exact(candidate, ["id", "carrier", "url", "wire_profile"]) }
    for scope in scopes { try exact(scope, ["scope", "scope_version", "critical", "payload"]) }
    try exact(correlation, ["v", "tags"])
    for tag in tags { try exact(tag, ["key", "value"]) }
  }

  private static func exact(_ object: [String: Any], _ keys: Set<String>) throws {
    guard Set(object.keys) == keys else { throw ArtifactCodecErrorV2.invalidArtifact }
  }

  private static func validate(_ artifact: ArtifactWireV2) throws {
    guard artifact.v == 2, artifact.profile == "flowersec/2" else {
      throw ArtifactCodecErrorV2.invalidArtifact
    }
    let session = artifact.session
    guard
      registry(session.channelID, max: 128), session.initExpireAtUnixSeconds > 0,
      session.establishTimeoutSeconds == 30, session.rekeyPrepareTimeoutSeconds == 10,
      session.rekeyCompletionTimeoutSeconds == 30,
      (1...128).contains(session.maxInboundStreams), session.selectedFeatures == 0,
      canonical32(session.e2eePSKBase64URL) != nil,
      canonical32(session.contractHashBase64URL) != nil,
      !session.allowedSuites.isEmpty,
      session.allowedSuites == session.allowedSuites.sorted(),
      Set(session.allowedSuites).count == session.allowedSuites.count,
      session.allowedSuites.allSatisfy({ $0 == 1 || $0 == 2 }),
      session.allowedSuites.contains(session.defaultSuite)
    else { throw ArtifactCodecErrorV2.invalidArtifact }

    let canonicalSession: [String: Any] = [
      "allowed_suites": session.allowedSuites, "channel_id": session.channelID,
      "default_suite": session.defaultSuite,
      "establish_timeout_seconds": session.establishTimeoutSeconds,
      "idle_timeout_seconds": session.idleTimeoutSeconds,
      "max_inbound_streams": session.maxInboundStreams, "profile": "flowersec/2",
      "rekey_completion_timeout_seconds": session.rekeyCompletionTimeoutSeconds,
      "rekey_prepare_timeout_seconds": session.rekeyPrepareTimeoutSeconds,
      "selected_features": session.selectedFeatures,
    ]
    let canonical = try JSONSerialization.data(withJSONObject: canonicalSession, options: [.sortedKeys, .withoutEscapingSlashes])
    var preimage = Data("flowersec-v2-session-contract\0".utf8)
    preimage.append(contentsOf: withUnsafeBytes(of: UInt32(canonical.count).bigEndian, Array.init))
    preimage.append(canonical)
    let expected = Data(SHA256.hash(data: preimage)).base64URLEncodedStringV2()
    guard expected == session.contractHashBase64URL else { throw ArtifactCodecErrorV2.invalidArtifact }

    let path = artifact.path
    guard registry(path.rendezvousGroupID, max: 128), registry(path.listenerAudience, max: 128),
      (1...4).contains(path.candidates.count)
    else { throw ArtifactCodecErrorV2.invalidCandidate }
    switch path.kind {
    case "direct":
      guard ascii(path.routingToken ?? "", max: 8_192) else { throw ArtifactCodecErrorV2.invalidArtifact }
    case "tunnel":
      guard (path.role == 1 || path.role == 2),
        registry(path.localEndpointInstanceID ?? "", max: 128),
        registry(path.expectedPeerEndpointInstanceID ?? "", max: 128),
        path.localEndpointInstanceID != path.expectedPeerEndpointInstanceID,
        ascii(path.token ?? "", max: 8_192)
      else { throw ArtifactCodecErrorV2.invalidArtifact }
    default: throw ArtifactCodecErrorV2.invalidArtifact
    }
    var ids = Set<String>()
    for candidate in path.candidates {
      guard candidate.id.range(of: "^[a-z0-9][a-z0-9._-]*$", options: .regularExpression) != nil,
        candidate.id.utf8.count <= 64, ids.insert(candidate.id).inserted,
        ["websocket", "raw_quic", "webtransport"].contains(candidate.carrier),
        candidate.wireProfile == "flowersec-\(path.kind)/2",
        validCandidateURL(candidate, kind: path.kind)
      else { throw ArtifactCodecErrorV2.invalidCandidate }
    }
    guard artifact.scoped.count <= 8 else { throw ArtifactCodecErrorV2.invalidArtifact }
    var scopeNames = Set<String>()
    for scope in artifact.scoped {
      guard scope.scope.range(of: "^[a-z][a-z0-9._-]{0,63}$", options: .regularExpression) != nil,
        scope.scopeVersion > 0, scopeNames.insert(scope.scope).inserted,
        try JSONEncoder().encode(scope.payload).count <= 4_096
      else { throw ArtifactCodecErrorV2.invalidArtifact }
    }
    guard artifact.correlation.v == 2, artifact.correlation.tags.count <= 8 else {
      throw ArtifactCodecErrorV2.invalidArtifact
    }
    var tagNames = Set<String>()
    for tag in artifact.correlation.tags {
      guard tag.key.range(of: "^[a-z][a-z0-9._-]{0,31}$", options: .regularExpression) != nil,
        tagNames.insert(tag.key).inserted, ascii(tag.value, max: 128)
      else { throw ArtifactCodecErrorV2.invalidArtifact }
    }
  }

  private static func canonical32(_ value: String) -> Data? {
    guard !value.contains("="), let data = Data(base64URLEncodedV2: value), data.count == 32,
      data.base64URLEncodedStringV2() == value else { return nil }
    return data
  }

  private static func registry(_ value: String, max: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= max
      && value.range(of: "^[A-Za-z0-9._~-]+$", options: .regularExpression) != nil
  }

  private static func ascii(_ value: String, max: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= max && value.unicodeScalars.allSatisfy { $0.value <= 0x7f }
  }

  private static func validCandidateURL(_ candidate: CandidateWireV2, kind: String) -> Bool {
    guard candidate.url.utf8.count <= 2_048, !candidate.url.contains(where: { "\\?#%".contains($0) }),
      let components = URLComponents(string: candidate.url), components.user == nil,
      components.password == nil, components.host != nil else { return false }
    let scheme = components.scheme?.lowercased()
    switch candidate.carrier {
    case "websocket": return scheme == "wss" && components.path == "/flowersec/v2/\(kind)"
    case "raw_quic": return scheme == "quic" && (components.path.isEmpty || components.path == "/")
    case "webtransport": return scheme == "https" && components.path == "/flowersec/webtransport/v2/\(kind)"
    default: return false
    }
  }
}

private struct ArtifactWireV2: Decodable, Sendable {
  let v: Int; let profile: String; let session: SessionWireV2; let path: PathWireV2
  let scoped: [ScopeWireV2]; let correlation: CorrelationWireV2
}
private struct SessionWireV2: Decodable, Sendable {
  let channelID: String; let initExpireAtUnixSeconds: Int64; let idleTimeoutSeconds: UInt32
  let establishTimeoutSeconds: UInt16; let rekeyPrepareTimeoutSeconds: UInt16
  let rekeyCompletionTimeoutSeconds: UInt16; let maxInboundStreams: UInt16
  let e2eePSKBase64URL: String; let allowedSuites: [UInt16]; let defaultSuite: UInt16
  let selectedFeatures: UInt32; let contractHashBase64URL: String
  enum CodingKeys: String, CodingKey {
    case channelID = "channel_id"; case initExpireAtUnixSeconds = "init_expire_at_unix_s"
    case idleTimeoutSeconds = "idle_timeout_seconds"; case establishTimeoutSeconds = "establish_timeout_seconds"
    case rekeyPrepareTimeoutSeconds = "rekey_prepare_timeout_seconds"
    case rekeyCompletionTimeoutSeconds = "rekey_completion_timeout_seconds"
    case maxInboundStreams = "max_inbound_streams"; case e2eePSKBase64URL = "e2ee_psk_b64u"
    case allowedSuites = "allowed_suites"; case defaultSuite = "default_suite"
    case selectedFeatures = "selected_features"; case contractHashBase64URL = "contract_hash_b64u"
  }
}
private struct PathWireV2: Decodable, Sendable {
  let kind: String; let rendezvousGroupID: String; let listenerAudience: String
  let routingToken: String?; let role: UInt8?; let localEndpointInstanceID: String?
  let expectedPeerEndpointInstanceID: String?; let token: String?; let candidates: [CandidateWireV2]
  enum CodingKeys: String, CodingKey {
    case kind; case rendezvousGroupID = "rendezvous_group_id"; case listenerAudience = "listener_audience"
    case routingToken = "routing_token"; case role; case localEndpointInstanceID = "local_endpoint_instance_id"
    case expectedPeerEndpointInstanceID = "expected_peer_endpoint_instance_id"; case token; case candidates
  }
}
private struct CandidateWireV2: Decodable, Sendable {
  let id: String; let carrier: String; let url: String; let wireProfile: String
  enum CodingKeys: String, CodingKey { case id, carrier, url; case wireProfile = "wire_profile" }
}
private struct ScopeWireV2: Decodable, Sendable {
  let scope: String; let scopeVersion: UInt16; let critical: Bool; let payload: [String: ArtifactJSONValueV2]
  enum CodingKeys: String, CodingKey { case scope; case scopeVersion = "scope_version"; case critical, payload }
}
private struct CorrelationWireV2: Decodable, Sendable { let v: Int; let tags: [TagWireV2] }
private struct TagWireV2: Decodable, Sendable { let key: String; let value: String }
private indirect enum ArtifactJSONValueV2: Codable, Sendable {
  case null, bool(Bool), number(Double), string(String), array([ArtifactJSONValueV2]), object([String: ArtifactJSONValueV2])
  init(from decoder: Decoder) throws {
    let c = try decoder.singleValueContainer()
    if c.decodeNil() { self = .null } else if let v = try? c.decode(Bool.self) { self = .bool(v) }
    else if let v = try? c.decode(Double.self) { self = .number(v) }
    else if let v = try? c.decode(String.self) { self = .string(v) }
    else if let v = try? c.decode([ArtifactJSONValueV2].self) { self = .array(v) }
    else { self = .object(try c.decode([String: ArtifactJSONValueV2].self)) }
  }
  func encode(to encoder: Encoder) throws {
    var c = encoder.singleValueContainer()
    switch self {
    case .null: try c.encodeNil()
    case .bool(let v): try c.encode(v)
    case .number(let v): try c.encode(v)
    case .string(let v): try c.encode(v)
    case .array(let v): try c.encode(v)
    case .object(let v): try c.encode(v)
    }
  }
}

private enum JSONDuplicateKeyScannerV2 {
  static func validate(_ data: Data) throws {
    guard let text = String(data: data, encoding: .utf8) else { throw ArtifactCodecErrorV2.invalidArtifact }
    var parser = Parser(bytes: Array(text.utf8)); try parser.value(); parser.space()
    guard parser.index == parser.bytes.count else { throw ArtifactCodecErrorV2.invalidArtifact }
  }
  private struct Parser {
    let bytes: [UInt8]; var index = 0
    mutating func space() { while index < bytes.count && [9,10,13,32].contains(bytes[index]) { index += 1 } }
    mutating func value() throws {
      space(); guard index < bytes.count else { throw ArtifactCodecErrorV2.invalidArtifact }
      switch bytes[index] { case 123: try object(); case 91: try array(); case 34: _ = try string()
      default: try scalar() }
    }
    mutating func object() throws {
      index += 1; space(); var keys = Set<String>()
      if take(125) { return }
      while true { space(); let key = try string(); guard keys.insert(key).inserted else { throw ArtifactCodecErrorV2.invalidArtifact }
        space(); guard take(58) else { throw ArtifactCodecErrorV2.invalidArtifact }; try value(); space()
        if take(125) { return }; guard take(44) else { throw ArtifactCodecErrorV2.invalidArtifact }
      }
    }
    mutating func array() throws { index += 1; space(); if take(93) { return }; while true { try value(); space(); if take(93) { return }; guard take(44) else { throw ArtifactCodecErrorV2.invalidArtifact } } }
    mutating func string() throws -> String {
      guard take(34) else { throw ArtifactCodecErrorV2.invalidArtifact }; let start = index
      while index < bytes.count { if bytes[index] == 34 { var quoted = Data([34]); quoted.append(contentsOf: bytes[start..<index]); quoted.append(34); index += 1; guard let value = try? JSONDecoder().decode(String.self, from: quoted) else { throw ArtifactCodecErrorV2.invalidArtifact }; return value }
        if bytes[index] == 92 { index += 2 } else { index += 1 } }
      throw ArtifactCodecErrorV2.invalidArtifact
    }
    mutating func scalar() throws { let start = index; while index < bytes.count && ![44,93,125,9,10,13,32].contains(bytes[index]) { index += 1 }; guard index > start else { throw ArtifactCodecErrorV2.invalidArtifact } }
    mutating func take(_ byte: UInt8) -> Bool { guard index < bytes.count, bytes[index] == byte else { return false }; index += 1; return true }
  }
}

private extension Data {
  init?(base64URLEncodedV2 value: String) {
    var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    text += String(repeating: "=", count: (4 - text.count % 4) % 4)
    self.init(base64Encoded: text)
  }
  func base64URLEncodedStringV2() -> String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}
