import Crypto
import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

public enum ArtifactErrorV3: Error, Equatable, Sendable {
  case artifactTooLarge
  case invalidArtifact
}

/// An opaque, fully validated Flowersec v3 artifact.
public final class ArtifactV3: @unchecked Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  let value: ArtifactWireV3
  let canonicalJSON: Data
  let canonicalCandidates: [CanonicalCandidateV3]
  let candidateSetJSON: Data
  let candidateSetHash: Data

  fileprivate init(
    value: ArtifactWireV3,
    canonicalJSON: Data,
    canonicalCandidates: [CanonicalCandidateV3],
    candidateSetJSON: Data,
    candidateSetHash: Data
  ) {
    self.value = value
    self.canonicalJSON = canonicalJSON
    self.canonicalCandidates = canonicalCandidates
    self.candidateSetJSON = candidateSetJSON
    self.candidateSetHash = candidateSetHash
  }

  func filteredForController(candidateIDs: Set<String>) -> ArtifactV3 {
    ArtifactV3(
      value: value,
      canonicalJSON: canonicalJSON,
      canonicalCandidates: canonicalCandidates.filter { candidateIDs.contains($0.id) },
      candidateSetJSON: candidateSetJSON,
      candidateSetHash: candidateSetHash
    )
  }

  public var description: String { "Flowersec.ArtifactV3(<redacted>)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

/// Parses the strict JCS Flowersec v3 wire contract without exposing credentials.
public func parseArtifactV3(_ data: Data) throws -> ArtifactV3 {
  try ArtifactCodecV3.decode(data)
}

/// The unversioned artifact surface is the strict v3 wire contract.
public typealias Artifact = ArtifactV3
public typealias ArtifactError = ArtifactErrorV3

public func parseArtifact(_ data: Data) throws -> Artifact {
  try parseArtifactV3(data)
}

public enum ArtifactLeaseErrorV3: Error, Equatable, Sendable {
  case unavailable
}

/// A copyable handle backed by one shared, atomic v3 lease state.
public struct ArtifactLeaseV3: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  let artifact: ArtifactV3
  private let state: ArtifactLeaseStateV3
  private let controllerCapability: ControllerLeaseCapabilityV3?

  public init(
    artifact: ArtifactV3,
    commitSpend: @escaping @Sendable () async throws -> Void,
    retire: @escaping @Sendable () async throws -> Void = {}
  ) {
    self.artifact = artifact
    self.state = ArtifactLeaseStateV3(spend: commitSpend, retire: retire)
    self.controllerCapability = nil
  }

  fileprivate init(
    artifact: ArtifactV3,
    state: ArtifactLeaseStateV3,
    controllerCapability: ControllerLeaseCapabilityV3
  ) {
    self.artifact = artifact
    self.state = state
    self.controllerCapability = controllerCapability
  }

  public var description: String { "Flowersec.ArtifactLeaseV3(<redacted>)" }
  public var debugDescription: String { description }

  func claim() async throws -> ClaimedArtifactLeaseV3 {
    try await state.claim(controllerCapability: controllerCapability)
    return ClaimedArtifactLeaseV3(artifact: artifact, state: state)
  }

  func claimForConnectionController() async throws -> ClaimedArtifactLeaseV3 {
    let capability = ControllerLeaseCapabilityV3()
    try await state.claimForConnectionController(capability: capability)
    return ClaimedArtifactLeaseV3(
      artifact: artifact, state: state, controllerCapability: capability)
  }
}

public typealias ArtifactLease = ArtifactLeaseV3
public typealias ArtifactLeaseError = ArtifactLeaseErrorV3

struct ClaimedArtifactLeaseV3: Sendable {
  let artifact: ArtifactV3
  fileprivate let state: ArtifactLeaseStateV3
  fileprivate let controllerCapability: ControllerLeaseCapabilityV3?

  fileprivate init(
    artifact: ArtifactV3,
    state: ArtifactLeaseStateV3,
    controllerCapability: ControllerLeaseCapabilityV3? = nil
  ) {
    self.artifact = artifact
    self.state = state
    self.controllerCapability = controllerCapability
  }

  func commitSpend() async throws { try await state.commitSpend() }
  func retire() async throws { try await state.retire() }
  var isConsumed: Bool { get async { await state.isConsumed } }
  var isSpending: Bool { get async { await state.isSpending } }

  func connectorLease() -> ArtifactLeaseV3 {
    connectorLease(artifact: artifact)
  }

  func connectorLease(artifact: ArtifactV3) -> ArtifactLeaseV3 {
    precondition(controllerCapability != nil)
    return ArtifactLeaseV3(
      artifact: artifact, state: state, controllerCapability: controllerCapability!)
  }
}

private final class ControllerLeaseCapabilityV3: @unchecked Sendable {}

private actor ArtifactLeaseStateV3 {
  private enum State { case idle, claimed, spending, consumed, retired }

  private let spend: @Sendable () async throws -> Void
  private let cleanup: @Sendable () async throws -> Void
  private var state = State.idle
  private var controllerCapability: ObjectIdentifier?
  private var controllerCapabilityUsed = false

  init(
    spend: @escaping @Sendable () async throws -> Void,
    retire: @escaping @Sendable () async throws -> Void
  ) {
    self.spend = spend
    self.cleanup = retire
  }

  func claim(controllerCapability: ControllerLeaseCapabilityV3?) throws {
    if let controllerCapability {
      guard state == .claimed,
        self.controllerCapability == ObjectIdentifier(controllerCapability),
        !controllerCapabilityUsed
      else { throw ArtifactLeaseErrorV3.unavailable }
      controllerCapabilityUsed = true
    } else {
      guard state == .idle else { throw ArtifactLeaseErrorV3.unavailable }
      state = .claimed
    }
  }

  func claimForConnectionController(capability: ControllerLeaseCapabilityV3) throws {
    guard state == .idle else { throw ArtifactLeaseErrorV3.unavailable }
    state = .claimed
    controllerCapability = ObjectIdentifier(capability)
  }

  var isConsumed: Bool { state == .consumed }

  var isSpending: Bool { state == .spending }

  func commitSpend() async throws {
    guard state == .claimed else { throw ArtifactLeaseErrorV3.unavailable }
    state = .spending

    let completion = ArtifactSpendCompletionV3()
    let spend = self.spend
    let callback = Task.detached(priority: Task.currentPriority) {
      let result: Result<Void, Error>
      do {
        result = .success(try await spend())
      } catch {
        result = .failure(error)
      }
      completion.resolve(result)
    }
    do {
      try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          completion.install(continuation)
        }
      } onCancel: {
        callback.cancel()
        completion.resolve(.failure(CancellationError()))
      }
      state = .consumed
    } catch {
      state = .consumed
      throw error
    }
  }

  func retire() async throws {
    guard state == .claimed else { throw ArtifactLeaseErrorV3.unavailable }
    state = .retired
    try await cleanup()
  }
}

private final class ArtifactSpendCompletionV3: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Void, Error>?
  private var result: Result<Void, Error>?

  func install(_ continuation: CheckedContinuation<Void, Error>) {
    let resolved = lock.withLock { () -> Result<Void, Error>? in
      if let result { return result }
      self.continuation = continuation
      return nil
    }
    if let resolved { continuation.resume(with: resolved) }
  }

  func resolve(_ result: Result<Void, Error>) {
    var continuation: CheckedContinuation<Void, Error>?
    let won = lock.withLock {
      guard self.result == nil else { return false }
      self.result = result
      continuation = self.continuation
      self.continuation = nil
      return true
    }
    if won { continuation?.resume(with: result) }
  }
}

struct ArtifactWireV3: Decodable, Sendable {
  let v: UInt8
  let profile: String
  let session: SessionWireV3
  let path: PathWireV3
  let scoped: [ScopeWireV3]
  let correlation: CorrelationWireV3
}

struct SessionWireV3: Decodable, Sendable {
  let channelID: String
  let initExpireAtUnixSeconds: UInt64
  let idleTimeoutSeconds: UInt64
  let establishTimeoutSeconds: UInt64
  let rekeyPrepareTimeoutSeconds: UInt64
  let rekeyCompletionTimeoutSeconds: UInt64
  let maxInboundStreams: UInt64
  let e2eePSKBase64URL: String
  let allowedSuites: [UInt64]
  let defaultSuite: UInt64
  let selectedFeatures: UInt64
  let contractHashBase64URL: String

  enum CodingKeys: String, CodingKey {
    case channelID = "channel_id"
    case initExpireAtUnixSeconds = "init_expire_at_unix_s"
    case idleTimeoutSeconds = "idle_timeout_seconds"
    case establishTimeoutSeconds = "establish_timeout_seconds"
    case rekeyPrepareTimeoutSeconds = "rekey_prepare_timeout_seconds"
    case rekeyCompletionTimeoutSeconds = "rekey_completion_timeout_seconds"
    case maxInboundStreams = "max_inbound_streams"
    case e2eePSKBase64URL = "e2ee_psk_b64u"
    case allowedSuites = "allowed_suites"
    case defaultSuite = "default_suite"
    case selectedFeatures = "selected_features"
    case contractHashBase64URL = "contract_hash_b64u"
  }
}

struct PathWireV3: Decodable, Sendable {
  let kind: String
  let rendezvousGroupID: String
  let listenerAudience: String
  let routingToken: String?
  let role: UInt64?
  let localEndpointInstanceID: String?
  let expectedPeerEndpointInstanceID: String?
  let token: String?
  let candidates: [CandidateWireV3]

  enum CodingKeys: String, CodingKey {
    case kind
    case rendezvousGroupID = "rendezvous_group_id"
    case listenerAudience = "listener_audience"
    case routingToken = "routing_token"
    case role
    case localEndpointInstanceID = "local_endpoint_instance_id"
    case expectedPeerEndpointInstanceID = "expected_peer_endpoint_instance_id"
    case token, candidates
  }
}

struct CandidateWireV3: Decodable, Sendable {
  let id: String
  let carrier: String
  let url: String
  let wireProfile: String
  let tls: TLSPolicyWireV3

  enum CodingKeys: String, CodingKey {
    case id, carrier, url, tls
    case wireProfile = "wire_profile"
  }
}

struct TLSPolicyWireV3: Decodable, Equatable, Sendable {
  let mode: String
  let pins: [CertificatePinWireV3]?
}

struct CertificatePinWireV3: Decodable, Equatable, Sendable {
  let algorithm: String
  let valueBase64URL: String
  let notAfterUnixSeconds: UInt64

  enum CodingKeys: String, CodingKey {
    case algorithm
    case valueBase64URL = "value_b64u"
    case notAfterUnixSeconds = "not_after_unix_s"
  }
}

struct ScopeWireV3: Decodable, Sendable {
  let scope: String
  let scopeVersion: UInt64
  let critical: Bool
  let payload: [String: JSONValueV3]

  enum CodingKeys: String, CodingKey {
    case scope
    case scopeVersion = "scope_version"
    case critical, payload
  }
}

struct CorrelationWireV3: Decodable, Sendable {
  let v: UInt8
  let tags: [CorrelationTagWireV3]
}

struct CorrelationTagWireV3: Decodable, Sendable {
  let key: String
  let value: String
}

indirect enum JSONValueV3: Decodable, Sendable {
  case null
  case bool(Bool)
  case integer(Int64)
  case string(String)
  case array([JSONValueV3])
  case object([String: JSONValueV3])

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .bool(value)
    } else if let value = try? container.decode(Int64.self) {
      self = .integer(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode([JSONValueV3].self) {
      self = .array(value)
    } else {
      self = .object(try container.decode([String: JSONValueV3].self))
    }
  }
}

struct CanonicalCandidateV3: Equatable, Sendable {
  let carrier: String
  let id: String
  let normalizedURL: String
  let tls: TLSPolicyWireV3
  let wireProfile: String

  func object() -> [String: Any] {
    var tlsObject: [String: Any] = ["mode": tls.mode]
    if let pins = tls.pins {
      tlsObject["pins"] = pins.map {
        [
          "algorithm": $0.algorithm,
          "not_after_unix_s": $0.notAfterUnixSeconds,
          "value_b64u": $0.valueBase64URL,
        ]
      }
    }
    return [
      "carrier": carrier,
      "id": id,
      "normalized_url": normalizedURL,
      "tls": tlsObject,
      "wire_profile": wireProfile,
    ]
  }

  func tlsPolicyDigest() throws -> Data {
    try FlowersecJCSV3.hashLP(domain: "flowersec-v3-tls-policy\0", value: object()["tls"]!)
  }

  func activePinHashes(at unixSeconds: UInt64) throws -> [Data]? {
    switch tls.mode {
    case "ca": return nil
    case "pin":
      let active = try (tls.pins ?? []).filter { unixSeconds < $0.notAfterUnixSeconds }.map {
        guard let value = FlowersecJCSV3.canonical32($0.valueBase64URL) else {
          throw ArtifactErrorV3.invalidArtifact
        }
        return value
      }
      guard !active.isEmpty else { throw TransportSecurityFailureV3.tlsPolicyExpired }
      return active
    default: throw ArtifactErrorV3.invalidArtifact
    }
  }
}

enum ArtifactCodecV3 {
  static let maximumSafeInteger: UInt64 = 9_007_199_254_740_991
  static let maxBytes = 65_536

  static func decode(_ data: Data) throws -> ArtifactV3 {
    guard data.count <= maxBytes else { throw ArtifactErrorV3.artifactTooLarge }
    do {
      try JSONPreflightV3.validateArtifact(data)
      let rawRoot = try JSONSerialization.jsonObject(with: data)
      guard let root = rawRoot as? [String: Any], try FlowersecJCSV3.encode(rawRoot) == data else {
        throw ArtifactErrorV3.invalidArtifact
      }
      try validateShapes(root)
      let value = try JSONDecoder().decode(ArtifactWireV3.self, from: data)
      let candidates = try validate(value, rawRoot: root)
      let candidateObjects = candidates.map { $0.object() }
      let candidateJSON = try FlowersecJCSV3.encode(candidateObjects)
      guard candidateJSON.count <= 12_288 else { throw ArtifactErrorV3.invalidArtifact }
      let candidateHash = FlowersecJCSV3.hashLP(
        domain: TransportV3Contract.candidatesLabel, canonical: candidateJSON)
      return ArtifactV3(
        value: value,
        canonicalJSON: data,
        canonicalCandidates: candidates,
        candidateSetJSON: candidateJSON,
        candidateSetHash: candidateHash
      )
    } catch let error as ArtifactErrorV3 {
      throw error
    } catch {
      throw ArtifactErrorV3.invalidArtifact
    }
  }

  private static func validateShapes(_ root: [String: Any]) throws {
    try exact(root, ["v", "profile", "session", "path", "scoped", "correlation"])
    guard
      let session = root["session"] as? [String: Any],
      let path = root["path"] as? [String: Any],
      let scopes = root["scoped"] as? [[String: Any]],
      let correlation = root["correlation"] as? [String: Any],
      let candidates = path["candidates"] as? [[String: Any]],
      let tags = correlation["tags"] as? [[String: Any]]
    else { throw ArtifactErrorV3.invalidArtifact }
    try exact(
      session,
      [
        "channel_id", "init_expire_at_unix_s", "idle_timeout_seconds",
        "establish_timeout_seconds", "rekey_prepare_timeout_seconds",
        "rekey_completion_timeout_seconds", "max_inbound_streams", "e2ee_psk_b64u",
        "allowed_suites", "default_suite", "selected_features", "contract_hash_b64u",
      ])
    guard let kind = path["kind"] as? String else { throw ArtifactErrorV3.invalidArtifact }
    if kind == "direct" {
      try exact(
        path, ["kind", "rendezvous_group_id", "listener_audience", "routing_token", "candidates"])
    } else if kind == "tunnel" {
      try exact(
        path,
        [
          "kind", "rendezvous_group_id", "listener_audience", "role",
          "local_endpoint_instance_id", "expected_peer_endpoint_instance_id", "token", "candidates",
        ])
    } else {
      throw ArtifactErrorV3.invalidArtifact
    }
    for candidate in candidates {
      try exact(candidate, ["id", "carrier", "url", "wire_profile", "tls"])
      guard let tls = candidate["tls"] as? [String: Any], let mode = tls["mode"] as? String else {
        throw ArtifactErrorV3.invalidArtifact
      }
      if mode == "ca" {
        try exact(tls, ["mode"])
      } else if mode == "pin", let pins = tls["pins"] as? [[String: Any]] {
        try exact(tls, ["mode", "pins"])
        for pin in pins { try exact(pin, ["algorithm", "not_after_unix_s", "value_b64u"]) }
      } else {
        throw ArtifactErrorV3.invalidArtifact
      }
    }
    for scope in scopes {
      try exact(scope, ["scope", "scope_version", "critical", "payload"])
      guard scope["payload"] is [String: Any] else { throw ArtifactErrorV3.invalidArtifact }
    }
    try exact(correlation, ["v", "tags"])
    for tag in tags { try exact(tag, ["key", "value"]) }
  }

  private static func validate(
    _ artifact: ArtifactWireV3, rawRoot: [String: Any]
  ) throws -> [CanonicalCandidateV3] {
    guard artifact.v == 3, artifact.profile == TransportV3Contract.sessionProfile else {
      throw ArtifactErrorV3.invalidArtifact
    }
    try validateSession(artifact.session)
    let path = artifact.path
    guard registry(path.rendezvousGroupID, max: 128), registry(path.listenerAudience, max: 128),
      (1...4).contains(path.candidates.count)
    else { throw ArtifactErrorV3.invalidArtifact }
    switch path.kind {
    case "direct":
      guard ascii(path.routingToken ?? "", max: 8_192) else {
        throw ArtifactErrorV3.invalidArtifact
      }
    case "tunnel":
      guard path.role == 1 || path.role == 2,
        registry(path.localEndpointInstanceID ?? "", max: 128),
        registry(path.expectedPeerEndpointInstanceID ?? "", max: 128),
        path.localEndpointInstanceID != path.expectedPeerEndpointInstanceID,
        ascii(path.token ?? "", max: 8_192)
      else { throw ArtifactErrorV3.invalidArtifact }
    default: throw ArtifactErrorV3.invalidArtifact
    }

    var ids = Set<String>()
    var endpoints = Set<String>()
    var candidates: [CanonicalCandidateV3] = []
    for candidate in path.candidates {
      guard validCandidateID(candidate.id), ids.insert(candidate.id).inserted,
        ["websocket", "raw_quic", "webtransport"].contains(candidate.carrier),
        candidate.wireProfile == TransportV3Contract.wireProfile(for: path.kind)
      else { throw ArtifactErrorV3.invalidArtifact }
      try validateTLSPolicy(candidate.tls)
      let normalized = try normalizeURL(candidate.url, carrier: candidate.carrier, kind: path.kind)
      let endpoint = candidate.carrier + "\0" + path.kind + "\0" + normalized
      guard endpoints.insert(endpoint).inserted else { throw ArtifactErrorV3.invalidArtifact }
      let canonical = CanonicalCandidateV3(
        carrier: candidate.carrier, id: candidate.id, normalizedURL: normalized,
        tls: candidate.tls, wireProfile: candidate.wireProfile)
      guard try FlowersecJCSV3.encode(canonical.object()).count <= 2_304 else {
        throw ArtifactErrorV3.invalidArtifact
      }
      candidates.append(canonical)
    }
    candidates.sort { $0.id.utf8.lexicographicallyPrecedes($1.id.utf8) }

    guard artifact.scoped.count <= 8,
      let rawScopes = rawRoot["scoped"] as? [[String: Any]],
      rawScopes.count == artifact.scoped.count
    else { throw ArtifactErrorV3.invalidArtifact }
    var scopes = Set<String>()
    for (index, scope) in artifact.scoped.enumerated() {
      guard validLowerID(scope.scope, max: 64), (1...65_535).contains(scope.scopeVersion),
        scopes.insert(scope.scope).inserted,
        let payload = rawScopes[index]["payload"] as? [String: Any],
        try FlowersecJCSV3.encode(payload).count <= 4_096
      else { throw ArtifactErrorV3.invalidArtifact }
      var nodes = 0
      try validateScoped(payload, depth: 1, nodes: &nodes, root: true)
    }

    guard artifact.correlation.v == 3, artifact.correlation.tags.count <= 8 else {
      throw ArtifactErrorV3.invalidArtifact
    }
    var tags = Set<String>()
    for tag in artifact.correlation.tags {
      guard validLowerID(tag.key, max: 32), ascii(tag.value, max: 128),
        tags.insert(tag.key).inserted
      else { throw ArtifactErrorV3.invalidArtifact }
    }
    return candidates
  }

  private static func validateSession(_ session: SessionWireV3) throws {
    guard registry(session.channelID, max: 128),
      (1...maximumSafeInteger).contains(session.initExpireAtUnixSeconds),
      session.idleTimeoutSeconds <= UInt64(UInt32.max), session.establishTimeoutSeconds == 30,
      session.rekeyPrepareTimeoutSeconds == 10, session.rekeyCompletionTimeoutSeconds == 30,
      (1...128).contains(session.maxInboundStreams), session.selectedFeatures == 0,
      FlowersecJCSV3.canonical32(session.e2eePSKBase64URL) != nil,
      FlowersecJCSV3.canonical32(session.contractHashBase64URL) != nil,
      !session.allowedSuites.isEmpty,
      zip(session.allowedSuites, session.allowedSuites.dropFirst()).allSatisfy(<),
      session.allowedSuites.allSatisfy({ $0 == 1 || $0 == 2 }),
      session.allowedSuites.contains(session.defaultSuite)
    else { throw ArtifactErrorV3.invalidArtifact }
    let projection: [String: Any] = [
      "allowed_suites": session.allowedSuites, "channel_id": session.channelID,
      "default_suite": session.defaultSuite,
      "establish_timeout_seconds": session.establishTimeoutSeconds,
      "idle_timeout_seconds": session.idleTimeoutSeconds,
      "max_inbound_streams": session.maxInboundStreams,
      "profile": TransportV3Contract.sessionProfile,
      "rekey_completion_timeout_seconds": session.rekeyCompletionTimeoutSeconds,
      "rekey_prepare_timeout_seconds": session.rekeyPrepareTimeoutSeconds,
      "selected_features": session.selectedFeatures,
    ]
    let expected = try FlowersecJCSV3.hashLP(
      domain: TransportV3Contract.sessionContractLabel, value: projection
    ).base64URLEncodedStringV3()
    guard expected == session.contractHashBase64URL else { throw ArtifactErrorV3.invalidArtifact }
  }

  private static func validateTLSPolicy(_ policy: TLSPolicyWireV3) throws {
    if policy.mode == "ca" {
      guard policy.pins == nil else { throw ArtifactErrorV3.invalidArtifact }
      return
    }
    guard policy.mode == "pin", let pins = policy.pins, (1...4).contains(pins.count) else {
      throw ArtifactErrorV3.invalidArtifact
    }
    for pin in pins {
      guard pin.algorithm == "sha-256", (1...maximumSafeInteger).contains(pin.notAfterUnixSeconds),
        FlowersecJCSV3.canonical32(pin.valueBase64URL) != nil
      else { throw ArtifactErrorV3.invalidArtifact }
    }
    guard
      zip(pins, pins.dropFirst()).allSatisfy({ left, right in
        (left.algorithm, left.valueBase64URL) < (right.algorithm, right.valueBase64URL)
      })
    else { throw ArtifactErrorV3.invalidArtifact }
  }

  private static func validateScoped(
    _ value: Any, depth: Int, nodes: inout Int, root: Bool = false
  ) throws {
    guard depth <= 16 else { throw ArtifactErrorV3.invalidArtifact }
    nodes += 1
    guard nodes <= 256 else { throw ArtifactErrorV3.invalidArtifact }
    switch value {
    case is NSNull, is Bool: return
    case let string as String:
      guard string.utf8.count <= 1_024 else { throw ArtifactErrorV3.invalidArtifact }
    case let number as NSNumber:
      let value = number.doubleValue
      guard value.isFinite, value.rounded(.towardZero) == value,
        value >= -Double(maximumSafeInteger), value <= Double(maximumSafeInteger)
      else { throw ArtifactErrorV3.invalidArtifact }
    case let array as [Any]:
      guard !root, array.count <= 64 else { throw ArtifactErrorV3.invalidArtifact }
      for item in array { try validateScoped(item, depth: depth + 1, nodes: &nodes) }
    case let object as [String: Any]:
      guard object.count <= 64, object.keys.allSatisfy({ $0.utf8.count <= 128 }) else {
        throw ArtifactErrorV3.invalidArtifact
      }
      for item in object.values { try validateScoped(item, depth: depth + 1, nodes: &nodes) }
    default: throw ArtifactErrorV3.invalidArtifact
    }
  }

  static func normalizeURL(_ raw: String, carrier: String, kind: String) throws -> String {
    guard (1...2_048).contains(raw.utf8.count),
      !raw.contains(where: { "\\?#%".contains($0) }),
      let separator = raw.range(of: "://")
    else { throw ArtifactErrorV3.invalidArtifact }
    let rawScheme = String(raw[..<separator.lowerBound])
    let schemeBytes = Array(rawScheme.utf8)
    guard !schemeBytes.isEmpty, asciiAlpha(schemeBytes[0]),
      schemeBytes.allSatisfy({ asciiAlphaNumeric($0) || "+.-".utf8.contains($0) })
    else { throw ArtifactErrorV3.invalidArtifact }
    let scheme = rawScheme.lowercased()
    let remainder = String(raw[separator.upperBound...])
    let slash = remainder.firstIndex(of: "/")
    let authority = slash.map { String(remainder[..<$0]) } ?? remainder
    let path = slash.map { String(remainder[$0...]) } ?? ""
    guard !authority.isEmpty, !authority.contains("@") else {
      throw ArtifactErrorV3.invalidArtifact
    }
    let normalizedAuthority = try normalizeAuthority(authority)
    let normalizedPath: String
    switch (carrier, scheme) {
    case ("websocket", "wss"):
      normalizedPath = TransportV3Contract.webSocketPath(for: kind)
      guard path == normalizedPath else { throw ArtifactErrorV3.invalidArtifact }
    case ("raw_quic", "quic"):
      guard path.isEmpty || path == "/" else { throw ArtifactErrorV3.invalidArtifact }
      normalizedPath = ""
    case ("webtransport", "https"):
      normalizedPath = TransportV3Contract.webTransportPath(for: kind)
      guard path == normalizedPath else { throw ArtifactErrorV3.invalidArtifact }
    default: throw ArtifactErrorV3.invalidArtifact
    }
    let result = "\(scheme)://\(normalizedAuthority)\(normalizedPath)"
    guard result.utf8.count <= 2_048 else { throw ArtifactErrorV3.invalidArtifact }
    return result
  }

  private static func normalizeAuthority(_ authority: String) throws -> String {
    let host: String
    let portText: String?
    if authority.hasPrefix("[") {
      guard let close = authority.firstIndex(of: "]") else { throw ArtifactErrorV3.invalidArtifact }
      let address = String(authority[authority.index(after: authority.startIndex)..<close])
      guard !address.isEmpty, !address.contains(".") else { throw ArtifactErrorV3.invalidArtifact }
      let tail = String(authority[authority.index(after: close)...])
      if tail.isEmpty {
        portText = nil
      } else {
        guard tail.hasPrefix(":"), tail.count > 1 else { throw ArtifactErrorV3.invalidArtifact }
        portText = String(tail.dropFirst())
      }
      var parsed = in6_addr()
      guard inet_pton(AF_INET6, address, &parsed) == 1 else {
        throw ArtifactErrorV3.invalidArtifact
      }
      var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
      guard inet_ntop(AF_INET6, &parsed, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
        throw ArtifactErrorV3.invalidArtifact
      }
      let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
      host =
        "[" + String(decoding: buffer[..<end].map(UInt8.init(bitPattern:)), as: UTF8.self) + "]"
    } else {
      guard authority.filter({ $0 == ":" }).count <= 1 else {
        throw ArtifactErrorV3.invalidArtifact
      }
      if let colon = authority.firstIndex(of: ":") {
        host = try normalizeHost(String(authority[..<colon]))
        portText = String(authority[authority.index(after: colon)...])
      } else {
        host = try normalizeHost(authority)
        portText = nil
      }
    }
    guard let portText else { return host }
    guard !portText.isEmpty, portText.utf8.allSatisfy({ (48...57).contains($0) }),
      let port = UInt32(portText), (1...65_535).contains(port)
    else { throw ArtifactErrorV3.invalidArtifact }
    return port == 443 ? host : "\(host):\(port)"
  }

  private static func normalizeHost(_ raw: String) throws -> String {
    guard !raw.isEmpty else { throw ArtifactErrorV3.invalidArtifact }
    if raw.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) {
      let parts = raw.split(separator: ".", omittingEmptySubsequences: false)
      guard parts.count == 4 else { throw ArtifactErrorV3.invalidArtifact }
      return try parts.map { part in
        guard !part.isEmpty, !(part.count > 1 && part.first == "0"), let octet = UInt8(part)
        else { throw ArtifactErrorV3.invalidArtifact }
        return String(octet)
      }.joined(separator: ".")
    }
    let ascii: String
    do {
      ascii = try IDNAHostV3.lookupASCII(raw)
    } catch {
      throw ArtifactErrorV3.invalidArtifact
    }
    let last =
      ascii.split(separator: ".", omittingEmptySubsequences: false).last.map(String.init) ?? ""
    let lower = last.lowercased()
    let numeric = !lower.isEmpty && lower.utf8.allSatisfy({ (48...57).contains($0) })
    let hex =
      lower.hasPrefix("0x")
      && lower.dropFirst(2).utf8.allSatisfy({ byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      })
    guard !numeric, !hex else { throw ArtifactErrorV3.invalidArtifact }
    return ascii
  }

  private static func exact(_ object: [String: Any], _ keys: Set<String>) throws {
    guard Set(object.keys) == keys else { throw ArtifactErrorV3.invalidArtifact }
  }

  private static func registry(_ value: String, max: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= max
      && value.utf8.allSatisfy { asciiAlphaNumeric($0) || "._~-".utf8.contains($0) }
  }

  private static func validLowerID(_ value: String, max: Int) -> Bool {
    let bytes = Array(value.utf8)
    return !bytes.isEmpty && bytes.count <= max && (97...122).contains(bytes[0])
      && bytes.allSatisfy {
        (97...122).contains($0) || (48...57).contains($0) || "._-".utf8.contains($0)
      }
  }

  private static func validCandidateID(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    return !bytes.isEmpty && bytes.count <= 64
      && ((97...122).contains(bytes[0]) || (48...57).contains(bytes[0]))
      && bytes.allSatisfy {
        (97...122).contains($0) || (48...57).contains($0) || "._-".utf8.contains($0)
      }
  }

  private static func ascii(_ value: String, max: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= max
      && value.unicodeScalars.allSatisfy { $0.value <= 0x7f }
  }

  private static func asciiAlpha(_ byte: UInt8) -> Bool {
    (65...90).contains(byte) || (97...122).contains(byte)
  }

  private static func asciiAlphaNumeric(_ byte: UInt8) -> Bool {
    asciiAlpha(byte) || (48...57).contains(byte)
  }
}

enum FlowersecJCSV3 {
  static func encode(_ value: Any) throws -> Data {
    guard JSONSerialization.isValidJSONObject(value) else { throw ArtifactErrorV3.invalidArtifact }
    return try encodeValue(value)
  }

  private static func encodeValue(_ value: Any) throws -> Data {
    if let object = value as? [String: Any] {
      let keys = object.keys.sorted {
        Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16))
      }
      var result = Data([0x7b])
      for (index, key) in keys.enumerated() {
        if index != 0 { result.append(0x2c) }
        result.append(try encodeScalar(key))
        result.append(0x3a)
        result.append(try encodeValue(object[key]!))
      }
      result.append(0x7d)
      return result
    }
    if let object = value as? NSDictionary {
      var converted: [String: Any] = [:]
      for (key, item) in object {
        guard let key = key as? String else { throw ArtifactErrorV3.invalidArtifact }
        converted[key] = item
      }
      return try encodeValue(converted)
    }
    if let array = value as? [Any] {
      var result = Data([0x5b])
      for (index, item) in array.enumerated() {
        if index != 0 { result.append(0x2c) }
        result.append(try encodeValue(item))
      }
      result.append(0x5d)
      return result
    }
    if let array = value as? NSArray {
      return try encodeValue(array.map { $0 })
    }
    return try encodeScalar(value)
  }

  private static func encodeScalar(_ value: Any) throws -> Data {
    guard JSONSerialization.isValidJSONObject([value]),
      let data = try? JSONSerialization.data(
        withJSONObject: [value], options: [.withoutEscapingSlashes]),
      data.count >= 2 else { throw ArtifactErrorV3.invalidArtifact }
    return Data(data.dropFirst().dropLast())
  }

  static func hashLP(domain: String, value: Any) throws -> Data {
    hashLP(domain: domain, canonical: try encode(value))
  }

  static func hashLP(domain: String, canonical: Data) -> Data {
    var preimage = Data(domain.utf8)
    preimage.appendUInt32BE(UInt32(canonical.count))
    preimage.append(canonical)
    return Data(SHA256.hash(data: preimage))
  }

  static func canonical32(_ value: String) -> Data? {
    guard !value.contains("="), let decoded = Data(base64URLEncodedV3: value), decoded.count == 32,
      decoded.base64URLEncodedStringV3() == value
    else { return nil }
    return decoded
  }
}

extension Data {
  fileprivate init?(base64URLEncodedV3 value: String) {
    var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(
      of: "_", with: "/")
    text += String(repeating: "=", count: (4 - text.count % 4) % 4)
    self.init(base64Encoded: text)
  }

  func base64URLEncodedStringV3() -> String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}
