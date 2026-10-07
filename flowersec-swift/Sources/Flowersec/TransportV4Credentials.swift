import Clibsodium
import Crypto
import Foundation

enum V4ActivationSource: String, Sendable {
  case liveAuthority = "live_authority"
  case preauthorizedPool = "preauthorized_pool"
}

struct V4CredentialConfiguration: Sendable {
  let namespaces: [V4NamespaceVerifier]
  let tenant: String
  let audience: String
  let clientSubject: String
  let serverSubject: String
  let cryptoProfiles: [String]
  var webSocketOrigin: String? = nil
}

struct V4PoolServerAllowInput: Sendable {
  let grant: Data
  let recipient: Data
  let incarnation: Data
  #if os(macOS) || os(iOS)
  let control: TransportControlHTTPSConfiguration
  #endif
}

struct V4CredentialInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  let artifact: Data
  let clientCertificate: Data
  let serverCertificate: Data
  let activation: Data
  let source: V4ActivationSource
  let candidateIndex: Int
  let grant: Data
  let relayCertificate: Data
  let poolTunnels: [V4PoolMaterialBundle.Tunnel]
  let liveTunnel: TransportLiveTunnelConfiguration?
  let localRole: V4CryptoRole
  let poolServerAllow: V4PoolServerAllowInput?
  init(artifact: Data, clientCertificate: Data, serverCertificate: Data, activation: Data,
    source: V4ActivationSource, candidateIndex: Int, grant: Data = Data(), relayCertificate: Data = Data(),
    poolTunnels: [V4PoolMaterialBundle.Tunnel] = [], liveTunnel: TransportLiveTunnelConfiguration? = nil, localRole: V4CryptoRole = .client, poolServerAllow: V4PoolServerAllowInput? = nil) {
    self.artifact = artifact; self.clientCertificate = clientCertificate; self.serverCertificate = serverCertificate
    self.activation = activation; self.source = source; self.candidateIndex = candidateIndex
    self.localRole = localRole; self.poolServerAllow = poolServerAllow
    self.grant = grant; self.relayCertificate = relayCertificate; self.poolTunnels = poolTunnels; self.liveTunnel = liveTunnel
  }
  func withRole(_ role: V4CryptoRole) -> Self {
    Self(artifact: artifact, clientCertificate: clientCertificate, serverCertificate: serverCertificate, activation: activation,
      source: source, candidateIndex: candidateIndex, grant: grant, relayCertificate: relayCertificate,
      poolTunnels: poolTunnels, liveTunnel: liveTunnel, localRole: role, poolServerAllow: poolServerAllow)
  }
  var description: String { "Flowersec.CredentialInput(<redacted>)" }
  var debugDescription: String { description }
}

// Only this file's actual verification path constructs this capability. It
// authorizes mathematical credential preparation, never durable once spend,
// provider identity, possession of private keys, admission, Noise, or READY.
final class V4CredentialAdmission: @unchecked Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  private struct Freshness {
    let namespace: V4NamespaceVerifier
    var sequence: UInt64
    var deadline: V4SecurityDeadline
  }
  let environment: V4EnvironmentFoundation
  private let reservation: V4ResourceReference
  private var preparationDeadline: V4SecurityDeadline
  private var sessionDeadline: V4SecurityDeadline
  private var evidence: [V4CredentialEvidence]
  private var originals: [V4NamespaceValue]
  private var freshness: [Freshness] = []
  private let policy: V4CredentialPolicy
  private var terminal: Error?
  private var closed = false
  private var handshakeClaimed = false
  private var tunnelPreparation: V4LiveGrantPreparation?
  private let tunnelInput: V4CredentialInput
  fileprivate let webSocketOrigin: String?
  let localRole: V4CryptoRole
  let pathKind: UInt64
  let artifactDigest: Data
  let certificateDigests: [Data]
  private(set) var activationDigest: Data
  let candidateID: Data
  let routeDigest: Data
  private(set) var attemptID: Data
  let source: V4ActivationSource
  let connectionFacts: V4ConnectionFacts
  let cryptoProfile: String
  private(set) var initiationNotAfterMS: UInt64
  private(set) var sessionNotAfterMS: UInt64
  var description: String { "Flowersec.CredentialAdmission(<redacted>)" }
  var debugDescription: String { description }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }

  fileprivate init(
    admission: V4CredentialWorkAdmission, input: V4CredentialInput,
    originals: [V4NamespaceValue], evidence: [V4CredentialEvidence],
    candidateID: Data, routeDigest: Data, profile: String,
    initiation: UInt64, sessionEnd: UInt64, webSocketOrigin: String?
  ) throws {
    environment = admission.environment
    reservation = admission.reservation
    self.originals = originals
    tunnelInput = input
    self.webSocketOrigin = webSocketOrigin
    localRole = input.localRole
    guard let candidate = try originals[0].field("candidates").children.enumerated()
      .first(where: { $0.offset == input.candidateIndex })?.element
    else { throw V4NamespaceFailure.untrusted }
    pathKind = try candidate.u("path_kind")
    self.evidence = evidence
    self.candidateID = candidateID
    self.routeDigest = routeDigest
    self.source = input.source
    connectionFacts = V4ConnectionFacts(source: input.source == .preauthorizedPool ? .preauthorizedPool : .liveAuthority)
    cryptoProfile = profile
    artifactDigest = evidence[0].digest
    certificateDigests = [evidence[1].digest, evidence[2].digest]
    activationDigest = evidence.count == 4 ? evidence[3].digest : Data()
    attemptID = originals.count == 4 ? try originals[3].b("attempt_id") : Data(repeating: 0, count: 16)
    initiationNotAfterMS = initiation
    sessionNotAfterMS = sessionEnd
    preparationDeadline = try V4SecurityDeadline(clock: environment.clock, capMS: initiation)
    sessionDeadline = try V4SecurityDeadline(clock: environment.clock, capMS: sessionEnd)
    policy = V4CredentialPolicy(
      stalenessMS: evidence.map(\.policy.stalenessMS).min()!,
      signerLifetimeMS: evidence.map(\.policy.signerLifetimeMS).min()!)
    for item in evidence where !freshness.contains(where: { $0.namespace === item.namespace }) {
      let current = try item.namespace.credentialFreshness(policy)
      freshness.append(
        Freshness(
          namespace: item.namespace, sequence: current.sequence,
          deadline: try V4SecurityDeadline(clock: environment.clock, capMS: current.capMS)))
    }
    try checkPreparation(in: environment)
  }

  deinit { reservation.release() }

  func checkPreparation(in originalEnvironment: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      try checkSessionAuthorization(in: originalEnvironment)
      try preparationDeadline.check()
    }
  }

  func checkSessionAuthorization(in originalEnvironment: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      guard originalEnvironment === environment else { throw V4ResourceFailure.owner }
      guard !closed else { throw V4NamespaceFailure.closed }
      if let terminal { throw terminal }
      do {
        try reservation.check()
        try sessionDeadline.check()
        try tunnelPreparation?.checkDependencies()
        for item in evidence { try item.namespace.checkEvidence(item) }
        for index in freshness.indices {
          let current = try freshness[index].namespace.credentialFreshness(policy)
          if current.sequence != freshness[index].sequence {
            freshness[index].deadline = try V4SecurityDeadline(
              clock: environment.clock, capMS: current.capMS)
            freshness[index].sequence = current.sequence
          }
          try freshness[index].deadline.check()
        }
      } catch V4TimeFailure.pending { throw V4TimeFailure.pending } catch V4TimeFailure.unavailable
      { throw V4TimeFailure.unavailable } catch V4NamespaceFailure.pendingState {
        throw V4NamespaceFailure.pendingState
      } catch {
        terminal = error
        throw error
      }
    }
  }

  // Reuse the original tightened authorization clocks. A retirement observer
  // cannot reset a projection or extend it after a namespace update.
  func retirementDeadline(in originalEnvironment: V4EnvironmentFoundation,
    maximum: Duration) throws -> ContinuousClock.Instant {
    try environment.gate.withLock {
      guard maximum > .zero else { throw V4TimeFailure.expired }
      try checkSessionAuthorization(in: originalEnvironment)
      var remaining = try sessionDeadline.remainingTicks()
      for item in freshness { remaining = min(remaining, try item.deadline.remainingTicks()) }
      if let tunnelPreparation { remaining = min(remaining, try tunnelPreparation.forwardingRemainingTicks()) }
      guard remaining > 0, remaining <= UInt64(Int64.max) else { throw V4TimeFailure.expired }
      let now = ContinuousClock.now
      return min(now.advanced(by: maximum), now.advanced(by: .milliseconds(Int64(remaining))))
    }
  }

  func claimHandshake(in originalEnvironment: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      try checkPreparation(in: originalEnvironment)
      guard !handshakeClaimed, originals.count == 4 else { throw V4CryptoFailure.phase }
      if pathKind == 1 { _ = try tunnelGrant() }
      handshakeClaimed = true
    }
  }

  func close() {
    environment.gate.withLock {
      guard !closed else { return }
      closed = true
      preparationDeadline.cancel()
      sessionDeadline.cancel()
      for item in freshness { item.deadline.cancel() }
      originals = []
      evidence = []
      freshness = []
      tunnelPreparation?.close(); tunnelPreparation = nil
      reservation.seal()
    }
  }
}

enum V4CredentialVerifier {
  private static let nodes = 16_384
  static var charge: V4ResourceVector {
    V4ResourceVector(
      sdkBytes: V4NamespaceRegistry.backingBytes + 8
        * (2 * 65_536 + 2 * 8192 + 4096 + 2048
          + UInt64(nodes * 4 * MemoryLayout<V4NamespaceDocument.Node>.stride)),
      items: 4, work: 1)
  }

  static func verify(
    _ admission: V4CredentialWorkAdmission, configuration: V4CredentialConfiguration,
    input: V4CredentialInput
  ) throws -> V4CredentialAdmission {
    let environment = admission.environment
    try admission.reservation.check()
    guard admission.reservation.belongs(to: environment.account),
      (1...8).contains(configuration.namespaces.count),
      (1...2).contains(configuration.cryptoProfiles.count),
      (0..<16).contains(input.candidateIndex),
      [
        configuration.tenant, configuration.audience, configuration.clientSubject,
        configuration.serverSubject,
      ]
      .allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) })
    else { throw V4NamespaceFailure.configuration }
    let registry = try V4NamespaceRegistry()
    for profile in configuration.cryptoProfiles { _ = try registry.profileAlgorithm(profile) }
    for (index, namespace) in configuration.namespaces.enumerated() {
      try namespace.checkOwner(environment)
      guard !configuration.namespaces[..<index].contains(where: { $0 === namespace }) else {
        throw V4NamespaceFailure.configuration
      }
    }
    func decode(_ data: Data, _ schema: String, _ bytes: Int) throws -> V4NamespaceValue {
      try V4NamespaceDocument(
        data, schema: schema, bytes: bytes, nodes: nodes, registry: registry,
        context: ["activation_source_profile": input.source.rawValue]
      ).root
    }
    func resolve(_ value: V4NamespaceValue) throws -> V4NamespaceVerifier {
      let matched = try configuration.namespaces.filter { try $0.matchesCredential(value) }
      guard matched.count == 1 else { throw V4NamespaceFailure.untrusted }
      return matched[0]
    }
    let artifact = try decode(input.artifact, "Artifact", 65_536)
    let profile = try artifact.t("crypto_profile_id")
    guard configuration.cryptoProfiles.contains(profile),
      try artifact.t("tenant_id") == configuration.tenant,
      try artifact.t("audience") == configuration.audience
    else { throw V4NamespaceFailure.untrusted }
    let parentNamespace = try resolve(artifact)
    let parent = try parentNamespace.verifyCredential(
      artifact, kind: 1, originalEnvironment: environment)
    var originals = [artifact]
    var evidence = [parent]
    for (role, bytes) in [input.clientCertificate, input.serverCertificate].enumerated() {
      let certificate = try decode(bytes, "IdentityCertificate", 8192)
      for name in ["tenant_id", "audience", "crypto_profile_id"] {
        guard try certificate.field(name).raw.elementsEqual(artifact.field(name).raw) else {
          throw V4NamespaceFailure.untrusted
        }
      }
      guard try certificate.u("role") == UInt64(role),
        try certificate.t("subject_id")
          == (role == 0 ? configuration.clientSubject : configuration.serverSubject)
      else { throw V4NamespaceFailure.untrusted }
      let item = try resolve(certificate).verifyCredential(
        certificate, kind: 0, originalEnvironment: environment)
      guard
        try item.digest
          == artifact.b(role == 0 ? "client_identity_digest" : "server_identity_digest"),
        parent.policy.stalenessMS <= item.policy.stalenessMS,
        parent.policy.signerLifetimeMS <= item.policy.signerLifetimeMS
      else { throw V4NamespaceFailure.untrusted }
      try identityKey(certificate)
      originals.append(certificate)
      evidence.append(item)
    }
    let candidates = try artifact.field("candidates")
    guard
      let candidate = candidates.children.enumerated().first(where: {
        $0.offset == input.candidateIndex
      })?.element,
      try candidate.u("path_kind") <= 1
    else { throw V4NamespaceFailure.untrusted }
    if try candidate.u("path_kind") == 0 { try closure(candidate, evidence: evidence) }
    let route = try routeDocument(candidate, registry: registry)
    let routeDigest = try route.digest("route_digest")
    if input.source == .liveAuthority && input.activation.isEmpty {
      // The issued Artifact and complete identity pair are already trusted.
      // A missing TxB proof remains a preparation dependency, never evidence.
      let prepared = try V4CredentialAdmission(admission: admission, input: input,
        originals: originals, evidence: evidence, candidateID: candidate.b("candidate_id"),
        routeDigest: routeDigest, profile: profile,
        initiation: artifact.u("initiation_not_after_ms"),
        sessionEnd: min(try artifact.u("session_not_after_ms"), evidence[1].expiresMS, evidence[2].expiresMS),
        webSocketOrigin: configuration.webSocketOrigin)
      try prepared.configureTunnel(configuration: configuration, registry: registry)
      return prepared
    }
    let activation = try decode(input.activation, "ActivationAuthorization", 4096)
    for (field, original) in [
      ("tenant_id", "tenant_id"), ("artifact_issuer_key_id", "issuer_key_id"),
      ("lease_id", "lease_id"), ("audience", "audience"),
      ("client_identity_digest", "client_identity_digest"),
      ("server_identity_digest", "server_identity_digest"),
    ] {
      guard try activation.field(field).raw.elementsEqual(artifact.field(original).raw) else {
        throw V4NamespaceFailure.untrusted
      }
    }
    let issued = try activation.u("issued_at_ms")
    let initiation = try activation.u("activation_not_after_ms")
    let sessionEnd = try activation.u("session_not_after_ms")
    guard try issued >= artifact.u("issued_at_ms"),
      try initiation <= artifact.u("initiation_not_after_ms"),
      try sessionEnd <= artifact.u("session_not_after_ms")
    else { throw V4NamespaceFailure.untrusted }
    let activationEvidence = try parentNamespace.verifyActivation(activation, parent: parent)
    let once = try parentNamespace.onceAuthority(parent)
    try selection(
      input, artifact: artifact, activation: activation, once: once,
      candidate: candidate, routeDigest: routeDigest, registry: registry)
    originals.append(activation)
    evidence.append(activationEvidence)
    let complete = try V4CredentialAdmission(
      admission: admission, input: input, originals: originals, evidence: evidence,
      candidateID: candidate.b("candidate_id"), routeDigest: routeDigest, profile: profile,
      initiation: initiation,
      sessionEnd: min(sessionEnd, evidence[1].expiresMS, evidence[2].expiresMS),
      webSocketOrigin: configuration.webSocketOrigin)
    try complete.configureTunnel(configuration: configuration, registry: registry)
    return complete
  }

  static func identityKey(_ certificate: V4NamespaceValue) throws {
    let identity = try certificate.b("ed25519_public_key")
    guard identity.count == 32, sodium_init() >= 0,
      identity.withUnsafeBytes({
        crypto_core_ed25519_is_valid_point($0.bindMemory(to: UInt8.self).baseAddress!)
      }) == 1
    else { throw V4NamespaceFailure.untrusted }
    let noise = try certificate.field("noise_static_public_key")
    let publicKey = try noise.b("public_key_bytes")
    if try noise.u("algorithm") == 0 {
      let scalar = try Curve25519.KeyAgreement.PrivateKey(
        rawRepresentation: Data(repeating: 0x5a, count: 32))
      let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
      let secret = try scalar.sharedSecretFromKeyAgreement(with: peer)
      guard secret.withUnsafeBytes({ $0.contains(where: { $0 != 0 }) }) else {
        throw V4NamespaceFailure.untrusted
      }
    } else {
      let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
      guard peer.x963Representation == publicKey else { throw V4NamespaceFailure.untrusted }
    }
  }

  private static func closure(_ candidate: V4NamespaceValue, evidence: [V4CredentialEvidence])
    throws
  {
    var known: [V4NamespaceVerifier] = []
    for item in evidence where !known.contains(where: { $0 === item.namespace }) {
      known.append(item.namespace)
    }
    let refs = try candidate.field("revocation_namespace_refs")
    guard refs.count == known.count else { throw V4NamespaceFailure.untrusted }
    for reference in refs.children {
      guard let namespace = try known.first(where: { try $0.matchesCredential(reference) }) else {
        throw V4NamespaceFailure.untrusted
      }
      try namespace.checkCredentialReference(reference)
    }
  }

  static func routeDocument(_ candidate: V4NamespaceValue, registry: V4NamespaceRegistry) throws
    -> V4NamespaceValue
  {
    let kind = try candidate.u("path_kind")
    var fields = [
      (UInt64(0), try candidate.field("path_kind")), (1, try candidate.field("candidate_id")),
    ]
    for (key, name) in [(UInt64(2), "direct_leg"), (3, "client_leg"), (4, "server_leg")] {
      if let value = try candidate.optional(name) { fields.append((key, value)) }
    }
    guard fields.count == (kind == 0 ? 3 : 4) else { throw V4NamespaceFailure.untrusted }
    var bytes = V4NamespaceValue.head(5, UInt64(fields.count))
    for (key, value) in fields {
      bytes.append(V4NamespaceValue.head(0, key))
      bytes.append(contentsOf: value.raw)
    }
    return try V4NamespaceDocument(
      bytes, schema: "Route", bytes: 65_536, nodes: nodes, registry: registry
    ).root
  }

  private static func selection(
    _ input: V4CredentialInput, artifact: V4NamespaceValue,
    activation: V4NamespaceValue, once: V4NamespaceValue, candidate: V4NamespaceValue,
    routeDigest: Data, registry: V4NamespaceRegistry
  ) throws {
    if input.source == .liveAuthority {
      guard try activation.b("candidate_selection") == candidate.b("candidate_id"),
        try activation.b("route_selection") == routeDigest
      else { throw V4NamespaceFailure.untrusted }
      return
    }
    let selection = try activation.field("candidate_selection")
    guard try selection.field("once_authority_ref").raw.elementsEqual(once.raw),
      try selection.b("artifact_digest") == activation.b("artifact_digest")
    else { throw V4NamespaceFailure.untrusted }
    let indices = try selection.field("candidate_indices")
    var set = V4NamespaceValue.head(5, 2)
    set.append(V4NamespaceValue.head(0, 0))
    set.append(contentsOf: try activation.field("artifact_digest").raw)
    set.append(V4NamespaceValue.head(0, 1))
    set.append(V4NamespaceValue.head(4, UInt64(indices.count)))
    let candidates = try artifact.field("candidates")
    var found = false
    for entry in indices.children {
      let index = try entry.uint()
      guard
        let selected = candidates.children.enumerated().first(where: { UInt64($0.offset) == index }
        )?.element
      else { throw V4NamespaceFailure.untrusted }
      found = found || index == input.candidateIndex
      let digest = try routeDocument(selected, registry: registry).digest("route_digest")
      set.append(V4NamespaceValue.head(5, 3))
      set.append(V4NamespaceValue.head(0, 0))
      set.append(V4NamespaceValue.head(0, index))
      set.append(V4NamespaceValue.head(0, 1))
      set.append(contentsOf: try selected.field("candidate_id").raw)
      set.append(V4NamespaceValue.head(0, 2))
      set.append(V4NamespaceValue.head(2, 32))
      set.append(digest)
    }
    let document = try V4NamespaceDocument(
      set, schema: "PoolSelectionSet", bytes: 2048, nodes: nodes, registry: registry
    ).root
    guard found, try document.digest("candidate_set_digest") == selection.b("candidate_set_digest"),
      try document.digest("route_set_digest") == activation.b("route_selection")
    else { throw V4NamespaceFailure.untrusted }
  }
}

// A native preparation plan is projected only from the original authenticated
// candidate. It does not confer once-spend, handshake, or Session authority.
final class V4WebSocketRoute: @unchecked Sendable {
  let credential: V4CredentialAdmission
  let environment: V4EnvironmentFoundation
  let localRole: V4CryptoRole
  let dialerRole: UInt64
  let listenerRole: UInt64
  let physicalRole: UInt64
  var isRelay: Bool { physicalRole == 2 }
  var isDialer: Bool { dialerRole == physicalRole }
  let accessClass: UInt64
  var requiresTLS: Bool { accessClass == 0 }
  let host: String
  let port: Int
  let path: String
  let subprotocol: String
  let origin: String?
  let allowedOrigins: [String]
  let allowAbsentOrigin: Bool
  let maximumFrame: Int
  let pins: [V4TLSPin]?
  fileprivate init(
    credential: V4CredentialAdmission, environment: V4EnvironmentFoundation,
    leg: V4NamespaceValue, maximumFrame: Int, tunnel: Bool = false, role: V4CryptoRole = .client, relay: Bool = false
  ) throws {
    self.credential = credential
    self.environment = environment
    localRole = role; physicalRole = relay ? 2 : UInt64(role.rawValue)
    dialerRole = try leg.u("dialer_role"); listenerRole = try leg.u("listener_role")
    accessClass = try leg.u("access_class")
    guard (accessClass == 0 || (!tunnel && accessClass == 1)), try leg.u("carrier") == 1,
      (!tunnel ? (dialerRole == 0 && listenerRole == 1) :
        ((dialerRole == UInt64(role.rawValue) && listenerRole == 2) ||
          (dialerRole == 2 && listenerRole == UInt64(role.rawValue))))
    else { throw V4CryptoFailure.configuration }
    if accessClass == 0, let tls = try leg.optional("tls_policy"), try tls.u("mode") == 1 {
      pins = try tls.field("pins").children.map {
        try V4TLSPin(
          digest: $0.b("leaf_der_sha256"), notBefore: $0.u("not_before_ms"),
          notAfter: $0.u("not_after_ms"))
      }
    } else {
      pins = nil
    }
    host = try leg.t("host")
    port = try Int(leg.u("port"))
    path = try leg.t("path")
    subprotocol = try leg.t("subprotocol")
    self.maximumFrame = maximumFrame
    let expectedPath = accessClass == 1 ? "/flowersec/v4/local" : (tunnel ? "/flowersec/v4/tunnel" : "/flowersec/v4/direct")
    let expectedProtocol = accessClass == 1 ? "flowersec.local.v4" : (tunnel ? "flowersec.tunnel.v4" : "flowersec.direct.v4")
    guard path == expectedPath, subprotocol == expectedProtocol,
      (304...1_048_576).contains(maximumFrame)
    else { throw V4CryptoFailure.configuration }
    let policy = try leg.optional("origin_policy")
    let signedOrigin = try leg.optional("origin")?.text()
    origin = accessClass == 1 ? signedOrigin : (dialerRole == physicalRole ? credential.webSocketOrigin : nil)
    allowedOrigins = try policy?.field("origins").children.map { try $0.text() } ?? origin.map { [$0] } ?? []
    allowAbsentOrigin = try policy?.field("allow_absent").equals(true) ?? (origin == nil)
    if accessClass == 1 {
      let authority = host.contains(":") ? "[\(host)]" : host
      guard V4CredentialText.isLoopbackAddress(host), (1024...65535).contains(port),
        origin == "http://\(authority):\(port)", policy == nil,
        try leg.optional("tls_policy") == nil, try leg.optional("alpn") == nil
      else { throw V4CryptoFailure.configuration }
    }
    if dialerRole == physicalRole, let origin {
      if let policy {
        guard try policy.field("origins").children.contains(where: { try $0.text() == origin })
        else {
          throw V4CryptoFailure.configuration
        }
      }
    } else if dialerRole == physicalRole, let policy {
      guard try policy.field("allow_absent").raw.elementsEqual([0xf5]) else {
        throw V4CryptoFailure.configuration
      }
    }
  }
  func check() throws { try credential.checkPreparation(in: environment) }
}
extension V4CredentialAdmission {
  fileprivate func configureTunnel(configuration: V4CredentialConfiguration, registry: V4NamespaceRegistry) throws {
    try environment.gate.withLock {
      let input = tunnelInput
      if pathKind == 0 {
        guard input.grant.isEmpty, input.relayCertificate.isEmpty, input.liveTunnel == nil
        else { throw V4NamespaceFailure.untrusted }
        return
      }
      guard pathKind == 1, tunnelPreparation == nil else { throw V4NamespaceFailure.untrusted }
      let candidate = try originalCandidate()
      let scope: V4LiveGrantScope; let relayWire: Data; let limits: Data
      if let future = input.liveTunnel {
        guard source == .liveAuthority, future.candidateIndex == input.candidateIndex,
          input.grant.isEmpty, input.relayCertificate.isEmpty, future.scope.roleMask == (input.localRole == .client ? 5 : 6)
        else { throw V4NamespaceFailure.untrusted }
        scope = future.scope; relayWire = future.relayCertificate; limits = future.grantLimits
      } else {
        guard source == .preauthorizedPool, !input.grant.isEmpty, !input.relayCertificate.isEmpty
        else { throw V4NamespaceFailure.untrusted }
        let grant = try V4NamespaceDocument(input.grant, schema: "Grant", bytes: 9302, nodes: 4096, registry: registry).root
        scope = try V4LiveGrantScope.signed(grant, parent: originals[0])
        relayWire = input.relayCertificate; limits = try Data(grant.field("limits").raw)
      }
      try scope.checkShape()
      guard scope.roleMask == (input.localRole == .client ? 5 : 6) else { throw V4NamespaceFailure.untrusted }
      let relay = try V4NamespaceDocument(relayWire, schema: "IdentityCertificate", bytes: 8192, nodes: 4096, registry: registry).root
      guard try relay.u("role") == 2, try relay.t("tenant_id") == configuration.tenant,
        try relay.t("crypto_profile_id") == cryptoProfile else { throw V4NamespaceFailure.untrusted }
      try V4CredentialVerifier.identityKey(relay)
      let relayOwners = try configuration.namespaces.filter { try $0.matchesCredential(relay) }
      let grantOwners = configuration.namespaces.filter { $0.matchesGrantScope(scope) }
      guard relayOwners.count == 1, grantOwners.count == 1 else { throw V4NamespaceFailure.untrusted }
      let relayEvidence = try relayOwners[0].verifyCredential(relay, kind: 0, originalEnvironment: environment)
      // Only references that include this endpoint are local dependencies.
      // Base credential namespaces must carry both endpoint and hop roles.
      let refs = try candidate.field("revocation_namespace_refs").children.filter { try $0.u("role_mask") & (input.localRole == .client ? 1 : 2) != 0 }
      var owners = evidence.prefix(3).map { ($0.namespace, UInt64(7)) }
      owners.append((grantOwners[0], scope.roleMask)); owners.append((relayOwners[0], scope.roleMask))
      for (owner, mask) in owners {
        guard let ref = try refs.first(where: { try owner.matchesCredential($0) }) else { throw V4NamespaceFailure.untrusted }
        try owner.checkCredentialReference(ref, requiredRoles: mask, allowAdditionalRoles: true)
      }
      for ref in refs {
        guard try owners.contains(where: { try $0.0.matchesCredential(ref) }) else { throw V4NamespaceFailure.untrusted }
      }
      let projection = try V4NamespaceDocument(limits, schema: "GrantLimits", bytes: 1024, nodes: 32, registry: registry).root
      let maximumFrame = try originals[0].field("session_contract").u("max_frame")
      // The local certificate bytes are already captured. Live TxB can carry a
      // full bounded activation; admission must fit before any irreversible
      // spend, in addition to the complete registered HOP_AUTH grammar.
      let initialMinimum = max(10_346, UInt64(originals[Int(input.localRole.rawValue) + 1].raw.count) + 4096 + 1024,
        UInt64(originals[2].raw.count) + 1024)
      guard maximumFrame >= initialMinimum, try projection.u("max_envelope_bytes") == maximumFrame + 8,
        try projection.u("max_queue_bytes") >= maximumFrame + 8, try projection.u("max_queue_items") > 0,
        try projection.u("max_total_bytes") >= 2 * (maximumFrame + 8),
        try projection.u("max_rate_bytes_per_s") > 0 else { throw V4NamespaceFailure.capacity }
      let prepared = try V4LiveGrantPreparation(environment: environment, namespace: grantOwners[0], scope: scope,
        parent: originals[0], parentEvidence: evidence[0], relay: relay, relayEvidence: relayEvidence,
        expectedLimits: limits, originalAdmission: self, candidate: candidate)
      tunnelPreparation = prepared
      let end = min(sessionNotAfterMS, scope.expiresMS, relayEvidence.expiresMS)
      try sessionDeadline.tighten(to: end)
      sessionNotAfterMS = end
      if source == .preauthorizedPool {
        try prepared.complete(input.grant, activation: originalActivation(), candidate: candidate,
          client: originals[1], server: originals[2], relay: relay)
      }
      try checkPreparation(in: environment)
    }
  }
  #if os(macOS) || os(iOS)
  func preparePoolServerGrant(_ bytes: Data, configuration: V4CredentialConfiguration) throws -> V4LiveGrantPreparation {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard source == .preauthorizedPool, localRole == .client, pathKind == 1,
        (1...9302).contains(bytes.count) else { throw V4NamespaceFailure.untrusted }
      let storage = try environment.liveGrantPreparationStorage()
      let registry = try V4NamespaceRegistry()
      let grant = try V4NamespaceDocument(bytes, schema: "Grant", bytes: 9302, nodes: 4096, registry: registry).root
      let scope = try V4LiveGrantScope.signed(grant, parent: originals[0])
      try scope.checkShape()
      guard scope.roleMask == 6 else { throw V4NamespaceFailure.untrusted }
      let relay = try originalRelayCertificate()
      let grantOwners = configuration.namespaces.filter { $0.matchesGrantScope(scope) }
      let relayOwners = try configuration.namespaces.filter { try $0.matchesCredential(relay) }
      guard grantOwners.count == 1, relayOwners.count == 1 else { throw V4NamespaceFailure.untrusted }
      let relayEvidence = try relayOwners[0].verifyCredential(relay, kind: 0, originalEnvironment: environment)
      let candidate = try originalCandidate()
      let refs = try candidate.field("revocation_namespace_refs").children.filter { try $0.u("role_mask") & 2 != 0 }
      var owners = evidence.prefix(3).map { ($0.namespace, UInt64(7)) }
      owners.append((grantOwners[0], UInt64(6))); owners.append((relayOwners[0], UInt64(6)))
      for (owner, mask) in owners {
        guard let ref = try refs.first(where: { try owner.matchesCredential($0) }) else { throw V4NamespaceFailure.untrusted }
        try owner.checkCredentialReference(ref, requiredRoles: mask, allowAdditionalRoles: true)
      }
      for ref in refs {
        guard try owners.contains(where: { try $0.0.matchesCredential(ref) }) else { throw V4NamespaceFailure.untrusted }
      }
      let limits = try Data(grant.field("limits").raw)
      let projection = try V4NamespaceDocument(limits, schema: "GrantLimits", bytes: 1024, nodes: 32, registry: registry).root
      let frame = try originals[0].field("session_contract").u("max_frame") + 8
      guard try projection.u("max_envelope_bytes") == frame,
        try projection.u("max_queue_bytes") >= frame, try projection.u("max_queue_items") > 0,
        try projection.u("max_total_bytes") >= 2 * frame, try projection.u("max_rate_bytes_per_s") > 0
      else { throw V4NamespaceFailure.capacity }
      let prepared = try V4LiveGrantPreparation(environment: environment, namespace: grantOwners[0], scope: scope,
        parent: originals[0], parentEvidence: evidence[0], relay: relay, relayEvidence: relayEvidence,
        expectedLimits: limits, originalAdmission: self, candidate: candidate, endpointRole: .server, prepaidStorage: storage)
      try prepared.complete(bytes, activation: originalActivation(), candidate: candidate,
        client: originals[1], server: originals[2], relay: relay)
      return prepared
    }
  }
  #endif
  func poolApplicationProfile(in original: V4EnvironmentFoundation, identity: V4LocalIdentity) throws -> UInt64 {
    try environment.gate.withLock {
      try checkPreparation(in: original); try identity.check(in: original)
      guard source == .preauthorizedPool else { throw V4CryptoFailure.phase }
      guard identity.profile.rawValue == cryptoProfile,
        try originals[Int(localRole.rawValue) + 1].b("ed25519_public_key") == identity.identityPublicKey,
        try originals[Int(localRole.rawValue) + 1].field("noise_static_public_key").b("public_key_bytes") == identity.dhPublicKey
      else { throw V4CryptoFailure.key }
      return try originals[0].field("session_contract").u("application_profile")
    }
  }
  func originalCandidate() throws -> V4NamespaceValue {
    guard let candidate = try originals[0].field("candidates").children.first(where: { try $0.b("candidate_id") == candidateID })
    else { throw V4NamespaceFailure.untrusted }; return candidate
  }
  func relayOriginals(in original: V4EnvironmentFoundation) throws -> (V4NamespaceValue, V4NamespaceValue, V4NamespaceValue) {
    try environment.gate.withLock {
      try checkPreparation(in: original); return (originals[0], originals[1], originals[2])
    }
  }
  func originalActivation() throws -> V4NamespaceValue {
    guard originals.count == 4 else { throw V4CryptoFailure.phase }; return originals[3]
  }
  func originalRelayCertificate() throws -> V4NamespaceValue {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard pathKind == 1, let prepared = tunnelPreparation else { throw V4CryptoFailure.phase }
      return prepared.relayCertificate
    }
  }
  func tunnelGrant() throws -> (V4NamespaceValue, V4NamespaceValue) {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard pathKind == 1, let prepared = tunnelPreparation, let grant = prepared.completedGrant,
        prepared.completedEvidence != nil else { throw V4CryptoFailure.phase }
      return (grant, prepared.relayCertificate)
    }
  }
  #if os(macOS) || os(iOS)
  // The authenticated receiver narrows the original establishment clock. Native
  // HOP, FSB, durable consume, Noise and READY all recheck this same admission;
  // a successfully promoted Session retains its independent session deadline.
  func constrainPoolServerAllow(registration: V4PoolServerRegistration, notAfterMS: UInt64) throws {
    try environment.gate.withLock {
      guard registration.plan.credential === self, source == .preauthorizedPool,
        localRole == .server, pathKind == 1, !handshakeClaimed,
        notAfterMS > 0, notAfterMS <= initiationNotAfterMS else { throw V4CryptoFailure.phase }
      try checkPreparation(in: environment)
      try preparationDeadline.tighten(to: notAfterMS)
    }
  }
  func bindOriginalRelayAttempt(_ publication: V4OriginalRelayPublication) throws {
    try environment.gate.withLock {
      try publication.check(admission: self)
      guard source == .liveAuthority, pathKind == 1, originals.count == 3, !handshakeClaimed,
        attemptID.allSatisfy({ $0 == 0 }) else { throw V4CryptoFailure.phase }
      attemptID = Data(publication.attempt)
    }
  }
  func completeOriginalRelayGrant(_ delivery: V4RelayLiveGrantDelivery) throws {
    try environment.gate.withLock {
      try delivery.check(admission: self)
      guard source == .liveAuthority, pathKind == 1, let prepared = tunnelPreparation else { throw V4CryptoFailure.phase }
      try prepared.completeRelayPublication(delivery, candidate: originalCandidate(), client: originals[1], server: originals[2])
    }
  }
  func completeLiveServerGrant(_ delivery: V4LiveServerGrantDelivery) throws {
    try environment.gate.withLock {
      try delivery.check(admission: self)
      guard source == .liveAuthority, localRole == .server, pathKind == 1, let prepared = tunnelPreparation else { throw V4CryptoFailure.phase }
      try prepared.completeServerPublication(delivery, candidate: originalCandidate(), client: originals[1], server: originals[2])
    }
  }
  func bindLiveServerAttempt(_ registration: V4LiveServerRegistration) throws {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard source == .liveAuthority, localRole == .server, originals.count == 3, !handshakeClaimed,
        attemptID.allSatisfy({ $0 == 0 }), registration.plan.credential === self,
        registration.attempt.count == 16, registration.attempt.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.phase }
      attemptID = Data(registration.attempt)
    }
  }
  #endif
  func completeLiveTunnelGrant(_ bytes: Data) throws {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard source == .liveAuthority, pathKind == 1, let prepared = tunnelPreparation else { throw V4CryptoFailure.phase }
      try prepared.complete(bytes, activation: originalActivation(), candidate: originalCandidate(),
        client: originals[1], server: originals[2], relay: prepared.relayCertificate)
    }
  }
}

extension V4CredentialAdmission {
  func relayWebSocketRoute(in original: V4EnvironmentFoundation) throws -> V4WebSocketRoute {
    try environment.gate.withLock {
      try checkPreparation(in: original)
      guard pathKind == 1 else { throw V4CryptoFailure.configuration }
      let candidate = try originalCandidate()
      return try V4WebSocketRoute(credential: self, environment: environment,
        leg: candidate.field(localRole == .client ? "client_leg" : "server_leg"),
        maximumFrame: Int(originals[0].field("session_contract").u("max_frame")), tunnel: true, role: localRole, relay: true)
    }
  }
  func webSocketRoute(in original: V4EnvironmentFoundation) throws -> V4WebSocketRoute {
    try environment.gate.withLock {
      try checkPreparation(in: original)
      guard
        let candidate = try originals[0].field("candidates").children.first(where: {
          try $0.b("candidate_id") == candidateID
        }), try candidate.u("path_kind") == pathKind
      else { throw V4CryptoFailure.configuration }
      return try V4WebSocketRoute(
        credential: self, environment: environment,
        leg: candidate.field(pathKind == 0 ? "direct_leg" : (localRole == .client ? "client_leg" : "server_leg")),
        maximumFrame: Int(originals[0].field("session_contract").u("max_frame")), tunnel: pathKind == 1, role: localRole)
    }
  }
}

// Immutable facts copied from the original verified pool proof. This object
// grants neither spend nor activation authority and cannot be reconstructed
// from a durable row or a receipt.
final class V4PoolSpendFacts {
  let credential: V4CredentialAdmission
  let tenant: String
  let issuer: Data
  let spendAuthority: String
  let winnerAuthority: String
  let key: Data
  let projection: Data
  fileprivate init(
    credential: V4CredentialAdmission, artifact: V4NamespaceValue,
    activation: V4NamespaceValue, candidateIndex: Int
  ) throws {
    self.credential = credential
    tenant = try artifact.t("tenant_id")
    issuer = try artifact.b("issuer_key_id")
    let once = try activation.field("candidate_selection").field("once_authority_ref")
    spendAuthority = try once.t("spend_authority_id")
    winnerAuthority = try once.t("winner_authority_id")
    // Attempt, candidate, source, store and carrier never participate in the key.
    key = V4Crypto.map([
      (0, V4Crypto.text(tenant)), (1, V4Crypto.bytes(issuer)),
      (2, V4Crypto.bytes(try artifact.b("lease_id"))),
    ])
    projection = V4Crypto.map([
      (0, V4Crypto.text("flowersec/swift/pool-consume/1")),
      (1, V4Crypto.bytes(credential.artifactDigest)),
      (2, V4Crypto.bytes(credential.activationDigest)),
      (3, V4Crypto.bytes(try artifact.b("session_nonce"))),
      (4, V4Crypto.bytes(credential.candidateID)),
      (5, V4Crypto.bytes(credential.routeDigest)),
      (6, V4NamespaceValue.head(0, UInt64(candidateIndex))),
      (7, V4Crypto.bytes(Data(activation.raw))),
    ])
  }
}
extension V4CredentialAdmission {
  func prepareLiveActivation(signingKeyID: String) throws {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard source == .liveAuthority, originals.count == 3, !handshakeClaimed else { throw V4CryptoFailure.phase }
      try evidence[0].namespace.checkLiveActivationDependency(parent: evidence[0],
        signingKeyID: signingKeyID, initiation: initiationNotAfterMS, sessionEnd: sessionNotAfterMS)
    }
  }
  func beginLiveAuthorization(signingKeyID: String) throws -> Data {
    try environment.gate.withLock {
      try prepareLiveActivation(signingKeyID: signingKeyID)
      guard attemptID.allSatisfy({ $0 == 0 }) else { throw V4CryptoFailure.phase }
      attemptID = try V4Crypto.random(16)
      guard attemptID.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.key }
      let artifact = originals[0]
      let candidates = try artifact.field("candidates").children
      guard let index = try candidates.enumerated().first(where: { try $0.element.b("candidate_id") == candidateID })?.offset else { throw V4CryptoFailure.phase }
      // The shared Go/TS reference application's 13-element request envelope.
      let fields: [Data] = [V4Crypto.text("live-authorization-1"),
        try V4Crypto.text(artifact.t("tenant_id")), try V4Crypto.text(artifact.t("audience")),
        V4Crypto.text(cryptoProfile), try V4Crypto.bytes(artifact.b("issuer_key_id")),
        try V4Crypto.bytes(artifact.b("lease_id")), V4Crypto.bytes(attemptID),
        V4Crypto.bytes(artifactDigest), V4Crypto.bytes(certificateDigests[0]), V4Crypto.bytes(certificateDigests[1]),
        V4NamespaceValue.head(4, 3) + V4NamespaceValue.head(0, UInt64(index)) + V4Crypto.bytes(candidateID) + V4Crypto.bytes(routeDigest),
        V4NamespaceValue.head(0, initiationNotAfterMS), V4NamespaceValue.head(0, 1)]
      let encoded = V4NamespaceValue.head(4, 13) + fields.reduce(Data(), +)
      guard encoded.count <= 1024 else { throw V4CryptoFailure.capacity }
      return encoded
    }
  }
  func originalControlCustody() throws -> V4ResourceCustody {
    try environment.originalResourceCustody(reservation)
  }
  func completeLiveAuthorization(_ bytes: Data, signingKeyID: String,
    configuration: V4CredentialConfiguration) throws -> V4NamespaceValue {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard source == .liveAuthority, originals.count == 3, !handshakeClaimed,
        attemptID.contains(where: { $0 != 0 }), (1...4096).contains(bytes.count)
      else { throw V4CryptoFailure.phase }
      let candidates = try originals[0].field("candidates").children
      guard let index = try candidates.enumerated().first(where: { try $0.element.b("candidate_id") == candidateID })?.offset else { throw V4CryptoFailure.phase }
      // Borrow the original cold-verification footprint admitted before TxA.
      // No new authorization owner, namespace subscription or work pool exists.
      let work = V4CredentialWorkAdmission(environment: environment, reservation: try reservation.borrow())
      let input = V4CredentialInput(artifact: Data(originals[0].raw), clientCertificate: Data(originals[1].raw),
        serverCertificate: Data(originals[2].raw), activation: bytes, source: .liveAuthority, candidateIndex: index, liveTunnel: tunnelInput.liveTunnel, localRole: localRole)
      let complete: V4CredentialAdmission
      do { complete = try V4CredentialVerifier.verify(work, configuration: configuration, input: input) }
      catch { work.reservation.release(); throw error }
      guard complete.attemptID == attemptID, complete.candidateID == candidateID,
        complete.routeDigest == routeDigest, complete.artifactDigest == artifactDigest,
        complete.certificateDigests == certificateDigests,
        complete.initiationNotAfterMS <= initiationNotAfterMS, complete.sessionNotAfterMS <= sessionNotAfterMS,
        try complete.originals[3].t("signing_key_id") == signingKeyID
      else { throw V4NamespaceFailure.untrusted }
      if let grant = tunnelPreparation?.completedGrant {
        guard try grant.b("attempt_id") == complete.attemptID,
          try grant.u("not_after_ms") <= complete.sessionNotAfterMS else { throw V4NamespaceFailure.untrusted }
      }
      try preparationDeadline.tighten(to: complete.initiationNotAfterMS)
      try sessionDeadline.tighten(to: complete.sessionNotAfterMS)
      initiationNotAfterMS = complete.initiationNotAfterMS; sessionNotAfterMS = complete.sessionNotAfterMS
      originals = complete.originals; evidence = complete.evidence; activationDigest = complete.activationDigest
      complete.tunnelPreparation?.close(); complete.tunnelPreparation = nil
      try checkPreparation(in: environment)
      return originals[3]
    }
  }
  func checkLiveActivationComplete(in environment: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      guard source == .liveAuthority, originals.count == 4,
        attemptID.contains(where: { $0 != 0 }), !handshakeClaimed else { throw V4CryptoFailure.phase }
      if pathKind == 1 { _ = try tunnelGrant() }
    }
  }
}

extension V4CredentialAdmission {
  func parentWinnerSelection(authority: String) throws -> ParentWinnerSelection {
    try environment.gate.withLock {
      try checkPreparation(in: environment)
      let artifact = originals[0]; let activation = try originalActivation()
      let once = try evidence[0].namespace.onceAuthority(evidence[0])
      guard try once.t("winner_authority_id") == authority else { throw V4PoolFailure.configuration }
      let set: Data
      if source == .preauthorizedPool { set = try activation.field("candidate_selection").b("candidate_set_digest") }
      else { set = V4Crypto.hash(V4Crypto.bytes(candidateID) + V4Crypto.bytes(routeDigest)) }
      let key = V4Crypto.map([(0, V4Crypto.text(try artifact.t("tenant_id"))), (1, V4Crypto.bytes(try artifact.b("issuer_key_id"))),
        (2, V4Crypto.bytes(try artifact.b("lease_id")))])
      // Only public parent selection facts participate. Carrier, local role,
      // admission authority and per-leg Grant never change the common CAS.
      let projection = V4Crypto.map([(0, V4Crypto.text("flowersec/swift/parent-winner/1")),
        (1, V4NamespaceValue.head(0, source == .preauthorizedPool ? 1 : 0)), (2, V4Crypto.text(authority)),
        (3, V4Crypto.bytes(artifactDigest)), (4, V4Crypto.bytes(activationDigest)),
        (5, V4Crypto.bytes(set)), (6, V4Crypto.bytes(candidateID)), (7, V4Crypto.bytes(routeDigest)),
        (8, V4Crypto.bytes(attemptID)), (9, V4Crypto.bytes(certificateDigests[0])), (10, V4Crypto.bytes(certificateDigests[1])),
        (11, V4Crypto.text(try artifact.t("audience"))), (12, V4Crypto.text(try originals[2].t("revocation_authority_id"))),
        (13, V4Crypto.bytes(Data(activation.raw))), (14, V4NamespaceValue.head(0, try artifact.u("initiation_not_after_ms"))),
        (15, V4NamespaceValue.head(0, try artifact.u("session_not_after_ms")))])
      guard projection.count <= 16_384 else { throw V4PoolFailure.capacity }
      return ParentWinnerSelection(authority: authority, parent: key, projection: projection)
    }
  }
  func poolSpendFacts(in original: V4EnvironmentFoundation) throws -> V4PoolSpendFacts {
    try environment.gate.withLock {
      try checkPreparation(in: original)
      guard source == .preauthorizedPool,
        let index = try originals[0].field("candidates").children.enumerated().first(where: {
          try $0.element.b("candidate_id") == candidateID
        })?.offset
      else { throw V4CryptoFailure.phase }
      return try V4PoolSpendFacts(
        credential: self, artifact: originals[0],
        activation: originals[3], candidateIndex: index)
    }
  }
  func directPoolPlan(in original: V4EnvironmentFoundation, identity: V4LocalIdentity) throws
    -> V4DirectPoolPlan
  {
    try environment.gate.withLock {
      try checkPreparation(in: original)
      try identity.check(in: original)
      guard identity.profile.rawValue == cryptoProfile,
        try originals[Int(localRole.rawValue) + 1].b("ed25519_public_key") == identity.identityPublicKey,
        try originals[Int(localRole.rawValue) + 1].field("noise_static_public_key").b("public_key_bytes")
          == identity.dhPublicKey
      else { throw V4CryptoFailure.key }
      return try V4DirectPoolPlan(
        credential: self, environment: environment,
        artifact: originals[0], client: originals[1], server: originals[2], proof: originals.count == 4 ? originals[3] : nil,
        route: webSocketRoute(in: original))
    }
  }
}

// The complete original credential projection is prepared before native I/O or
// once consumption. Only direct WSS transport with authenticated-context
// binding is promoted by this implementation.
final class V4DirectPoolPlan: @unchecked Sendable {
  let credential: V4CredentialAdmission
  var role: V4CryptoRole { credential.localRole }
  var localCertificate: V4NamespaceValue { role == .client ? client : server }
  var peerCertificate: V4NamespaceValue { role == .client ? server : client }
  func serviceIdentity() throws -> ServiceCallerIdentity {
    try ServiceCallerIdentity(tenant: artifact.t("tenant_id"), audience: artifact.t("audience"),
      subject: localCertificate.t("subject_id"), identityDigest: artifact.b(role == .client ? "client_identity_digest" : "server_identity_digest"),
      peerSubject: peerCertificate.t("subject_id"), peerIdentityDigest: artifact.b(role == .client ? "server_identity_digest" : "client_identity_digest"))
  }
  let environment: V4EnvironmentFoundation
  let artifact: V4NamespaceValue
  let client: V4NamespaceValue
  let server: V4NamespaceValue
  private(set) var proof: V4NamespaceValue?
  let route: V4WebSocketRoute
  let maxStreams: Int
  let maxCredit: UInt64
  let idleMS: UInt64
  let applicationProfile: UInt64
  let maximumGeneralOutstanding: Int
  let resumeEnabled: Bool
  let maximumResumeTokenBytes: Int
  let maximumResumeTokenDurationMS: UInt64
  var slots: Int { min(2 * maxStreams + 128, 4096) + 128 }
  var window: UInt64 { min(16384, maxCredit / UInt64(max(1, maxStreams))) }
  func installLiveAuthorization(_ bytes: Data, signingKeyID: String, configuration: V4CredentialConfiguration) throws {
    try environment.gate.withLock {
      guard proof == nil else { throw V4CryptoFailure.phase }
      if credential.pathKind == 1 {
        #if os(macOS) || os(iOS)
        let material = try V4LiveTunnelMaterial.decode(bytes)
        let activation = try credential.completeLiveAuthorization(material.activation, signingKeyID: signingKeyID, configuration: configuration)
        try credential.completeLiveTunnelGrant(material.grant)
        proof = activation
        #else
        throw V4CryptoFailure.configuration
        #endif
      } else { proof = try credential.completeLiveAuthorization(bytes, signingKeyID: signingKeyID, configuration: configuration) }
      credential.connectionFacts.spent()
    }
  }
  #if os(macOS) || os(iOS)
  func installOriginalServerActivation(_ bytes: Data, registration: V4LiveServerRegistration,
    configuration: V4CredentialConfiguration) throws {
    try environment.gate.withLock {
      guard proof == nil, role == .server, registration.plan === self else { throw V4CryptoFailure.phase }
      try registration.checkCarrierAdmission()
      proof = try credential.completeLiveAuthorization(bytes, signingKeyID: registration.activationSigningKeyID, configuration: configuration)
    }
  }
  #endif
  func activationProof() throws -> V4NamespaceValue {
    try environment.gate.withLock {
      try credential.checkPreparation(in: environment)
      guard let proof else { throw V4CryptoFailure.phase }
      return proof
    }
  }
  fileprivate init(
    credential: V4CredentialAdmission, environment: V4EnvironmentFoundation,
    artifact: V4NamespaceValue, client: V4NamespaceValue, server: V4NamespaceValue,
    proof: V4NamespaceValue?, route: V4WebSocketRoute
  ) throws {
    self.credential = credential
    self.environment = environment
    self.artifact = artifact
    self.client = client
    self.server = server
    self.proof = proof
    self.route = route
    let contract = try artifact.field("session_contract")
    maxStreams = try Int(contract.u("max_streams"))
    maxCredit = try contract.u("max_credit")
    idleMS = try contract.u("idle_duration_ms")
    applicationProfile = try contract.u("application_profile")
    maximumGeneralOutstanding = applicationProfile == 0 ? 0 : try Int(contract.u("rpc_max_general_outstanding"))
    let resume = try artifact.field("resume_policy")
    resumeEnabled = try resume.field("enabled").equals(true)
    maximumResumeTokenBytes = resumeEnabled ? try Int(resume.u("max_token_bytes")) : 0
    maximumResumeTokenDurationMS = resumeEnabled ? try resume.u("max_issued_token_duration_ms") : 0
    if resumeEnabled {
      guard applicationProfile == 2, try resume.u("purpose") == 0, try resume.u("scope") == 0,
        maximumResumeTokenBytes > 0, maximumResumeTokenDurationMS > 0, try artifact.u("allowed_features") & 2 != 0 else {
        throw V4CryptoFailure.configuration
      }
    }
    if idleMS > 0 {
      guard idleMS >= 45_000,
        idleMS > (try environment.clock.profile.elapsed(0)).upperMS,
        try environment.clock.profile.deadlineDelta(upper: 0, deadline: idleMS) > 0
      else { throw V4CryptoFailure.configuration }
    }
    guard applicationProfile <= 2,
      applicationProfile == 0 || (1...1024).contains(maximumGeneralOutstanding),
      try artifact.u("required_features") & ~UInt64(2) == 0,
      try artifact.u("required_features") & 2 == 0 || resumeEnabled,
      (1...1024).contains(maxStreams), maxCredit >= UInt64(maxStreams), maxCredit <= 8 << 20
    else { throw V4CryptoFailure.configuration }
    let phaseBytes = 268 + 21 * maxStreams
    guard phaseBytes + 36 <= route.maximumFrame, 2 * phaseBytes + 3 <= 65536 else {
      throw V4CryptoFailure.capacity
    }
    let envelope = try contract.field("rekey_envelope")
    let credit = try V4RekeyCredit(
      burst: envelope.u("burst_rounds"),
      period: envelope.u("refill_period_ms"), startBudget: envelope.u("request_start_budget_ms"),
      serviceMS: artifact.u("session_not_after_ms") - artifact.u("issued_at_ms"),
      clock: environment.clock)
    if idleMS > 0, idleMS < credit.period + credit.startBudget + 45_000 {
      throw V4CryptoFailure.configuration
    }
  }
}
