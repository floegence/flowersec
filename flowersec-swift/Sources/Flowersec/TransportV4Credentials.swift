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
}

struct V4CredentialInput: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  let artifact: Data
  let clientCertificate: Data
  let serverCertificate: Data
  let activation: Data
  let source: V4ActivationSource
  let candidateIndex: Int
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
  private let environment: V4EnvironmentFoundation
  private let reservation: V4ResourceReference
  private let preparationDeadline: V4SecurityDeadline
  private let sessionDeadline: V4SecurityDeadline
  private var evidence: [V4CredentialEvidence]
  private var originals: [V4NamespaceValue]
  private var freshness: [Freshness] = []
  private let policy: V4CredentialPolicy
  private var terminal: Error?
  private var closed = false
  private var handshakeClaimed = false
  let artifactDigest: Data
  let certificateDigests: [Data]
  let activationDigest: Data
  let candidateID: Data
  let routeDigest: Data
  let attemptID: Data
  let source: V4ActivationSource
  let cryptoProfile: String
  let initiationNotAfterMS: UInt64
  let sessionNotAfterMS: UInt64
  var description: String { "Flowersec.CredentialAdmission(<redacted>)" }
  var debugDescription: String { description }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }

  fileprivate init(
    admission: V4CredentialWorkAdmission, input: V4CredentialInput,
    originals: [V4NamespaceValue], evidence: [V4CredentialEvidence],
    candidateID: Data, routeDigest: Data, profile: String,
    initiation: UInt64, sessionEnd: UInt64
  ) throws {
    environment = admission.environment
    reservation = admission.reservation
    self.originals = originals
    self.evidence = evidence
    self.candidateID = candidateID
    self.routeDigest = routeDigest
    self.source = input.source
    cryptoProfile = profile
    artifactDigest = evidence[0].digest
    certificateDigests = [evidence[1].digest, evidence[2].digest]
    activationDigest = evidence[3].digest
    attemptID = try originals[3].b("attempt_id")
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

  func claimHandshake(in originalEnvironment: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      try checkPreparation(in: originalEnvironment)
      guard !handshakeClaimed else { throw V4CryptoFailure.phase }
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
      try candidate.u("path_kind") == 0
    else { throw V4NamespaceFailure.untrusted }
    try closure(candidate, evidence: evidence)
    let route = try routeDocument(candidate, registry: registry)
    let routeDigest = try route.digest("route_digest")
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
    return try V4CredentialAdmission(
      admission: admission, input: input, originals: originals, evidence: evidence,
      candidateID: candidate.b("candidate_id"), routeDigest: routeDigest, profile: profile,
      initiation: initiation,
      sessionEnd: min(sessionEnd, evidence[1].expiresMS, evidence[2].expiresMS))
  }

  private static func identityKey(_ certificate: V4NamespaceValue) throws {
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
  let host: String
  let port: Int
  let path: String
  let subprotocol: String
  let origin: String?
  let maximumFrame: Int
  let pins: [V4TLSPin]?
  fileprivate init(
    credential: V4CredentialAdmission, environment: V4EnvironmentFoundation,
    leg: V4NamespaceValue, maximumFrame: Int
  ) throws {
    self.credential = credential
    self.environment = environment
    guard try leg.u("access_class") == 0, try leg.u("carrier") == 1,
      try leg.u("dialer_role") == 0, try leg.u("listener_role") == 1
    else { throw V4CryptoFailure.configuration }
    let tls = try leg.field("tls_policy")
    if try tls.u("mode") == 1 {
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
    guard path == "/flowersec/v4/direct", subprotocol == "flowersec.direct.v4",
      (304...1_048_576).contains(maximumFrame)
    else { throw V4CryptoFailure.configuration }
    let policy = try leg.optional("origin_policy")
    origin = try leg.optional("origin")?.text()
    if let origin {
      if let policy {
        guard try policy.field("origins").children.contains(where: { try $0.text() == origin })
        else {
          throw V4CryptoFailure.configuration
        }
      }
    } else if let policy {
      guard try policy.field("allow_absent").raw.elementsEqual([0xf5]) else {
        throw V4CryptoFailure.configuration
      }
    }
  }
  func check() throws { try credential.checkPreparation(in: environment) }
}
extension V4CredentialAdmission {
  func webSocketRoute(in original: V4EnvironmentFoundation) throws -> V4WebSocketRoute {
    try environment.gate.withLock {
      try checkPreparation(in: original)
      guard
        let candidate = try originals[0].field("candidates").children.first(where: {
          try $0.b("candidate_id") == candidateID
        }), try candidate.u("path_kind") == 0
      else { throw V4CryptoFailure.configuration }
      return try V4WebSocketRoute(
        credential: self, environment: environment,
        leg: candidate.field("direct_leg"),
        maximumFrame: Int(originals[0].field("session_contract").u("max_frame")))
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
      guard source == .preauthorizedPool, identity.profile.rawValue == cryptoProfile,
        try originals[1].b("ed25519_public_key") == identity.identityPublicKey,
        try originals[1].field("noise_static_public_key").b("public_key_bytes")
          == identity.dhPublicKey
      else { throw V4CryptoFailure.key }
      return try V4DirectPoolPlan(
        credential: self, environment: environment,
        artifact: originals[0], client: originals[1], server: originals[2], proof: originals[3],
        route: webSocketRoute(in: original))
    }
  }
}

// The complete original credential projection is prepared before native I/O or
// once consumption. Only direct WSS transport with authenticated-context
// binding is promoted by this implementation.
final class V4DirectPoolPlan: @unchecked Sendable {
  let credential: V4CredentialAdmission
  let environment: V4EnvironmentFoundation
  let artifact: V4NamespaceValue
  let client: V4NamespaceValue
  let server: V4NamespaceValue
  let proof: V4NamespaceValue
  let route: V4WebSocketRoute
  let maxStreams: Int
  let maxCredit: UInt64
  let idleMS: UInt64
  var slots: Int { min(2 * maxStreams + 128, 4096) + 128 }
  var window: UInt64 { min(16384, maxCredit / UInt64(max(1, maxStreams))) }
  fileprivate init(
    credential: V4CredentialAdmission, environment: V4EnvironmentFoundation,
    artifact: V4NamespaceValue, client: V4NamespaceValue, server: V4NamespaceValue,
    proof: V4NamespaceValue, route: V4WebSocketRoute
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
    if idleMS > 0 {
      guard idleMS >= 45_000,
        idleMS > (try environment.clock.profile.elapsed(0)).upperMS,
        try environment.clock.profile.deadlineDelta(upper: 0, deadline: idleMS) > 0
      else { throw V4CryptoFailure.configuration }
    }
    guard try contract.u("application_profile") == 0,
      try artifact.u("required_features") == 0,
      try artifact.field("resume_policy").field("enabled").raw.elementsEqual([0xf4]),
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
