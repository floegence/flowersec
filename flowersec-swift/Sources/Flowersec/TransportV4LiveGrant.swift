import Foundation

/// Future Grant authority is independently configured. This value carries no
/// signed Grant, issuer signing capability, replay claim or forwarding right.
public struct TransportGrantScope: Sendable, Equatable, CustomStringConvertible, CustomReflectable {
  public let tenant: String
  public let authority: String
  public let capacityDigest: Data
  public let generation: UInt64
  public let policyID: String
  public let policyRevision: UInt64
  public let issuer: Data
  public let audience: String
  public let service: String
  public let roleMask: UInt64
  public let cohort: UInt64
  public let issuedMS: UInt64
  public let expiresMS: UInt64
  public let parentAuthority: String
  public let parentCapacity: Data
  public let parentGeneration: UInt64
  public let parentIssuer: Data
  public let parentCohort: UInt64
  public init(tenant: String, authority: String, capacityDigest: Data, generation: UInt64,
    policyID: String, policyRevision: UInt64, issuer: Data, audience: String, service: String,
    roleMask: UInt64, cohort: UInt64, issuedMS: UInt64, expiresMS: UInt64,
    parentAuthority: String, parentCapacity: Data, parentGeneration: UInt64, parentIssuer: Data, parentCohort: UInt64) {
    self.tenant = tenant; self.authority = authority; self.capacityDigest = capacityDigest; self.generation = generation
    self.policyID = policyID; self.policyRevision = policyRevision; self.issuer = issuer; self.audience = audience
    self.service = service; self.roleMask = roleMask; self.cohort = cohort; self.issuedMS = issuedMS; self.expiresMS = expiresMS
    self.parentAuthority = parentAuthority; self.parentCapacity = parentCapacity; self.parentGeneration = parentGeneration
    self.parentIssuer = parentIssuer; self.parentCohort = parentCohort
  }
  public var description: String { "Flowersec.GrantScope(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
  static func signed(_ grant: V4NamespaceValue, parent: V4NamespaceValue) throws -> Self {
    let own = try grant.field("namespace")
    return try Self(tenant: grant.t("tenant_id"), authority: own.t("revocation_authority_id"),
      capacityDigest: own.b("namespace_capacity_digest"), generation: own.u("generation"),
      policyID: own.t("revocation_policy_id"), policyRevision: own.u("revocation_policy_revision"),
      issuer: grant.b("issuer_key_id"), audience: grant.t("audience"), service: grant.t("service"),
      roleMask: own.u("role_mask"), cohort: own.u("revocation_epoch"), issuedMS: grant.u("issued_at_ms"), expiresMS: grant.u("not_after_ms"),
      parentAuthority: parent.t("revocation_authority_id"), parentCapacity: parent.b("namespace_capacity_digest"),
      parentGeneration: parent.u("revocation_authority_generation"), parentIssuer: parent.b("issuer_key_id"), parentCohort: parent.u("revocation_epoch"))
  }
  func checkShape() throws {
    guard [tenant, authority, policyID, audience, service, parentAuthority].allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
      capacityDigest.count == 32, capacityDigest.contains(where: { $0 != 0 }), parentCapacity.count == 32,
      parentCapacity.contains(where: { $0 != 0 }), generation > 0, parentGeneration > 0,
      issuer.count == 16, issuer.contains(where: { $0 != 0 }), parentIssuer.count == 16,
      parentIssuer.contains(where: { $0 != 0 }), roleMask == 5 || roleMask == 6, expiresMS > issuedMS
    else { throw V4NamespaceFailure.configuration }
  }
}

typealias V4LiveGrantScope = TransportGrantScope

/// Independently supplied future Grant scope, limits and relay certificate.
/// No field can be filled from a control response or a claimed signer.
public struct TransportLiveTunnelConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let scope: TransportGrantScope
  public let relayCertificate: Data
  public let grantLimits: Data
  public let candidateIndex: Int
  public let issuancePath: String
  public init(scope: TransportGrantScope, relayCertificate: Data, grantLimits: Data,
    candidateIndex: Int = 0, issuancePath: String = "/issue/artifact") {
    self.scope = scope; self.relayCertificate = relayCertificate; self.grantLimits = grantLimits
    self.candidateIndex = candidateIndex; self.issuancePath = issuancePath
  }
  public var description: String { "Flowersec.LiveTunnelConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

/// An original preparation fixes its independently trusted scope and parent
/// before TxA. Completion authenticates only the original TxB local Grant.
/// Native hop/allow/relay admission must separately claim this completion;
/// possession of it alone never permits handshake or forwarding.
final class V4LiveGrantPreparation: @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let namespace: V4NamespaceVerifier
  let scope: V4LiveGrantScope
  private let parent: V4NamespaceValue
  private let parentEvidence: V4CredentialEvidence
  private weak var originalAdmission: V4CredentialAdmission?
  private let originalCandidate: V4NamespaceValue
  private let storage: V4CryptoReservation
  private let endpointRole: V4CryptoRole
  private let expectedLimits: Data
  private let originalRelay: V4NamespaceValue
  private let relayEvidence: V4CredentialEvidence
  private let forwardingDeadline: V4SecurityDeadline
  private let authorizationCache = V4LiveGrantAuthorizationCache()
  private var completed: V4NamespaceValue?
  private var evidence: V4CredentialEvidence?
  private var closed = false
  init(environment: V4EnvironmentFoundation, namespace: V4NamespaceVerifier,
    scope: V4LiveGrantScope, parent: V4NamespaceValue, parentEvidence: V4CredentialEvidence,
    relay: V4NamespaceValue, relayEvidence: V4CredentialEvidence, expectedLimits: Data,
    originalAdmission: V4CredentialAdmission, candidate: V4NamespaceValue, endpointRole: V4CryptoRole? = nil, prepaidStorage: V4CryptoReservation? = nil) throws {
    try scope.checkShape()
    self.endpointRole = endpointRole ?? originalAdmission.localRole
    self.environment = environment; self.namespace = namespace; self.scope = scope
    forwardingDeadline = try V4SecurityDeadline(clock: environment.clock, capMS: scope.expiresMS)
    self.parent = parent; self.parentEvidence = parentEvidence; self.originalRelay = relay
    self.relayEvidence = relayEvidence; self.expectedLimits = expectedLimits
    self.originalAdmission = originalAdmission; self.originalCandidate = candidate
    if let prepaidStorage {
      guard prepaidStorage.environment === environment else { throw V4ResourceFailure.owner }
      try prepaidStorage.check(); storage = prepaidStorage
    } else { storage = try environment.liveGrantPreparationStorage() }
    let registry = try V4NamespaceRegistry()
    _ = try V4NamespaceDocument(expectedLimits, schema: "GrantLimits", bytes: 1024, nodes: 32, registry: registry)
    guard relayEvidence.kind == 0, originalAdmission.artifactDigest == parentEvidence.digest,
      try candidate.u("path_kind") == 1, try candidate.b("candidate_id") == originalAdmission.candidateID,
      try V4CredentialVerifier.routeDocument(candidate, registry: registry).digest("route_digest") == originalAdmission.routeDigest,
      try relay.u("role") == 2,
      try relay.digest("certificate_digest") == relayEvidence.digest else { throw V4NamespaceFailure.untrusted }
    try V4CredentialVerifier.identityKey(relay)
    let matching = try candidate.field("revocation_namespace_refs").children.contains(where: {
      try $0.t("tenant_id") == scope.tenant && $0.t("revocation_authority_id") == scope.authority
        && $0.b("namespace_capacity_digest") == scope.capacityDigest && $0.u("generation") == scope.generation
        && (try $0.u("role_mask") & scope.roleMask) == scope.roleMask
    })
    guard matching else { throw V4NamespaceFailure.untrusted }
    try check()
  }
  func check() throws {
    try environment.gate.withLock {
      guard !closed else { throw V4NamespaceFailure.closed }
      guard let originalAdmission else { throw V4NamespaceFailure.closed }
      try originalAdmission.checkPreparation(in: environment)
      try checkDependencies()
    }
  }
  func checkDependencies() throws {
    try environment.gate.withLock {
      guard !closed else { throw V4NamespaceFailure.closed }
      try storage.check(); try forwardingDeadline.check()
      try parentEvidence.namespace.checkEvidence(parentEvidence)
      try relayEvidence.namespace.checkEvidence(relayEvidence)
      try namespace.checkOwner(environment)
      try namespace.checkLiveGrantDependency(scope, parent: parent, evidence: parentEvidence,
        cache: authorizationCache)
      if let evidence { try namespace.checkEvidence(evidence) }
    }
  }
  func complete(_ bytes: Data, activation: V4NamespaceValue, candidate: V4NamespaceValue,
    client: V4NamespaceValue, server: V4NamespaceValue, relay: V4NamespaceValue) throws {
    try completeVerified(bytes, activation: activation, candidate: candidate, client: client, server: server, relay: relay)
  }
  #if os(macOS) || os(iOS)
  func completeRelayPublication(_ delivery: V4RelayLiveGrantDelivery, candidate: V4NamespaceValue,
    client: V4NamespaceValue, server: V4NamespaceValue) throws {
    guard let originalAdmission else { throw V4NamespaceFailure.closed }
    try delivery.check(admission: originalAdmission)
    try completeVerified(delivery.grant, activation: nil, candidate: candidate, client: client, server: server, relay: originalRelay)
  }
  func completeServerPublication(_ delivery: V4LiveServerGrantDelivery, candidate: V4NamespaceValue,
    client: V4NamespaceValue, server: V4NamespaceValue) throws {
    guard let originalAdmission else { throw V4NamespaceFailure.closed }
    try delivery.check(admission: originalAdmission)
    try completeVerified(delivery.grant, activation: nil, candidate: candidate, client: client, server: server, relay: originalRelay)
  }
  #endif
  private func completeVerified(_ bytes: Data, activation: V4NamespaceValue?, candidate: V4NamespaceValue,
    client: V4NamespaceValue, server: V4NamespaceValue, relay: V4NamespaceValue) throws {
    try environment.gate.withLock {
      try check()
      guard let originalAdmission else { throw V4NamespaceFailure.closed }
      guard completed == nil, evidence == nil, originalAdmission.attemptID.contains(where: { $0 != 0 }),
        candidate.raw.elementsEqual(originalCandidate.raw) else { throw V4CryptoFailure.phase }
      let registry = try V4NamespaceRegistry()
      let grant = try V4NamespaceDocument(bytes, schema: "Grant", bytes: 9302, nodes: 4096, registry: registry).root
      if let activation {
        let activationEvidence = try parentEvidence.namespace.verifyActivation(activation, parent: parentEvidence)
        try activationEvidence.namespace.checkEvidence(activationEvidence)
        guard try activation.b("attempt_id") == originalAdmission.attemptID,
          try activation.raw.elementsEqual(originalAdmission.originalActivation().raw),
          try activation.b("client_identity_digest") == parent.b("client_identity_digest"),
          try activation.b("server_identity_digest") == parent.b("server_identity_digest") else { throw V4NamespaceFailure.untrusted }
      } else {
        guard originalAdmission.source == .liveAuthority else { throw V4CryptoFailure.phase }
      }
      let route = try V4CredentialVerifier.routeDocument(candidate, registry: registry)
      let own = try grant.field("namespace"); let parentRef = try grant.field("parent_ref")
      guard try grant.t("tenant_id") == scope.tenant, try own.t("tenant_id") == scope.tenant,
        try own.t("revocation_authority_id") == scope.authority, try own.b("namespace_capacity_digest") == scope.capacityDigest,
        try own.u("generation") == scope.generation, try own.u("role_mask") == scope.roleMask,
        try own.u("revocation_epoch") == scope.cohort, try own.t("revocation_policy_id") == scope.policyID,
        try own.u("revocation_policy_revision") == scope.policyRevision, try grant.b("issuer_key_id") == scope.issuer,
        try grant.t("audience") == scope.audience, try grant.t("service") == scope.service,
        try grant.u("issued_at_ms") == scope.issuedMS, try grant.u("not_after_ms") == scope.expiresMS,
        try parentRef.t("tenant_id") == scope.tenant, try parentRef.t("revocation_authority_id") == scope.parentAuthority,
        try parentRef.b("namespace_capacity_digest") == scope.parentCapacity, try parentRef.u("authority_generation") == scope.parentGeneration,
        try parentRef.b("artifact_issuer_key_id") == parentEvidence.issuer, try parentRef.b("lease_id") == parentEvidence.lease,
        try parentRef.u("revocation_epoch") == parentEvidence.cohort, try parentRef.b("artifact_digest") == parentEvidence.digest,
        try parentRef.u("issued_at_ms") == parent.u("issued_at_ms"),
        try parentRef.u("initiation_not_after_ms") == parent.u("initiation_not_after_ms"),
        try parentRef.u("session_not_after_ms") == parent.u("session_not_after_ms"),
        try parentRef.t("revocation_policy_id") == parent.t("revocation_policy_id"),
        try parentRef.u("revocation_policy_revision") == parent.u("revocation_policy_revision"),
        try grant.field("route_descriptor").raw.elementsEqual(route.raw),
        try grant.b("route_digest") == route.digest("route_digest"),
        try grant.b("attempt_id") == originalAdmission.attemptID,
        try grant.b("session_contract_digest") == parent.field("session_contract").digest("session_contract_digest"),
        try grant.b("relay_identity_digest") == relayEvidence.digest, relay.raw.elementsEqual(originalRelay.raw)
      else { throw V4NamespaceFailure.untrusted }
      let identities = try grant.field("identity_digests").children.map { try $0.bytes() }
      let sessionEnd = endpointRole == originalAdmission.localRole
        ? originalAdmission.sessionNotAfterMS : try parent.u("session_not_after_ms")
      guard identities == [try client.digest("certificate_digest"), try server.digest("certificate_digest")],
        scope.roleMask == (endpointRole == .client ? 5 : 6),
        scope.expiresMS <= parentEvidence.expiresMS,
        scope.expiresMS <= sessionEnd else { throw V4NamespaceFailure.untrusted }
      let legs = [try route.field("client_leg"), try route.field("server_leg")]
      let grantLegs = try grant.field("legs").children.map { $0 }
      guard legs.count == 2, grantLegs.count == 2 else { throw V4NamespaceFailure.untrusted }
      for index in 0..<2 {
        guard try grantLegs[index].b("leg_id") == legs[index].b("leg_id"),
          try grantLegs[index].u("logical_role") == UInt64(index) else { throw V4NamespaceFailure.untrusted }
      }
      let contract = try parent.field("session_contract"); let limits = try grant.field("limits")
      guard try limits.u("max_envelope_bytes") == contract.u("max_frame") + 8,
        limits.raw.elementsEqual(expectedLimits) else { throw V4NamespaceFailure.untrusted }
      let verified = try namespace.verifyLiveGrant(grant, scope: scope, parent: parent, evidence: parentEvidence)
      try check()
      completed = grant; evidence = verified
    }
  }
  func forwardingRemainingTicks() throws -> UInt64 {
    try environment.gate.withLock { try checkDependencies(); return try forwardingDeadline.remainingTicks() }
  }
  var completedGrant: V4NamespaceValue? { environment.gate.withLock { completed } }
  var completedEvidence: V4CredentialEvidence? { environment.gate.withLock { evidence } }
  var relayCertificate: V4NamespaceValue { originalRelay }
  func close() { environment.gate.withLock { closed = true; forwardingDeadline.cancel(); completed = nil; evidence = nil; storage.seal() } }
  deinit { close() }
}

#if os(macOS) || os(iOS)
struct V4LiveTunnelMaterial: Sendable {
  let activation: Data
  let grant: Data
  static func decode(_ bytes: Data) throws -> Self {
    var cursor = V4PoolWireCursor(bytes, maximum: 73_728)
    try cursor.array(3)
    guard try cursor.text(maximum: 32) == "live-tunnel-material-1" else { throw TransportControlError.responseInvalid }
    let activation = try cursor.bytes(maximum: 4096); let grant = try cursor.bytes(maximum: 9302)
    try cursor.end()
    guard !activation.isEmpty, !grant.isEmpty else { throw TransportControlError.responseInvalid }
    return Self(activation: activation, grant: grant)
  }
}
#endif
