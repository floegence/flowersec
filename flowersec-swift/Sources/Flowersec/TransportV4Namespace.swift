import Clibsodium
import Foundation

struct V4NamespaceTrustRoot: Sendable {
  let tenant: String
  let authority: String
  let keyID: Data
  let publicKey: Data
  let maximumTrustLifetimeMS: UInt64
}

struct V4NamespaceConfiguration: Sendable {
  let stateBytes: Int
  let stateNodes: Int
  let bootstrapMS: UInt64
}

// A pinned in-process namespace owner. Only the original Environment can
// construct it, and every admission checks the original reservation and clock.
// Trust replacement/durable continuity and credential minting are unavailable;
// this owner verifies one immutable TrustConfig and complete Head/State updates.
final class V4NamespaceVerifier: @unchecked Sendable {
  private struct Head {
    let value: V4NamespaceValue
    let deadline: V4SecurityDeadline
    let sequence: UInt64
    let floors: [UInt64]
  }
  private static let trustBytes = 262_144
  private static let responseBytes = 270_336
  private static let trustNodes = 32_768
  private static let headNodes = 128
  private let environment: V4EnvironmentFoundation
  private let pinnedRoot: V4NamespaceTrustRoot
  private let configuration: V4NamespaceConfiguration
  private let registry: V4NamespaceRegistry
  private let reservation: V4ResourceReference
  private let bootstrapDeadline: V4SecurityDeadline
  private let bootstrapWindow: V4LocalWorkWindow
  private var nonce: Data
  private var trust: V4NamespaceValue?
  private var trustDeadline: V4SecurityDeadline?
  private var observed: Head?
  private var active: Head?
  private var state: V4NamespaceValue?
  private var closed = false
  private var limits: [String: UInt64] = [:]
  private var capacityDigest = Data()

  static func charge(_ configuration: V4NamespaceConfiguration) throws -> V4ResourceVector {
    guard configuration.stateBytes > 0, configuration.stateBytes <= 1 << 24,
      configuration.stateNodes > 0, configuration.stateNodes <= 1 << 20,
      configuration.bootstrapMS > 0, configuration.bootstrapMS <= 90_000
    else { throw V4NamespaceFailure.configuration }
    // Original input, retained/next State, parse slabs and temporary signature
    // preimages coexist. The generated immutable registry is also covered.
    let nodeBytes =
      UInt64(trustNodes + configuration.stateNodes + headNodes)
      * UInt64(MemoryLayout<V4NamespaceDocument.Node>.stride)
    let bytes =
      V4NamespaceRegistry.backingBytes + 8
      * (UInt64(trustBytes + responseBytes + configuration.stateBytes) + nodeBytes) + 8192
    return V4ResourceVector(sdkBytes: bytes, items: 1, work: 1)
  }

  // The factory is internal and proves this reference belongs to the original
  // Environment. No caller-authenticated flag or key learned from wire input.
  init(_ admission: V4NamespaceAdmission) throws {
    let environment = admission.environment
    let pinnedRoot = admission.pinnedRoot
    let configuration = admission.configuration
    let reservation = admission.reservation
    guard reservation.belongs(to: environment.account),
      V4NamespaceRegistry.securityID(pinnedRoot.tenant.utf8),
      V4NamespaceRegistry.securityID(pinnedRoot.authority.utf8),
      pinnedRoot.keyID.count == 16, pinnedRoot.keyID.contains(where: { $0 != 0 }),
      Self.validKey(pinnedRoot.publicKey), pinnedRoot.maximumTrustLifetimeMS > 0
    else { throw V4NamespaceFailure.configuration }
    _ = try Self.charge(configuration)
    self.environment = environment
    self.pinnedRoot = pinnedRoot
    self.configuration = configuration
    self.reservation = reservation
    self.registry = try V4NamespaceRegistry()
    let sample = environment.clock.sample()
    guard let interval = sample.interval else { throw V4TimeFailure.unavailable }
    bootstrapDeadline = try V4SecurityDeadline(
      clock: environment.clock, capMS: Self.add(interval.lowerMS, configuration.bootstrapMS))
    bootstrapWindow = try V4LocalWorkWindow(
      clock: environment.clock, durationMS: configuration.bootstrapMS)
    var generator = SystemRandomNumberGenerator()
    nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
  }

  deinit { reservation.release() }

  private static func validKey(_ key: Data) -> Bool {
    guard key.count == 32, sodium_init() >= 0 else { return false }
    return key.withUnsafeBytes {
      crypto_core_ed25519_is_valid_point($0.bindMemory(to: UInt8.self).baseAddress!) == 1
    }
  }
  private static func add(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
    let (value, overflow) = a.addingReportingOverflow(b)
    guard !overflow else { throw V4NamespaceFailure.untrusted }
    return value
  }
  private func sample() throws -> V4TimeInterval {
    guard !closed else { throw V4NamespaceFailure.closed }
    try reservation.check()
    let sample = environment.clock.sample()
    guard let interval = sample.interval else { throw sample.failure ?? V4TimeFailure.unavailable }
    return interval
  }
  private func time(_ from: UInt64, _ until: UInt64, now: V4TimeInterval) throws {
    guard from < until, now.upperMS < until else { throw V4TimeFailure.expired }
    guard from <= now.upperMS else { throw V4NamespaceFailure.untrusted }
    guard from <= now.lowerMS else { throw V4TimeFailure.pending }
  }
  private func namespace(_ value: V4NamespaceValue) throws {
    guard try value.t("tenant_id") == pinnedRoot.tenant,
      try value.t("revocation_authority_id") == pinnedRoot.authority
    else { throw V4NamespaceFailure.untrusted }
  }
  private func root(_ value: V4NamespaceValue) throws {
    try namespace(value)
    guard try value.b("signing_key_id") == pinnedRoot.keyID else {
      throw V4NamespaceFailure.untrusted
    }
  }
  private func binding(_ value: V4NamespaceValue, trust: V4NamespaceValue, digest: Data) throws {
    try namespace(value)
    guard try value.u("authority_generation") == trust.u("authority_generation"),
      try value.b("namespace_capacity_digest") == digest
    else { throw V4NamespaceFailure.untrusted }
  }

  func bootstrapNonce() throws -> Data {
    try environment.gate.withLock {
      _ = try sample()
      guard trust == nil else { throw V4NamespaceFailure.closed }
      try bootstrapDeadline.check()
      try bootstrapWindow.check()
      return Data(nonce)
    }
  }

  func bootstrap(response: Data, state bytes: Data) throws {
    try environment.gate.withLock {
      let now = try sample()
      guard trust == nil else { throw V4NamespaceFailure.closed }
      try bootstrapDeadline.check()
      try bootstrapWindow.check()
      let reply = try V4NamespaceDocument(
        response, schema: "TrustBootstrapResponse", bytes: Self.responseBytes,
        nodes: Self.trustNodes, registry: registry
      ).root
      try root(reply)
      try reply.verify("trust_bootstrap_signature", publicKey: pinnedRoot.publicKey)
      guard try reply.b("request_nonce") == nonce else { throw V4NamespaceFailure.untrusted }
      try time(reply.u("issued_at_ms"), reply.u("not_after_ms"), now: now)
      let candidate = try V4NamespaceDocument(
        reply.b("trust_config"), schema: "TrustConfig", bytes: Self.trustBytes,
        nodes: Self.trustNodes, registry: registry
      ).root
      let (digest, constraints) = try validateTrust(candidate, now: now)
      let head = try verifyHead(
        reply.b("freshness_head"), trust: candidate, digest: digest, now: now)
      let state = try verifyState(
        bytes, head: head, trust: candidate, digest: digest,
        limits: constraints, now: now)
      let deadline = try V4SecurityDeadline(
        clock: environment.clock, capMS: candidate.u("not_after_ms"))
      // No partially authenticated bootstrap state escapes this commit gate.
      _ = try sample()
      try bootstrapDeadline.check()
      try bootstrapWindow.check()
      try head.deadline.check()
      try deadline.check()
      trust = candidate
      trustDeadline = deadline
      capacityDigest = digest
      limits = constraints
      observed = head
      active = head
      self.state = state
      nonce.resetBytes(in: nonce.indices)
    }
  }

  private func validateTrust(_ trust: V4NamespaceValue, now: V4TimeInterval) throws
    -> (Data, [String: UInt64])
  {
    try root(trust)
    try trust.verify("trust_config_signature", publicKey: pinnedRoot.publicKey)
    let start = try trust.u("issued_at_ms")
    let end = try trust.u("not_after_ms")
    try time(start, end, now: now)
    guard end - start <= pinnedRoot.maximumTrustLifetimeMS,
      try trust.u("authority_generation") > 0
    else { throw V4NamespaceFailure.untrusted }
    let capacity = try trust.field("capacity")
    let publication = try trust.field("publication")
    let digest = try capacity.digest("namespace_capacity_digest")
    guard try capacity.u("max_state_encoded_bytes") <= configuration.stateBytes,
      try capacity.u("max_head_encoded_bytes") >= 795,
      try UInt64(trust.raw.count) <= capacity.u("max_trust_proof_bytes")
    else { throw V4NamespaceFailure.capacity }
    var constraints: [String: UInt64] = [:]
    for name in [
      "max_state_encoded_bytes", "max_revoked_issuers", "max_revoked_certificates",
      "max_revoked_leases", "max_cohort_policy_segments",
    ] {
      constraints[name] = try capacity.u(name)
    }
    constraints["max_revoked_issuer_authorizations"] = try capacity.u("max_trust_proof_entries")
    var entries: UInt64 = 0
    for field in [
      "credential_policies", "issuer_authorizations", "head_delegations",
      "activation_delegations", "once_authorities",
    ] {
      entries = try Self.add(entries, UInt64(trust.field(field).count))
    }
    guard entries <= (try capacity.u("max_trust_proof_entries")) else {
      throw V4NamespaceFailure.capacity
    }
    for field in ["issuer_authorizations", "head_delegations", "activation_delegations"] {
      for entry in try trust.field(field).children {
        try binding(entry, trust: trust, digest: digest)
        let key = try entry.b(
          field == "issuer_authorizations" ? "issuer_public_key" : "signer_public_key")
        guard Self.validKey(key) else { throw V4NamespaceFailure.untrusted }
        if field == "head_delegations" {
          try publicationBinding(entry, publication)
          guard
            try entry.u("not_after_ms") - entry.u("issued_at_ms")
              <= publication.u("max_signer_lifetime_ms")
          else { throw V4NamespaceFailure.untrusted }
        }
      }
    }
    // Revocation identity fixes a single original key across all authorizations.
    for field in ["issuer_authorizations", "activation_delegations"] {
      for entry in try trust.field(field).children {
        let id = try entry.b("issuer_key_id")
        let key = try entry.b(
          field == "issuer_authorizations" ? "issuer_public_key" : "signer_public_key")
        for otherField in ["issuer_authorizations", "activation_delegations"] {
          for other in try trust.field(otherField).children {
            if try other.b("issuer_key_id") == id {
              guard
                try other.b(
                  otherField == "issuer_authorizations" ? "issuer_public_key" : "signer_public_key")
                  == key
              else { throw V4NamespaceFailure.untrusted }
            }
          }
        }
      }
    }
    for entry in try trust.field("once_authorities").children {
      guard try entry.t("tenant_id") == pinnedRoot.tenant else {
        throw V4NamespaceFailure.untrusted
      }
    }
    for field in ["retired_issuers", "rejected_head_signers"] {
      let array = try trust.field(field)
      for item in array.children {
        for before in array.children {
          if before.index == item.index { break }
          guard !before.raw.elementsEqual(item.raw) else { throw V4NamespaceFailure.untrusted }
        }
      }
    }
    return (digest, constraints)
  }

  private func publicationBinding(_ value: V4NamespaceValue, _ publication: V4NamespaceValue) throws
  {
    for name in ["publication_policy_id", "publication_policy_revision"] {
      guard try value.field(name).raw.elementsEqual(publication.field(name).raw) else {
        throw V4NamespaceFailure.untrusted
      }
    }
  }

  private func verifyHead(
    _ bytes: Data, trust: V4NamespaceValue, digest: Data,
    now: V4TimeInterval
  ) throws -> Head {
    let head = try V4NamespaceDocument(
      bytes, schema: "FreshnessHead", bytes: 795, nodes: Self.headNodes, registry: registry
    ).root
    try binding(head, trust: trust, digest: digest)
    let signerID = try head.b("signing_key_id")
    for rejected in try trust.field("rejected_head_signers").children {
      guard try rejected.bytes() != signerID else { throw V4NamespaceFailure.untrusted }
    }
    guard
      let signer = try trust.field("head_delegations").children.first(where: {
        try $0.b("signer_key_id") == signerID
      }), try signer.digest("head_signer_delegation_digest") == head.b("signer_delegation_digest")
    else { throw V4NamespaceFailure.untrusted }
    try head.verify("freshness_head_signature", publicKey: signer.b("signer_public_key"))
    let publication = try trust.field("publication")
    try publicationBinding(head, publication)
    let start = try head.u("this_update_ms")
    let end = try head.u("next_update_ms")
    let cap = try min(end, signer.u("not_after_ms"), trust.u("not_after_ms"))
    try time(max(start, signer.u("issued_at_ms"), trust.u("issued_at_ms")), cap, now: now)
    guard try start >= signer.u("issued_at_ms"), try end <= signer.u("not_after_ms"),
      try end - start <= publication.u("max_head_validity_ms")
    else { throw V4NamespaceFailure.untrusted }
    let sequence = try head.u("head_sequence")
    let floors = try head.field("credential_revocation_floors").children.map { try $0.uint() }
    if let observed {
      if sequence < observed.sequence { throw V4NamespaceFailure.rollback }
      if sequence == observed.sequence {
        guard head.raw.elementsEqual(observed.value.raw) else {
          close()
          throw V4NamespaceFailure.equivocation
        }
        try observed.deadline.check()
        return observed
      }
      guard try start >= observed.value.u("this_update_ms"),
        floors[0] >= observed.floors[0], floors[1] >= observed.floors[1]
      else { throw V4NamespaceFailure.rollback }
    }
    return try Head(
      value: head, deadline: V4SecurityDeadline(clock: environment.clock, capMS: cap),
      sequence: sequence, floors: floors)
  }

  func refresh(head bytes: Data, state: Data) throws {
    try environment.gate.withLock {
      let now = try sample()
      guard let trust, let trustDeadline else { throw V4NamespaceFailure.notBootstrapped }
      try trustDeadline.check()
      let head = try verifyHead(bytes, trust: trust, digest: capacityDigest, now: now)
      // An authenticated newer Head fences the old State immediately. Failure
      // to retrieve/validate its complete State cannot restore an older Head.
      observed = head
      let next = try verifyState(
        state, head: head, trust: trust, digest: capacityDigest,
        limits: limits, now: now)
      try preserveHistory(next)
      _ = try sample()
      try trustDeadline.check()
      try head.deadline.check()
      self.state = next
      active = head
    }
  }

  func checkCurrent() throws {
    try environment.gate.withLock {
      _ = try sample()
      guard let trustDeadline, let active, let observed, state != nil else {
        throw V4NamespaceFailure.notBootstrapped
      }
      try trustDeadline.check()
      try active.deadline.check()
      guard active.sequence == observed.sequence else { throw V4NamespaceFailure.pendingState }
    }
  }
  var currentSequence: UInt64? {
    environment.gate.withLock {
      do {
        try checkCurrent()
        return active?.sequence
      } catch { return nil }
    }
  }
  var authority: String { pinnedRoot.authority }

  private func verifyState(
    _ bytes: Data, head: Head, trust: V4NamespaceValue, digest: Data,
    limits: [String: UInt64], now: V4TimeInterval
  ) throws -> V4NamespaceValue {
    let state = try V4NamespaceDocument(
      bytes, schema: "RevocationState", bytes: configuration.stateBytes,
      nodes: configuration.stateNodes, registry: registry, limits: limits
    ).root
    guard try UInt64(bytes.count) == head.value.u("state_encoded_bytes"),
      try state.digest("revocation_state_digest") == head.value.b("state_digest")
    else { throw V4NamespaceFailure.untrusted }
    for name in [
      "schema_revision", "tenant_id", "revocation_authority_id", "namespace_capacity_digest",
      "authority_generation", "credential_revocation_floors", "publication_policy_id",
      "publication_policy_revision",
    ] {
      guard try state.field(name).raw.elementsEqual(head.value.field(name).raw) else {
        throw V4NamespaceFailure.untrusted
      }
    }
    try binding(state, trust: trust, digest: digest)
    let capacity = try trust.field("capacity")
    let impacts = try [
      capacity.u("max_certificate_impact_ms"), capacity.u("max_connection_impact_ms"),
    ]
    for kind in 0..<2 where head.floors[kind] > 0 {
      guard now.lowerMS >= (try Self.add(cohortEnd(head.floors[kind] - 1, capacity), impacts[kind]))
      else {
        throw V4TimeFailure.pending
      }
    }
    let segments = try state.field("cohort_policy_segments")
    for segment in segments.children {
      let first = try segment.u("first_cohort")
      let last = try segment.u("last_cohort")
      for (kind, name) in ["certificate_impact_ms", "connection_impact_ms"].enumerated() {
        guard let value = try segment.optional(name) else { continue }
        let impact = try value.uint()
        guard impact <= impacts[kind] else { throw V4NamespaceFailure.untrusted }
        _ = try Self.add(cohortEnd(last, capacity), impact)
        for old in segments.children {
          if old.index == segment.index { break }
          if try old.optional(name) != nil, try first <= old.u("last_cohort"),
            try last >= old.u("first_cohort")
          {
            throw V4NamespaceFailure.untrusted
          }
        }
      }
    }
    for (kind, pair) in [
      ("revoked_certificates", "expires_at_ms"),
      ("revoked_leases", "latest_impact_not_after_ms"),
    ].enumerated() {
      for entry in try state.field(pair.0).children {
        guard try entry.u(pair.1) <= Self.add(cohortEnd(entry.u("cohort"), capacity), impacts[kind])
        else {
          throw V4NamespaceFailure.untrusted
        }
      }
    }
    for issuer in try state.field("revoked_issuers").children {
      try verifyIssuerImpact(issuer, trust: trust)
    }
    return state
  }

  private func cohortEnd(_ cohort: UInt64, _ capacity: V4NamespaceValue) throws -> UInt64 {
    let next = try Self.add(cohort, 1)
    let (offset, overflow) = next.multipliedReportingOverflow(
      by: try capacity.u("cohort_duration_ms"))
    guard !overflow else { throw V4NamespaceFailure.untrusted }
    return try Self.add(capacity.u("cohort_time_origin_ms"), offset)
  }

  private func verifyIssuerImpact(_ issuer: V4NamespaceValue, trust: V4NamespaceValue) throws {
    let id = try issuer.b("issuer_key_id")
    let impacts = try issuer.field("authorizations")
    var matched = 0
    for (field, domain) in [
      ("issuer_authorizations", "credential_issuer_authorization_digest"),
      ("activation_delegations", "connection_activation_delegation_digest"),
    ] {
      for authorization in try trust.field(field).children
      where try authorization.b("issuer_key_id") == id {
        let digest = try authorization.digest(domain)
        guard
          let impact = try impacts.children.first(where: {
            try $0.b("authorization_digest") == digest
          })
        else { throw V4NamespaceFailure.untrusted }
        for name in ["max_affected_cohorts", "signing_not_before_ms", "signing_not_after_ms"] {
          guard try impact.field(name).raw.elementsEqual(authorization.field(name).raw) else {
            throw V4NamespaceFailure.untrusted
          }
        }
        matched += 1
      }
    }
    guard matched == impacts.count else { throw V4NamespaceFailure.untrusted }
  }

  private func preserveHistory(_ next: V4NamespaceValue) throws {
    guard let state else { return }
    // This bounded immutable-trust owner does not claim GC or trust retirement.
    // Retain each original denial/segment; exhaustion fails closed until a real
    // continuity owner can prove the independent retirement requirements.
    for field in [
      "revoked_issuers", "revoked_certificates", "revoked_leases", "cohort_policy_segments",
    ] {
      let current = try next.field(field)
      for original in try state.field(field).children {
        if field == "revoked_leases" {
          guard
            let retained = try current.children.first(where: {
              try $0.b("issuer_key_id") == original.b("issuer_key_id")
                && $0.b("lease_id") == original.b("lease_id")
            }), try retained.u("cohort") == original.u("cohort"),
            try retained.b("artifact_digest") == original.b("artifact_digest"),
            try retained.u("latest_impact_not_after_ms") >= original.u("latest_impact_not_after_ms")
          else { throw V4NamespaceFailure.rollback }
          continue
        }
        guard current.children.contains(where: { $0.raw.elementsEqual(original.raw) }) else {
          throw V4NamespaceFailure.rollback
        }
      }
    }
  }

  func close() {
    environment.gate.withLock {
      if closed { return }
      closed = true
      nonce.resetBytes(in: nonce.indices)
      bootstrapDeadline.cancel()
      bootstrapWindow.cancel()
      trustDeadline?.cancel()
      active?.deadline.cancel()
      observed?.deadline.cancel()
      trust = nil
      active = nil
      observed = nil
      state = nil
      limits = [:]
      capacityDigest = Data()
      // The compact owner and pinned root stay charged until the final alias
      // exits. Closing cannot refund the caller's still-retained handle.
      reservation.seal()
    }
  }
}

struct V4CredentialPolicy: Sendable {
  let stalenessMS: UInt64
  let signerLifetimeMS: UInt64
}

// Evidence has no public/memberwise constructor. Only the current namespace
// signature/issuance checks below can mint it for the original Environment.
struct V4CredentialEvidence {
  let namespace: V4NamespaceVerifier
  let kind: Int
  let cohort: UInt64
  let issuer: Data
  let digest: Data
  let lease: Data?
  let permissionDigest: Data
  let policy: V4CredentialPolicy
  let issuedMS: UInt64
  let expiresMS: UInt64
  fileprivate init(
    namespace: V4NamespaceVerifier, kind: Int, cohort: UInt64, issuer: Data,
    digest: Data, lease: Data?, permissionDigest: Data,
    policy: V4CredentialPolicy, issuedMS: UInt64, expiresMS: UInt64
  ) {
    self.namespace = namespace
    self.kind = kind
    self.cohort = cohort
    self.issuer = issuer
    self.digest = digest
    self.lease = lease
    self.permissionDigest = permissionDigest
    self.policy = policy
    self.issuedMS = issuedMS
    self.expiresMS = expiresMS
  }
}

extension V4NamespaceVerifier {
  func checkOwner(_ owner: V4EnvironmentFoundation) throws {
    guard environment === owner else { throw V4NamespaceFailure.untrusted }
    try checkCurrent()
  }

  func matchesCredential(_ value: V4NamespaceValue) throws -> Bool {
    try value.t("tenant_id") == pinnedRoot.tenant
      && value.t("revocation_authority_id") == pinnedRoot.authority
  }

  func checkCredentialReference(_ value: V4NamespaceValue) throws {
    try checkCurrent()
    try namespace(value)
    guard let trust, try value.u("generation") == trust.u("authority_generation"),
      try value.b("namespace_capacity_digest") == capacityDigest,
      try value.u("role_mask") == 3
    else { throw V4NamespaceFailure.untrusted }
  }

  private func credentialBinding(_ value: V4NamespaceValue) throws {
    try checkCurrent()
    try namespace(value)
    guard let trust,
      try value.u("revocation_authority_generation") == trust.u("authority_generation"),
      try value.b("namespace_capacity_digest") == capacityDigest
    else { throw V4NamespaceFailure.untrusted }
  }

  private func credentialPolicy(_ value: V4NamespaceValue) throws -> V4CredentialPolicy {
    guard let trust else { throw V4NamespaceFailure.notBootstrapped }
    guard
      let policy = try trust.field("credential_policies").children.first(where: {
        try $0.t("revocation_policy_id") == value.t("revocation_policy_id")
          && $0.u("revocation_policy_revision") == value.u("revocation_policy_revision")
      })
    else { throw V4NamespaceFailure.untrusted }
    return try V4CredentialPolicy(
      stalenessMS: policy.u("max_staleness_ms"),
      signerLifetimeMS: policy.u("max_head_signer_lifetime_ms"))
  }

  private func credentialImpact(_ cohort: UInt64, kind: Int) throws -> UInt64 {
    guard let trust, let state else { throw V4NamespaceFailure.notBootstrapped }
    let capacity = try trust.field("capacity")
    let name = kind == 0 ? "certificate_impact_ms" : "connection_impact_ms"
    var impact: UInt64?
    for segment in try state.field("cohort_policy_segments").children {
      guard let bound = try segment.optional(name), try cohort >= segment.u("first_cohort"),
        try cohort <= segment.u("last_cohort")
      else { continue }
      guard impact == nil else { throw V4NamespaceFailure.untrusted }
      impact = try bound.uint()
    }
    guard let impact,
      try impact <= capacity.u(kind == 0 ? "max_certificate_impact_ms" : "max_connection_impact_ms")
    else { throw V4NamespaceFailure.untrusted }
    return try Self.add(cohortEnd(cohort, capacity), impact)
  }

  func verifyCredential(
    _ value: V4NamespaceValue, kind: Int,
    originalEnvironment: V4EnvironmentFoundation
  ) throws -> V4CredentialEvidence {
    try environment.gate.withLock {
      try checkOwner(originalEnvironment)
      guard
        kind == 0 && value.schema == "IdentityCertificate"
          || kind == 1 && value.schema == "Artifact"
      else { throw V4NamespaceFailure.untrusted }
      try credentialBinding(value)
      guard let trust else { throw V4NamespaceFailure.notBootstrapped }
      let issued = try value.u("issued_at_ms")
      let end = try value.u(kind == 0 ? "expires_at_ms" : "session_not_after_ms")
      try time(issued, end, now: sample())
      let capacity = try trust.field("capacity")
      let origin = try capacity.u("cohort_time_origin_ms")
      let duration = try capacity.u("cohort_duration_ms")
      let cohort = try value.u("revocation_epoch")
      guard issued >= origin, (issued - origin) / duration == cohort,
        try end <= credentialImpact(cohort, kind: kind)
      else { throw V4NamespaceFailure.untrusted }
      let issuer = try value.b("issuer_key_id")
      guard
        let permission = try trust.field("issuer_authorizations").children.first(where: { entry in
          guard try entry.b("issuer_key_id") == issuer,
            try entry.u("credential_kind") == UInt64(kind),
            try entry.t("audience") == value.t("audience"),
            try entry.t("crypto_profile_id") == value.t("crypto_profile_id"),
            try issued >= entry.u("signing_not_before_ms"),
            try issued < entry.u("signing_not_after_ms"),
            try cohort >= entry.u("first_cohort"), try cohort <= entry.u("last_cohort"),
            try end <= entry.u("max_credential_not_after_ms")
          else { return false }
          if kind == 1 { return true }
          return try entry.t("subject_id") == value.t("subject_id")
            && entry.u("role") == value.u("role")
        })
      else { throw V4NamespaceFailure.untrusted }
      try value.verify(
        kind == 0 ? "certificate_signature" : "artifact_signature",
        publicKey: permission.b("issuer_public_key"))
      let evidence = try V4CredentialEvidence(
        namespace: self, kind: kind, cohort: cohort,
        issuer: issuer, digest: value.digest(kind == 0 ? "certificate_digest" : "artifact_digest"),
        lease: kind == 1 ? value.b("lease_id") : nil,
        permissionDigest: permission.digest("credential_issuer_authorization_digest"),
        policy: credentialPolicy(value), issuedMS: issued, expiresMS: end)
      try checkEvidence(evidence)
      return evidence
    }
  }

  func onceAuthority(_ parent: V4CredentialEvidence) throws -> V4NamespaceValue {
    try environment.gate.withLock {
      try checkEvidence(parent)
      guard parent.namespace === self, parent.kind == 1, let trust,
        let value = try trust.field("once_authorities").children.first(where: {
          try $0.b("artifact_issuer_key_id") == parent.issuer
        })
      else { throw V4NamespaceFailure.untrusted }
      return value
    }
  }

  func verifyActivation(_ value: V4NamespaceValue, parent: V4CredentialEvidence) throws
    -> V4CredentialEvidence
  {
    try environment.gate.withLock {
      guard value.schema == "ActivationAuthorization", parent.namespace === self, parent.kind == 1,
        let trust
      else { throw V4NamespaceFailure.untrusted }
      try checkEvidence(parent)
      let once = try onceAuthority(parent)
      let issued = try value.u("issued_at_ms")
      let until = try value.u("activation_not_after_ms")
      let end = try value.u("session_not_after_ms")
      try time(issued, until, now: sample())
      guard try value.t("tenant_id") == pinnedRoot.tenant,
        try value.t("authority_id") == once.t("spend_authority_id"),
        try value.b("artifact_issuer_key_id") == parent.issuer,
        try value.b("artifact_digest") == parent.digest,
        try value.b("lease_id") == parent.lease,
        try end <= credentialImpact(parent.cohort, kind: 1), end <= parent.expiresMS,
        let permission = try trust.field("activation_delegations").children.first(where: {
          try $0.t("signing_key_id") == value.t("signing_key_id")
        })
      else { throw V4NamespaceFailure.untrusted }
      guard try permission.u("purpose") == 1,
        try permission.b("artifact_issuer_key_id") == parent.issuer,
        try permission.t("authority_id") == value.t("authority_id"),
        try issued >= permission.u("signing_not_before_ms"),
        try issued < permission.u("signing_not_after_ms"),
        try parent.cohort >= permission.u("first_parent_cohort"),
        try parent.cohort <= permission.u("last_parent_cohort"),
        try until <= permission.u("max_activation_not_after_ms"),
        try end <= permission.u("max_session_not_after_ms")
      else { throw V4NamespaceFailure.untrusted }
      try value.verify("activation_signature", publicKey: permission.b("signer_public_key"))
      let evidence = try V4CredentialEvidence(
        namespace: self, kind: 1, cohort: parent.cohort,
        issuer: permission.b("issuer_key_id"), digest: value.digest("activation_digest"),
        lease: nil,
        permissionDigest: permission.digest("connection_activation_delegation_digest"),
        policy: parent.policy, issuedMS: issued, expiresMS: end)
      try checkEvidence(evidence)
      return evidence
    }
  }

  func credentialFreshness(_ policy: V4CredentialPolicy) throws -> (sequence: UInt64, capMS: UInt64)
  {
    try environment.gate.withLock {
      try checkCurrent()
      guard let trust, let active else { throw V4NamespaceFailure.notBootstrapped }
      guard try trust.field("publication").u("max_signer_lifetime_ms") <= policy.signerLifetimeMS
      else {
        throw V4NamespaceFailure.untrusted
      }
      let start = try active.value.u("this_update_ms")
      let cap = try min(
        Self.add(start, policy.stalenessMS), active.value.u("next_update_ms"),
        trust.u("not_after_ms"))
      try time(start, cap, now: sample())
      return (active.sequence, cap)
    }
  }

  func checkEvidence(_ evidence: V4CredentialEvidence) throws {
    try environment.gate.withLock {
      guard evidence.namespace === self else { throw V4NamespaceFailure.untrusted }
      try checkCurrent()
      guard let trust, let state else { throw V4NamespaceFailure.notBootstrapped }
      _ = try credentialFreshness(evidence.policy)
      try time(evidence.issuedMS, evidence.expiresMS, now: sample())
      let floors = try state.field("credential_revocation_floors").children.map { try $0.uint() }
      guard evidence.cohort >= floors[evidence.kind] else { throw V4NamespaceFailure.untrusted }
      for retired in try trust.field("retired_issuers").children {
        guard try retired.bytes() != evidence.issuer else { throw V4NamespaceFailure.untrusted }
      }
      for issuer in try state.field("revoked_issuers").children {
        guard try issuer.b("issuer_key_id") != evidence.issuer else {
          throw V4NamespaceFailure.untrusted
        }
      }
      if evidence.kind == 0 {
        for certificate in try state.field("revoked_certificates").children {
          guard try certificate.b("certificate_digest") != evidence.digest else {
            throw V4NamespaceFailure.untrusted
          }
        }
      }
      if let lease = evidence.lease {
        for entry in try state.field("revoked_leases").children {
          guard try entry.b("issuer_key_id") != evidence.issuer || entry.b("lease_id") != lease
          else {
            throw V4NamespaceFailure.untrusted
          }
        }
      }
    }
  }
}
