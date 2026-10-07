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

// A pinned in-process namespace owner. Only the original TransportEnvironment can
// construct it, and every admission checks the original reservation and clock.
// Trust replacement is accepted only through the online continuity checks below;
// the complete signed TrustConfig history remains pinned while Head/State updates
// advance. Credential minting still requires the current authenticated pair.
final class V4NamespaceVerifier: @unchecked Sendable {
  private struct Head {
    let value: V4NamespaceValue
    let deadline: V4SecurityDeadline
    let generation: UInt64
    let sequence: UInt64
    let floors: [UInt64]
  }
  private struct TimeCheck {
    let now: V4TimeInterval
    var lowerBound: UInt64 = 0
    var cap: UInt64 = .max

    mutating func issuance(_ start: UInt64, _ end: UInt64) throws {
      guard start < end else { throw V4NamespaceFailure.untrusted }
      guard now.upperMS < end else { throw V4TimeFailure.expired }
      guard start <= now.upperMS else { throw V4NamespaceFailure.futureTimestamp }
      lowerBound = max(lowerBound, start)
      cap = min(cap, end)
    }
    mutating func requireLower(_ bound: UInt64) { lowerBound = max(lowerBound, bound) }
    var pending: Bool { now.lowerMS < lowerBound }
  }
  private struct BootstrapInput {
    let response: Data
    let state: Data
    let head: Head
    let trustDeadline: V4SecurityDeadline
  }
  private var bootstrapInput: BootstrapInput?
  private var bootstrapLowerBound: UInt64 = 0
  private var bootstrapMaterialDeadline: V4SecurityDeadline?
  private var bootstrapWasPending = false
  private var bootstrapFailure: (any Error)?
  private var pendingRefresh: (head: Head, state: Data, trust: Data?)?
  // A TrustConfig supplied while an older Head is already pending has its own
  // proof timeline. Keep it separate from the candidate's original trust so a
  // pending signer revocation cannot be lost on a later Head retry.
  private var pendingTrustUpdate: Data?
  private var retiredRefreshThrough: UInt64?
  private var bootstrapWaiting = false
  #if os(macOS) || os(iOS)
    private let bootstrapEvents = V4SessionEvents(maximum: 1)
  #endif
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
  private var trustBytes: Data?
  private var trustHistory: [Data] = []
  private var trustDeadline: V4SecurityDeadline?
  private var observed: Head?
  private var active: Head?
  private var state: V4NamespaceValue?
  private var closed = false
  private var limits: [String: UInt64] = [:]
  // Complete States that are authenticated before their Head can be installed
  // still carry security denials. Keep the identities independently of the
  // active State so a retained pending candidate cannot erase them. The
  // limits and the byte ceiling are checked before each commit.
  private var denialIssuers: [Data] = []
  private var denialCertificates: [Data] = []
  private var denialLeases: [(issuer: Data, lease: Data)] = []
  private var denialBytes: UInt64 = 0
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
      * (UInt64(trustBytes + responseBytes + configuration.stateBytes) + nodeBytes)
      // Denial identities are retained independently of the active State while
      // a complete newer Head waits for an older candidate. Reserve one bounded
      // identity arena so the retention path cannot grow outside the charge.
      + UInt64(configuration.stateBytes) + 8192
    return V4ResourceVector(sdkBytes: bytes, items: 1, work: 1, tasks: 2, timers: 1)
  }

  // The factory is internal and proves this reference belongs to the original
  // TransportEnvironment. No caller-authenticated flag or key learned from wire input.
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
      let now = try sample()
      guard trust == nil else { throw V4NamespaceFailure.closed }
      try checkBootstrapBounds(now)
      return Data(nonce)
    }
  }

  private func checkBootstrapBounds(_ now: V4TimeInterval) throws {
    if let bootstrapFailure { throw bootstrapFailure }
    // A signed material's original monotonic projection remains a hard
    // expiry even if a later anchor narrows the current trusted interval.
    do { try bootstrapMaterialDeadline?.check() } catch V4TimeFailure.expired {
      bootstrapFailure = V4TimeFailure.expired
      throw V4TimeFailure.expired
    }
    do {
      try bootstrapDeadline.check()
      try bootstrapWindow.check()
    } catch V4TimeFailure.expired {
      let failure: V4NamespaceFailure = bootstrapWasPending ? .timeNotProven : .bootstrapDeadline
      bootstrapFailure = failure
      throw failure
    }
  }

  func bootstrap(response: Data, state bytes: Data) throws {
    try bootstrap(response: response, state: bytes, waiting: false)
  }

  #if os(macOS) || os(iOS)
    // The original reservation prepays one timer and its structured close waiter.
    // The snapshot, provider tail and namespace execution tail survive until both
    // child tasks have physically exited, including cancellation and owner close.
    func bootstrapWhenReady(response: Data, state: Data) async throws {
      let tail = try environment.gate.withLock {
        _ = try sample()
        guard !bootstrapWaiting else { throw V4NamespaceFailure.closed }
        let tail = try reservation.borrow(executionTail: true)
        bootstrapWaiting = true
        return tail
      }
      defer {
        environment.gate.withLock {
          // The cancellation handler can race task unwinding. Seal under the
          // same gate before making this owner available to another caller.
          if Task.isCancelled { cancelBootstrapWait() }
          bootstrapWaiting = false
        }
        tail.release()
      }
      try await withTaskCancellationHandler {
        while true {
          try Task.checkCancellation()
          do {
            try bootstrap(response: response, state: state, waiting: true)
            return
          } catch V4TimeFailure.pending {
            let revision = bootstrapEvents.revision
            let delay = try environment.gate.withLock {
              let now = try sample()
              try checkBootstrapBounds(now)
              return try min(
                environment.clock.profile.proveDelta(
                  lower: now.lowerMS, bound: bootstrapLowerBound),
                bootstrapDeadline.remainingTicks(),
                bootstrapMaterialDeadline?.remainingTicks() ?? .max)
            }
            try await withThrowingTaskGroup(of: Void.self) { group in
              group.addTask { try await Task.sleep(for: .milliseconds(delay)) }
              group.addTask { [bootstrapEvents] in try await bootstrapEvents.wait(after: revision) }
              defer { group.cancelAll() }
              _ = try await group.next()
            }
          }
        }
      } onCancel: {
        self.cancelBootstrapWait()
      }
    }

    private func cancelBootstrapWait() {
      environment.gate.withLock {
        guard trust == nil else { return }
        // Cancellation terminates the original bootstrap gate without replacing
        // its nonce, pending bytes or earliest deadlines, or closing the Environment.
        if bootstrapFailure == nil { bootstrapFailure = V4TimeFailure.canceled }
        bootstrapDeadline.cancel()
        bootstrapWindow.cancel()
        bootstrapEvents.signal()
      }
    }
  #endif

  private func bootstrap(response: Data, state bytes: Data, waiting: Bool) throws {
    try environment.gate.withLock {
      let now = try sample()
      guard trust == nil, !bootstrapWaiting || waiting else { throw V4NamespaceFailure.closed }
      if let bootstrapInput {
        guard bootstrapInput.response == response, bootstrapInput.state == bytes else {
          throw V4NamespaceFailure.untrusted
        }
      }
      var timing = TimeCheck(now: now)
      try checkBootstrapBounds(now)
      let reply = try V4NamespaceDocument(
        response, schema: "TrustBootstrapResponse", bytes: Self.responseBytes,
        nodes: Self.trustNodes, registry: registry
      ).root
      try root(reply)
      try reply.verify("trust_bootstrap_signature", publicKey: pinnedRoot.publicKey)
      guard try reply.b("request_nonce") == nonce else { throw V4NamespaceFailure.untrusted }
      try timing.issuance(reply.u("issued_at_ms"), reply.u("not_after_ms"))
      let candidate = try V4NamespaceDocument(
        reply.b("trust_config"), schema: "TrustConfig", bytes: Self.trustBytes,
        nodes: Self.trustNodes, registry: registry
      ).root
      let (digest, constraints) = try validateTrust(candidate, timing: &timing)
      let verifiedHead = try verifyHead(
        reply.b("freshness_head"), trust: candidate, digest: digest, timing: &timing,
        allowPendingCandidate: false)
      let head = bootstrapInput?.head ?? verifiedHead
      let state = try verifyState(
        bytes, head: head, trust: candidate, digest: digest,
        limits: constraints)
      let deadline =
        try bootstrapInput?.trustDeadline
        ?? V4SecurityDeadline(
          clock: environment.clock, capMS: candidate.u("not_after_ms"))
      // Only a completely verified pair can pin pending input. Every retry keeps
      // its original nonce, bytes and earliest local/security deadlines.
      if let materialDeadline = bootstrapMaterialDeadline {
        try materialDeadline.tighten(to: timing.cap)
      } else {
        bootstrapMaterialDeadline = try V4SecurityDeadline(
          clock: environment.clock, capMS: timing.cap)
      }
      bootstrapWasPending = bootstrapWasPending || timing.pending
      bootstrapLowerBound = max(bootstrapLowerBound, timing.lowerBound)
      // No partially authenticated bootstrap state escapes this commit gate.
      try checkBootstrapBounds(sample())
      try head.deadline.check()
      try deadline.check()
      if timing.pending {
        if bootstrapInput == nil {
          bootstrapInput = BootstrapInput(
            response: Data(response), state: Data(bytes), head: head, trustDeadline: deadline)
        }
        throw V4TimeFailure.pending
      }
      if waiting { try Task.checkCancellation() }
      trust = candidate
      trustBytes = Data(candidate.raw)
      trustHistory = [Data(candidate.raw)]
      trustDeadline = deadline
      capacityDigest = digest
      limits = constraints
      observed = head
      active = head
      self.state = state
      bootstrapInput = nil
      nonce.resetBytes(in: nonce.indices)
    }
  }

  private func validateTrust(_ trust: V4NamespaceValue, timing: inout TimeCheck) throws
    -> (Data, [String: UInt64])
  {
    try root(trust)
    try trust.verify("trust_config_signature", publicKey: pinnedRoot.publicKey)
    let start = try trust.u("issued_at_ms")
    let end = try trust.u("not_after_ms")
    try timing.issuance(start, end)
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

  // A TrustConfig is an append-only authorization journal.  Matching IDs keep
  // their original signed bytes; revocation identities and rejected Head
  // signers are never removed.  A generation change is allowed only after all
  // permissions from the previous generation have been explicitly retired.
  private func validateTrustTransition(
    _ candidate: V4NamespaceValue, state currentState: V4NamespaceValue?
  ) throws {
    guard let current = trust else { return }
    guard trustHistory.count < 8 else { throw V4NamespaceFailure.capacity }
    guard try candidate.u("revision") > current.u("revision"),
      try candidate.u("issued_at_ms") >= current.u("issued_at_ms"),
      try candidate.u("authority_generation") >= current.u("authority_generation")
    else { throw V4NamespaceFailure.rollback }
    for field in ["capacity", "publication"] {
      guard try candidate.field(field).raw.elementsEqual(current.field(field).raw) else {
        throw V4NamespaceFailure.untrusted
      }
    }

    func containsRaw(_ value: V4NamespaceValue, _ raw: ArraySlice<UInt8>) -> Bool {
      value.children.contains { $0.raw.elementsEqual(raw) }
    }
    for originalBytes in trustHistory {
      let original = try V4NamespaceDocument(
        originalBytes, schema: "TrustConfig", bytes: Self.trustBytes,
        nodes: Self.trustNodes, registry: registry).root
      for field in ["retired_issuers", "rejected_head_signers"] {
        for item in try original.field(field).children {
          guard containsRaw(try candidate.field(field), item.raw) else {
            throw V4NamespaceFailure.untrusted
          }
        }
      }
      let identities: [(String, [String])] = [
        ("issuer_authorizations", ["authorization_id"]),
        ("head_delegations", ["delegation_id"]),
        ("activation_delegations", ["signing_key_id"]),
        ("once_authorities", ["artifact_issuer_key_id"]),
        ("credential_policies", ["revocation_policy_id", "revocation_policy_revision"]),
      ]
      for (field, names) in identities {
        for oldEntry in try original.field(field).children {
          for nextEntry in try candidate.field(field).children {
            let same = try names.allSatisfy {
              try oldEntry.field($0).raw.elementsEqual(nextEntry.field($0).raw)
            }
            if same {
              guard oldEntry.raw.elementsEqual(nextEntry.raw) else {
                throw V4NamespaceFailure.untrusted
              }
            }
          }
        }
      }
      // A stable signer/issuer identity cannot acquire a different key in a
      // later revision, even if a caller changes the authorization ID.
      for (field, publicField) in [
        ("issuer_authorizations", "issuer_public_key"),
        ("activation_delegations", "signer_public_key"),
      ] {
        for oldEntry in try original.field(field).children {
          let oldID = try oldEntry.b("issuer_key_id")
          let oldKey = try oldEntry.b(publicField)
          for nextField in ["issuer_authorizations", "activation_delegations"] {
            for nextEntry in try candidate.field(nextField).children
            where try nextEntry.b("issuer_key_id") == oldID {
              guard try nextEntry.b(
                nextField == "issuer_authorizations" ? "issuer_public_key" : "signer_public_key"
              ) == oldKey else { throw V4NamespaceFailure.untrusted }
            }
          }
        }
      }
      if try candidate.u("authority_generation") > original.u("authority_generation") {
        for field in ["issuer_authorizations", "activation_delegations"] {
          for entry in try original.field(field).children {
            guard containsRaw(
              try candidate.field("retired_issuers"), try entry.field("issuer_key_id").raw)
            else { throw V4NamespaceFailure.untrusted }
          }
        }
        for entry in try original.field("head_delegations").children {
          guard containsRaw(
            try candidate.field("rejected_head_signers"), try entry.field("signer_key_id").raw)
          else { throw V4NamespaceFailure.untrusted }
        }
      }
    }

    // A newly introduced permission cannot reuse an issuer that is already
    // retired in the lineage or revoked in the currently installed State.
    let groups = ["issuer_authorizations", "activation_delegations"]
    for field in groups {
      for entry in try candidate.field(field).children {
        let issuer = try entry.b("issuer_key_id")
        let known = try trustHistory.contains { originalBytes in
          let original = try V4NamespaceDocument(
            originalBytes, schema: "TrustConfig", bytes: Self.trustBytes,
            nodes: Self.trustNodes, registry: registry).root
          return try original.field(field).children.contains { old in
            old.raw.elementsEqual(entry.raw)
          }
        }
        if !known {
          if try candidate.field("retired_issuers").children.contains(where: { try $0.bytes() == issuer }) {
            throw V4NamespaceFailure.untrusted
          }
          if let currentState,
            try currentState.field("revoked_issuers").children.contains(where: { try $0.b("issuer_key_id") == issuer })
          {
            throw V4NamespaceFailure.untrusted
          }
        }
      }
    }
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
    timing: inout TimeCheck, allowPendingCandidate: Bool = false
  ) throws -> Head {
    let head = try V4NamespaceDocument(
      bytes, schema: "FreshnessHead", bytes: 795, nodes: Self.headNodes, registry: registry
    ).root
    try binding(head, trust: trust, digest: digest)
    let signerID = try head.b("signing_key_id")
    for rejected in try trust.field("rejected_head_signers").children {
      if try rejected.bytes() == signerID {
        if allowPendingCandidate && timing.pending { break }
        throw V4NamespaceFailure.untrusted
      }
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
    try timing.issuance(max(start, signer.u("issued_at_ms"), trust.u("issued_at_ms")), cap)
    guard try start >= signer.u("issued_at_ms"), try end <= signer.u("not_after_ms"),
      try end - start <= publication.u("max_head_validity_ms")
    else { throw V4NamespaceFailure.untrusted }
    let sequence = try head.u("head_sequence")
    let generation = try trust.u("authority_generation")
    let floors = try head.field("credential_revocation_floors").children.map { try $0.uint() }
    let capacity = try trust.field("capacity")
    guard try UInt64(bytes.count) <= capacity.u("max_head_encoded_bytes"),
      try head.u("state_encoded_bytes") <= capacity.u("max_state_encoded_bytes")
    else { throw V4NamespaceFailure.untrusted }
    let impacts = try [
      capacity.u("max_certificate_impact_ms"), capacity.u("max_connection_impact_ms"),
    ]
    for kind in 0..<2 where floors[kind] > 0 {
      timing.requireLower(try Self.add(cohortEnd(floors[kind] - 1, capacity), impacts[kind]))
    }
    if let observed, !allowPendingCandidate {
      if generation < observed.generation { throw V4NamespaceFailure.rollback }
      if generation == observed.generation, sequence < observed.sequence {
        throw V4NamespaceFailure.rollback
      }
      if generation == observed.generation, sequence == observed.sequence {
        guard head.raw.elementsEqual(observed.value.raw) else {
          close()
          throw V4NamespaceFailure.equivocation
        }
        try observed.deadline.check()
        return observed
      }
      if generation == observed.generation {
        guard try start >= observed.value.u("this_update_ms"),
          floors[0] >= observed.floors[0], floors[1] >= observed.floors[1]
        else { throw V4NamespaceFailure.rollback }
      }
    }
    return try Head(
      value: head, deadline: V4SecurityDeadline(clock: environment.clock, capMS: cap),
      generation: try trust.u("authority_generation"), sequence: sequence, floors: floors)
  }

  func refresh(trust trustBytes: Data? = nil, head bytes: Data, state: Data) throws {
    try environment.gate.withLock {
      let now = try sample()
      guard let installedTrust = trust, let installedDeadline = trustDeadline,
        let installedTrustBytes = self.trustBytes
      else { throw V4NamespaceFailure.notBootstrapped }
      try installedDeadline.check()
      var timing = TimeCheck(now: now)
      if let pendingRefresh {
        do { try pendingRefresh.head.deadline.check() } catch V4TimeFailure.expired {
          retiredRefreshThrough = max(retiredRefreshThrough ?? 0, pendingRefresh.head.sequence)
          self.pendingRefresh = nil
        }
      }
      let samePending = pendingRefresh.map {
        $0.head.value.raw.elementsEqual(bytes) && $0.state == state
      } ?? false

      // A retry of a pending candidate must use the exact TrustConfig that
      // authenticated its original Head. Otherwise a newly published trust
      // revision could silently rewrite the candidate's authorization context.
      // An explicitly supplied revision is an independent publication even
      // while the Head retry is pending. With no revision, retain the exact
      // original candidate authorization context.
      let requestedTrustBytes = trustBytes ?? pendingTrustUpdate
      let suppliedTrustBytes = requestedTrustBytes ?? (samePending ? pendingRefresh?.trust : nil)
      let pairTrust: V4NamespaceValue
      let pairTrustRaw: Data
      let pairDigest: Data
      let pairLimits: [String: UInt64]
      var trustChanged = false
      if let suppliedTrustBytes {
        pairTrust = try V4NamespaceDocument(
          suppliedTrustBytes, schema: "TrustConfig", bytes: Self.trustBytes,
          nodes: Self.trustNodes, registry: registry).root
        let (digest, constraints) = try validateTrust(pairTrust, timing: &timing)
        pairTrustRaw = Data(suppliedTrustBytes)
        pairDigest = digest
        pairLimits = constraints
        trustChanged = !pairTrustRaw.elementsEqual(installedTrustBytes)
        if trustChanged { try validateTrustTransition(pairTrust, state: self.state) }
      } else {
        pairTrust = installedTrust
        pairTrustRaw = installedTrustBytes
        pairDigest = capacityDigest
        pairLimits = limits
      }

      // Trust authorization is an independent publication stream. Once its
      // own issuance lower bound is proven, publish it before validating the
      // replacement Head/State so a bad pair cannot roll back signer or issuer
      // revocations. A pending trust remains private until its original pair
      // reaches the same commit gate.
      var trustPublished = false
      if trustChanged && !timing.pending {
        self.trust = pairTrust
        self.trustBytes = pairTrustRaw
        trustHistory.append(pairTrustRaw)
        capacityDigest = pairDigest
        limits = pairLimits
        trustDeadline = try V4SecurityDeadline(
          clock: environment.clock, capMS: pairTrust.u("not_after_ms"))
        pendingTrustUpdate = nil
        trustPublished = true
      }

      // If a newly authenticated trust revision rejects a retained signer's
      // identity, release that candidate immediately while keeping the valid
      // active pair and the rejection evidence.
      if !samePending, trustChanged, let pendingRefresh {
        let signer = try pendingRefresh.head.value.b("signing_key_id")
        if try pairTrust.field("rejected_head_signers").children.contains(where: { try $0.bytes() == signer }) {
          retiredRefreshThrough = max(retiredRefreshThrough ?? 0, pendingRefresh.head.sequence)
          self.pendingRefresh = nil
        }
      }
      if samePending {
        let signer = try pendingRefresh!.head.value.b("signing_key_id")
        let revokedByCurrent = try self.trust!.field("rejected_head_signers").children.contains(where: { try $0.bytes() == signer })
        let revokedByCandidate = try pairTrust.field("rejected_head_signers").children.contains(where: { try $0.bytes() == signer })
        if revokedByCurrent || (!timing.pending && revokedByCandidate) {
          retiredRefreshThrough = max(retiredRefreshThrough ?? 0, pendingRefresh!.head.sequence)
          self.pendingRefresh = nil
          throw V4NamespaceFailure.untrusted
        }
      }
      let verifiedHead = try verifyHead(
        bytes, trust: pairTrust, digest: pairDigest, timing: &timing,
        allowPendingCandidate: samePending)
      if let pendingRefresh, !samePending,
        (verifiedHead.generation < pendingRefresh.head.generation
          || (verifiedHead.generation == pendingRefresh.head.generation
            && verifiedHead.sequence <= pendingRefresh.head.sequence))
      {
        throw V4NamespaceFailure.untrusted
      }
      if let retiredRefreshThrough, verifiedHead.sequence <= retiredRefreshThrough,
        verifiedHead.generation == (observed?.generation ?? verifiedHead.generation)
      {
        throw V4TimeFailure.expired
      }
      let head = samePending ? pendingRefresh!.head : verifiedHead
      _ = try sample()
      if trustPublished { try trustDeadline!.check() } else { try installedDeadline.check() }
      try head.deadline.check()
      if !timing.pending && !samePending { observed = head }
      let next = try verifyState(
        state, head: head, trust: pairTrust, digest: pairDigest, limits: pairLimits)
      try preserveHistory(next)
      if !timing.pending { try recordDenials(next) }
      if !samePending, pendingRefresh != nil {
        throw V4TimeFailure.pending
      }
      _ = try sample()
      if trustPublished { try trustDeadline!.check() } else { try installedDeadline.check() }
      try head.deadline.check()
      if timing.pending {
        if samePending, requestedTrustBytes != nil, trustChanged {
          pendingTrustUpdate = pairTrustRaw
        }
        if pendingRefresh == nil {
          // Keep the exact TrustConfig that authenticated this Head. Even if
          // another revision is published while it waits, retrying H2 must
          // never silently switch authorization context.
          pendingRefresh = (head: head, state: Data(state), trust: pairTrustRaw)
        }
        throw V4TimeFailure.pending
      }
      if samePending, let active,
        active.generation > head.generation
          || (active.generation == head.generation && active.sequence >= head.sequence)
      {
        self.pendingRefresh = nil
        throw V4NamespaceFailure.rollback
      }
      if trustChanged && !trustPublished {
        trust = pairTrust
        self.trustBytes = pairTrustRaw
        trustHistory.append(pairTrustRaw)
        capacityDigest = pairDigest
        limits = pairLimits
        trustDeadline = try V4SecurityDeadline(
          clock: environment.clock, capMS: pairTrust.u("not_after_ms"))
        pendingTrustUpdate = nil
      }
      if observed == nil || head.generation > observed!.generation
        || (head.generation == observed!.generation && head.sequence >= observed!.sequence)
      { observed = head }
      self.state = next
      active = head
      if samePending || pendingRefresh == nil { pendingRefresh = nil }
    }
  }

  func refresh(head bytes: Data, state: Data) throws {
    try refresh(trust: nil, head: bytes, state: state)
  }

  func checkCurrent() throws {
    try environment.gate.withLock {
      _ = try sample()
      guard let trustDeadline, let active, observed != nil, state != nil else {
        throw V4NamespaceFailure.notBootstrapped
      }
      try trustDeadline.check()
      try active.deadline.check()
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
    limits: [String: UInt64]
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
    // A new authority generation is a deliberate continuity boundary. The
    // TrustConfig transition has already required every old permission to be
    // retired/rejected, so old revocation entries cannot be carried into the
    // fresh generation's state by accident.
    if try next.u("authority_generation") > state.u("authority_generation") { return }
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

  private func recordDenials(_ next: V4NamespaceValue) throws {
    guard let trust else { throw V4NamespaceFailure.notBootstrapped }
    let capacity = try trust.field("capacity")
    var issuers = denialIssuers
    var certificates = denialCertificates
    var leases = denialLeases
    var bytes = denialBytes

    func add(_ value: Data, to target: inout [Data], limitName: String) throws {
      if target.contains(where: { $0.elementsEqual(value) }) { return }
      guard UInt64(target.count) < (try capacity.u(limitName)) else {
        throw V4NamespaceFailure.capacity
      }
      let (nextBytes, overflow) = bytes.addingReportingOverflow(UInt64(value.count))
      guard !overflow, nextBytes <= UInt64(configuration.stateBytes) else {
        throw V4NamespaceFailure.capacity
      }
      target.append(value)
      bytes = nextBytes
    }

    do {
      for issuer in try next.field("revoked_issuers").children {
        try add(
          issuer.b("issuer_key_id"), to: &issuers, limitName: "max_revoked_issuers")
      }
      for certificate in try next.field("revoked_certificates").children {
        try add(
          certificate.b("certificate_digest"), to: &certificates,
          limitName: "max_revoked_certificates")
      }
      for lease in try next.field("revoked_leases").children {
        let issuer = try lease.b("issuer_key_id")
        let value = try lease.b("lease_id")
        if leases.contains(where: { $0.issuer.elementsEqual(issuer) && $0.lease.elementsEqual(value) }) {
          continue
        }
        guard UInt64(leases.count) < (try capacity.u("max_revoked_leases")) else {
          throw V4NamespaceFailure.capacity
        }
        let (afterIssuer, issuerOverflow) = bytes.addingReportingOverflow(UInt64(issuer.count))
        let (nextBytes, leaseOverflow) = afterIssuer.addingReportingOverflow(UInt64(value.count))
        guard !issuerOverflow, !leaseOverflow, nextBytes <= UInt64(configuration.stateBytes) else {
          throw V4NamespaceFailure.capacity
        }
        leases.append((issuer: issuer, lease: value))
        bytes = nextBytes
      }
    } catch V4NamespaceFailure.capacity {
      // Denial retention is part of the authorization invariant. If the
      // bounded arena cannot commit the complete set, fence the namespace
      // immediately so the old active pair cannot authorize another use.
      // close() preserves pending owner tails and subscriber reservations.
      close()
      throw V4NamespaceFailure.capacity
    }

    denialIssuers = issuers
    denialCertificates = certificates
    denialLeases = leases
    denialBytes = bytes
    #if os(macOS) || os(iOS)
      bootstrapEvents.signal()
    #endif
  }

  private func clearDenials() {
    func clear(_ value: inout Data) { value.resetBytes(in: value.indices) }
    for index in denialIssuers.indices {
      clear(&denialIssuers[index])
    }
    for index in denialCertificates.indices {
      clear(&denialCertificates[index])
    }
    for index in denialLeases.indices {
      clear(&denialLeases[index].issuer)
      clear(&denialLeases[index].lease)
    }
    denialIssuers.removeAll(keepingCapacity: false)
    denialCertificates.removeAll(keepingCapacity: false)
    denialLeases.removeAll(keepingCapacity: false)
    denialBytes = 0
  }

  func close() {
    environment.gate.withLock {
      if closed { return }
      closed = true
      #if os(macOS) || os(iOS)
        bootstrapEvents.signal()
      #endif
      nonce.resetBytes(in: nonce.indices)
      bootstrapDeadline.cancel()
      bootstrapWindow.cancel()
      bootstrapMaterialDeadline?.cancel()
      bootstrapInput?.head.deadline.cancel()
      bootstrapInput?.trustDeadline.cancel()
      bootstrapInput = nil
      pendingRefresh?.head.deadline.cancel()
      pendingRefresh = nil
      if var pendingTrust = pendingTrustUpdate { pendingTrust.resetBytes(in: pendingTrust.indices) }
      pendingTrustUpdate = nil
      trustDeadline?.cancel()
      active?.deadline.cancel()
      observed?.deadline.cancel()
      trust = nil
      if var bytes = trustBytes { bytes.resetBytes(in: bytes.indices) }
      trustBytes = nil
      for index in trustHistory.indices { trustHistory[index].resetBytes(in: trustHistory[index].indices) }
      trustHistory.removeAll(keepingCapacity: false)
      active = nil
      observed = nil
      state = nil
      limits = [:]
      clearDenials()
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
// signature/issuance checks below can mint it for the original TransportEnvironment.
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

  func matchesGrantScope(_ scope: V4LiveGrantScope) -> Bool {
    scope.tenant == pinnedRoot.tenant && scope.authority == pinnedRoot.authority
  }
  func checkCredentialReference(
    _ value: V4NamespaceValue, requiredRoles: UInt64 = 3,
    allowAdditionalRoles: Bool = false
  ) throws {
    try checkCurrent()
    try namespace(value)
    let roleMask = try value.u("role_mask")
    guard let trust, try value.u("generation") == trust.u("authority_generation"),
      try value.b("namespace_capacity_digest") == capacityDigest,
      roleMask & requiredRoles == requiredRoles,
      allowAdditionalRoles || roleMask == requiredRoles
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

  // A future proof's deployment dependency is checked without minting a
  // CredentialEvidence. Only verifyActivation can authenticate TxB bytes.
  func checkLiveActivationDependency(
    parent: V4CredentialEvidence, signingKeyID: String,
    initiation: UInt64, sessionEnd: UInt64
  ) throws {
    try environment.gate.withLock {
      try checkEvidence(parent)
      guard parent.namespace === self, parent.kind == 1, let trust,
        V4NamespaceRegistry.securityID(signingKeyID.utf8),
        let delegation = try trust.field("activation_delegations").children.first(where: {
          try $0.t("signing_key_id") == signingKeyID
        })
      else { throw V4NamespaceFailure.untrusted }
      let once = try onceAuthority(parent)
      let now = try sample()
      // A live authority may issue a shorter proof than its parent permits.
      // Require a usable intersection here; verifyActivation checks the actual
      // signed proof against every original delegation and parent ceiling.
      guard try delegation.u("purpose") == 1,
        try delegation.b("artifact_issuer_key_id") == parent.issuer,
        try delegation.t("authority_id") == once.t("spend_authority_id"),
        try parent.cohort >= delegation.u("first_parent_cohort"),
        try parent.cohort <= delegation.u("last_parent_cohort"),
        try now.lowerMS >= delegation.u("signing_not_before_ms"),
        try now.upperMS < delegation.u("signing_not_after_ms"),
        try now.upperMS
          < min(
            initiation, sessionEnd,
            delegation.u("max_activation_not_after_ms"), delegation.u("max_session_not_after_ms"))
      else { throw V4NamespaceFailure.untrusted }
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
      guard let trust, let state, let observed else { throw V4NamespaceFailure.notBootstrapped }
      _ = try credentialFreshness(evidence.policy)
      try time(evidence.issuedMS, evidence.expiresMS, now: sample())
      guard evidence.cohort >= observed.floors[evidence.kind] else {
        throw V4NamespaceFailure.untrusted
      }
      for retired in try trust.field("retired_issuers").children {
        guard try retired.bytes() != evidence.issuer else { throw V4NamespaceFailure.untrusted }
      }
      for issuer in try state.field("revoked_issuers").children {
        guard try issuer.b("issuer_key_id") != evidence.issuer else {
          throw V4NamespaceFailure.untrusted
        }
      }
      for issuer in denialIssuers {
        guard !issuer.elementsEqual(evidence.issuer) else {
          throw V4NamespaceFailure.untrusted
        }
      }
      if evidence.kind == 0 {
        for certificate in try state.field("revoked_certificates").children {
          guard try certificate.b("certificate_digest") != evidence.digest else {
            throw V4NamespaceFailure.untrusted
          }
        }
        for certificate in denialCertificates {
          guard !certificate.elementsEqual(evidence.digest) else {
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
        for entry in denialLeases {
          guard !(entry.issuer.elementsEqual(evidence.issuer) && entry.lease.elementsEqual(lease))
          else {
            throw V4NamespaceFailure.untrusted
          }
        }
      }
    }
  }
}

extension V4NamespaceVerifier {
  // Future Grant scope is checked against independently installed own trust,
  // original signed parent and publication policy. No unsigned evidence is
  // constructed, and no hop or replay owner exists at this boundary.
  func checkLiveGrantDependency(
    _ scope: V4LiveGrantScope, parent: V4NamespaceValue,
    evidence: V4CredentialEvidence
  ) throws {
    _ = try liveGrantPermission(scope, parent: parent, evidence: evidence)
  }
  private func liveGrantPermission(
    _ scope: V4LiveGrantScope, parent: V4NamespaceValue,
    evidence: V4CredentialEvidence
  ) throws -> (V4NamespaceValue, V4CredentialPolicy) {
    try environment.gate.withLock {
      try scope.checkShape()
      try checkCurrent()
      try evidence.namespace.checkOwner(environment)
      try evidence.namespace.checkEvidence(evidence)
      guard evidence.kind == 1, parent.schema == "Artifact",
        evidence.digest == (try parent.digest("artifact_digest")),
        scope.tenant == pinnedRoot.tenant, scope.authority == pinnedRoot.authority, let trust,
        let state,
        let observed,
        scope.capacityDigest == capacityDigest,
        scope.generation == (try trust.u("authority_generation")),
        scope.parentIssuer == evidence.issuer, scope.parentCohort == evidence.cohort,
        scope.parentAuthority == (try parent.t("revocation_authority_id")),
        scope.parentCapacity == (try parent.b("namespace_capacity_digest")),
        scope.parentGeneration == (try parent.u("revocation_authority_generation")),
        scope.tenant == (try parent.t("tenant_id")), scope.expiresMS <= evidence.expiresMS,
        scope.cohort >= observed.floors[1],
        scope.expiresMS <= (try credentialImpact(scope.cohort, kind: 1))
      else { throw V4NamespaceFailure.untrusted }
      for retired in try trust.field("retired_issuers").children {
        guard try retired.bytes() != scope.issuer else { throw V4NamespaceFailure.untrusted }
      }
      for issuer in try state.field("revoked_issuers").children {
        guard try issuer.b("issuer_key_id") != scope.issuer else {
          throw V4NamespaceFailure.untrusted
        }
      }
      for issuer in denialIssuers {
        guard !issuer.elementsEqual(scope.issuer) else { throw V4NamespaceFailure.untrusted }
      }
      guard
        let permission = try trust.field("issuer_authorizations").children.first(where: { entry in
          try entry.u("credential_kind") == 2 && entry.b("issuer_key_id") == scope.issuer
            && entry.t("audience") == scope.audience && entry.t("service") == scope.service
            && entry.t("parent_authority_id") == scope.parentAuthority
            && entry.b("parent_capacity_digest") == scope.parentCapacity
            && entry.u("parent_generation") == scope.parentGeneration
            && entry.b("parent_artifact_issuer_key_id") == scope.parentIssuer
            && scope.parentCohort >= entry.u("first_parent_cohort")
            && scope.parentCohort <= entry.u("last_parent_cohort")
            && scope.cohort >= entry.u("first_cohort") && scope.cohort <= entry.u("last_cohort")
            && scope.issuedMS >= entry.u("signing_not_before_ms")
            && scope.issuedMS < entry.u("signing_not_after_ms")
            && scope.expiresMS <= entry.u("max_credential_not_after_ms")
        }),
        let policy = try trust.field("credential_policies").children.first(where: {
          try $0.t("revocation_policy_id") == scope.policyID
            && $0.u("revocation_policy_revision") == scope.policyRevision
        })
      else { throw V4NamespaceFailure.untrusted }
      let requirements = try V4CredentialPolicy(
        stalenessMS: policy.u("max_staleness_ms"),
        signerLifetimeMS: policy.u("max_head_signer_lifetime_ms"))
      _ = try credentialFreshness(requirements)
      try time(scope.issuedMS, scope.expiresMS, now: sample())
      return (permission, requirements)
    }
  }
  func verifyLiveGrant(
    _ grant: V4NamespaceValue, scope: V4LiveGrantScope,
    parent: V4NamespaceValue, evidence: V4CredentialEvidence
  ) throws -> V4CredentialEvidence {
    try environment.gate.withLock {
      let (permission, policy) = try liveGrantPermission(scope, parent: parent, evidence: evidence)
      let own = try grant.field("namespace")
      guard grant.schema == "Grant", try grant.t("tenant_id") == scope.tenant,
        try own.t("tenant_id") == scope.tenant,
        try own.t("revocation_authority_id") == scope.authority,
        try own.b("namespace_capacity_digest") == scope.capacityDigest,
        try own.u("generation") == scope.generation,
        try own.u("role_mask") == scope.roleMask, try own.u("revocation_epoch") == scope.cohort,
        try own.t("revocation_policy_id") == scope.policyID,
        try own.u("revocation_policy_revision") == scope.policyRevision,
        try grant.b("issuer_key_id") == scope.issuer, try grant.t("audience") == scope.audience,
        try grant.t("service") == scope.service, try grant.u("issued_at_ms") == scope.issuedMS,
        try grant.u("not_after_ms") == scope.expiresMS
      else { throw V4NamespaceFailure.untrusted }
      let parentRef = try grant.field("parent_ref")
      guard try parentRef.t("tenant_id") == scope.tenant,
        try parentRef.t("revocation_authority_id") == scope.parentAuthority,
        try parentRef.b("namespace_capacity_digest") == scope.parentCapacity,
        try parentRef.u("authority_generation") == scope.parentGeneration,
        try parentRef.b("artifact_issuer_key_id") == evidence.issuer,
        try parentRef.b("lease_id") == evidence.lease,
        try parentRef.b("artifact_digest") == evidence.digest,
        try parentRef.u("revocation_epoch") == evidence.cohort,
        try parentRef.u("issued_at_ms") == parent.u("issued_at_ms"),
        try parentRef.u("initiation_not_after_ms") == parent.u("initiation_not_after_ms"),
        try parentRef.u("session_not_after_ms") == parent.u("session_not_after_ms"),
        try parentRef.t("revocation_policy_id") == parent.t("revocation_policy_id"),
        try parentRef.u("revocation_policy_revision") == parent.u("revocation_policy_revision")
      else { throw V4NamespaceFailure.untrusted }
      try grant.verify("grant_signature", publicKey: permission.b("issuer_public_key"))
      let verified = try V4CredentialEvidence(
        namespace: self, kind: 1, cohort: scope.cohort,
        issuer: scope.issuer, digest: grant.digest("grant_digest"), lease: nil,
        permissionDigest: permission.digest("credential_issuer_authorization_digest"),
        policy: policy,
        issuedMS: scope.issuedMS, expiresMS: scope.expiresMS)
      try checkEvidence(verified)
      return verified
    }
  }
}
