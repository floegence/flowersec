#if os(macOS) || os(iOS)
import Foundation

/// Independent SourceAuthority trust and fence binding. The generation names
/// the deployment's current authority fence, not an SDK SourceGeneration.
/// The original authority signs and checks it before any TopUp/Ack write.
public struct TransportPoolSourceAuthorityConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let https: TransportControlHTTPSConfiguration
  public let sourceIncarnation: Data
  public let bindingGeneration: UInt64
  public let authorityKeyID: Data
  public let authorityPublicKey: Data
  public init(https: TransportControlHTTPSConfiguration, sourceIncarnation: Data, bindingGeneration: UInt64,
    authorityKeyID: Data, authorityPublicKey: Data) {
    self.https = https; self.sourceIncarnation = sourceIncarnation; self.bindingGeneration = bindingGeneration
    self.authorityKeyID = authorityKeyID; self.authorityPublicKey = authorityPublicKey
  }
  public var description: String { "Flowersec.PoolSourceAuthorityConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

/// Automatic replenishment keeps its original durable journal and standalone
/// mTLS controls. It never depends on a Session supplied by this same pool.
public struct TransportManagedPoolSourceConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let authority: TransportPoolSourceAuthorityConfiguration
  public let topUp: TransportControlHTTPSConfiguration
  public let journal: TransportPoolRefillJournalConfiguration
  public let poolDigest: Data
  public let clientCertificate: Data
  public let applicationProfile: String
  public let lowWatermark: Int
  public let targetCount: Int
  public let requestLifetimeMilliseconds: UInt64
  public init(authority: TransportPoolSourceAuthorityConfiguration, topUp: TransportControlHTTPSConfiguration,
    journal: TransportPoolRefillJournalConfiguration, poolDigest: Data, clientCertificate: Data,
    applicationProfile: String = "transport", lowWatermark: Int = 2, targetCount: Int = 4,
    requestLifetimeMilliseconds: UInt64 = 90_000) {
    self.authority = authority; self.topUp = topUp; self.journal = journal
    self.poolDigest = poolDigest; self.clientCertificate = clientCertificate; self.applicationProfile = applicationProfile
    self.lowWatermark = lowWatermark; self.targetCount = targetCount; self.requestLifetimeMilliseconds = requestLifetimeMilliseconds
  }
  public var description: String { "Flowersec.ManagedPoolSourceConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

private final class V4PoolOwnerProofControl: @unchecked Sendable {
  private let provider: V4ControlHTTPS
  private let configuration: TransportPoolSourceAuthorityConfiguration
  private let registry: V4NamespaceRegistry
  private let environment: V4EnvironmentFoundation
  init(environment: V4EnvironmentFoundation, configuration: TransportPoolSourceAuthorityConfiguration,
    registry: V4NamespaceRegistry) throws {
    let c = configuration
    guard c.sourceIncarnation.count == 16, c.sourceIncarnation.contains(where: { $0 != 0 }), c.bindingGeneration > 0,
      c.authorityKeyID.count == 16, c.authorityKeyID.contains(where: { $0 != 0 }),
      c.authorityPublicKey.count == 32 else { throw TransportControlError.invalidConfiguration }
    self.environment = environment; self.configuration = c; self.registry = registry
    provider = try V4ControlHTTPS(environment: environment, configuration: c.https)
  }
  func proof(_ intent: V4PoolRefillIntent, check: @escaping @Sendable () throws -> Void) async throws -> V4ControlHTTPResponse {
    let c = configuration
    guard intent.source == c.sourceIncarnation else { throw V4PoolFailure.conflict }
    let object: [String: Any] = ["wire_revision": 4, "tenant_id": intent.tenant,
      "source_incarnation": intent.source.base64EncodedString(), "operation_id": intent.operation.base64EncodedString(),
      "request_digest": try intent.digest().base64EncodedString(), "binding_generation": String(c.bindingGeneration),
      "pool_digest": intent.pool.base64EncodedString(), "client_identity_digest": intent.identity.base64EncodedString(),
      "request_deadline_ms": String(intent.deadlineMS), "desired_count": intent.desired, "max_item_bytes": intent.maximumItemBytes]
    let request = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    guard request.count <= 4096 else { throw V4PoolFailure.configuration }
    let bytes = try await provider.post(path: "/pool/owner-proof", body: request, maximumResponseBytes: 512,
      requestContentType: "application/json", check: check)
    try environment.gate.withLock {
      try check()
      let proof = try V4NamespaceDocument(bytes.bytes, schema: "OwnerFenceProof", bytes: 512, nodes: 32, registry: registry).root
      guard try proof.t("tenant_id") == intent.tenant, try proof.b("source_incarnation") == intent.source,
        try proof.b("operation_id") == intent.operation, try proof.b("request_digest") == intent.digest(),
        try proof.u("current_generation") == c.bindingGeneration, try proof.b("authority_key_id") == c.authorityKeyID,
        let now = environment.clock.sample().interval else { throw V4NamespaceFailure.untrusted }
      let issued = try proof.u("issued_at_ms"); let expires = try proof.u("expires_at_ms")
      guard issued <= now.lowerMS, now.upperMS < expires, issued < expires else { throw V4TimeFailure.expired }
      try proof.verify("topup_owner_fence_signature", publicKey: c.authorityPublicKey)
      try check()
    }
    return bytes
  }
  func close() { provider.close() }
}

private enum V4ManagedPoolFailure: Error { case permanentFence }

final class V4ManagedPoolMaterialSource: V4ConfiguredMaterialSourceOwner, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let client: V4ClientEnvironment
  private let configuration: TransportManagedPoolSourceConfiguration
  private let identity: TransportApplicationIdentity
  private let localIncarnation: Data
  private let credentials: V4CredentialConfiguration
  private let certificateEvidence: V4CredentialEvidence?
  private let certificateFailure: Error?
  private let certificateDigest: Data
  private let journal: V4PoolRefillJournal
  private let registry: V4NamespaceRegistry
  private let ownerProof: V4PoolOwnerProofControl
  private let topUp: V4ControlHTTPS
  private var worker: Task<Void, Never>?
  private var acquisitionActive = false
  private var closed = false
  private let generation: UInt64 = 1
  private var wakeRequested = true
  init(client: V4ClientEnvironment, configuration: TransportManagedPoolSourceConfiguration,
    identity: TransportApplicationIdentity) throws {
    let c = configuration
    guard ["transport", "services", "execution"].contains(c.applicationProfile), c.poolDigest.count == 32,
      (1...8192).contains(c.clientCertificate.count), (1...4).contains(c.targetCount), c.lowWatermark >= 0,
      c.lowWatermark < c.targetCount, (1000...90_000).contains(c.requestLifetimeMilliseconds)
    else { throw TransportControlError.invalidConfiguration }
    self.client = client; self.configuration = c; self.identity = identity; localIncarnation = try V4Crypto.random(16)
    let suppliedCredentials = try client.liveCredentialConfiguration()
    credentials = suppliedCredentials
    let sourceStorage = try client.foundation.managedPoolStorage(maximumRows: c.journal.maximumRows, maximumBytes: c.journal.maximumBytes)
    let registered = try V4NamespaceRegistry(); registry = registered
    let certificate = try V4NamespaceDocument(c.clientCertificate, schema: "IdentityCertificate", bytes: 8192, nodes: 4096, registry: registered).root
    certificateDigest = try certificate.digest("certificate_digest")
    let validation: (V4CredentialEvidence?, Error?) = {
      do {
        try identity.owner.check(in: client.foundation)
        try V4CredentialVerifier.identityKey(certificate)
        let matching = try suppliedCredentials.namespaces.filter { try $0.matchesCredential(certificate) }
        guard matching.count == 1, try certificate.u("role") == 0,
          try certificate.t("tenant_id") == suppliedCredentials.tenant, try certificate.t("audience") == suppliedCredentials.audience,
          try certificate.t("subject_id") == suppliedCredentials.clientSubject,
          try certificate.t("crypto_profile_id") == identity.owner.profile.rawValue,
          try certificate.b("ed25519_public_key") == identity.owner.identityPublicKey,
          try certificate.field("noise_static_public_key").b("public_key_bytes") == identity.owner.dhPublicKey
        else { throw TransportConnectError.invalidMaterial }
        return (try matching[0].verifyCredential(certificate, kind: 0, originalEnvironment: client.foundation), nil)
      } catch { return (nil, error) }
    }()
    certificateEvidence = validation.0; certificateFailure = validation.1
    if c.journal.create, let error = validation.1 { throw error }
    // Validate both independent TLS assemblies before creating persistent
    // files. A corrected TLS configuration can retry the same explicit create.
    ownerProof = try V4PoolOwnerProofControl(environment: client.foundation, configuration: c.authority, registry: registry)
    topUp = try V4ControlHTTPS(environment: client.foundation, configuration: c.topUp)
    journal = try V4PoolRefillJournal(environment: client.foundation, configuration: c.journal,
      tenant: credentials.tenant, source: c.authority.sourceIncarnation, pool: c.poolDigest, preparedStorage: sourceStorage, preparedRegistry: registry)
    if let error = certificateFailure {
      // Original installed history authorizes only Ack recovery. It cannot
      // require usable old private keys or current certificate validity. The
      // exact retained identity digest still belongs to this exclusive journal.
      guard let recovered = try journal.recover(), recovered.phase == .installed,
        recovered.intent.identity == certificateDigest else { throw error }
    }
    try client.foundation.registerNativeConnection(self)
    // Reserve the real worker tail before its Task exists. One serial owner
    // holds every recovered operation, response and Ack through physical close.
    let tail = try journal.storage.executionTail()
    worker = Task { [weak self] in
      defer {
        if let source = self {
          source.client.foundation.gate.withLock { tail.release(); source.workerFinished() }
        } else { tail.release() }
      }
      while !Task.isCancelled {
        guard let source = self else { return }
        let proceed = source.client.foundation.gate.withLock { !source.closed }
        if !proceed { break }
        do { try await source.refillIfNeeded() }
        catch {
          source.client.foundation.gate.withLock {
            // Unknown responses keep pending journal identity. Only control
            // availability has a bounded retry; malformed/authentication input
            // and exhausted immutable request deadlines stop this source.
            if !(error as? TransportControlError == .unavailable || error as? TransportControlError == .busy) { source.closed = true }
          }
        }
        do { try await ContinuousClock().sleep(for: .milliseconds(250)) } catch { break }
      }
    }
  }
  private func checkControl() throws {
    try client.foundation.gate.withLock {
      try journal.check()
      guard !closed else { throw ConnectionMaterialSourceError.closed }
    }
  }
  private func checkIdentity() throws {
    if let certificateFailure { throw certificateFailure }
    guard let certificateEvidence else { throw TransportConnectError.invalidMaterial }
    try identity.owner.check(in: client.foundation)
    try certificateEvidence.namespace.checkEvidence(certificateEvidence)
  }
  func check(in environment: V4EnvironmentFoundation) throws {
    try client.foundation.gate.withLock {
      guard environment === client.foundation else { throw TransportConnectError.invalidMaterial }
      try checkControl(); try checkIdentity()
    }
  }
  private func exchange(path: String, body: Data) async throws -> V4PoolControlReply {
    let bytes: V4ControlHTTPResponse
    let applicationError: Bool
    do {
      bytes = try await topUp.post(path: path, body: body, maximumResponseBytes: 524_288,
        allowApplicationError: true) { try self.checkControl() }
      applicationError = false
    } catch let error as V4ControlApplicationError { bytes = error.payload; applicationError = true }
    defer { withExtendedLifetime(bytes) {} }
    return try client.foundation.gate.withLock {
      try checkControl()
      return try V4PoolRefillWire.reply(bytes.bytes, applicationError: applicationError)
    }
  }
  private func refillIfNeeded() async throws {
    var recovery = try client.foundation.gate.withLock { () throws -> V4PoolRefillJournal.Recovery? in
      try checkControl()
      let saved = try journal.recover()
      if let saved, saved.phase != .acked {
        if saved.phase != .terminal { return saved }
        let terminal = try journal.terminal(saved)
        guard terminal.bindingGeneration <= configuration.authority.bindingGeneration else { throw V4PoolFailure.conflict }
        guard !terminal.permanent else { throw V4ManagedPoolFailure.permanentFence }
        if !terminal.retired { return saved }
      }
      try checkIdentity()
      guard let now = client.foundation.clock.sample().interval else { throw V4TimeFailure.unavailable }
      try journal.retireExpired(at: now.upperMS)
      let count = try journal.count
      guard wakeRequested || count <= configuration.lowWatermark else { return nil }
      wakeRequested = false
      guard count < configuration.targetCount else { return nil }
      let deadline = now.lowerMS.addingReportingOverflow(configuration.requestLifetimeMilliseconds)
      guard !deadline.overflow, now.upperMS < deadline.partialValue else { throw V4TimeFailure.expired }
      return try journal.begin(tenant: credentials.tenant, source: configuration.authority.sourceIncarnation,
        pool: configuration.poolDigest, desired: min(4, configuration.targetCount - count), maximumItemBytes: 65_536,
        deadline: deadline.partialValue, identity: certificateDigest)
    }
    guard var original = recovery else { return }
    if original.phase == .terminal {
      // An unretired receipt still occupies this operation. Ask the authority
      // for its original history until it publishes retirement; never issue a
      // new operation or resurrect a batch from this receipt.
      let proof = try await ownerProof.proof(original.intent) { try self.checkControl() }
      defer { withExtendedLifetime(proof) {} }
      let wire = try V4PoolRefillWire.request(original.intent,
        generation: configuration.authority.bindingGeneration, proof: proof.bytes)
      let reply = try await exchange(path: "/pool/top-up", body: wire)
      if reply.code == "source_unavailable" { throw TransportControlError.unavailable }
      guard let terminal = try V4PoolRefillWire.terminal(reply, original: original,
        currentGeneration: configuration.authority.bindingGeneration, registry: registry)
      else { throw TransportControlError.responseInvalid }
      try journal.confirmTerminal(terminal, original: original)
      if terminal.permanent { throw V4ManagedPoolFailure.permanentFence }
      return
    }
    if original.phase == .pending {
      let proof = try await ownerProof.proof(original.intent) { try self.checkControl() }
      defer { withExtendedLifetime(proof) {} }
      original = try journal.bindOriginalGeneration(configuration.authority.bindingGeneration, intent: original.intent)
      let wire = try V4PoolRefillWire.request(original.intent, generation: configuration.authority.bindingGeneration, proof: proof.bytes)
      let reply = try await exchange(path: "/pool/top-up", body: wire)
      if let terminal = try V4PoolRefillWire.terminal(reply, original: original,
        currentGeneration: configuration.authority.bindingGeneration, registry: registry) {
        try journal.confirmTerminal(terminal, original: original)
        if terminal.permanent { throw V4ManagedPoolFailure.permanentFence }
        return
      }
      if reply.code == "source_unavailable" { throw TransportControlError.unavailable }
      guard reply.code == "success" || reply.code == "replay", !reply.response.isEmpty else {
        // Authenticated error evidence is retained at its original journal. A
        // failed replenishment cannot silently retire intent and spend another.
        throw TransportControlError.responseInvalid
      }
      let response = try V4PoolRefillWire.response(reply.response, intent: original.intent,
        originalGeneration: original.generation, previousHighest: original.previousHighest, registry: registry)
      try client.foundation.gate.withLock {
        try checkControl(); try checkIdentity()
        for entry in response.entries {
          let credential = try V4PoolMaterialBundle.decode(entry.material)
            .validatedCredential(client: client, identity: identity, registry: registry)
          let profile = try client.validatePoolCredential(credential, identity: identity)
          guard ["transport", "services", "execution"][Int(profile)] == configuration.applicationProfile else { throw TransportConnectError.invalidMaterial }
          let certificate = try V4NamespaceDocument(credential.input.clientCertificate, schema: "IdentityCertificate",
            bytes: 8192, nodes: 4096, registry: registry).root
          let artifact = try V4NamespaceDocument(credential.input.artifact, schema: "Artifact", bytes: 65_536, nodes: 16_384, registry: registry).root
          guard try certificate.digest("certificate_digest") == original.intent.identity,
            try artifact.u("session_not_after_ms") == entry.expiry else { throw TransportConnectError.invalidMaterial }
        }
        try journal.install(response, intent: original.intent)
      }
      recovery = try journal.recover()
      guard let installed = recovery else { throw V4PoolFailure.storage }
      original = installed
    }
    if original.phase == .installed {
      // Ack recovery uses original intent and installed digest only. Expired or
      // unavailable old application private keys do not change that history.
      let response = try V4PoolRefillWire.response(original.response, intent: original.intent,
        originalGeneration: original.generation, previousHighest: original.previousHighest, registry: registry)
      let proof = try await ownerProof.proof(original.intent) { try self.checkControl() }
      defer { withExtendedLifetime(proof) {} }
      let wire = try V4PoolRefillWire.ack(original.intent, response: response,
        generation: configuration.authority.bindingGeneration, proof: proof.bytes)
      let reply = try await exchange(path: "/pool/ack", body: wire)
      if let terminal = try V4PoolRefillWire.terminal(reply, original: original,
        currentGeneration: configuration.authority.bindingGeneration, registry: registry) {
        try journal.confirmTerminal(terminal, original: original)
        if terminal.permanent { throw V4ManagedPoolFailure.permanentFence }
        return
      }
      if reply.code == "source_unavailable" { throw TransportControlError.unavailable }
      guard reply.code == "success" || reply.code == "replay", reply.response.isEmpty else { throw TransportControlError.responseInvalid }
      try client.foundation.gate.withLock {
        try checkControl()
        try journal.acknowledge(intent: original.intent, response: original.response)
      }
    }
  }
  func checkRequirements(_ requirements: ConnectionRequirements, in environment: V4EnvironmentFoundation) throws {
    try client.foundation.gate.withLock {
      try V4DirectEstablishment.requirements(requirements)
      try check(in: environment)
      guard requirements.applicationProfile == nil || requirements.applicationProfile == configuration.applicationProfile else { throw TransportConnectError.unsupported }
      let available = try journal.take(remove: false) { wire in
        let credential = try V4PoolMaterialBundle.decode(wire)
          .validatedCredential(client: self.client, identity: self.identity, registry: self.registry)
        _ = try self.client.validatePoolCredential(credential, identity: self.identity, requirements: requirements)
      }
      guard available != nil else { throw ConnectionMaterialSourceError.exhausted }
    }
  }
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    try V4DirectEstablishment.requirements(requirements)
    return try client.foundation.gate.withLock {
      try Task.checkCancellation()
      try check(in: client.foundation)
      guard !acquisitionActive else { throw TransportControlError.busy }
      guard requirements.applicationProfile == nil || requirements.applicationProfile == configuration.applicationProfile else { throw TransportConnectError.unsupported }
      acquisitionActive = true
      defer {
        acquisitionActive = false
        if closed && worker == nil { journal.close() }
      }
      guard let now = client.foundation.clock.sample().interval else { throw V4TimeFailure.unavailable }
      try journal.retireExpired(at: now.upperMS)
      // Acquisition takes one already installed local item. The independent
      // maintenance worker alone owns replenishment and its original deadline.
      guard let wire = try journal.take(validate: { wire in
        let credential = try V4PoolMaterialBundle.decode(wire)
          .validatedCredential(client: self.client, identity: self.identity, registry: self.registry)
        _ = try self.client.validatePoolCredential(credential, identity: self.identity, requirements: requirements)
        try Task.checkCancellation()
      }) else { throw ConnectionMaterialSourceError.exhausted }
      let credential = try V4PoolMaterialBundle.decode(wire)
        .validatedCredential(client: client, identity: identity, registry: registry)
      let material = try client.material(credential, identity: identity)
      guard let original = material.owner as? V4DirectPoolMaterial else { material.close(); throw TransportConnectError.invalidMaterial }
      do { try original.captureSource(incarnation: localIncarnation, generation: generation); return material }
      catch { material.close(); throw error }
    }
  }
  func close() {
    client.foundation.gate.withLock {
      closed = true; worker?.cancel(); ownerProof.close(); topUp.close()
      if worker == nil && !acquisitionActive { journal.close() }
    }
  }
  private func workerFinished() {
    client.foundation.gate.withLock { worker = nil; closed = true; ownerProof.close(); topUp.close(); if !acquisitionActive { journal.close() } }
  }
  func cleanupStatus() -> CleanupStatus {
    client.foundation.gate.withLock {
      let complete = closed && worker == nil && !acquisitionActive
      return CleanupStatus(complete: complete, cleanupIncomplete: closed && !complete,
        pendingCallbacks: UInt64((worker == nil ? 0 : 1) + (acquisitionActive ? 1 : 0)))
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    let worker = client.foundation.gate.withLock { self.worker }
    await worker?.value
    return cleanupStatus()
  }
  deinit { close() }
}
#endif
