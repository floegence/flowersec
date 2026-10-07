#if os(macOS) || os(iOS)
import Foundation

/// A configured issuer and original SpendLedger authority, authenticated
/// independently of the Session being established. Both calls use their
/// explicit TLS client identity and the TransportEnvironment's existing namespace trust.
public struct TransportLiveAuthoritySourceConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let issuance: TransportControlHTTPSConfiguration
  public let activation: TransportControlHTTPSConfiguration
  public let clientCertificate: Data
  public let serverCertificate: Data
  public let activationSigningKeyID: String
  public let applicationProfile: String
  public let maximumGeneralOutstanding: Int
  public let tunnel: TransportLiveTunnelConfiguration?
  public let relayPreparation: TransportControlHTTPSConfiguration?
  public init(issuance: TransportControlHTTPSConfiguration, activation: TransportControlHTTPSConfiguration,
    clientCertificate: Data, serverCertificate: Data, activationSigningKeyID: String,
    applicationProfile: String = "transport", maximumGeneralOutstanding: Int = 0,
    tunnel: TransportLiveTunnelConfiguration? = nil, relayPreparation: TransportControlHTTPSConfiguration? = nil) {
    self.issuance = issuance; self.activation = activation
    self.clientCertificate = clientCertificate; self.serverCertificate = serverCertificate
    self.activationSigningKeyID = activationSigningKeyID; self.applicationProfile = applicationProfile
    self.maximumGeneralOutstanding = maximumGeneralOutstanding; self.tunnel = tunnel; self.relayPreparation = relayPreparation
  }
  public var description: String { "Flowersec.LiveAuthoritySourceConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

/// Configured closed alternatives. Selecting a profile never installs a
/// fallback to another activation source when acquisition or activation fails.
public enum TransportMaterialSourceConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  case preauthorizedPool([TransportPoolCredential])
  case liveAuthority(TransportLiveAuthoritySourceConfiguration)
  case registeredLiveAuthority(TransportRegisteredLiveAuthoritySourceConfiguration)
  case managedPreauthorizedPool(TransportManagedPoolSourceConfiguration)
  public var description: String { "Flowersec.MaterialSourceConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

protocol V4ConfiguredMaterialSourceOwner: ConnectionMaterialSourceOwner {
  func check(in environment: V4EnvironmentFoundation) throws
  func checkRequirements(_ requirements: ConnectionRequirements, in environment: V4EnvironmentFoundation) throws
}
extension V4ConfiguredMaterialSourceOwner {
  func checkRequirements(_ requirements: ConnectionRequirements, in environment: V4EnvironmentFoundation) throws {
    try V4DirectEstablishment.requirements(requirements)
    try check(in: environment)
  }
}

enum V4RelayCarrierReady {
  static func send(admission: V4CredentialAdmission, provider: V4ControlHTTPS, custody: V4ResourceCustody,
    cleanup: V4ControlHTTPCallCleanup? = nil, check: @escaping @Sendable () throws -> Void) async throws {
    try check()
    let bytes = V4NamespaceValue.head(4, 5) + V4Crypto.text("tunnel-relay-ready-1")
      + V4Crypto.bytes(admission.artifactDigest) + V4Crypto.bytes(admission.candidateID)
      + V4Crypto.bytes(admission.routeDigest) + V4NamespaceValue.head(0, UInt64(admission.localRole.rawValue))
    let ack = try await provider.post(path: "/tunnel/relay-ready", body: bytes, maximumResponseBytes: 1, custody: custody, cleanup: cleanup, check: check)
    guard ack.bytes == Data([0xf5]) else { throw TransportControlError.responseInvalid }; try check()
  }
}

protocol V4LiveAuthorizationControl: Sendable {
  func carrierListening(_ material: V4DirectPoolMaterial) async throws
  func authorize(_ material: V4DirectPoolMaterial) async throws
  func materialFinished(success: Bool)
}
extension V4LiveAuthorizationControl {
  func materialFinished(success: Bool) {}
}

final class V4LiveControl: V4LiveAuthorizationControl, @unchecked Sendable {
  let configuration: V4CredentialConfiguration
  let signingKeyID: String
  private let provider: V4ControlHTTPS
  private let relayPreparation: V4ControlHTTPS?
  init(configuration: V4CredentialConfiguration, signingKeyID: String, provider: V4ControlHTTPS, relayPreparation: V4ControlHTTPS? = nil) {
    self.configuration = configuration; self.signingKeyID = signingKeyID; self.provider = provider; self.relayPreparation = relayPreparation
  }
  func carrierListening(_ material: V4DirectPoolMaterial) async throws {
    if let relayPreparation {
      try await V4RelayCarrierReady.send(admission: material.plan.credential, provider: relayPreparation, custody: try material.plan.credential.originalControlCustody(),
        cleanup: try material.controlCall(.relayReady)) { try material.check() }
    }
  }
  func authorize(_ material: V4DirectPoolMaterial) async throws {
    let plan = material.plan
    do {
      try material.check()
      let request = try plan.credential.beginLiveAuthorization(signingKeyID: signingKeyID)
      if plan.credential.pathKind == 1, relayPreparation == nil {
        throw TransportControlError.invalidConfiguration
      }
      if let relayPreparation {
        guard plan.credential.pathKind == 1 else { throw TransportControlError.invalidConfiguration }
        // Prepare already owns the actual carrier. This authenticated original
        // request fixes the relay's TxA projection without issuing any Grant.
        let acknowledgement = try await relayPreparation.post(path: "/tunnel/relay-prepare", body: request, maximumResponseBytes: 1, custody: try plan.credential.originalControlCustody(), cleanup: try material.controlCall(.relayPrepare)) {
          try material.check(); try plan.credential.prepareLiveActivation(signingKeyID: self.signingKeyID)
        }
        guard acknowledgement.bytes == Data([0xf5]) else { throw TransportControlError.responseInvalid }
      }
      plan.credential.connectionFacts.spendDispatched()
      let proof = try await provider.post(path: "/live/authorize", body: request, maximumResponseBytes: plan.credential.pathKind == 1 ? 73_728 : 4096, custody: try plan.credential.originalControlCustody(), cleanup: try material.controlCall(.authorize)) {
        try material.check(); try plan.credential.prepareLiveActivation(signingKeyID: self.signingKeyID)
      }
      defer { withExtendedLifetime(proof) {} }
      try material.check()
      // Decode the original TxB response once for relay publication. Installation
      // below independently verifies and commits these same original bytes.
      let tunnelMaterial = plan.credential.pathKind == 1 ? try V4LiveTunnelMaterial.decode(proof.bytes) : nil
      try plan.installLiveAuthorization(proof.bytes, signingKeyID: signingKeyID, configuration: configuration)
      if let tunnelMaterial, let relayPreparation {
        let publication = V4NamespaceValue.head(4, 4) + V4Crypto.text("tunnel-relay-activate-client-1")
          + V4Crypto.bytes(request) + V4Crypto.bytes(tunnelMaterial.activation) + V4Crypto.bytes(tunnelMaterial.grant)
        let acknowledgement = try await relayPreparation.post(path: "/tunnel/relay-activate-client", body: publication, maximumResponseBytes: 1, custody: try plan.credential.originalControlCustody(), cleanup: try material.controlCall(.relayActivate)) {
          try material.check()
          try plan.credential.checkLiveActivationComplete(in: plan.environment)
        }
        guard acknowledgement.bytes == Data([0xf5]) else { throw TransportControlError.responseInvalid }
        try material.check()
        try plan.credential.checkLiveActivationComplete(in: plan.environment)
      }
    } catch {
      // A failed original activation or relay publication consumes this attempt;
      // its caller's unsuccessful finish joins transport cleanup.
      plan.credential.close()
      throw error
    }
  }
}

private final class V4LiveSourceGeneration: @unchecked Sendable {
  let identity: TransportApplicationIdentity
  let configuration: TransportLiveAuthoritySourceConfiguration
  let generation: UInt64
  let credentials: V4CredentialConfiguration
  let storage: V4CryptoReservation
  let certificateEvidence: [V4CredentialEvidence]
  let issuance: V4ControlHTTPS
  let activation: V4LiveControl
  init(client: V4ClientEnvironment, configuration: TransportLiveAuthoritySourceConfiguration,
    identity: TransportApplicationIdentity, generation: UInt64) throws {
    let c = configuration; credentials = try client.liveCredentialConfiguration()
    let validGeneral = c.applicationProfile == "transport" ? c.maximumGeneralOutstanding == 0 : (1...1024).contains(c.maximumGeneralOutstanding)
    guard generation > 0, ["transport", "services", "execution"].contains(c.applicationProfile), validGeneral,
      (1...8192).contains(c.clientCertificate.count), (1...8192).contains(c.serverCertificate.count),
      V4NamespaceRegistry.securityID(c.activationSigningKeyID.utf8)
    else { throw TransportConnectError.invalidMaterial }
    guard (c.tunnel == nil) == (c.relayPreparation == nil) else { throw TransportControlError.invalidConfiguration }
    if let relay = c.relayPreparation {
      guard relay.basePath.isEmpty,
        relay.clientCertificatePEM == c.activation.clientCertificatePEM,
        relay.clientPrivateKeyPEM == c.activation.clientPrivateKeyPEM
      else { throw TransportControlError.invalidConfiguration }
    }
    if let tunnel = c.tunnel {
      try tunnel.scope.checkShape()
      guard (0..<16).contains(tunnel.candidateIndex), tunnel.scope.roleMask == 5,
        tunnel.issuancePath.hasPrefix("/issue/"), tunnel.issuancePath.utf8.count <= 128,
        tunnel.issuancePath.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f && ![0x3f, 0x23, 0x25, 0x5c].contains($0) }),
        (1...8192).contains(tunnel.relayCertificate.count), (1...1024).contains(tunnel.grantLimits.count)
      else { throw TransportControlError.invalidConfiguration }
    }
    storage = try client.foundation.liveMaterialSourceStorage()
    try identity.owner.check(in: client.foundation)
    let registry = try V4NamespaceRegistry()
    var evidence: [V4CredentialEvidence] = []
    for (role, bytes) in [c.clientCertificate, c.serverCertificate].enumerated() {
      let certificate = try V4NamespaceDocument(bytes, schema: "IdentityCertificate", bytes: 8192,
        nodes: 4096, registry: registry).root
      try V4CredentialVerifier.identityKey(certificate)
      let namespace = try credentials.namespaces.filter { try $0.matchesCredential(certificate) }
      guard namespace.count == 1, try certificate.u("role") == UInt64(role),
        try certificate.t("tenant_id") == credentials.tenant, try certificate.t("audience") == credentials.audience,
        try certificate.t("subject_id") == (role == 0 ? credentials.clientSubject : credentials.serverSubject),
        try certificate.t("crypto_profile_id") == identity.profile.rawValue
      else { throw TransportConnectError.invalidMaterial }
      if role == 0 {
        guard try certificate.b("ed25519_public_key") == identity.signingPublicKey,
          try certificate.field("noise_static_public_key").b("public_key_bytes") == identity.noiseStaticPublicKey
        else { throw TransportConnectError.invalidMaterial }
      }
      evidence.append(try namespace[0].verifyCredential(certificate, kind: 0, originalEnvironment: client.foundation))
    }
    self.identity = identity; self.configuration = c; self.generation = generation; certificateEvidence = evidence
    issuance = try V4ControlHTTPS(environment: client.foundation, configuration: c.issuance)
    let activationProvider = try V4ControlHTTPS(environment: client.foundation, configuration: c.activation)
    let relay = try c.relayPreparation.map { try V4ControlHTTPS(environment: client.foundation, configuration: $0) }
    activation = V4LiveControl(configuration: credentials, signingKeyID: c.activationSigningKeyID, provider: activationProvider, relayPreparation: relay)
  }
  func check(in environment: V4EnvironmentFoundation) throws {
    try storage.check(); try identity.owner.check(in: environment)
    for item in certificateEvidence { try item.namespace.checkEvidence(item) }
  }
}

final class V4LiveMaterialSource: V4ConfiguredMaterialSourceOwner, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let client: V4ClientEnvironment
  private let incarnation: Data
  private var current: V4LiveSourceGeneration?
  private var closed = false
  private var active: Task<ConnectionMaterial, Error>?
  init(client: V4ClientEnvironment, configuration: TransportLiveAuthoritySourceConfiguration,
    identity: TransportApplicationIdentity) throws {
    self.client = client; incarnation = try V4Crypto.random(16)
    current = try V4LiveSourceGeneration(client: client, configuration: configuration, identity: identity, generation: 1)
    try client.foundation.registerNativeConnection(self)
  }
  func check(in environment: V4EnvironmentFoundation) throws {
    try client.foundation.gate.withLock {
      guard environment === client.foundation else { throw TransportConnectError.invalidMaterial }
      guard !closed, let current else { throw ConnectionMaterialSourceError.closed }
      try current.check(in: environment)
    }
  }
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    try await acquire(requirements, cleanup: nil)
  }
  func acquire(_ requirements: ConnectionRequirements, cleanup: V4ControlHTTPCallCleanup?) async throws -> ConnectionMaterial {
    try V4DirectEstablishment.requirements(requirements)
    let task = try client.foundation.gate.withLock {
      try check(in: client.foundation)
      guard active == nil, let generation = current else { throw TransportControlError.busy }
      guard requirements.applicationProfile == nil || requirements.applicationProfile == generation.configuration.applicationProfile
      else { throw TransportConnectError.unsupported }
      let task = Task { [self, generation] in
        try Task.checkCancellation()
        let request = V4NamespaceValue.head(4, 1) + V4Crypto.bytes(try V4Crypto.random(32))
        let artifact = try await generation.issuance.post(path: generation.configuration.tunnel?.issuancePath ?? "/issue/direct", body: request, maximumResponseBytes: 65_536, custody: try generation.storage.controlCustody(), cleanup: cleanup) {
          try generation.check(in: self.client.foundation)
        }
        defer { withExtendedLifetime(artifact) {} }
        return try client.foundation.gate.withLock {
          guard !closed, !Task.isCancelled else { throw TransportControlError.canceled }
          try generation.check(in: client.foundation)
          let input = V4CredentialInput(artifact: artifact.bytes, clientCertificate: generation.configuration.clientCertificate,
            serverCertificate: generation.configuration.serverCertificate, activation: Data(), source: .liveAuthority, candidateIndex: generation.configuration.tunnel?.candidateIndex ?? 0,
            liveTunnel: generation.configuration.tunnel)
          let material = try client.directMaterial(input, identity: generation.identity, live: generation.activation)
          do {
            guard let original = material.owner as? V4DirectPoolMaterial else { throw TransportConnectError.invalidMaterial }
            try V4DirectEstablishment.requirements(requirements, route: original.plan.route)
            let application = ["transport", "services", "execution"][Int(original.plan.applicationProfile)]
            guard application == generation.configuration.applicationProfile,
              original.plan.maximumGeneralOutstanding == generation.configuration.maximumGeneralOutstanding
            else { throw TransportConnectError.invalidMaterial }
            try original.plan.credential.prepareLiveActivation(signingKeyID: generation.configuration.activationSigningKeyID)
            try original.captureSource(incarnation: incarnation, generation: generation.generation)
            return material
          } catch { material.close(); throw error }
        }
      }
      active = task; return task
    }
    defer { client.foundation.gate.withLock { active = nil } }
    return try await withTaskCancellationHandler {
      do { return try await task.value }
      catch {
        if Task.isCancelled || error is CancellationError { throw TransportControlError.canceled }
        if let control = error as? TransportControlError { throw control }
        if let transport = error as? TransportConnectError { throw transport }
        if error is V4TimeFailure { throw TransportConnectError.expired }
        if error is V4NamespaceFailure || error is V4CryptoFailure { throw TransportConnectError.securityFailed }
        if error is V4ResourceFailure { throw SessionError.resourceExhausted }
        throw TransportConnectError.connectionFailed
      }
    } onCancel: { task.cancel() }
  }
  func replace(configuration: TransportLiveAuthoritySourceConfiguration, identity: TransportApplicationIdentity) throws {
    try client.foundation.gate.withLock {
      guard !closed, let old = current else { throw ConnectionMaterialSourceError.closed }
      guard old.generation < .max else { throw ConnectionMaterialSourceError.generationConflict }
      let candidate = try V4LiveSourceGeneration(client: client, configuration: configuration, identity: identity, generation: old.generation + 1)
      current = candidate
    }
  }
  func close() { client.foundation.gate.withLock { closed = true; current = nil; active?.cancel() } }
  func cleanupStatus() -> CleanupStatus {
    client.foundation.gate.withLock { CleanupStatus(complete: closed && active == nil, cleanupIncomplete: closed && active != nil, pendingCallbacks: active == nil ? 0 : 1) }
  }
  func waitCleanup() async throws -> CleanupStatus {
    let task = client.foundation.gate.withLock { active }
    if let task { _ = try? await task.value }
    return cleanupStatus()
  }
  deinit { close() }
}
#endif
