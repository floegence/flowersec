#if os(macOS) || os(iOS)
import Foundation

/// One original installed tunnel parent and independently pinned registered
/// authority. Installation contains future Grant policy, never a final Grant
/// or activation. This source has one acquisition and no recovery entrance.
public struct TransportRegisteredLiveAuthoritySourceConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let control: TransportControlHTTPSConfiguration
  public let authority: String
  public let artifact: Data
  public let clientCertificate: Data
  public let serverCertificate: Data
  public let activationSigningKeyID: String
  public let tunnel: TransportLiveTunnelConfiguration
  public let relayPreparation: TransportControlHTTPSConfiguration
  public let applicationProfile: String
  public let maximumGeneralOutstanding: Int
  public init(control: TransportControlHTTPSConfiguration, authority: String, artifact: Data,
    clientCertificate: Data, serverCertificate: Data, activationSigningKeyID: String,
    tunnel: TransportLiveTunnelConfiguration, relayPreparation: TransportControlHTTPSConfiguration,
    applicationProfile: String = "transport", maximumGeneralOutstanding: Int = 0) {
    self.control = control; self.authority = authority; self.artifact = artifact
    self.clientCertificate = clientCertificate; self.serverCertificate = serverCertificate
    self.activationSigningKeyID = activationSigningKeyID; self.tunnel = tunnel
    self.relayPreparation = relayPreparation; self.applicationProfile = applicationProfile
    self.maximumGeneralOutstanding = maximumGeneralOutstanding
  }
  public var description: String { "Flowersec.RegisteredLiveAuthoritySourceConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

private struct V4RegisteredLiveProjection: Encodable {
  let authority: String; let tenant: String; let audience: String; let cryptoProfile: String
  let candidateIndex: UInt64; let activationNotAfterMS: String; let attemptNo: UInt64
  let issuer: String; let lease: String; let attempt: String; let artifact: String
  let clientIdentity: String; let serverIdentity: String; let candidateID: String; let routeDigest: String
}
private struct V4RegisteredLivePayload: Encodable {
  let kind: String; let incarnation: String; let parent: String; let candidate: UInt64
  var attempt: String?; var authentication: String?; var signature: String?
  var request: V4RegisteredLiveProjection?
}
private struct V4RegisteredLiveEnvelope: Encodable { let payload: String; let proof: String }

private struct V4RegisteredLiveReply: Decodable {
  struct Key: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
  }
  let incarnation: String; let authority: String; let prepared: Bool; let grant: String
  init(from decoder: any Decoder) throws {
    let values = try decoder.container(keyedBy: Key.self)
    let allowed: Set<String> = ["incarnation", "authority", "clientGrant", "serverGrant", "delivered", "matched",
      "prepared", "registered", "reserved", "attempt", "activation", "grant", "continuation", "lease", "projection"]
    guard values.allKeys.allSatisfy({ allowed.contains($0.stringValue) }) else { throw TransportControlError.responseInvalid }
    func text(_ key: String, required: Bool = false) throws -> String {
      let name = Key(stringValue: key)!
      if !values.contains(name), !required { return "" }
      return try values.decode(String.self, forKey: name)
    }
    func flag(_ key: String) throws -> Bool {
      let name = Key(stringValue: key)!
      if values.contains(name) { return try values.decode(Bool.self, forKey: name) }
      return false
    }
    incarnation = try text("incarnation", required: true); authority = try text("authority", required: true)
    prepared = try flag("prepared"); grant = try text("grant")
    for key in ["clientGrant", "serverGrant", "attempt", "activation", "continuation", "lease", "projection"] {
      guard try text(key).isEmpty else { throw TransportControlError.responseInvalid }
    }
    for key in ["delivered", "matched", "registered", "reserved"] {
      guard try flag(key) == false else { throw TransportControlError.responseInvalid }
    }
  }
}

private final class V4RegisteredLiveControl: V4LiveAuthorizationControl, V4NativeConnectionLifecycle, @unchecked Sendable {
  enum Phase: Equatable { case available, bound, preparing, prepared, authorizing, delivered, handedOff, retired }
  private let environment: V4EnvironmentFoundation
  private let configuration: TransportRegisteredLiveAuthoritySourceConfiguration
  private let credentials: V4CredentialConfiguration
  private let identity: V4LocalIdentity
  private var incarnation: Data
  private var sourceIncarnation: Data
  private let storage: V4CryptoReservation
  private let provider: V4ControlHTTPS
  private let relay: V4ControlHTTPS
  private var phase: Phase = .available
  private var admission: V4CredentialAdmission?
  private var custody: V4ResourceCustody?
  private var deadline: V4SecurityDeadline?
  private var originalRequest = Data()
  private var projection: V4RegisteredLiveProjection?
  private var deliveryDigests: [Data]?
  private var readySent = false
  private weak var originalMaterial: V4DirectPoolMaterial?
  private var activeOperations = 0

  init(client: V4ClientEnvironment, configuration: TransportRegisteredLiveAuthoritySourceConfiguration,
    identity: TransportApplicationIdentity) throws {
    let c = configuration
    let validGeneral = c.applicationProfile == "transport" ? c.maximumGeneralOutstanding == 0 : (1...1024).contains(c.maximumGeneralOutstanding)
    guard V4NamespaceRegistry.securityID(c.authority.utf8), V4NamespaceRegistry.securityID(c.activationSigningKeyID.utf8),
      (1...65_536).contains(c.artifact.count), (1...8192).contains(c.clientCertificate.count),
      (1...8192).contains(c.serverCertificate.count), ["transport", "services", "execution"].contains(c.applicationProfile),
      validGeneral, (0..<16).contains(c.tunnel.candidateIndex), c.tunnel.scope.roleMask == 5,
      (1...8192).contains(c.tunnel.relayCertificate.count), (1...1024).contains(c.tunnel.grantLimits.count),
      c.control.basePath.isEmpty, c.relayPreparation.basePath.isEmpty,
      c.control.clientCertificatePEM == c.relayPreparation.clientCertificatePEM,
      c.control.clientPrivateKeyPEM == c.relayPreparation.clientPrivateKeyPEM
    else { throw TransportControlError.invalidConfiguration }
    try c.tunnel.scope.checkShape()
    try identity.owner.check(in: client.foundation)
    let originalCredentials = try client.liveCredentialConfiguration()
    guard c.tunnel.scope.tenant == originalCredentials.tenant else { throw TransportControlError.invalidConfiguration }
    let controlIncarnation = try V4Crypto.random(32), acquisitionIncarnation = try V4Crypto.random(16)
    guard controlIncarnation.contains(where: { $0 != 0 }), acquisitionIncarnation.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.key }
    environment = client.foundation; self.configuration = c; self.identity = identity.owner; credentials = originalCredentials
    incarnation = controlIncarnation; sourceIncarnation = acquisitionIncarnation
    storage = try client.foundation.liveMaterialSourceStorage()
    provider = try V4ControlHTTPS(environment: client.foundation, configuration: c.control)
    relay = try V4ControlHTTPS(environment: client.foundation, configuration: c.relayPreparation)
    try client.foundation.registerNativeConnection(self)
  }
  func checkAvailable() throws {
    try environment.gate.withLock {
      guard phase == .available else { throw ConnectionMaterialSourceError.closed }
      try storage.check(); try identity.check(in: environment)
    }
  }
  func bind(_ material: V4DirectPoolMaterial) throws {
    try environment.gate.withLock {
      try checkAvailable()
      let plan = material.plan; let credential = plan.credential
      guard plan.environment === environment, plan.role == .client, credential.pathKind == 1,
        credential.source == .liveAuthority, credential.localRole == .client,
        credential.attemptID.allSatisfy({ $0 == 0 }),
        ["transport", "services", "execution"][Int(plan.applicationProfile)] == configuration.applicationProfile,
        plan.maximumGeneralOutstanding == configuration.maximumGeneralOutstanding
      else { throw TransportConnectError.invalidMaterial }
      try credential.prepareLiveActivation(signingKeyID: configuration.activationSigningKeyID)
      // Capturing the request makes the original attempt before native Prepare;
      // it performs no authorization call and cannot be repeated after failure.
      originalRequest = try credential.beginLiveAuthorization(signingKeyID: configuration.activationSigningKeyID)
      projection = try requestProjection(originalRequest, admission: credential)
      admission = credential; custody = try credential.originalControlCustody()
      deadline = try V4SecurityDeadline(clock: environment.clock, capMS: credential.initiationNotAfterMS)
      try material.captureSource(incarnation: sourceIncarnation, generation: 1)
      originalMaterial = material; phase = .bound
    }
  }
  private func requestProjection(_ wire: Data, admission: V4CredentialAdmission) throws -> V4RegisteredLiveProjection {
    var cursor = V4PoolWireCursor(wire, maximum: 1024)
    try cursor.array(13)
    guard try cursor.text(maximum: 32) == "live-authorization-1" else { throw TransportControlError.responseInvalid }
    let tenant = try cursor.text(maximum: 128), audience = try cursor.text(maximum: 128), profile = try cursor.text(maximum: 128)
    let issuer = try cursor.bytes(maximum: 16), lease = try cursor.bytes(maximum: 16), attempt = try cursor.bytes(maximum: 16)
    let parent = try cursor.bytes(maximum: 32), client = try cursor.bytes(maximum: 32), server = try cursor.bytes(maximum: 32)
    try cursor.array(3)
    let index = try cursor.uint(), candidate = try cursor.bytes(maximum: 16), route = try cursor.bytes(maximum: 32)
    let cutoff = try cursor.uint(), number = try cursor.uint(); try cursor.end()
    guard tenant == credentials.tenant, audience == credentials.audience, profile == admission.cryptoProfile,
      issuer.count == 16, lease.count == 16, attempt.count == 16, attempt.contains(where: { $0 != 0 }),
      parent == admission.artifactDigest, client == admission.certificateDigests[0], server == admission.certificateDigests[1],
      index == UInt64(configuration.tunnel.candidateIndex), candidate == admission.candidateID, route == admission.routeDigest,
      cutoff == admission.initiationNotAfterMS, attempt == admission.attemptID, number == 1
    else { throw TransportControlError.responseInvalid }
    return V4RegisteredLiveProjection(authority: configuration.authority, tenant: tenant, audience: audience,
      cryptoProfile: profile, candidateIndex: index, activationNotAfterMS: String(cutoff), attemptNo: number,
      issuer: issuer.base64EncodedString(), lease: lease.base64EncodedString(), attempt: attempt.base64EncodedString(),
      artifact: parent.base64EncodedString(), clientIdentity: client.base64EncodedString(), serverIdentity: server.base64EncodedString(),
      candidateID: candidate.base64EncodedString(), routeDigest: route.base64EncodedString())
  }
  private func check(_ material: V4DirectPoolMaterial) throws {
    try environment.gate.withLock {
      guard phase != .available, phase != .retired, phase != .handedOff,
        material.plan.environment === environment, material.identity === identity, material.plan.credential === admission,
        material.sourceIncarnation == sourceIncarnation, material.sourceGeneration == 1,
        let custody, let deadline, let admission, let projection,
        projection.attempt == admission.attemptID.base64EncodedString(),
        projection.artifact == admission.artifactDigest.base64EncodedString(),
        projection.candidateID == admission.candidateID.base64EncodedString(), projection.routeDigest == admission.routeDigest.base64EncodedString()
      else { throw TransportControlError.closed }
      try storage.check(); try custody.check(in: environment); try deadline.check()
      try material.check(); try identity.check(in: environment)
      if Task.isCancelled { throw TransportControlError.canceled }
    }
  }
  private func payload(_ kind: String) throws -> V4RegisteredLivePayload {
    try environment.gate.withLock {
      guard let projection else { throw TransportControlError.closed }
      return V4RegisteredLivePayload(kind: kind, incarnation: incarnation.base64EncodedString(),
        parent: projection.artifact, candidate: projection.candidateIndex)
    }
  }
  private func call(_ payload: V4RegisteredLivePayload, material: V4DirectPoolMaterial) async throws -> V4RegisteredLiveReply {
    try check(material)
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var content = try encoder.encode(payload); defer { V4Crypto.wipe(&content) }
    var message = Data("flowersec/original-tunnel-control/1\0".utf8) + content; defer { V4Crypto.wipe(&message) }
    var signature = try identity.signRegisteredControl(message, in: environment); defer { V4Crypto.wipe(&signature) }
    guard let text = String(data: content, encoding: .utf8) else { throw TransportControlError.responseInvalid }
    var body = try encoder.encode(V4RegisteredLiveEnvelope(payload: text, proof: signature.base64EncodedString()))
    defer { V4Crypto.wipe(&body) }
    let original = try environment.gate.withLock { () throws -> V4ResourceCustody in
      try check(material); guard let custody else { throw TransportControlError.closed }; return custody
    }
    // The registered source fixes the path; independently installed routing
    // cannot append another authority protocol or choose a different endpoint.
    let response = try await provider.post(path: "/flowersec/control/live", body: body, maximumResponseBytes: 262_144,
      requestContentType: "application/json", responseContentType: "application/json", custody: original,
      cleanup: try material.controlCall(payload.kind == "live_client_prepared" ? .registeredPrepare : .authorize)) { try self.check(material) }
    defer { withExtendedLifetime(response) {} }
    try check(material)
    let reply = try JSONDecoder().decode(V4RegisteredLiveReply.self, from: response.bytes)
    guard reply.incarnation == payload.incarnation, reply.authority == configuration.authority,
      payload.kind == "live_client_prepared" && reply.prepared && reply.grant.isEmpty
        || payload.kind == "live_authorize" && !reply.prepared && !reply.grant.isEmpty
    else { throw TransportControlError.responseInvalid }
    return reply
  }
  private func external(_ path: String, body: Data, material: V4DirectPoolMaterial) async throws {
    let original = try environment.gate.withLock { () throws -> V4ResourceCustody in
      try check(material); guard let custody else { throw TransportControlError.closed }; return custody
    }
    let response = try await relay.post(path: path, body: body, maximumResponseBytes: 1, custody: original,
      cleanup: try material.controlCall(path == "/tunnel/relay-prepare" ? .relayPrepare : .relayActivate)) { try self.check(material) }
    guard response.bytes == Data([0xf5]) else { throw TransportControlError.responseInvalid }
    try check(material)
  }
  private func prepare(_ material: V4DirectPoolMaterial) async throws {
    try environment.gate.withLock {
      try check(material); guard phase == .bound else { throw TransportControlError.responseInvalid }; phase = .preparing
    }
    var request = try payload("live_client_prepared")
    request.attempt = material.plan.credential.attemptID.base64EncodedString()
    _ = try await call(request, material: material)
    try environment.gate.withLock {
      try check(material); guard phase == .preparing else { throw TransportControlError.responseInvalid }; phase = .prepared
    }
  }
  func carrierListening(_ material: V4DirectPoolMaterial) async throws {
    environment.gate.withLock { activeOperations += 1 }
    defer { environment.gate.withLock { activeOperations -= 1 } }
    do {
      try environment.gate.withLock {
        try check(material); guard phase == .bound, !readySent else { throw TransportControlError.responseInvalid }; readySent = true
      }
      try await V4RelayCarrierReady.send(admission: material.plan.credential, provider: relay,
        custody: try material.plan.credential.originalControlCustody(), cleanup: try material.controlCall(.relayReady)) { try self.check(material) }
      try await prepare(material)
    } catch { close(); material.plan.credential.close(); throw error }
  }
  func authorize(_ material: V4DirectPoolMaterial) async throws {
    environment.gate.withLock { activeOperations += 1 }
    defer { environment.gate.withLock { activeOperations -= 1 } }
    do {
      let request = try environment.gate.withLock { () throws -> Data in
        try check(material); guard phase == .bound || phase == .prepared else { throw TransportControlError.responseInvalid }
        return originalRequest
      }
      try await external("/tunnel/relay-prepare", body: request, material: material)
      if environment.gate.withLock({ phase == .bound }) { try await prepare(material) }
      try environment.gate.withLock {
        try check(material); guard phase == .prepared else { throw TransportControlError.responseInvalid }; phase = .authorizing
      }
      var authentication = try V4Crypto.random(32)
      defer { V4Crypto.wipe(&authentication) }
      guard authentication.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.key }
      authentication.append(request)
      var signature = try identity.signRegisteredAuthorization(authentication, in: environment)
      defer { V4Crypto.wipe(&signature) }
      var payload = try self.payload("live_authorize")
      payload.authentication = authentication.base64EncodedString(); payload.signature = signature.base64EncodedString()
      payload.request = environment.gate.withLock { projection }
      material.plan.credential.connectionFacts.spendDispatched()
      let reply = try await call(payload, material: material)
      guard reply.grant.utf8.count <= ((73_728 + 2) / 3) * 4,
        var wire = Data(base64Encoded: reply.grant), !wire.isEmpty, wire.count <= 73_728,
        wire.base64EncodedString() == reply.grant else { throw TransportControlError.responseInvalid }
      defer { V4Crypto.wipe(&wire) }
      let delivery = try V4LiveTunnelMaterial.decode(wire)
      try check(material)
      try material.plan.installLiveAuthorization(wire, signingKeyID: configuration.activationSigningKeyID, configuration: credentials)
      let digests = try environment.gate.withLock { () throws -> [Data] in
        try check(material); guard phase == .authorizing else { throw TransportControlError.responseInvalid }
        let proof = try material.plan.credential.originalActivation()
        let (grant, _) = try material.plan.credential.tunnelGrant()
        guard proof.raw.elementsEqual(delivery.activation), grant.raw.elementsEqual(delivery.grant) else {
          throw TransportControlError.responseInvalid
        }
        let values = [try proof.digest("activation_digest"), try grant.digest("grant_digest")]
        guard values[0] == material.plan.credential.activationDigest else { throw TransportControlError.responseInvalid }
        deliveryDigests = values; phase = .delivered; return values
      }
      let publication = V4NamespaceValue.head(4, 4) + V4Crypto.text("tunnel-relay-activate-client-1")
        + V4Crypto.bytes(request) + V4Crypto.bytes(delivery.activation) + V4Crypto.bytes(delivery.grant)
      try await external("/tunnel/relay-activate-client", body: publication, material: material)
      try material.plan.credential.checkLiveActivationComplete(in: environment)
      try environment.gate.withLock {
        try check(material)
        let (grant, _) = try material.plan.credential.tunnelGrant()
        guard phase == .delivered, originalRequest == request, deliveryDigests == digests,
          material.plan.credential.activationDigest == digests[0], try grant.digest("grant_digest") == digests[1]
        else { throw TransportControlError.responseInvalid }
        phase = .handedOff; originalMaterial = nil; releaseControl()
      }
    } catch { close(); material.plan.credential.close(); throw error }
  }
  private func releaseControl() {
    provider.close(); relay.close(); deadline?.cancel(); deadline = nil; admission = nil; custody = nil
    projection = nil; deliveryDigests = nil; V4Crypto.wipe(&originalRequest); V4Crypto.wipe(&incarnation); V4Crypto.wipe(&sourceIncarnation); storage.seal()
  }
  func materialFinished(success: Bool) { close() }
  func close() {
    environment.gate.withLock {
      // Handoff is a terminal publication fact; retiring the source later
      // cannot withdraw the already consumed original authorization.
      guard phase != .handedOff, phase != .retired else { return }
      phase = .retired
      let material = originalMaterial
      admission?.close(); releaseControl(); material?.close()
    }
  }
  func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let control = provider.cleanupStatus(), external = relay.cleanupStatus()
      let material = originalMaterial?.cleanupStatus()
      let pending = UInt64(activeOperations) + control.pendingCallbacks + external.pendingCallbacks
        + (material?.pendingCallbacks ?? 0)
      return CleanupStatus(complete: (phase == .retired || phase == .handedOff)
        && activeOperations == 0 && control.complete && external.complete && (material?.complete ?? true),
        pendingCallbacks: pending)
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    while !cleanupStatus().complete {
      try await ContinuousClock().sleep(for: .milliseconds(10))
    }
    return cleanupStatus()
  }
  deinit { close() }
}

final class V4RegisteredLiveMaterialSource: V4ConfiguredMaterialSourceOwner, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let client: V4ClientEnvironment
  private let configuration: TransportRegisteredLiveAuthoritySourceConfiguration
  private let identity: TransportApplicationIdentity
  private var original: V4RegisteredLiveControl?
  private var withdrawn = false
  private var closed = false
  init(client: V4ClientEnvironment, configuration: TransportRegisteredLiveAuthoritySourceConfiguration,
    identity: TransportApplicationIdentity) throws {
    self.client = client; self.configuration = configuration; self.identity = identity
    original = try V4RegisteredLiveControl(client: client, configuration: configuration, identity: identity)
    try client.foundation.registerNativeConnection(self)
  }
  func check(in environment: V4EnvironmentFoundation) throws {
    try client.foundation.gate.withLock {
      guard environment === client.foundation else { throw TransportConnectError.invalidMaterial }
      guard !closed, !withdrawn, let original else { throw ConnectionMaterialSourceError.closed }
      try original.checkAvailable()
    }
  }
  func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
    try client.foundation.gate.withLock {
      try check(in: client.foundation)
      // Withdraw before any fallible acquisition work. No failed operation can
      // publish this installed parent into a new incarnation or attempt.
      withdrawn = true
      guard let control = original else { throw ConnectionMaterialSourceError.closed }
      var material: ConnectionMaterial?
      do {
        try Task.checkCancellation(); try V4DirectEstablishment.requirements(requirements)
        guard requirements.applicationProfile == nil || requirements.applicationProfile == configuration.applicationProfile else {
          throw TransportConnectError.unsupported
        }
        let input = V4CredentialInput(artifact: configuration.artifact, clientCertificate: configuration.clientCertificate,
          serverCertificate: configuration.serverCertificate, activation: Data(), source: .liveAuthority,
          candidateIndex: configuration.tunnel.candidateIndex, liveTunnel: configuration.tunnel)
        let captured = try client.directMaterial(input, identity: identity, live: control); material = captured
        guard let owner = captured.owner as? V4DirectPoolMaterial else { throw TransportConnectError.invalidMaterial }
        try V4DirectEstablishment.requirements(requirements, route: owner.plan.route)
        try control.bind(owner); try Task.checkCancellation()
        return captured
      } catch {
        material?.close(); control.close(); throw error
      }
    }
  }
  func close() {
    client.foundation.gate.withLock { closed = true; withdrawn = true; original?.close() }
  }
  func cleanupStatus() -> CleanupStatus {
    client.foundation.gate.withLock {
      guard closed || withdrawn else { return CleanupStatus(complete: false, pendingCallbacks: 0) }
      guard let original else { return CleanupStatus(complete: true, pendingCallbacks: 0) }
      let status = original.cleanupStatus()
      if status.complete { self.original = nil }
      return status
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    let owner = client.foundation.gate.withLock { original }
    if let owner { _ = try await owner.waitCleanup() }
    return cleanupStatus()
  }
  deinit { close() }
}
#endif
