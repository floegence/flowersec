import Crypto
import Foundation

struct V4HandshakeInput: Sendable, CustomStringConvertible, CustomReflectable {
  let artifact: Data
  let clientHello: Data
  let serverHello: Data
  let transportContext: Data
  let fsb: Data
  let fsa: Data
  let tunnelHop: V4TunnelHop?
  init(artifact: Data, clientHello: Data, serverHello: Data, transportContext: Data,
    fsb: Data, fsa: Data, tunnelHop: V4TunnelHop? = nil) {
    self.artifact = artifact; self.clientHello = clientHello; self.serverHello = serverHello
    self.transportContext = transportContext; self.fsb = fsb; self.fsa = fsa
    self.tunnelHop = tunnelHop
  }
  var description: String { "Flowersec.HandshakeInput(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

enum V4HandshakeFlight: Sendable { case noise, ready }
// Success means the original ordered native publisher has accepted the exact
// bytes' irreversible submission obligation. An uncertain/failed submission
// closes this attempt; generating bytes alone can never mark READY submitted.
protocol V4HandshakeWriter {
  func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws
  func checkHop(_ hop: V4TunnelHop) throws
}
extension V4HandshakeWriter {
  func checkHop(_ hop: V4TunnelHop) throws { throw V4CryptoFailure.authentication }
}

struct V4ReadyBinding {
  let profile: V4CryptoProfile
  let context: Data
  let admission: Data
  let certificates: [Data]
  let identities: [Data]
  let fsb: Data
  let fsa: Data
  let features: UInt64
  func message(hash: Data, role: V4CryptoRole, proof: Data? = nil) -> Data {
    var fields: [(UInt64, Data)] = [
      (0, V4NamespaceValue.head(0, UInt64(role.rawValue))), (1, V4Crypto.text(profile.rawValue)),
    ]
    for (index, value) in [hash, fsb, fsa, context, admission, certificates[Int(role.rawValue)]]
      .enumerated()
    {
      fields.append((UInt64(index + 2), V4Crypto.bytes(value)))
    }
    if let proof {
      fields.append((8, V4NamespaceValue.head(0, features)))
      fields.append((9, V4Crypto.bytes(proof)))
    }
    return V4Crypto.domain(proof == nil ? "ready-identity" : "ready-mac", [V4Crypto.map(fields)])
  }
  func key(root: SymmetricKey, hash: Data, role: V4CryptoRole) -> SymmetricKey {
    V4Crypto.expand(
      root,
      info: V4Crypto.domain(
        "ready-key", [Data(profile.rawValue.utf8), hash, context]) + Data([role.rawValue]))
  }
  func verify(_ input: Data, root: SymmetricKey, hash: Data, role: V4CryptoRole) throws {
    guard input.count == 103 else { throw V4CryptoFailure.authentication }
    let wire = Data(input)
    guard wire.count == 103, wire.prefix(4) == Data([0xa2, 0, 0x58, 0x40]),
      wire[68..<71] == Data([1, 0x58, 0x20])
    else { throw V4CryptoFailure.authentication }
    let proof = Data(wire[4..<68])
    guard
      HMAC<SHA256>.isValidAuthenticationCode(
        wire.suffix(32), authenticating: message(hash: hash, role: role, proof: proof),
        using: key(root: root, hash: hash, role: role)),
      StrictEd25519V4Reference.verify(
        signature: proof, message: message(hash: hash, role: role),
        publicKey: identities[Int(role.rawValue)])
    else { throw V4CryptoFailure.authentication }
  }
}

// No memberwise/raw-root factory exists outside this file. Only the two READY
// transition below can mint this one-use handoff to the reliable record owner.
final class V4EstablishedAdmission {
  let owner: V4CryptoReservation
  let credential: V4CredentialAdmission
  let profile: V4CryptoProfile
  let role: V4CryptoRole
  let hash: Data
  let born: V4ClockSample
  let maxFrame: Int
  let maxStreams: Int
  let maxCredit: UInt64
  let rekeyEnvelope: Data
  let context: Data
  let serviceMS: UInt64
  let applicationProfile: UInt64
  let features: UInt64
  let streamStorage: V4CryptoReservation?
  private var root: SymmetricKey?
  fileprivate init(
    owner: V4CryptoReservation, credential: V4CredentialAdmission,
    profile: V4CryptoProfile, role: V4CryptoRole, hash: Data, born: V4ClockSample,
    root: SymmetricKey, maxFrame: Int, maxStreams: Int, maxCredit: UInt64,
    rekeyEnvelope: Data, context: Data, serviceMS: UInt64, applicationProfile: UInt64,
    streamStorage: V4CryptoReservation?, features: UInt64 = 0
  ) {
    self.owner = owner
    self.credential = credential
    self.profile = profile
    self.role = role
    self.hash = hash
    self.born = born
    self.root = root
    self.maxFrame = maxFrame
    self.maxStreams = maxStreams
    self.maxCredit = maxCredit
    self.rekeyEnvelope = rekeyEnvelope
    self.context = context
    self.serviceMS = serviceMS
    self.applicationProfile = applicationProfile
    self.features = features
    self.streamStorage = streamStorage
  }
  func takeRoot() throws -> SymmetricKey {
    guard let root else { throw V4CryptoFailure.phase }
    self.root = nil
    return root
  }
}

final class V4Handshake: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
  static var charge: V4ResourceVector {
    V4ResourceVector(
      sdkBytes: V4NamespaceRegistry.backingBytes + 16_777_216
        + UInt64(8 * 32768 * MemoryLayout<V4NamespaceDocument.Node>.stride),
      items: 1, work: 1, handshakes: 1, sessions: 1)
  }
  private let owner: V4CryptoReservation
  private let credential: V4CredentialAdmission
  private let tunnelHop: V4TunnelHop?
  private let role: V4CryptoRole
  private var identity: V4LocalIdentity?
  private var noise: V4NoiseState?
  private let binding: V4ReadyBinding
  private let maxFrame: Int
  private let maxStreams: Int
  private let maxCredit: UInt64
  private let rekeyEnvelope: Data
  private let serviceMS: UInt64
  private let applicationProfile: UInt64
  private let streamStorage: V4CryptoReservation?
  private let window: V4LocalWorkWindow
  private var hash = Data()
  private var root: SymmetricKey?
  private var born: V4ClockSample?
  private var localNoiseSubmitted = false
  private var peerNoiseSeen = false
  private var localReadySubmitted = false
  private var peerReadyVerified = false
  private var busy = false
  private var closed = false
  var description: String { "Flowersec.Handshake(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }

  init(
    owner: V4CryptoReservation, admission: V4CredentialAdmission, role: V4CryptoRole,
    identity: V4LocalIdentity, input: V4HandshakeInput, streamStorage: V4CryptoReservation? = nil
  ) throws {
    self.owner = owner
    credential = admission
    tunnelHop = input.tunnelHop
    self.role = role
    self.identity = identity
    self.streamStorage = streamStorage
    let environment = owner.environment
    window = try V4LocalWorkWindow(clock: environment.clock, durationMS: 10_000)
    try owner.check()
    if let streamStorage {
      guard streamStorage.environment === environment else { throw V4ResourceFailure.owner }
      try streamStorage.check()
    }
    try admission.checkPreparation(in: environment)
    try identity.check(in: environment)
    let registry = try V4NamespaceRegistry()
    func decode(_ bytes: Data, _ schema: String, _ cap: Int) throws -> V4NamespaceValue {
      try V4NamespaceDocument(
        bytes, schema: schema, bytes: cap, nodes: 32768, registry: registry,
        context: ["activation_source_profile": admission.source.rawValue]
      ).root
    }
    func same(_ a: V4NamespaceValue, _ name: String, _ b: V4NamespaceValue, _ other: String? = nil)
      throws
    {
      guard try a.field(name).raw.elementsEqual(b.field(other ?? name).raw) else {
        throw V4CryptoFailure.authentication
      }
    }
    func expect(_ value: V4NamespaceValue, _ field: String, _ bytes: Data) throws {
      guard try value.b(field) == bytes else { throw V4CryptoFailure.authentication }
    }
    let artifact = try decode(input.artifact, "Artifact", 65_536)
    guard try artifact.digest("artifact_digest") == admission.artifactDigest,
      let profile = V4CryptoProfile(rawValue: admission.cryptoProfile), identity.profile == profile
    else { throw V4CryptoFailure.authentication }
    let fsb = try decode(input.fsb, "FSB4", 65_536)
    let fsa = try decode(input.fsa, "FSA4", 16_384)
    let client = try decode(fsb.b("client_certificate"), "IdentityCertificate", 8192)
    let server = try decode(fsa.b("server_certificate"), "IdentityCertificate", 8192)
    let certificates = try [
      client.digest("certificate_digest"), server.digest("certificate_digest"),
    ]
    guard certificates == admission.certificateDigests else { throw V4CryptoFailure.authentication }
    let identities = try [client.b("ed25519_public_key"), server.b("ed25519_public_key")]
    let publicKeys = try [client, server].map {
      try $0.field("noise_static_public_key").b("public_key_bytes")
    }
    guard identity.identityPublicKey == identities[Int(role.rawValue)],
      identity.dhPublicKey == publicKeys[Int(role.rawValue)]
    else { throw V4CryptoFailure.key }
    try fsb.verify("fsb_signature", publicKey: identities[0])
    try fsa.verify("fsa_signature", publicKey: identities[1])
    let activation = try decode(fsb.b("activation_authorization"), "ActivationAuthorization", 4096)
    guard try activation.digest("activation_digest") == admission.activationDigest else {
      throw V4CryptoFailure.authentication
    }
    for name in ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"] {
      try same(fsb, name, artifact)
    }
    for (name, bytes) in [
      ("artifact_digest", admission.artifactDigest), ("candidate_id", admission.candidateID),
      ("route_digest", admission.routeDigest), ("attempt_id", admission.attemptID),
    ] { try expect(fsb, name, bytes) }
    let clientHello = try decode(input.clientHello, "ClientHello", 16_384)
    let serverHello = try decode(input.serverHello, "ServerHello", 16_384)
    for name in [
      "protocol_id", "profile_revision", "crypto_profile_id", "artifact_digest",
      "candidate_id", "route_digest", "attempt_id", "client_nonce",
    ] {
      try same(clientHello, name, serverHello)
    }
    for name in ["artifact_digest", "candidate_id", "route_digest", "attempt_id"] {
      try same(clientHello, name, fsb)
    }
    try same(clientHello, "crypto_profile_id", artifact)
    try same(clientHello, "client_nonce", artifact, "session_nonce")
    let transcript = V4Crypto.hash(
      V4Crypto.domain("hello-transcript", [input.clientHello, input.serverHello]))
    let context = try decode(input.transportContext, "TransportContext", 4096)
    for name in ["crypto_profile_id", "session_nonce"] { try same(context, name, artifact) }
    for name in ["artifact_digest", "route_digest", "attempt_id"] { try same(context, name, fsb) }
    guard try context.u("path_kind") == admission.pathKind,
      let selected = try artifact.field("candidates").children.first(where: {
        try $0.b("candidate_id") == admission.candidateID
      }), try selected.u("path_kind") == admission.pathKind
    else { throw V4CryptoFailure.configuration }
    let legName = admission.pathKind == 0 ? "direct_leg" : (role == .client ? "client_leg" : "server_leg")
    guard try context.u("access_class") == selected.field(legName).u("access_class") else {
      throw V4CryptoFailure.configuration
    }
    if admission.pathKind == 1 {
      guard let tunnelHop else { throw V4CryptoFailure.authentication }
      try tunnelHop.claimHandshake(admission: admission, role: role, in: environment)
    } else {
      guard tunnelHop == nil else { throw V4CryptoFailure.authentication }
    }
    let mode = try serverHello.u("binding_mode")
    let features = try serverHello.u("selected_features")
    guard try clientHello.u("supported_binding_modes") & (1 << mode) != 0,
      features
        == (try clientHello.u("offered_features") & serverHello.u("server_offered_features")
          & artifact.u("allowed_features") & 3),
      try artifact.u("required_features") & ~features == 0
    else { throw V4CryptoFailure.authentication }
    // Reliable native records support the application recovery feature.
    // Datagram negotiation remains outside this carrier implementation.
    guard features & ~UInt64(2) == 0, try features & 2 == 0 || artifact.field("session_contract").u("application_profile") == 2 else { throw V4CryptoFailure.configuration }
    let contextDigest = try context.digest("transport_context_digest")
    let admissionBinding = try fsb.digest("admission_binding")
    for value in [fsb, fsa, context] {
      try expect(value, "hello_transcript_digest", transcript)
      guard try value.u("binding_mode") == mode, try value.u("selected_features") == features else {
        throw V4CryptoFailure.authentication
      }
      if value.schema != "TransportContext" {
        try expect(value, "transport_context_digest", contextDigest)
      }
    }
    guard try fsa.u("status") == 0, try fsa.u("code") == 0 else {
      throw V4CryptoFailure.authentication
    }
    try expect(fsa, "route_digest", admission.routeDigest)
    try expect(fsa, "admission_binding", admissionBinding)
    try expect(fsa, "client_identity_digest", certificates[0])
    try expect(fsa, "server_identity_digest", certificates[1])
    let contract = try artifact.field("session_contract")
    maxFrame = try Int(contract.u("max_frame"))
    maxStreams = try Int(contract.u("max_streams"))
    maxCredit = try contract.u("max_credit")
    rekeyEnvelope = try Data(contract.field("rekey_envelope").raw)
    serviceMS = try artifact.u("session_not_after_ms") - artifact.u("issued_at_ms")
    applicationProfile = try contract.u("application_profile")
    guard (36...1_048_576).contains(maxFrame), (0...1035).contains(maxStreams), maxCredit <= 8 << 20
    else {
      throw V4CryptoFailure.capacity
    }
    let rekey = try contract.field("rekey_envelope")
    let phaseBytes = 268 + 21 * maxStreams
    guard phaseBytes + 36 <= maxFrame, 2 * phaseBytes + 3 <= 65_536 else {
      throw V4CryptoFailure.capacity
    }
    _ = try V4RekeyCredit(
      burst: rekey.u("burst_rounds"), period: rekey.u("refill_period_ms"),
      startBudget: rekey.u("request_start_budget_ms"), serviceMS: serviceMS,
      clock: environment.clock)
    binding = try V4ReadyBinding(
      profile: profile, context: contextDigest, admission: admissionBinding,
      certificates: certificates, identities: identities, fsb: fsb.digest("fsb_digest"),
      fsa: fsa.digest("fsa_digest"), features: features)
    let prologue =
      V4Crypto.domain("noise-prologue", [Data("4".utf8), Data(profile.rawValue.utf8)])
      + Data([0, 1]) + V4Crypto.lp(contextDigest) + V4Crypto.lp(input.fsb) + V4Crypto.lp(input.fsa)
    var psk = try artifact.b("e2ee_psk")
    defer { V4Crypto.wipe(&psk) }
    noise = try V4NoiseState(
      profile: profile, role: role, localPublic: identity.dhPublicKey,
      peerPublic: publicKeys[Int(role.peer.rawValue)],
      sharedStatic: { try identity.shared($0, in: environment) }, psk: psk, prologue: prologue)
    try check()
  }
  private func check() throws {
    try owner.environment.gate.withLock {
      guard !closed else { throw V4CryptoFailure.closed }
      try owner.check()
      try credential.checkPreparation(in: owner.environment)
      try tunnelHop?.check(admission: credential, role: role, in: owner.environment)
      try window.check()
      try identity?.check(in: owner.environment)
    }
  }
  private func run<T>(_ operation: () throws -> T) throws -> T {
    let tail = try owner.environment.gate.withLock { () throws -> V4ResourceReference in
      guard !busy else { throw V4CryptoFailure.phase }
      try check()
      let tail = try owner.executionTail()
      busy = true
      return tail
    }
    defer {
      owner.environment.gate.withLock {
        busy = false
        if closed { clearSecrets() }
      }
      tail.release()
    }
    do {
      let result = try operation()
      try check()
      return result
    } catch {
      close()
      throw error
    }
  }
  func submitNoise(to writer: any V4HandshakeWriter) throws {
    try run {
      guard !localNoiseSubmitted, let noise else { throw V4CryptoFailure.phase }
      let buffer = try owner.environment.cryptoBuffer(capacity: binding.profile.publicBytes + 16)
      let ephemeral = try V4SoftwareDH.generate(binding.profile)
      try check()
      try buffer.store(noise.write(ephemeral: ephemeral))
      try check()
      if let tunnelHop { try writer.checkHop(tunnelHop) }
      try writer.submit(.noise, buffer: buffer)
      try check()
      localNoiseSubmitted = true
    }
  }
  func receiveNoise(_ message: Data) throws {
    try run {
      guard !peerNoiseSeen, let noise else { throw V4CryptoFailure.phase }
      peerNoiseSeen = true
      try noise.read(message)
    }
  }
  private func finishNoise() throws {
    if root != nil { return }
    guard localNoiseSubmitted, peerNoiseSeen, let noise else { throw V4CryptoFailure.phase }
    let sample = owner.environment.clock.sample()
    guard sample.failure == nil, sample.interval != nil, sample.mark != nil else {
      throw sample.failure ?? V4TimeFailure.unavailable
    }
    let material = try noise.finish(context: binding.context)
    hash = material.hash
    root = material.root
    born = sample
    self.noise = nil
  }
  func submitReady(to writer: any V4HandshakeWriter) throws {
    try run {
      guard !localReadySubmitted else { throw V4CryptoFailure.phase }
      try finishNoise()
      let buffer = try owner.environment.cryptoBuffer(capacity: 103)
      let proof = try identity!.signHandshake(
        binding.message(hash: hash, role: role), in: owner.environment)
      try check()
      let tag = V4Crypto.mac(
        binding.key(root: root!, hash: hash, role: role),
        binding.message(hash: hash, role: role, proof: proof))
      try buffer.store(Data([0xa2, 0, 0x58, 0x40]) + proof + Data([1, 0x58, 0x20]) + tag)
      try check()
      if let tunnelHop { try writer.checkHop(tunnelHop) }
      try writer.submit(.ready, buffer: buffer)
      try check()
      localReadySubmitted = true
    }
  }
  func receiveReady(_ bytes: Data) throws {
    try run {
      guard !peerReadyVerified else { throw V4CryptoFailure.phase }
      try finishNoise()
      try binding.verify(bytes, root: root!, hash: hash, role: role.peer)
      try check()
      peerReadyVerified = true
    }
  }
  func establish() throws -> V4ReliableChannel {
    try owner.environment.gate.withLock {
      guard !busy else { throw V4CryptoFailure.phase }
      do {
        try check()
        guard localReadySubmitted, peerReadyVerified, let root, let born else {
          throw V4CryptoFailure.phase
        }
        let established = V4EstablishedAdmission(
          owner: owner, credential: credential, profile: binding.profile, role: role,
          hash: hash, born: born, root: root, maxFrame: maxFrame, maxStreams: maxStreams,
          maxCredit: maxCredit, rekeyEnvelope: rekeyEnvelope, context: binding.context,
          serviceMS: serviceMS, applicationProfile: applicationProfile, streamStorage: streamStorage, features: binding.features
        )
        let channel = try V4ReliableChannel(established)
        self.root = nil
        identity = nil
        closed = true
        window.cancel()
        return channel
      } catch {
        close()
        throw error
      }
    }
  }
  func close() {
    owner.environment.gate.withLock {
      guard !closed else { return }
      closed = true
      window.cancel()
      owner.seal()
      if !busy { clearSecrets() }
    }
  }
  private func clearSecrets() {
    noise?.close(); noise = nil; identity = nil; root = nil
  }
  deinit { close() }
}
