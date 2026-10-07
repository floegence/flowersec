import Foundation

// Only the original native carrier can create this admission. Server hops
// retain their preparation until authenticated FSB commits local admission.
// The private constructor and one-use carrier claim preserve the physical owner,
// credential, role and independently verified relay across all four flights.
#if os(macOS) || os(iOS)
protocol V4TunnelAuthenticationCarrier: AnyObject, Sendable {
  var tunnelCarrierIdentity: AnyObject { get }
  func claimTunnelChallenge(credential: V4CredentialAdmission) throws -> (Data, Data)
  func check() throws
  func receive() async throws -> V4CryptoBuffer
  func publish(_ input: V4CryptoBuffer) throws
  func flush() async throws
  func close()
}
#endif

final class V4TunnelHop: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
  private let environment: V4EnvironmentFoundation
  private let credential: V4CredentialAdmission
  private let role: V4CryptoRole
  private let carrier: AnyObject
  private let carrierCheck: () throws -> Void
  private var handshakeClaimed = false
  private init(environment: V4EnvironmentFoundation, credential: V4CredentialAdmission,
    role: V4CryptoRole, carrier: AnyObject, carrierCheck: @escaping () throws -> Void) {
    self.environment = environment; self.credential = credential; self.role = role
    self.carrier = carrier; self.carrierCheck = carrierCheck
  }
  var description: String { "Flowersec.TunnelHop(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
  func check(admission: V4CredentialAdmission, role: V4CryptoRole,
    in original: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      guard original === environment, admission === credential, role == self.role,
        credential.pathKind == 1 else { throw V4CryptoFailure.authentication }
      try credential.checkPreparation(in: environment)
      try carrierCheck()
      _ = try credential.tunnelGrant()
    }
  }
  func checkCarrier(_ original: AnyObject) throws {
    try environment.gate.withLock {
      guard original === carrier else { throw V4CryptoFailure.authentication }
      try check(admission: credential, role: role, in: environment)
    }
  }
  func claimHandshake(admission: V4CredentialAdmission, role: V4CryptoRole,
    in original: V4EnvironmentFoundation) throws {
    try environment.gate.withLock {
      try check(admission: admission, role: role, in: original)
      guard !handshakeClaimed else { throw V4CryptoFailure.phase }
      handshakeClaimed = true
    }
  }

  #if os(macOS) || os(iOS)
  // The existing handshake reservation owns the temporary registry, decoders,
  // signing work and native callback tail. Native Prepare has already created
  // its own unpredictable incarnation/challenge before durable spend or TxB.
  static func authenticate(socket: any V4TunnelAuthenticationCarrier, plan: V4DirectPoolPlan,
    identity: V4LocalIdentity, storage: V4CryptoReservation) async throws -> V4TunnelHop {
    let environment = plan.environment
    guard storage.environment === environment, plan.credential.pathKind == 1 else {
      throw V4CryptoFailure.configuration
    }
    let tail = try storage.executionTail()
    defer { tail.release() }
    let registry = try V4NamespaceRegistry()
    let credential = plan.credential
    let (grant, relay) = try credential.tunnelGrant()
    let candidate = try credential.originalCandidate()
    let leg = try candidate.field(plan.role == .client ? "client_leg" : "server_leg")
    let endpointRole = UInt64(plan.role.rawValue)
    let dialer = try leg.u("dialer_role"); let listenerRole = try leg.u("listener_role")
    guard (dialer == endpointRole && listenerRole == 2) || (dialer == 2 && listenerRole == endpointRole),
      try leg.u("access_class") == 0, plan.route.maximumFrame >= 10_346,
      identity.identityPublicKey == (try plan.localCertificate.b("ed25519_public_key"))
    else { throw V4CryptoFailure.authentication }
    let (incarnation, challenge) = try socket.claimTunnelChallenge(credential: credential)
    func check() throws {
      try Task.checkCancellation(); try storage.check()
      try credential.checkPreparation(in: environment); try identity.check(in: environment)
      try socket.check()
    }
    func decode(_ bytes: Data, schema: String, maximum: Int,
      context: [String: String] = [:]) throws -> V4NamespaceValue {
      try V4NamespaceDocument(bytes, schema: schema, bytes: maximum, nodes: 4096,
        registry: registry, context: context).root
    }
    func send(_ bytes: Data) async throws {
      try check()
      guard !bytes.isEmpty, bytes.count <= plan.route.maximumFrame else { throw V4CryptoFailure.capacity }
      let wire = V4Crypto.integer(UInt64(bytes.count), width: 4) + Data([16, 0, 0, 0]) + bytes
      let buffer = try environment.cryptoBuffer(capacity: wire.count, credential: credential)
      try buffer.store(wire)
      try socket.publish(buffer)
      try await socket.flush()
      try check()
    }
    func receive(maximum: Int) async throws -> Data {
      try check()
      let buffer = try await socket.receive()
      defer { buffer.close() }
      let bytes = try buffer.withBytes { wire -> Data in
        guard wire.count > 8, wire.count <= maximum + 8,
          V4Crypto.number(wire.prefix(4)) == wire.count - 8,
          wire[4] == 16, wire[5..<8] == Data([0, 0, 0])
        else { throw V4CryptoFailure.authentication }
        return Data(wire.dropFirst(8))
      }
      try check(); return bytes
    }
    do {
      try check()
      let hello = V4Crypto.map([
        (0, V4NamespaceValue.head(0, 0)), (1, V4Crypto.bytes(incarnation)),
        (2, V4Crypto.bytes(challenge)), (3, V4Crypto.bytes(Data(grant.raw))),
        (4, V4Crypto.bytes(Data(plan.localCertificate.raw))),
      ])
      _ = try decode(hello, schema: "HOP_AUTH_HELLO", maximum: 10_346,
        context: ["hop_sender_role": "endpoint"])
      let peerWire: Data
      if plan.route.isDialer { try await send(hello); peerWire = try await receive(maximum: 10_346) }
      else { peerWire = try await receive(maximum: 10_346); try await send(hello) }
      let listener = try decode(peerWire, schema: "HOP_AUTH_HELLO",
        maximum: 10_346, context: ["hop_sender_role": "relay"])
      guard try listener.b("identity_certificate") == Data(relay.raw),
        try listener.u("phase") == 0 else { throw V4CryptoFailure.authentication }
      let hopContext = V4Crypto.map([
        (0, V4Crypto.bytes(plan.route.isDialer ? incarnation : try listener.b("local_incarnation"))),
        (1, V4Crypto.bytes(plan.route.isDialer ? try listener.b("local_incarnation") : incarnation)),
        (2, V4Crypto.bytes(try leg.b("leg_id"))), (3, V4NamespaceValue.head(0, dialer)),
        (4, V4NamespaceValue.head(0, listenerRole)),
        (5, V4Crypto.bytes(plan.route.isDialer ? challenge : try listener.b("local_challenge"))),
        (6, V4Crypto.bytes(plan.route.isDialer ? try listener.b("local_challenge") : challenge)),
      ])
      guard hopContext.count == 129 else { throw V4CryptoFailure.authentication }
      _ = try decode(hopContext, schema: "HopChallengeContext", maximum: 129)
      let (domain, _) = try registry.compoundDomain("grant_possession", operation: "ed25519")
      let prefix = domain + V4Crypto.lp(try grant.digest("grant_digest"))
        + V4Crypto.lp(credential.routeDigest) + V4Crypto.lp(try leg.b("leg_id"))
        + V4Crypto.lp(try grant.b("pairing_id")) + V4Crypto.lp(hopContext)
      try check()
      let message = prefix + Data([plan.role.rawValue])
      let proof = try identity.signHandshake(message, in: environment)
      guard StrictEd25519V4Reference.verify(signature: proof, message: message,
        publicKey: try plan.localCertificate.b("ed25519_public_key")) else { throw V4CryptoFailure.authentication }
      try check()
      let endpoint = V4Crypto.map([(0, V4NamespaceValue.head(0, 1)), (1, V4Crypto.bytes(proof))])
      _ = try decode(endpoint, schema: "HOP_AUTH_ENDPOINT_PROOF", maximum: 70)
      try await send(endpoint)
      let response = try decode(await receive(maximum: 70), schema: "HOP_AUTH_RELAY_PROOF", maximum: 70)
      guard try response.u("phase") == 2,
        StrictEd25519V4Reference.verify(signature: try response.b("proof"),
          message: prefix + Data([2]), publicKey: try relay.b("ed25519_public_key"))
      else { throw V4CryptoFailure.authentication }
      try check()
      return V4TunnelHop(environment: environment, credential: credential, role: plan.role,
        carrier: socket.tunnelCarrierIdentity, carrierCheck: { try socket.check() })
    } catch {
      socket.close()
      throw error
    }
  }
  #endif
}
