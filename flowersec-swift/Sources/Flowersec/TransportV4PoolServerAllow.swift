#if os(macOS) || os(iOS)
import Foundation

// This original material owns one independent server Grant and sender. The
// prepared request can be used only after its own pool consume returns success.
final class V4PoolServerAllow: @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let plan: V4DirectPoolPlan
  private let input: V4PoolServerAllowInput
  private let grant: V4LiveGrantPreparation
  private let control: V4ControlHTTPS
  private let storage: V4CryptoReservation
  init(environment: V4EnvironmentFoundation, plan: V4DirectPoolPlan,
    configuration: V4CredentialConfiguration, input: V4PoolServerAllowInput) throws {
    guard plan.environment === environment, plan.role == .client,
      plan.credential.source == .preauthorizedPool, plan.credential.pathKind == 1,
      (1...9302).contains(input.grant.count),
      [input.recipient, input.incarnation].allSatisfy({ $0.count == 16 && $0.contains(where: { $0 != 0 }) }),
      input.control.basePath.isEmpty, (1...2000).contains(input.control.timeoutMilliseconds) else { throw TransportConnectError.invalidMaterial }
    storage = try environment.materialSourceStorage(bytes: 3 * (input.grant.count + 1024), items: 1)
    self.environment = environment; self.plan = plan; self.input = input
    grant = try plan.credential.preparePoolServerGrant(input.grant, configuration: configuration)
    control = try V4ControlHTTPS(environment: environment, configuration: input.control)
  }
  func prepare(material: V4DirectPoolMaterial, carrier: V4PreparedWebSocket) throws -> V4PreparedPoolServerAllow {
    try environment.gate.withLock {
      guard material.plan === plan else { throw TransportConnectError.invalidMaterial }
      try storage.check(); try material.check(); try carrier.check(); try grant.check()
      guard let signed = grant.completedGrant else { throw TransportConnectError.invalidMaterial }
      let localGrant = try plan.credential.tunnelGrant().0
      guard try signed.b("pairing_id") == localGrant.b("pairing_id") else { throw TransportConnectError.securityFailed }
      let candidate = try plan.credential.originalCandidate()
      let candidates = try plan.artifact.field("candidates").children.map { $0 }
      guard let index = try candidates.firstIndex(where: { try $0.b("candidate_id") == plan.credential.candidateID })
      else { throw TransportConnectError.invalidMaterial }
      let notAfter = min(grant.scope.expiresMS, plan.credential.initiationNotAfterMS,
        try plan.artifact.u("session_not_after_ms"))
      let deadline = try V4SecurityDeadline(clock: environment.clock, capMS: notAfter)
      try deadline.check()
      var request = Data(); request.reserveCapacity(input.grant.count + 1024)
      request.append(V4NamespaceValue.head(4, 14))
      request.append(V4Crypto.text("tunnel-server-allow-1"))
      request.append(V4Crypto.text(try plan.artifact.t("tenant_id")))
      request.append(V4Crypto.text(try plan.artifact.t("audience")))
      for value in [plan.credential.artifactDigest, try signed.digest("grant_digest"),
        try grant.relayCertificate.digest("certificate_digest"), plan.credential.attemptID,
        try signed.b("pairing_id"), try candidate.field("server_leg").b("leg_id"), input.recipient, input.incarnation] {
        request.append(V4Crypto.bytes(value))
      }
      request.append(V4NamespaceValue.head(4, 3)); request.append(V4NamespaceValue.head(0, UInt64(index)))
      request.append(V4Crypto.bytes(plan.credential.candidateID)); request.append(V4Crypto.bytes(plan.credential.routeDigest))
      request.append(V4NamespaceValue.head(0, notAfter)); request.append(V4Crypto.bytes(input.grant))
      defer { request.resetBytes(in: 0..<request.count) }
      guard request.count <= 10_326 else { throw TransportConnectError.invalidMaterial }
      let original = V4PoolServerAllowCarrier(carrier)
      let call = try control.prepare(path: "/tunnel/server-allow", body: request, maximumResponseBytes: 1,
        custody: plan.credential.originalControlCustody(), cleanup: material.controlCall(.poolServerAllow)) { [self] in
        try material.check(); try original.check(); try self.grant.check(); try deadline.check()
      }
      return V4PreparedPoolServerAllow(call: call, carrier: original)
    }
  }
  deinit { control.close(); grant.close() }
}

private final class V4PoolServerAllowCarrier: @unchecked Sendable {
  private let gate = NSLock()
  private let prepared: V4PreparedWebSocket
  private let identity: ObjectIdentifier
  private var consumed: V4ConsumedWebSocket?
  init(_ prepared: V4PreparedWebSocket) {
    self.prepared = prepared; identity = ObjectIdentifier(prepared.tunnelCarrierIdentity)
  }
  func install(_ socket: V4ConsumedWebSocket) throws {
    try gate.withLock {
      guard consumed == nil, ObjectIdentifier(socket.tunnelCarrierIdentity) == identity else {
        throw TransportConnectError.invalidMaterial
      }
      try socket.check(); consumed = socket
    }
  }
  func check() throws {
    try gate.withLock {
      if let consumed { try consumed.check() } else { try prepared.check() }
    }
  }
}

final class V4PreparedPoolServerAllow: @unchecked Sendable {
  private let call: V4PreparedControlHTTPCall
  private let carrier: V4PoolServerAllowCarrier
  fileprivate init(call: V4PreparedControlHTTPCall, carrier: V4PoolServerAllowCarrier) {
    self.call = call; self.carrier = carrier
  }
  func publish(afterConsuming socket: V4ConsumedWebSocket) async throws {
    try carrier.install(socket)
    if Task.isCancelled { throw TransportConnectError.canceled }
    let response = try await call.run()
    guard response.bytes.elementsEqual([0xf5]) else { throw TransportControlError.responseInvalid }
    try carrier.check()
  }
}
#endif
