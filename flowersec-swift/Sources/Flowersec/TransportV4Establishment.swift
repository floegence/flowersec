#if os(macOS) || os(iOS)
  import Foundation

  public enum TransportV4ConnectError: Error, Sendable, Equatable {
    case invalidMaterial, unsupported, securityFailed, connectionFailed, expired, canceled, closed
    case admissionRejected(code: UInt16)
  }

  // Only this file's original dual-READY path can promote the consumed native
  // socket to Session lifetime. Neither a raw record owner nor copied fields
  // can satisfy this constructor.
  final class V4NativeSessionAdmission: @unchecked Sendable {
    let socket: V4ConsumedWebSocket
    let core: V4ReliableSession
    let plan: V4DirectPoolPlan
    let storage: V4CryptoReservation
    fileprivate init(
      socket: V4ConsumedWebSocket, core: V4ReliableSession,
      plan: V4DirectPoolPlan, storage: V4CryptoReservation
    ) {
      self.socket = socket
      self.core = core
      self.plan = plan
      self.storage = storage
    }
  }

  final class V4DirectPoolMaterial: ConnectionMaterialOwner, @unchecked Sendable {
    let plan: V4DirectPoolPlan
    let identity: V4LocalIdentity
    private var used = false
    private var closed = false
    private var running = false
    private var cancel: (@Sendable () -> Void)?
    init(plan: V4DirectPoolPlan, identity: V4LocalIdentity) {
      self.plan = plan
      self.identity = identity
    }
    func claim(in environment: V4EnvironmentFoundation) throws {
      try environment.gate.withLock {
        guard environment === plan.environment, !used, !closed else {
          throw TransportV4ConnectError.invalidMaterial
        }
        try plan.credential.checkPreparation(in: environment)
        try identity.check(in: environment)
        used = true
        running = true
      }
    }
    func check() throws {
      try plan.environment.gate.withLock {
        guard !closed, running else { throw TransportV4ConnectError.closed }
        try plan.credential.checkPreparation(in: plan.environment)
        try identity.check(in: plan.environment)
      }
    }
    func cancellation(_ action: @escaping @Sendable () -> Void) throws {
      try plan.environment.gate.withLock {
        try check()
        cancel = action
      }
    }
    func finish(success: Bool) {
      plan.environment.gate.withLock {
        running = false
        cancel = nil
        closed = true
        if !success { plan.credential.close() }
      }
    }
    func close() {
      plan.environment.gate.withLock {
        if closed { return }
        closed = true
        cancel?()
        if running || !used { plan.credential.close() }
      }
    }
    func cleanupStatus() -> CleanupStatus {
      plan.environment.gate.withLock {
        CleanupStatus(complete: closed && !running, pendingCallbacks: running ? 1 : 0)
      }
    }
    func waitCleanup() async throws -> CleanupStatus {
      // Native cancellation is synchronous, while real socket/task completion
      // remains owned by the original connect operation.
      while !cleanupStatus().complete {
        try await ContinuousClock().sleep(for: .milliseconds(10))
      }
      return cleanupStatus()
    }
  }

  enum V4DirectEstablishment {
    static func requirements(_ value: ConnectionRequirements) throws {
      guard !value.independentReliableReadProgress, !value.boundStreamInputIsolation,
        !value.datagram, value.applicationProfile == nil || value.applicationProfile == "transport"
      else { throw TransportV4ConnectError.unsupported }
    }
    static func connect(
      material: V4DirectPoolMaterial, address: String, roots: [Data],
      store: V4SQLitePoolStore, requirements: ConnectionRequirements
    ) async throws -> V4NativeSession {
      try self.requirements(requirements)
      let plan = material.plan
      let environment = plan.environment
      try material.claim(in: environment)
      var prepared: V4PreparedWebSocket?
      var consumed: V4ConsumedWebSocket?
      var handshake: V4Handshake?
      var session: V4NativeSession?
      var successful = false
      defer { material.finish(success: successful) }
      do {
        // All persistent runtime/key/stream owners are admitted before spend.
        let native = try environment.nativeSessionStorage(slots: plan.slots)
        let streamStorage = try environment.reliableSessionStorage(
          maxCredit: plan.maxCredit,
          slots: plan.slots)
        let handshakeStorage = try environment.reserveHandshake()
        prepared = try await V4PreparedWebSocket.prepare(
          route: plan.route,
          numericAddress: address, trustRootsPEM: roots)
        let original = prepared!
        try material.cancellation { original.close() }
        try material.check()
        if Task.isCancelled { throw TransportV4ConnectError.canceled }
        let socket = try original.consumePool(using: store)
        consumed = socket
        let exchange = V4InitialWebSocket(socket: socket, plan: plan)
        let clientHello = try hello(plan)
        try exchange.send(type: 1, body: clientHello)
        try await socket.flush()
        let serverHello = try await exchange.receive(type: 1, maximum: 16384)
        try material.check()
        let context = try context(plan, clientHello: clientHello, serverHello: serverHello)
        let fsb = try admission(plan, context: context, identity: material.identity)
        try exchange.send(type: 2, body: fsb)
        try await socket.flush()
        let fsa = try await exchange.receive(type: 3, maximum: 16384)
        try response(plan, context: context, fsb: fsb, fsa: fsa)
        try material.check()
        let crypto = try environment.handshake(
          admission: plan.credential, role: .client,
          identity: material.identity,
          input: V4HandshakeInput(
            artifact: Data(plan.artifact.raw), clientHello: clientHello,
            serverHello: serverHello, transportContext: context, fsb: fsb, fsa: fsa),
          reservation: handshakeStorage, streamStorage: streamStorage)
        handshake = crypto
        try crypto.submitNoise(to: exchange)
        try await socket.flush()
        try crypto.receiveNoise(await exchange.receive(type: 4, maximum: 81))
        try crypto.submitReady(to: exchange)
        try await socket.flush()
        try crypto.receiveReady(await exchange.receive(type: 5, maximum: 103))
        try material.check()
        if Task.isCancelled { throw TransportV4ConnectError.canceled }
        let core = try crypto.establish().makeSession()
        let admission = V4NativeSessionAdmission(
          socket: socket, core: core, plan: plan, storage: native)
        try socket.promote(admission)
        let result = try V4NativeSession(admission)
        session = result
        try material.check()
        if Task.isCancelled { throw TransportV4ConnectError.canceled }
        successful = true
        return result
      } catch {
        handshake?.close()
        if let session { try? await session.close() }
        consumed?.close()
        prepared?.close()
        if let consumed {
          await consumed.waitClosed()
        } else if let prepared {
          await prepared.waitClosed()
        }
        if let value = error as? TransportV4ConnectError { throw value }
        if Task.isCancelled { throw TransportV4ConnectError.canceled }
        if error is V4TimeFailure { throw TransportV4ConnectError.expired }
        if error is V4NamespaceFailure || error is V4CryptoFailure {
          throw TransportV4ConnectError.securityFailed
        }
        throw TransportV4ConnectError.connectionFailed
      }
    }
    private static func decode(
      _ bytes: Data, schema: String, source: V4ActivationSource = .preauthorizedPool
    )
      throws -> V4NamespaceValue
    {
      try V4NamespaceDocument(
        bytes, schema: schema, bytes: 65536, nodes: 4096,
        registry: V4NamespaceRegistry(), context: ["activation_source_profile": source.rawValue]
      ).root
    }
    static func hello(_ plan: V4DirectPoolPlan) throws -> Data {
      let value = V4Crypto.map([
        (0, V4Crypto.text("flowersec/4")), (1, V4Crypto.text("4")),
        (2, V4Crypto.text(plan.credential.cryptoProfile)),
        (3, V4Crypto.bytes(plan.credential.artifactDigest)),
        (4, V4Crypto.bytes(plan.credential.candidateID)),
        (5, V4Crypto.bytes(plan.credential.routeDigest)),
        (6, V4Crypto.bytes(plan.credential.attemptID)),
        (7, V4Crypto.bytes(try plan.artifact.b("session_nonce"))),
        (8, V4NamespaceValue.head(0, 0)), (9, V4NamespaceValue.head(0, 2)),
        (10, V4Crypto.bytes(Data())),
      ])
      _ = try decode(value, schema: "ClientHello")
      return value
    }
    static func context(_ plan: V4DirectPoolPlan, clientHello: Data, serverHello: Data) throws
      -> Data
    {
      let client = try decode(clientHello, schema: "ClientHello")
      let server = try decode(serverHello, schema: "ServerHello")
      for name in [
        "protocol_id", "profile_revision", "crypto_profile_id", "artifact_digest",
        "candidate_id", "route_digest", "attempt_id", "client_nonce",
      ] {
        guard try client.field(name).raw.elementsEqual(server.field(name).raw) else {
          throw V4CryptoFailure.authentication
        }
      }
      guard try server.u("binding_mode") == 1, try server.u("selected_features") == 0 else {
        throw V4CryptoFailure.authentication
      }
      let transcript = V4Crypto.hash(
        V4Crypto.domain("hello-transcript", [clientHello, serverHello]))
      let value = V4Crypto.map([
        (0, V4Crypto.text("4")), (1, V4Crypto.text(plan.credential.cryptoProfile)),
        (2, V4NamespaceValue.head(0, 0)), (3, V4NamespaceValue.head(0, 0)),
        (4, V4Crypto.bytes(plan.credential.artifactDigest)),
        (5, V4Crypto.bytes(plan.credential.routeDigest)),
        (6, V4Crypto.bytes(plan.credential.attemptID)),
        (7, V4Crypto.bytes(try plan.artifact.b("session_nonce"))),
        (8, V4Crypto.bytes(transcript)), (9, V4NamespaceValue.head(0, 0)),
        (10, V4NamespaceValue.head(0, 1)), (11, V4NamespaceValue.head(0, 0)),
        (12, V4Crypto.bytes(Data())),
      ])
      _ = try decode(value, schema: "TransportContext")
      return value
    }
    private static func admission(
      _ plan: V4DirectPoolPlan, context: Data,
      identity: V4LocalIdentity
    ) throws -> Data {
      let c = try decode(context, schema: "TransportContext")
      var fields: [(UInt64, Data)] = [
        (0, V4Crypto.bytes(plan.credential.artifactDigest)),
        (1, V4Crypto.text(try plan.artifact.t("tenant_id"))),
        (2, V4Crypto.bytes(try plan.artifact.b("issuer_key_id"))),
        (3, V4Crypto.bytes(try plan.artifact.b("lease_id"))),
        (4, V4Crypto.bytes(try plan.artifact.b("session_nonce"))),
        (5, V4Crypto.bytes(plan.credential.candidateID)),
        (6, V4Crypto.bytes(plan.credential.routeDigest)),
        (7, V4Crypto.bytes(plan.credential.attemptID)),
        (8, V4Crypto.bytes(try V4Crypto.random(32))),
        (9, V4Crypto.bytes(try c.b("hello_transcript_digest"))),
        (10, V4NamespaceValue.head(0, 0)), (11, V4NamespaceValue.head(0, 1)),
        (12, V4Crypto.bytes(try c.digest("transport_context_digest"))),
        (13, V4Crypto.bytes(Data(plan.proof.raw))), (14, V4Crypto.bytes(Data(plan.client.raw))),
      ]
      let signature = try identity.signHandshake(
        V4Crypto.domain("fsb4/signature", [V4Crypto.map(fields)]),
        in: plan.environment)
      fields.append((15, V4Crypto.bytes(signature)))
      let bytes = V4Crypto.map(fields)
      _ = try decode(bytes, schema: "FSB4")
      return bytes
    }
    static func response(_ plan: V4DirectPoolPlan, context: Data, fsb: Data, fsa: Data) throws {
      let c = try decode(context, schema: "TransportContext")
      let request = try decode(fsb, schema: "FSB4")
      let result = try decode(fsa, schema: "FSA4")
      guard try result.b("server_certificate") == Data(plan.server.raw) else {
        throw V4CryptoFailure.authentication
      }
      try result.verify("fsa_signature", publicKey: plan.server.b("ed25519_public_key"))
      guard try result.b("route_digest") == plan.credential.routeDigest,
        try result.b("hello_transcript_digest") == c.b("hello_transcript_digest"),
        try result.u("selected_features") == 0, try result.u("binding_mode") == 1
      else { throw V4CryptoFailure.authentication }
      try plan.credential.checkPreparation(in: plan.environment)
      // Rejection schema deliberately zeroes admission/session facts. The
      // original signed server identity, hello, route and mode authenticate
      // its refusal without treating zero fields as an admission grant.
      if try result.u("status") == 1 {
        throw TransportV4ConnectError.admissionRejected(code: try UInt16(result.u("code")))
      }
      let bindings: [(String, Data)] = [
        ("admission_binding", try request.digest("admission_binding")),
        ("route_digest", plan.credential.routeDigest),
        ("hello_transcript_digest", try c.b("hello_transcript_digest")),
        ("transport_context_digest", try c.digest("transport_context_digest")),
        ("client_identity_digest", plan.credential.certificateDigests[0]),
        ("server_identity_digest", plan.credential.certificateDigests[1]),
      ]
      for (name, bytes) in bindings {
        guard try result.b(name) == bytes else { throw V4CryptoFailure.authentication }
      }
      guard try result.u("selected_features") == 0, try result.u("binding_mode") == 1 else {
        throw V4CryptoFailure.authentication
      }
      try plan.credential.checkPreparation(in: plan.environment)
      guard try result.u("code") == 0 else { throw V4CryptoFailure.authentication }
    }
  }
  private final class V4InitialWebSocket: V4HandshakeWriter {
    let socket: V4ConsumedWebSocket
    let plan: V4DirectPoolPlan
    init(socket: V4ConsumedWebSocket, plan: V4DirectPoolPlan) {
      self.socket = socket
      self.plan = plan
    }
    func send(type: UInt8, body: Data) throws {
      guard !body.isEmpty, body.count <= plan.route.maximumFrame else {
        throw V4CryptoFailure.capacity
      }
      let bytes = V4Crypto.integer(UInt64(body.count), width: 4) + Data([type, 0, 0, 0]) + body
      let buffer = try plan.environment.cryptoBuffer(
        capacity: bytes.count, credential: plan.credential)
      try buffer.store(bytes)
      try socket.publish(buffer)
    }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws {
      try send(type: flight == .noise ? 4 : 5, body: buffer.withBytes { $0 })
    }
    func receive(type: UInt8, maximum: Int) async throws -> Data {
      let buffer = try await socket.receive()
      defer { buffer.close() }
      return try buffer.withBytes { bytes in
        guard bytes.count > 8, bytes.count <= maximum + 8,
          V4Crypto.number(bytes.prefix(4)) == bytes.count - 8,
          bytes[4] == type, bytes[5..<8] == Data([0, 0, 0])
        else { throw V4CryptoFailure.authentication }
        return Data(bytes.dropFirst(8))
      }
    }
  }
#endif
