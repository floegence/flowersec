#if os(macOS) || os(iOS)
  import Crypto
  import Foundation
  import NIOCore
  import NIOWebSocket
  import SQLite3
  import XCTest

  @testable import Flowersec

  private final class V4PreparedMessageProbe: @unchecked Sendable {
    private let gate = NSLock()
    private var didPrepare = false
    private var didInvoke = false
    var prepared: Bool { gate.withLock { didPrepare } }
    var invoked: Bool { gate.withLock { didInvoke } }
    func markPrepared() { gate.withLock { didPrepare = true } }
    func markInvoked() { gate.withLock { didInvoke = true } }
  }

  private final class V4NativeManagementDiagnosticLog: @unchecked Sendable {
    private let gate = NSLock()
    private var events: [TransportDiagnosticEvent] = []
    private var expired = false
    func expire() { gate.withLock { expired = true } }
    func check() throws { if gate.withLock({ expired }) { throw ServiceFailure.deadlineExceeded } }
    var snapshot: [TransportDiagnosticEvent] { gate.withLock { events } }
    func append(_ event: TransportDiagnosticEvent) { gate.withLock { events.append(event) } }
  }

  private final class V4ManagedPoolAuthority: @unchecked Sendable {
    enum Scenario: CaseIterable { case success, refused, close }
    let source = Data(repeating: 93, count: 16)
    let pool = Data(repeating: 94, count: 32)
    let keyID = Data(repeating: 95, count: 16)
    private let input: V4CredentialInput
    private let scenario: Scenario
    private let gate = NSLock()
    private var released = false
    private var proofRequested = false
    private var acknowledged = false
    private var original: V4PoolRefillIntent?
    private var proof = Data()
    private var response: V4PoolRefillResponse?
    init(input: V4CredentialInput, scenario: Scenario) throws {
      self.input = input
      self.scenario = scenario
    }
    // Independently observe durable pending state; never mutate or reopen its
    // exclusive owner to fabricate completion or recovery.
    static func pendingJournal(_ directory: URL) throws -> [Data] {
      var handle: OpaquePointer?
      let opened = sqlite3_open_v2(
        directory.appendingPathComponent("refill.sqlite3").path, &handle,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
      defer { if let handle { sqlite3_close(handle) } }
      guard opened == SQLITE_OK, let db = handle else { throw V4PoolFailure.storage }
      // An ACK can be on the wire while the worker commits its local receipt.
      sqlite3_busy_timeout(db, 1000)
      func failure(_ phase: String) -> NSError {
        NSError(
          domain: "ManagedPoolJournalObservation", code: Int(sqlite3_errcode(db)),
          userInfo: [NSLocalizedDescriptionKey: "\(phase): \(String(cString: sqlite3_errmsg(db)))"])
      }
      var statement: OpaquePointer?
      guard
        sqlite3_prepare_v2(
          db,
          "SELECT CAST(phase AS TEXT),intent,generation,previous_highest,response,terminal FROM operation WHERE id=1",
          -1, &statement, nil) == SQLITE_OK, let statement
      else { throw failure("prepare") }
      defer { sqlite3_finalize(statement) }
      guard sqlite3_step(statement) == SQLITE_ROW else { throw failure("row") }
      let row = (0..<6).map { column -> Data in
        let count = Int(sqlite3_column_bytes(statement, Int32(column)))
        guard count > 0, let bytes = sqlite3_column_blob(statement, Int32(column)) else {
          return Data()
        }
        return Data(bytes: bytes, count: count)
      }
      guard sqlite3_step(statement) == SQLITE_DONE else { throw failure("end") }
      return row
    }
    func release() { gate.withLock { released = true } }
    private func wait(_ check: @escaping @Sendable () -> Bool) async throws {
      let start = ContinuousClock.now
      while !check() {
        guard start.duration(to: .now) < .seconds(5) else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    func waitForProof() async throws {
      try await wait { self.gate.withLock { self.proofRequested } }
    }
    func waitForAcknowledgement() async throws {
      try await wait { self.gate.withLock { self.acknowledged } }
    }
    func respond(_ path: String, body: Data) async throws -> Data {
      if path == "/pool/owner-proof" {
        gate.withLock { proofRequested = true }
        try await wait { self.gate.withLock { self.released } }
        return try gate.withLock {
          guard let object = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw TransportControlError.responseInvalid
          }
          func bytes(_ key: String) throws -> Data {
            guard let value = object[key] as? String, let bytes = Data(base64Encoded: value) else {
              throw TransportControlError.responseInvalid
            }
            return bytes
          }
          guard object["tenant_id"] as? String == "tenant",
            object["binding_generation"] as? String == "1",
            let deadline = (object["request_deadline_ms"] as? String).flatMap(UInt64.init),
            let desired = object["desired_count"] as? UInt64,
            let maximum = object["max_item_bytes"] as? UInt64
          else { throw TransportControlError.responseInvalid }
          let intent = V4PoolRefillIntent(
            operation: try bytes("operation_id"), tenant: "tenant",
            source: try bytes("source_incarnation"),
            desired: desired, maximumItemBytes: maximum, pool: try bytes("pool_digest"),
            deadlineMS: deadline,
            identity: try bytes("client_identity_digest"))
          guard intent.source == source, intent.pool == pool,
            try intent.digest() == bytes("request_digest")
          else { throw TransportControlError.responseInvalid }
          if let original {
            guard intent == original else { throw TransportControlError.responseInvalid }
          } else {
            original = intent
          }
          let fields: [UInt64: V4CBORValue] = [
            0: .text("tenant"), 1: .bytes(source), 2: .bytes(intent.operation),
            3: .bytes(try intent.digest()), 4: .uint(1), 5: .uint(900), 6: .uint(2000),
            7: .bytes(keyID),
          ]
          let unsigned = NamespaceFixture.map(fields).encoded()
          let message =
            Data("flowersec/v6/topup-owner-fence\0".utf8)
            + V4Crypto.integer(UInt64(unsigned.count), width: 4) + unsigned
          var signed = fields
          signed[8] = .bytes(
            try NamespaceFixture.sign(message, seed: scenario == .refused ? 96 : 91))
          proof = NamespaceFixture.map(signed).encoded()
          return proof
        }
      }
      return try gate.withLock {
        guard let original else { throw TransportControlError.responseInvalid }
        if path == "/pool/top-up" {
          guard try body == V4PoolRefillWire.request(original, generation: 1, proof: proof) else {
            throw TransportControlError.responseInvalid
          }
          let material =
            V4NamespaceValue.head(4, 4) + V4Crypto.bytes(input.artifact)
            + V4Crypto.bytes(input.activation)
            + V4Crypto.bytes(input.clientCertificate) + V4Crypto.bytes(input.serverCertificate)
          let entry = NamespaceFixture.map([
            0: .uint(1), 1: .uint(1), 2: .uint(1800), 3: .bytes(material),
            4: .bytes(V4Crypto.hash(material)), 5: .bytes(original.identity),
          ])
          var fields: [UInt64: V4CBORValue] = [
            0: .bytes(original.operation), 1: .text("tenant"), 2: .bytes(source),
            3: .uint(1), 4: .array([entry]), 5: .uint(1), 6: .bool(false), 8: .bool(true),
          ]
          fields[9] = .bytes(V4Crypto.hash(NamespaceFixture.map(fields).encoded()))
          let wire = NamespaceFixture.map(fields).encoded()
          response = try V4PoolRefillWire.response(
            wire, intent: original, originalGeneration: 1, previousHighest: 0,
            registry: V4NamespaceRegistry())
          return V4NamespaceValue.head(4, 4) + V4Crypto.text("success") + V4Crypto.bytes(wire)
            + Data([0x80, 0x80])
        }
        guard path == "/pool/ack", let response,
          try body
            == V4PoolRefillWire.ack(original, response: response, generation: 1, proof: proof)
        else { throw TransportControlError.responseInvalid }
        acknowledged = true
        return V4NamespaceValue.head(4, 4) + V4Crypto.text("success") + V4Crypto.bytes(Data())
          + Data([0x80, 0x80])
      }
    }
  }

  @MainActor
  final class TransportNativeSessionTests: XCTestCase {
    func testPublicConfiguredFactoryVerifiesFreshBootstrapAndImportsOriginalIdentity() async throws
    {
      let fixture = try CredentialFixture()
      fixture.candidateLeg = NamespaceFixture.map([
        0: .uint(0), 1: .bytes(Data(repeating: 50, count: 16)), 2: .uint(1),
        3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text("localhost"), 7: .uint(443),
        8: .text("/flowersec/v4/direct"), 9: .text("http/1.1"), 10: .text("flowersec.direct.v4"),
        11: NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
      ])
      let original = fixture.bootstrapResponse
      let state = fixture.bootstrapState
      let timeStart = ContinuousClock.now
      let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      let directory = root.appendingPathComponent(
        ".flowersec/swift-native-factory-\(UUID().uuidString)")
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: directory) }
      let namespace = TransportTrustNamespace(
        authority: "authority", rootKeyID: fixture.base.pin.keyID,
        rootPublicKey: fixture.base.pin.publicKey, maximumTrustLifetimeMilliseconds: 10000,
        maximumStateBytes: 8192, maximumStateNodes: 4096
      ) { nonce in
        let value = try V4NamespaceDocument(
          original, schema: "TrustBootstrapResponse", bytes: 270336,
          nodes: 32768, registry: V4NamespaceRegistry()
        ).root
        var fields = try (0...8).map { (UInt64($0), Data(try value.fieldID($0).raw)) }
        fields[3] = (3, V4Crypto.bytes(nonce))
        let signature = try NamespaceFixture.key(7).signature(
          for:
            V4Crypto.domain("trust-bootstrap/signature", [V4Crypto.map(fields)]))
        fields.append((9, V4Crypto.bytes(signature)))
        return TransportNamespaceSnapshot(response: V4Crypto.map(fields), state: state)
      }
      var configuration = TransportClientConfiguration(
        tenant: "tenant", audience: "service",
        clientSubject: "client", serverSubject: "server", namespaces: [namespace],
        endpoints: [
          TransportEndpoint(hostname: "localhost", port: 443, numericAddress: "127.0.0.1")
        ],
        history: TransportPoolHistory(
          directory: directory, storeID: Data(repeating: 2, count: 16),
          generation: 1, artifactIssuerKeyID: Data(repeating: 5, count: 16),
          spendAuthority: "spend",
          winnerAuthority: "winner", create: true, checkContinuity: {}),
        trustedTime: {
          let elapsed = timeStart.duration(to: .now).components
          let milliseconds = UInt64(
            elapsed.seconds * 1000 + elapsed.attoseconds / 1_000_000_000_000_000)
          return TransportTrustedTime(
            lowerMilliseconds: 1000 + milliseconds,
            upperMilliseconds: 1010 + milliseconds)
        })
      configuration.timePolicy.driftNumerator = 0
      configuration.timePolicy.quantizationMilliseconds = 0
      let environment = try await TransportEnvironment(configuration: configuration)
      try await environment.refreshTrustedTime()
      try await environment.refreshNamespace(
        authority: "authority",
        head: fixture.base.head(state: state, sequence: 2), state: state)
      do {
        try await environment.refreshNamespace(
          authority: "unconfigured", head: Data(), state: Data())
        XCTFail("received namespace selected new trust")
      } catch {}
      var identity: TransportApplicationIdentity? =
        try await environment.importApplicationIdentity(
          profile: .x25519,
          signingSeed: Data(repeating: 21, count: 32),
          noiseStaticPrivateKey: Data(repeating: 31, count: 32))
      let input = try fixture.input(source: .preauthorizedPool, indices: [0])
      var material: ConnectionMaterial? = try await environment.preparePoolMaterial(
        TransportPoolCredential(
          artifact: input.artifact, clientCertificate: input.clientCertificate,
          serverCertificate: input.serverCertificate, activationAuthorization: input.activation),
        identity: identity!)
      material?.close()
      material = nil
      var generated: TransportApplicationIdentity? =
        try await environment.generateApplicationIdentity(profile: .p256)
      XCTAssertEqual(generated?.noiseStaticPublicKey.count, 65)
      generated?.close()
      generated = nil
      identity?.close()
      identity = nil
      try await environment.close()
      let cleanup = await environment.cleanupStatus()
      XCTAssertTrue(cleanup.complete)
    }
    func testCurrentLoopbackHTTPPreservesOriginalAuthenticationAndRefusesTLSBeforeAcquire()
      async throws
    {
      for profile in V4CryptoProfile.allCases {
        let fixture = try NativeSessionFixture(profile: profile, loopbackHTTP: true)
        defer { fixture.cleanup() }
        let source = try await fixture.source()
        let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
        do {
          _ = try await fixture.environment.connect(
            source: source,
            requirements: ConnectionRequirements(localConsumerTLS13Verification: true))
          XCTFail("A signed local HTTP route claimed consumer TLS verification")
        } catch {
          let failure = try XCTUnwrap(error as? ConnectError)
          XCTAssertEqual(failure.code, .unsupported)
          XCTAssertEqual(failure.connection.spendState, .unspent)
          XCTAssertTrue(failure.cleanup.complete)
        }
        XCTAssertEqual(owner.acquisitionCount, 0)
        XCTAssertFalse(fixture.peer.established)
        let session = try await fixture.environment.connect(source: source)
        XCTAssertEqual(owner.acquisitionCount, 1)
        XCTAssertTrue(fixture.peer.established)
        XCTAssertEqual(fixture.listener.request?.uri, "/flowersec/v4/local")
        XCTAssertEqual(
          fixture.listener.request?.headers["origin"], ["http://127.0.0.1:\(fixture.listener.port)"]
        )
        let stream = try await session.openStream(kind: "example.echo")
        let input = Data("authenticated-loopback".utf8)
        let written = try await stream.write(input)
        XCTAssertEqual(written, input.count)
        try await stream.closeWrite()
        var output = Data()
        while let chunk = try await stream.read(maxBytes: 64) { output.append(chunk) }
        XCTAssertEqual(output, input)
        try await stream.close()
        try await session.rekey()
        _ = try await session.probeLiveness()
        try await session.close()
        source.close()
        try await fixture.environment.close()
      }
    }
    func testActualPublicPoolWSSHandshakeStreamsRekeyAndPingForBothProfiles() async throws {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile)
        defer { test.cleanup() }
        let material = try await test.material()
        let session = try await test.environment.connectMaterial(material)
        XCTAssertTrue(test.peer.established)
        let stream = try await session.openStream(kind: "example.echo")
        let firstWrite = try await stream.write(Data([1, 2, 3]))
        let firstRead = try await stream.read(maxBytes: 16)
        XCTAssertEqual(firstWrite, 3)
        XCTAssertEqual(firstRead, Data([1, 2, 3]))
        try await session.rekey()
        XCTAssertEqual(test.peer.epoch, 1)
        let secondWrite = try await stream.write(Data([4, 5]))
        let secondRead = try await stream.read(maxBytes: 16)
        XCTAssertEqual(secondWrite, 2)
        XCTAssertEqual(secondRead, Data([4, 5]))
        _ = try await session.probeLiveness()
        try await stream.finish()
        let eof = try await stream.read(maxBytes: 16)
        XCTAssertNil(eof)
        let accepting = Task { try await session.acceptStream() }
        try await test.peer.openStream()
        let incoming = try await accepting.value
        XCTAssertEqual(incoming.kind, "example.from-server")
        let remoteRead = try await incoming.stream.read(maxBytes: 16)
        XCTAssertEqual(remoteRead, Data([9]))
        try await incoming.stream.close()
        try await session.close()
        let termination = await session.waitTermination()
        XCTAssertEqual(termination, SessionTermination(error: .closed))
        XCTAssertTrue(material.cleanupStatus().complete)
        do {
          _ = try await test.environment.connectMaterial(material)
          XCTFail("original consumed material replayed")
        } catch {}
        try await test.environment.close()
        XCTAssertNil(test.peer.error)
      }
    }
    func testManagedPoolAcquireIsLocalWhileBackgroundRefillRetainsOriginalIntent() async throws {
      for scenario in V4ManagedPoolAuthority.Scenario.allCases {
        let test = try NativeSessionFixture(profile: .x25519)
        defer { test.cleanup() }
        let controls = try V4ManagedPoolAuthority(input: test.input, scenario: scenario)
        let authority = try V4ControlTestAuthority(
          identity: .init(), maximumRequestBytes: 8192,
          contentTypes: { path in
            (
              path == "/pool/owner-proof" ? "application/json" : "application/cbor",
              "application/cbor"
            )
          },
          respondAsync: { path, body in try await controls.respond(path, body: body) },
          respond: { _, _ in throw V4CryptoFailure.phase })
        let source = try await test.environment.makeManagedPreauthorizedPoolSource(
          .init(
            authority: .init(
              https: authority.configuration(), sourceIncarnation: controls.source,
              bindingGeneration: 1, authorityKeyID: controls.keyID,
              authorityPublicKey: NamespaceFixture.key(91).publicKey.rawRepresentation),
            topUp: authority.configuration(),
            journal: .init(
              directory: test.directory, backingIdentity: Data(repeating: 92, count: 32),
              create: true,
              maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }),
            poolDigest: controls.pool, clientCertificate: test.input.clientCertificate,
            lowWatermark: 0, targetCount: 1, requestLifetimeMilliseconds: 5000),
          identity: TransportApplicationIdentity(test.client))
        var session: (any Session)?
        func exhausted() async throws {
          let started = ContinuousClock.now
          do {
            let material = try await source.acquire()
            material.close()
            XCTFail("Empty pool must return exhausted immediately")
          } catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .exhausted) }
          XCTAssertLessThan(
            started.duration(to: .now), .seconds(1),
            "Acquire must not wait for the held HTTPS response")
        }
        func canceled() async throws {
          let caller = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await source.acquire()
          }
          do {
            let material = try await caller.value
            material.close()
            XCTFail("Canceled caller must not withdraw an installed item")
          } catch { XCTAssertTrue(error is CancellationError) }
        }
        do {
          do {
            let wrong = try await source.acquire(.init(applicationProfile: "services"))
            wrong.close()
            XCTFail("Profile mismatch must not consume refill material")
          } catch { XCTAssertEqual(error as? TransportConnectError, .unsupported) }
          try await exhausted()
          // This original proof was initiated by configured background upkeep.
          // Holding its real HTTPS reply keeps the durable operation pending.
          try await controls.waitForProof()
          let pending = try V4ManagedPoolAuthority.pendingJournal(test.directory)
          let originalIntent = try V4PoolRefillIntent.decode(pending[1])
          XCTAssertEqual(originalIntent.deadlineMS, 6000)
          let retained = test.fixture.base.root.snapshot()
          for _ in 0..<2 { try await exhausted() }
          do {
            let unexpected = try await test.environment.connect(source: source)
            try await unexpected.close()
            XCTFail("Empty source must not start native establishment")
          } catch let failure as ConnectError {
            XCTAssertEqual(failure.connection.spendState, .unspent)
            XCTAssertEqual(failure.connection.networkReady, .notStarted)
            XCTAssertTrue(failure.cleanup.complete)
            XCTAssertEqual(failure.cleanup.pendingCallbacks, 0)
          }
          try await canceled()
          XCTAssertEqual(
            try V4ManagedPoolAuthority.pendingJournal(test.directory), pending,
            "Acquire must preserve the original pending operation, generation and deadline")
          XCTAssertEqual(
            test.fixture.base.root.snapshot(), retained,
            "Empty/canceled Acquire must not retain resource tails")
          XCTAssertEqual(authority.requests, ["/pool/owner-proof"])
          XCTAssertEqual(
            source.cleanupStatus().pendingCallbacks, 1,
            "Only configured background maintenance remains")
          if scenario == .success {
            controls.release()
            try await controls.waitForAcknowledgement()
            let installed = try V4ManagedPoolAuthority.pendingJournal(test.directory)
            XCTAssertEqual(
              installed[1], pending[1], "Background installation must retain its original request")
            try await canceled()
            let material = try await source.acquire()
            try await exhausted()
            source.close()
            let cleanup = try await source.waitCleanup()
            XCTAssertTrue(cleanup.complete)
            XCTAssertEqual(cleanup.pendingCallbacks, 0)
            let connected = try await test.environment.connectMaterial(material)
            session = connected
            let stream = try await connected.openStream(kind: "managed.pool.echo")
            let payload = Data("installed refill survives canceled caller and source close".utf8)
            let written = try await stream.write(payload)
            let echoed = try await stream.read(maxBytes: 128)
            XCTAssertEqual(written, payload.count)
            XCTAssertEqual(echoed, payload)
            try await stream.finish()
            try await connected.close()
            session = nil
            XCTAssertTrue(material.cleanupStatus().complete)
            XCTAssertEqual(
              Array(authority.requests.prefix(4)),
              ["/pool/owner-proof", "/pool/top-up", "/pool/owner-proof", "/pool/ack"])
          } else {
            if scenario == .close { source.close() } else { controls.release() }
            let cleanup = try await source.waitCleanup()
            XCTAssertTrue(cleanup.complete)
            XCTAssertEqual(cleanup.pendingCallbacks, 0)
            XCTAssertEqual(
              try V4ManagedPoolAuthority.pendingJournal(test.directory), pending,
              "Close or invalid proof must not replace or retire the original pending operation")
            let released = test.fixture.base.root.snapshot()
            do {
              let invalid = try await source.acquire()
              invalid.close()
              XCTFail("Closed or unauthenticated source acquired material")
            } catch { XCTAssertFalse(error is CancellationError) }
            source.close()
            let repeated = try await source.waitCleanup()
            XCTAssertTrue(repeated.complete)
            XCTAssertEqual(repeated.pendingCallbacks, 0)
            XCTAssertEqual(
              test.fixture.base.root.snapshot(), released,
              "Closed Acquire must not create new tails")
            XCTAssertEqual(authority.requests, ["/pool/owner-proof"])
          }
          await authority.stopAsync()
          try await test.environment.close()
        } catch {
          source.close()
          _ = try? await source.waitCleanup()
          if let session { try? await session.close() }
          await authority.stopAsync()
          try? await test.environment.close()
          throw error
        }
      }
    }

    func testPublicTypedMessageOpenUsesTheOriginalNativeStreamAndScopedMetadata() async throws {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile)
        defer { test.cleanup() }
        let session = try await test.environment.connectMaterial(test.material())
        let outbound = try MessageDefinition(
          schemaDigest: Data(repeating: 1, count: 32), revision: "bytes-v1", maxMessageBytes: 64)
        let inbound = try MessageDefinition(
          schemaDigest: Data(repeating: 2, count: 32), revision: "bytes-v2", maxMessageBytes: 64)
        let definition = try MessageStreamDefinition(
          kind: "example.echo", revision: "messages-v1",
          openerToAcceptor: outbound, acceptorToOpener: inbound)
        let application = try StreamMetadata(
          namespace: "example/messages", version: 1, values: ["label": Data([7])])
        let messages = try await session.openMessageStream(
          definition: definition, applicationMetadata: application,
          inboundCodec: BytesMessageCodec(definition: inbound),
          outboundCodec: BytesMessageCodec(definition: outbound))
        let actualDefinition = await messages.definition
        let actualMetadata = await messages.applicationMetadata
        XCTAssertEqual(actualDefinition, definition)
        XCTAssertEqual(actualMetadata, application)
        let encoded = try V4StreamMetadataCodec.typed(
          definition: definition.digest, application: application
        ).encoded()
        XCTAssertEqual(test.peer.receivedMetadata, [encoded])
        let payload = Data([3, 4, 5])
        let progress = try await messages.send(payload)
        XCTAssertEqual(progress.submission, .submitted)
        XCTAssertEqual(progress.streamBytesAcceptedAtReturn, 7)
        let received = try await messages.receiveEncoded()
        XCTAssertEqual(received?.payload, payload)
        try await messages.close()
        let cleanup = try await messages.waitCleanup()
        XCTAssertTrue(cleanup.complete)
        try await session.close()
        try await test.environment.close()
        XCTAssertNil(test.peer.error)
      }
    }

    func testAcceptedTypedStreamConvertsOnceAndPreservesOpenerRelativeDirections() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let inbound = try MessageDefinition(
        schemaDigest: Data(repeating: 1, count: 32), revision: "in-v1", maxMessageBytes: 64)
      let outbound = try MessageDefinition(
        schemaDigest: Data(repeating: 2, count: 32), revision: "out-v1", maxMessageBytes: 64)
      let definition = try MessageStreamDefinition(
        kind: "example.from-server", revision: "messages-v1",
        openerToAcceptor: inbound, acceptorToOpener: outbound)
      let application = try StreamMetadata(
        namespace: "example/messages", version: 1,
        values: ["purpose": Data([1])])
      let lifetime = V4MessageRegistrationLifetime()
      let native = try XCTUnwrap(session as? any V4MessageStreamSession)
      try native.installMessageStreamRegistrations([
        definition.kind: V4MessageStreamRegistration(
          definition: definition, authorize: { _, context in try context.checkCancellation() },
          options: .standard, lifetime: lifetime)
      ])
      let accepting = Task { try await session.acceptStream() }
      try await test.peer.openStream(
        metadata: V4StreamMetadataCodec.typed(
          definition: definition.digest, application: application
        ).encoded(),
        payload: Data([0, 0, 0, 2, 7, 8]))
      let incoming = try await accepting.value
      let messages = try incoming.stream.asTypedMessages(
        definition: definition,
        inboundCodec: BytesMessageCodec(definition: inbound),
        outboundCodec: BytesMessageCodec(definition: outbound))
      let actualMetadata = await messages.applicationMetadata
      XCTAssertEqual(actualMetadata, application)
      XCTAssertThrowsError(
        try incoming.stream.asTypedMessages(
          definition: definition,
          inboundCodec: BytesMessageCodec(definition: inbound),
          outboundCodec: BytesMessageCodec(definition: outbound)))
      do {
        _ = try await incoming.stream.read(maxBytes: 1)
        XCTFail("claimed raw alias cannot read")
      } catch { XCTAssertEqual(error as? SessionError, .closed) }
      let value = try await messages.receiveEncoded()
      XCTAssertEqual(value?.payload, Data([7, 8]))
      lifetime.close()
      // Closing the original registration leaves the accepted typed owner live.
      let sent = try await messages.send(Data([3]))
      XCTAssertEqual(sent.streamBytesAcceptedAtReturn, 5)
      let echoed = try await messages.receiveEncoded()
      XCTAssertEqual(echoed?.payload, Data([3]))
      try await messages.close()
      _ = try await messages.waitCleanup()
      try await session.close()
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }

    func testMessageFacadeIsPreparedBeforeAuthorizationAndDeliveredWithItsOriginalContext()
      async throws
    {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let direction = try MessageDefinition(
        schemaDigest: Data(repeating: 3, count: 32), revision: "message-v1", maxMessageBytes: 64)
      let definition = try MessageStreamDefinition(
        kind: "example.from-server", revision: "messages-v1",
        openerToAcceptor: direction, acceptorToOpener: direction)
      let lifetime = V4MessageRegistrationLifetime()
      let probe = V4PreparedMessageProbe()
      let native = try XCTUnwrap(session as? any V4MessageStreamSession)
      try native.installMessageStreamRegistrations([
        definition.kind: V4MessageStreamRegistration(
          definition: definition,
          authorize: { _, context in
            try context.checkCancellation()
            XCTAssertTrue(probe.prepared)
          }, options: .standard, lifetime: lifetime, maximumConcurrentStreams: 1,
          prepare: { prepared, metadata in
            let codec = BytesMessageCodec(definition: direction)
            let messages = try TypedMessageStream<Data, Data>(
              prepared: prepared, definition: definition, opener: false,
              applicationMetadata: metadata, inboundCodec: codec, outboundCodec: codec,
              inboundDefinition: direction, outboundDefinition: direction)
            probe.markPrepared()
            return V4PreparedMessageHandler(
              gate: prepared.storage.environment.gate, check: prepared.check,
              invoke: { context in
                try context.checkCancellation()
                let value = try await messages.receive(context: context)
                XCTAssertEqual(value?.value, Data([7]))
                XCTAssertFalse(value?.applicationInputDelivered ?? true)
                probe.markInvoked()
                try await messages.close()
              }, close: { try? await messages.close() })
          })
      ])
      let accepting = Task { try await session.acceptStream() }
      try await test.peer.openStream(
        metadata: V4StreamMetadataCodec.typed(
          definition: definition.digest, application: .empty
        ).encoded(), payload: Data([0, 0, 0, 1, 7]))
      let incoming = try await accepting.value
      XCTAssertTrue(probe.prepared)
      XCTAssertFalse(probe.invoked)
      do {
        _ = try await incoming.stream.read(maxBytes: 1)
        XCTFail("raw alias must remain inaccessible")
      } catch { XCTAssertEqual(error as? SessionError, .closed) }
      lifetime.close()
      let application = try XCTUnwrap(session as? any V4ApplicationSession)
      try await application.invokeStreamHandler(
        incoming,
        handler: { delivered in
          let prepared = try XCTUnwrap(delivered.preparedMessageHandler)
          let context = try XCTUnwrap(delivered.applicationContext)
          try await prepared.invoke(context)
        })
      XCTAssertTrue(probe.invoked)
      do {
        try await application.invokeStreamHandler(
          incoming, handler: { _ in XCTFail("handler dispatched twice") })
        XCTFail("accepted typed handler must be claimed once")
      } catch { XCTAssertEqual(error as? SessionError, .closed) }
      try await session.close()
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }

    func testRawRegistrationClosePreservesItsAcceptedStream() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let native = try XCTUnwrap(session as? any V4MessageStreamSession)
      let lifetime = V4MessageRegistrationLifetime()
      try native.installStreamHandlerRegistry(
        V4StreamHandlerRegistry(
          rawKinds: ["example.from-server"], metadataContracts: [:], lifetime: lifetime,
          maximumConcurrentStreams: 1), messages: [:])
      let accepting = Task { try await session.acceptStream() }
      try await test.peer.openStream()
      let incoming = try await accepting.value
      lifetime.close()
      let first = try await incoming.stream.read(maxBytes: 1)
      XCTAssertEqual(first, Data([9]))
      let written = try await incoming.stream.write(Data([7]))
      XCTAssertEqual(written, 1)
      let echo = try await incoming.stream.read(maxBytes: 1)
      XCTAssertEqual(echo, Data([7]))
      try await incoming.stream.close()
      try await session.close()
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }

    func testOriginalPinExpiryFencesBufferedSessionDelivery() async throws {
      let test = try NativeSessionFixture(profile: .x25519, pinned: true)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.echo")
      let written = try await stream.write(Data([1, 2, 3]))
      XCTAssertEqual(written, 3)
      let first = try await stream.read(maxBytes: 1)
      XCTAssertEqual(first, Data([1]))
      // The remaining two bytes are already authenticated and buffered. They
      // must still cross the original pin deadline before public delivery.
      test.fixture.base.source.advance(400)
      do {
        _ = try await stream.read(maxBytes: 2)
        XCTFail("buffered bytes escaped the original pin deadline")
      } catch let error as SessionError { XCTAssertEqual(error, .timeout) }
      try await session.close()
      try await test.environment.close()
    }

    func testSignedFSARejectionAndForgedRejectionRemainDistinctAndSpent() async throws {
      for forged in [false, true] {
        let test = try NativeSessionFixture(
          profile: .x25519, mode: forged ? .forgedRejection : .rejection)
        defer { test.cleanup() }
        let material = try await test.material()
        do {
          _ = try await test.environment.connectMaterial(material)
          XCTFail("rejected FSA established")
        } catch let error as ConnectError {
          XCTAssertEqual(error.code, forged ? .securityFailed : .connectionFailed)
          XCTAssertEqual(error.connection.spendState, .spent)
          XCTAssertEqual(error.connection.admissionState, forged ? .unknown : .notStarted)
          XCTAssertEqual(error.connection.networkReady, .notStarted)
          XCTAssertTrue(error.cleanup.complete)
          XCTAssertFalse(error.cleanup.cleanupIncomplete)
          XCTAssertEqual(error.cleanup.pendingCallbacks, 0)
          XCTAssertEqual(error.localReport.cleanup, error.cleanup)
        }
        XCTAssertFalse(test.peer.established)
        XCTAssertEqual(test.peer.noiseInputs, 0)
        let replacement = try await test.material()
        do {
          _ = try await test.environment.connectMaterial(replacement)
          XCTFail("consumed lease replayed after FSA rejection")
        } catch {}
        try await test.environment.close()
      }
    }
    func testPublicSourceRejectionPreservesSpentFactsAndAttemptCleanup() async throws {
      for forged in [false, true] {
        let test = try NativeSessionFixture(
          profile: .x25519,
          mode: forged ? .forgedRejection : .rejection)
        defer { test.cleanup() }
        let source = try await test.source()
        let original = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
        do {
          _ = try await test.environment.connect(source: source)
          XCTFail("rejected source attempt published a Session")
        } catch {
          let failure = try XCTUnwrap(error as? ConnectError)
          XCTAssertEqual(failure.code, forged ? .securityFailed : .connectionFailed)
          XCTAssertEqual(failure.connection.spendState, .spent)
          XCTAssertEqual(failure.connection.admissionState, forged ? .unknown : .notStarted)
          XCTAssertEqual(failure.connection.networkReady, .notStarted)
          XCTAssertEqual(failure.connection.sourceProfile, .preauthorizedPool)
          XCTAssertEqual(failure.retryDisposition, .terminal)
          XCTAssertTrue(failure.cleanup.complete)
          XCTAssertFalse(failure.cleanup.cleanupIncomplete)
          XCTAssertEqual(failure.cleanup.pendingCallbacks, 0)
          XCTAssertEqual(failure.localReport.connection, failure.connection)
        }
        XCTAssertEqual(original.acquisitionCount, 1)
        XCTAssertFalse(
          source.cleanupStatus().complete,
          "the borrowed source stays open independently of its failed attempt")
        source.close()
        try await test.environment.close()
      }
    }

    func testDuplexBridgeClaimsBothOriginalStreamsAndCanceledWaitIsPassive() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-a")
      let b = try await session.openStream(kind: "example.bridge-b")
      let before = test.fixture.base.root.snapshot().used
      let bridge = try DuplexBridge(
        a, b,
        options: DuplexBridgeOptions(
          chunkBytes: 64, deadline: .seconds(5), cleanupTimeout: .milliseconds(100)))
      XCTAssertGreaterThan(test.fixture.base.root.snapshot().used.sdkBytes, before.sdkBytes)
      XCTAssertThrowsError(try DuplexBridge(a, b)) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .streamOwned)
      }
      do {
        _ = try await a.write(Data([1]))
        XCTFail("raw alias wrote after bridge claim")
      } catch let error as SessionError { XCTAssertEqual(error, .closed) }
      do {
        try await b.reset()
        XCTFail("raw alias reset after bridge claim")
      } catch let error as SessionError { XCTAssertEqual(error, .closed) }
      try bridge.start()
      try bridge.start()
      let waiting = Task { try await bridge.wait() }
      try await ContinuousClock().sleep(for: .milliseconds(20))
      waiting.cancel()
      do {
        _ = try await waiting.value
        XCTFail("canceled waiter completed")
      } catch let error as DuplexBridgeWaitError {
        XCTAssertEqual(error.failure, .waitCanceled)
        XCTAssertEqual(error.progress.outcome, .running)
      }
      XCTAssertEqual(bridge.progress().outcome, .running)
      bridge.abort()
      bridge.abort()
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .aborted)
      XCTAssertEqual(result.failure, .aborted)
      let repeated = try await bridge.wait()
      XCTAssertTrue(result === repeated)
      XCTAssertTrue(result.aToB.progress.unacceptedTail === repeated.aToB.progress.unacceptedTail)
      try await session.close()
      let cleanupDeadline = ContinuousClock.now.advanced(by: .seconds(5))
      while !bridge.cleanupStatus().complete {
        guard ContinuousClock.now < cleanupDeadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(10))
      }
      XCTAssertTrue(bridge.cleanupStatus().complete)
      try await test.environment.close()
    }

    func testDuplexBridgeRejectsIdenticalEndpointBeforeTakingOwnership() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.bridge-alias")
      let before = test.fixture.base.root.snapshot().used
      XCTAssertThrowsError(try DuplexBridge(stream, stream)) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .invalidEndpoint)
      }
      XCTAssertEqual(test.fixture.base.root.snapshot().used, before)
      let written = try await stream.write(Data([3]))
      let echoed = try await stream.read(maxBytes: 1)
      XCTAssertEqual(written, 1)
      XCTAssertEqual(echoed, Data([3]))
      try await stream.reset()
      try await session.close()
      try await test.environment.close()
    }

    func testInvalidManagementFrameRetainsDiagnosticUntilNativeRetirement() async throws {
      try await managementCleanupFixture(cause: .invalidFrame)
    }

    func testManagementClosePreservesTheNativeCleanupOwner() async throws {
      try await managementCleanupFixture(cause: .close)
    }

    func testManagementDeadlineRetainsTheNativeCleanupOwner() async throws {
      try await managementCleanupFixture(cause: .deadline)
    }

    private enum ManagementCleanupCause { case invalidFrame, close, deadline }

    private func managementCleanupFixture(cause: ManagementCleanupCause) async throws {
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let foundation = test.fixture.base.environment
      let storeDirectory = test.directory.appendingPathComponent("management-store")
      try FileManager.default.createDirectory(
        at: storeDirectory, withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700])
      let store = try SQLiteServiceExecutionStore(
        environment: foundation,
        configuration: SQLiteServiceExecutionConfiguration(
          directory: storeDirectory, authority: "example",
          storeID: Data(repeating: 11, count: 16), generation: 1, create: true,
          maximumHistoryRows: 2, maximumActive: 1, maximumResultBytes: 2048,
          maximumDatabaseBytes: 2 << 20,
          checkpointKey: ServiceCheckpointSigningKey(
            protection: .hmacSHA256,
            keyID: Data(repeating: 12, count: 16), secret: Data(repeating: 13, count: 32)),
          checkContinuity: {}))
      let registry = try ServiceRegistry(
        environment: foundation,
        configuration: ServiceRegistryConfiguration(
          authority: "example",
          queryBinding: ServiceContractQueryBinding(
            typeID: 12345, contractDigest: Data(repeating: 6, count: 32)),
          executionStore: store))
      let diagnostics = V4NativeManagementDiagnosticLog()
      let server = try registry.admission(
        identity: ServiceCallerIdentity(
          tenant: "tenant", audience: "service",
          subject: "server", identityDigest: Data(repeating: 8, count: 32), peerSubject: "client",
          peerIdentityDigest: Data(repeating: 9, count: 32)), execution: true, maximumGeneral: 1,
        check: { try diagnostics.check() })
      try foundation.installDiagnosticSink(
        TransportDiagnosticSinkConfiguration(samplingPartsPerMillion: 10_000) {
          diagnostics.append($0)
        }, random: { count in Data(repeating: count == 16 ? 1 : 0, count: count) })
      // The authenticated fixture is a client Session, so use its original
      // raw native stream as the admitted management transport. The server
      // management reader still parses the real bytes and owns native cleanup.
      let stream = try await session.openStream(kind: "example.management-cleanup")
      let native = try XCTUnwrap(stream as? V4NativeByteStream)
      let management = try V4ExecutionManagementChannel(
        environment: foundation,
        storage: foundation.executionManagementStorage(), initiates: false,
        factory: { throw ServiceFailure.serviceUnavailable })
      let managementHandler: V4ExecutionManagementHandler = { request, payload, diagnostic in
        try await server.handleManagementRequest(request, payload: payload, diagnostic: diagnostic)
      }
      await management.installHandler(
        managementHandler, checkSource: { try server.checkManagementSource() })
      test.peer.holdProtocolInput()
      await management.acceptPeer(native)
      let input = cause == .invalidFrame ? Data([0, 0]) : Data([0])
      do {
        try await test.peer.sendBridgePayload(toStream: 0, bytes: input)
        try await nativeManagementWait { diagnostics.snapshot.count == 1 }
        if cause == .close { server.close() }
        // The incomplete prefix leaves the original reader waiting. Expire
        // the admitted source check so its real management timer closes it.
        if cause == .deadline { diagnostics.expire() }
        try await nativeManagementWait {
          let terminal = await native.terminalError()
          return terminal == .streamReset && test.peer.heldProtocolInputs > 0
        }
        XCTAssertEqual(diagnostics.snapshot.map { $0.state }, [.started])
        XCTAssertFalse(native.rpcCleanupComplete)
        let retainedBeforeClose = await management.physicalPendingCount()
        XCTAssertGreaterThan(retainedBeforeClose, 0)
        let firstClose = Task { await management.close() }
        let secondClose = Task { await management.close() }
        await Task.yield()
        let retainedAfterClose = await management.physicalPendingCount()
        XCTAssertGreaterThan(retainedAfterClose, 0)
        XCTAssertFalse(native.rpcCleanupComplete)
        try await test.peer.releaseProtocolInput()
        // Advance the fixture's monotonic protocol clock while observing the
        // real retirement, including its finite batching delay.
        try await nativeManagementWait {
          let pending = await management.physicalPendingCount()
          let complete =
            native.rpcCleanupComplete && pending == 0 && diagnostics.snapshot.count == 3
          if !complete { test.fixture.base.source.advance(1) }
          return complete
        }
        await firstClose.value
        await secondClose.value
        XCTAssertEqual(diagnostics.snapshot.map { $0.state }, [.started, .failed, .closed])
        if cause == .deadline { XCTAssertEqual(diagnostics.snapshot[1].code, .expired) }
        XCTAssertEqual(Set(diagnostics.snapshot.map { $0.correlationID }).count, 1)
      } catch {
        try? await test.peer.releaseProtocolInput()
        await management.close()
        server.close()
        registry.close()
        await store.close()
        try? await session.close()
        throw error
      }
      await management.close()
      server.close()
      registry.close()
      await store.close()
      try await session.close()
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }

    private func nativeManagementWait(_ predicate: () async -> Bool) async throws {
      let deadline = ContinuousClock.now.advanced(by: .seconds(5))
      while !(await predicate()) {
        guard ContinuousClock.now < deadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }

    func testDuplexBridgeRejectsDifferentEnvironmentsBeforeClaimingEitherStream() async throws {
      let first = try NativeSessionFixture(profile: .x25519)
      let second = try NativeSessionFixture(profile: .x25519)
      defer {
        first.cleanup()
        second.cleanup()
      }
      let firstSession = try await first.environment.connectMaterial(first.material())
      let secondSession = try await second.environment.connectMaterial(second.material())
      let a = try await firstSession.openStream(kind: "example.bridge-foreign-a")
      let b = try await secondSession.openStream(kind: "example.bridge-foreign-b")
      XCTAssertThrowsError(try DuplexBridge(a, b)) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .ownerUnavailable)
      }
      let aWritten = try await a.write(Data([1]))
      let bWritten = try await b.write(Data([2]))
      XCTAssertEqual(aWritten, 1)
      XCTAssertEqual(bWritten, 1)
      try await a.reset()
      try await b.reset()
      try await firstSession.close()
      try await secondSession.close()
      try await first.environment.close()
      try await second.environment.close()
    }

    func testUnstartedDuplexBridgeAbortOwnsCleanupWithoutConsumingBytes() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-unstarted-a")
      let b = try await session.openStream(kind: "example.bridge-unstarted-b")
      let bridge = try DuplexBridge(
        a, b,
        options: DuplexBridgeOptions(
          chunkBytes: 16, deadline: .seconds(5), cleanupTimeout: .milliseconds(50)))
      bridge.abort()
      try bridge.start()  // Repeated Start joins the already aborted operation.
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .aborted)
      XCTAssertEqual(result.aToB.progress.sourceReadBytes, 0)
      XCTAssertEqual(result.bToA.progress.destinationAcceptedBytes, 0)
      try await session.close()
      _ = bridge.cleanupStatus()
      try await test.environment.close()
    }

    func testPreparedDuplexBridgeDeadlineExpiresWithoutStartOrConsumingBytes() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-prepared-expiry-a")
      let b = try await session.openStream(kind: "example.bridge-prepared-expiry-b")
      let bridge = try DuplexBridge(
        a, b,
        options: DuplexBridgeOptions(
          chunkBytes: 16, deadline: .milliseconds(20), cleanupTimeout: .milliseconds(50)))
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .aborted)
      XCTAssertEqual(result.failure, .deadlineExceeded)
      XCTAssertEqual(result.aToB.progress.sourceReadBytes, 0)
      XCTAssertEqual(result.bToA.progress.destinationAcceptedBytes, 0)
      XCTAssertThrowsError(try bridge.start()) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .deadlineExceeded)
      }
      try await session.close()
      _ = bridge.cleanupStatus()
      try await test.environment.close()
    }

    func testDuplexBridgeRejectsPreviouslyUsedRawStreamWithoutClaimingOtherEndpoint() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-used")
      let b = try await session.openStream(kind: "example.bridge-unused")
      _ = try await a.write(Data([5]))
      XCTAssertThrowsError(try DuplexBridge(a, b)) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .streamOwned)
      }
      let written = try await b.write(Data([6]))
      XCTAssertEqual(written, 1)
      try await a.reset()
      try await b.reset()
      try await session.close()
      try await test.environment.close()
    }

    func testDuplexBridgeFailurePreservesAcceptedBytesAndSharedPartialResult() async throws {
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-failure-a")
      let b = try await session.openStream(kind: "example.bridge-failure-b")
      let bridge = try DuplexBridge(
        a, b,
        options: DuplexBridgeOptions(
          chunkBytes: 2, deadline: .seconds(5), cleanupTimeout: .milliseconds(100)))
      try bridge.start()
      let payload = Data([20, 21, 22, 23])
      try await test.peer.sendBridgePayload(toStream: 0, bytes: payload)
      try await test.peer.waitBridgeInput(stream: 1, bytes: payload)
      try await test.peer.resetStreams()
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .failed)
      XCTAssertNotNil(result.failure)
      XCTAssertEqual(result.aToB.progress.sourceReadBytes, UInt64(payload.count))
      XCTAssertEqual(result.aToB.progress.destinationAcceptedBytes, UInt64(payload.count))
      XCTAssertEqual(result.aToB.progress.unacceptedTail.count, 0)
      let repeated = try await bridge.wait()
      XCTAssertTrue(result === repeated)
      try await session.close()
      _ = bridge.cleanupStatus()
      try await test.environment.close()
    }

    func testDuplexBridgeHalfCloseKeepsReversePumpAndReturnsActualCounts() async throws {
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-half-a")
      let b = try await session.openStream(kind: "example.bridge-half-b")
      let bridge = try DuplexBridge(
        a, b,
        options: DuplexBridgeOptions(
          chunkBytes: 2, deadline: .seconds(5), cleanupTimeout: .milliseconds(100)))
      try bridge.start()
      let left = Data([1, 2, 3, 4, 5])
      try await test.peer.sendBridgePayload(toStream: 0, bytes: left, finish: true)
      try await test.peer.waitBridgeInput(stream: 1, bytes: left, eof: true)
      XCTAssertEqual(bridge.progress().aToB.sourceStatus, .eof)
      XCTAssertTrue(bridge.progress().aToB.closeWriteCompleted)
      XCTAssertFalse(bridge.progress().bToA.closeWriteCompleted)
      XCTAssertEqual(bridge.progress().outcome, .running)
      // A's source EOF must not reset B's source or finish A's destination.
      let right = Data([6, 7, 8, 9])
      try await test.peer.sendBridgePayload(toStream: 1, bytes: right, finish: true)
      try await test.peer.waitBridgeInput(stream: 0, bytes: right, eof: true)
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .normal)
      XCTAssertNil(result.failure)
      XCTAssertEqual(result.aToB.progress.sourceReadBytes, UInt64(left.count))
      XCTAssertEqual(result.aToB.progress.destinationAcceptedBytes, UInt64(left.count))
      XCTAssertEqual(result.bToA.progress.sourceReadBytes, UInt64(right.count))
      XCTAssertEqual(result.bToA.progress.destinationAcceptedBytes, UInt64(right.count))
      XCTAssertEqual(result.aToB.progress.unacceptedTail.count, 0)
      XCTAssertTrue(result.aToB.sendDrained)
      XCTAssertTrue(result.bToA.sendDrained)
      let repeated = try await bridge.wait()
      XCTAssertTrue(result.aToB.progress.unacceptedTail === repeated.aToB.progress.unacceptedTail)
      try await session.close()
      try await test.environment.close()
    }

    func testDuplexBridgeNativeTCPUsesRealHalfCloseAndSeparatesSendGuarantees() async throws {
      let server = try await DuplexTCPTestServer.start()
      defer { Task { await server.close() } }
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.bridge-native")
      let tcp = try await test.environment.connectDuplexTCP(
        numericAddress: "127.0.0.1", port: server.port,
        chunkBytes: 4, kernelBufferBytes: 16_384, timeout: .seconds(5))
      let bridge = try DuplexBridge(
        stream, tcp,
        options: DuplexBridgeOptions(
          chunkBytes: 4, deadline: .seconds(5), cleanupTimeout: .milliseconds(100)))
      try bridge.start()
      let fromStream = Data([31, 32, 33, 34, 35])
      try await test.peer.sendBridgePayload(toStream: 0, bytes: fromStream, finish: true)
      try await server.waitInput(fromStream, eof: true)
      let fromTCP = Data([41, 42, 43, 44])
      try await server.send(fromTCP, finish: true)
      try await test.peer.waitBridgeInput(stream: 0, bytes: fromTCP, eof: true)
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .normal)
      XCTAssertEqual(result.aToB.destinationKind, .nativeTCP)
      XCTAssertEqual(result.bToA.destinationKind, .flowersecStream)
      XCTAssertFalse(result.aToB.sendDrained)
      XCTAssertTrue(result.aToB.nativeSendFinished)
      XCTAssertTrue(result.bToA.sendDrained)
      XCTAssertEqual(result.aToB.progress.sourceReadBytes, UInt64(fromStream.count))
      XCTAssertEqual(result.aToB.progress.destinationAcceptedBytes, UInt64(fromStream.count))
      XCTAssertEqual(result.bToA.progress.destinationAcceptedBytes, UInt64(fromTCP.count))
      XCTAssertNil(result.nativeError)
      try await session.close()
      try await test.environment.close()
      await server.close()
    }

    func testDuplexBridgeNativeTCPRejectsASecondBridgeAndExternalCloseAfterClaim() async throws {
      let server = try await DuplexTCPTestServer.start()
      defer { Task { await server.close() } }
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.bridge-native-owned")
      let tcp = try await test.environment.connectDuplexTCP(
        numericAddress: "127.0.0.1", port: server.port, timeout: .seconds(5))
      let bridge = try DuplexBridge(stream, tcp)
      let unclaimed = try await session.openStream(kind: "example.bridge-native-second")
      XCTAssertThrowsError(try DuplexBridge(unclaimed, tcp)) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .streamOwned)
      }
      let unclaimedCount = try await unclaimed.write(Data([9]))
      XCTAssertEqual(unclaimedCount, 1)
      XCTAssertThrowsError(try tcp.close()) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .streamOwned)
      }
      bridge.abort()
      _ = try await bridge.wait()
      try await session.close()
      try await test.environment.close()
      await server.close()
    }

    func testNativeDuplexBridgeAbortPreservesChargedTailUnderActualStreamBackpressure() async throws
    {
      let server = try await DuplexTCPTestServer.start()
      defer { Task { await server.close() } }
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      var phase = "connect"
      do {
        let session = try await test.environment.connectMaterial(test.material())
        phase = "open stream"
        let stream = try await session.openStream(kind: "example.bridge-native-tail")
        test.peer.holdBridgeInput()
        phase = "connect TCP"
        let tcp = try await test.environment.connectDuplexTCP(
          numericAddress: "127.0.0.1", port: server.port, chunkBytes: 16,
          kernelBufferBytes: 16_384, timeout: .seconds(5))
        let bridge = try DuplexBridge(
          tcp, stream,
          options: DuplexBridgeOptions(
            chunkBytes: 16, deadline: .seconds(5), cleanupTimeout: .milliseconds(50)))
        try bridge.start()
        let window = test.peer.bridgeWindow
        let payload = Data((0..<(window * 2)).map { UInt8($0 % 251) })
        // The writer can remain backpressured after the bridge has consumed its
        // charged tail. Observe that point before joining the writer.
        let sending = Task { try await server.send(payload) }
        defer { sending.cancel() }
        phase = "observe backpressure"
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while true {
          let progress = bridge.progress().aToB
          if progress.destinationAcceptedBytes == UInt64(window), progress.pendingTailBytes > 0 {
            break
          }
          guard ContinuousClock.now < deadline else { throw SessionError.timeout }
          try await ContinuousClock().sleep(for: .milliseconds(5))
        }
        phase = "abort bridge"
        bridge.abort()
        let result = try await bridge.wait()
        let transfer = result.aToB.progress
        XCTAssertEqual(result.outcome, .aborted)
        XCTAssertEqual(transfer.destinationAcceptedBytes, UInt64(window))
        XCTAssertGreaterThan(transfer.unacceptedTail.count, 0)
        XCTAssertLessThanOrEqual(transfer.unacceptedTail.count, 16)
        XCTAssertEqual(
          transfer.sourceReadBytes,
          transfer.destinationAcceptedBytes + UInt64(transfer.unacceptedTail.count))
        var tail = Data(count: transfer.unacceptedTail.count)
        let copied = try transfer.unacceptedTail.copyBytes(to: &tail)
        XCTAssertEqual(copied, tail.count)
        XCTAssertEqual(tail, payload.subdata(in: window..<(window + copied)))
        let repeated = try await bridge.wait()
        XCTAssertTrue(result.aToB.progress.unacceptedTail === repeated.aToB.progress.unacceptedTail)
        phase = "close session"
        try await session.close()
        _ = bridge.cleanupStatus()
        XCTAssertEqual(try transfer.unacceptedTail.copyBytes(to: &tail), copied)
        phase = "close environment"
        try await test.environment.close()
        await server.close()
        _ = await sending.result
      } catch {
        XCTFail("Native backpressure failed during \(phase): \(error)")
        try? await test.environment.close()
        await server.close()
        throw error
      }
    }

    func testNativeDuplexBridgeRejectsAliasedOrNativeOnlyEndpointsBeforeIO() async throws {
      let server = try await DuplexTCPTestServer.start()
      defer { Task { await server.close() } }
      let test = try NativeSessionFixture(profile: .x25519, mode: .bridge)
      defer { test.cleanup() }
      let tcp = try await test.environment.connectDuplexTCP(
        numericAddress: "127.0.0.1", port: server.port, timeout: .seconds(5))
      let alias = tcp
      XCTAssertThrowsError(try DuplexBridge(tcp, alias)) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .invalidEndpoint)
      }
      XCTAssertEqual(server.input, Data())
      try tcp.close()
      XCTAssertTrue(tcp.cleanupStatus().complete)
      try await test.environment.close()
      await server.close()
    }

    func testNativeDuplexBridgeRejectsOversizedChunkWithoutClaimingStream() async throws {
      let server = try await DuplexTCPTestServer.start()
      defer { Task { await server.close() } }
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.bridge-native-capacity")
      let tcp = try await test.environment.connectDuplexTCP(
        numericAddress: "127.0.0.1", port: server.port, chunkBytes: 8, timeout: .seconds(5))
      XCTAssertThrowsError(
        try DuplexBridge(stream, tcp, options: DuplexBridgeOptions(chunkBytes: 16))
      ) { error in
        XCTAssertEqual(error as? DuplexBridgeFailure, .configurationCapacity)
      }
      let written = try await stream.write(Data([7]))
      XCTAssertEqual(written, 1)
      XCTAssertEqual(server.input, Data())
      try tcp.close()
      try await stream.reset()
      try await session.close()
      try await test.environment.close()
      await server.close()
    }

    func testDuplexBridgeDeadlineKeepsTypedPartialResult() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let a = try await session.openStream(kind: "example.bridge-timeout-a")
      let b = try await session.openStream(kind: "example.bridge-timeout-b")
      let bridge = try DuplexBridge(
        a, b,
        options: DuplexBridgeOptions(
          chunkBytes: 16, deadline: .milliseconds(20), cleanupTimeout: .milliseconds(50)))
      try bridge.start()
      let result = try await bridge.wait()
      XCTAssertEqual(result.outcome, .aborted)
      XCTAssertEqual(result.failure, .deadlineExceeded)
      XCTAssertEqual(result.aToB.progress.sourceReadBytes, 0)
      XCTAssertEqual(result.bToA.progress.destinationAcceptedBytes, 0)
      XCTAssertLessThanOrEqual(result.aToB.progress.unacceptedTail.count, 16)
      try await session.close()
      try await test.environment.close()
    }

    func testPublicSessionUsesSignedLeafPinAndPreservesBothDirectionsMetadata() async throws {
      let test = try NativeSessionFixture(profile: .p256, pinned: true)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let metadata = try StreamMetadata(
        namespace: "acme/chat", version: .max,
        values: ["z": Data(), "aa": Data([0, 255]), "é": Data([1, 2, 3])])
      let stream = try await session.openStream(kind: "example.echo", metadata: metadata)
      XCTAssertEqual(test.peer.receivedMetadata, [try metadata.encoded()])
      let count = try await stream.write(Data([7, 8]))
      XCTAssertEqual(count, 2)
      let echoed = try await stream.read(maxBytes: 2)
      XCTAssertEqual(echoed, Data([7, 8]))
      let accepting = Task { try await session.acceptStream() }
      try await test.peer.openStream(metadata: metadata.encoded())
      let incoming = try await accepting.value
      XCTAssertEqual(incoming.metadata, metadata)
      XCTAssertEqual(try incoming.metadata.encoded(), try metadata.encoded())
      try await incoming.stream.close()
      try await stream.close()
      try await session.close()
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }
    func testCanceledReadAndProbePreserveSessionAndRepeatedCreditProgress() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.echo")
      let pendingRead = Task { try await stream.read(maxBytes: 64) }
      try await ContinuousClock().sleep(for: .milliseconds(20))
      pendingRead.cancel()
      do {
        _ = try await pendingRead.value
        XCTFail("canceled read delivered")
      } catch let error as SessionError { XCTAssertEqual(error, .canceled) }
      test.peer.holdPongs()
      let firstProbe = Task { try await session.probeLiveness() }
      try await test.peer.waitPongs(1)
      firstProbe.cancel()
      do {
        _ = try await firstProbe.value
        XCTFail("canceled probe succeeded")
      } catch let error as TransportLivenessError {
        XCTAssertEqual(error.reason, .canceled)
        XCTAssertTrue(error.progress.submitted)
        // Elapsed describes this canceled operation too; local publication
        // completion is independent of a matched authenticated PONG.
        XCTAssertNotNil(error.progress.elapsedMilliseconds)
      }
      let nextProbe = Task { try await session.probeLiveness() }
      try await test.peer.waitPongs(2)
      try await test.peer.releasePongs()
      _ = try await nextProbe.value
      // More than twice the original 1 KiB receive window in each direction.
      for value in UInt8(0)..<40 {
        let bytes = Data(repeating: value, count: 64)
        let written = try await stream.write(bytes)
        let received = try await stream.read(maxBytes: 64)
        XCTAssertEqual(written, 64)
        XCTAssertEqual(received, bytes)
      }
      try await test.peer.resetStreams()
      do {
        _ = try await stream.read(maxBytes: 64)
        XCTFail("remote reset became EOF")
      } catch let error as SessionError { XCTAssertEqual(error, .streamReset) }
      let terminal = await stream.terminalError()
      XCTAssertEqual(terminal, .streamReset)
      try await session.close()
      try await test.peer.waitClosed()
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }
    func testCancelDuringNativeAdmissionJoinsOriginalSocketAndEndsMaterial() async throws {
      let test = try NativeSessionFixture(profile: .p256, mode: .holdAdmission)
      defer { test.cleanup() }
      let material = try await test.material()
      // The Environment's original open SQLite store retains its own tail.
      let baseline = test.fixture.base.root.snapshot().executionTails
      XCTAssertGreaterThan(baseline, 0)
      let connecting = Task { try await test.environment.connectMaterial(material) }
      try await test.peer.waitAdmission()
      let claimedFacts = try XCTUnwrap(
        (material.owner as? V4ConnectionFactsOwner)?.connectionFactsOwner.snapshot())
      let concurrent = Task { try await test.environment.connectMaterial(material) }
      do {
        _ = try await concurrent.value
        XCTFail("a second concurrent material claim established a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .invalidMaterial)
        XCTAssertEqual(
          failure.connection, claimedFacts,
          "a losing claimant must not rewrite the original attempt facts")
      }
      XCTAssertFalse(
        material.cleanupStatus().complete,
        "a losing claimant must not close the original material")
      connecting.cancel()
      do {
        _ = try await connecting.value
        XCTFail("canceled connection established")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .connectionFailed)
        XCTAssertEqual(failure.retryDisposition, .terminal)
        XCTAssertTrue(failure.cleanup.complete)
        XCTAssertFalse(failure.cleanup.cleanupIncomplete)
        XCTAssertEqual(failure.cleanup.pendingCallbacks, 0)
        XCTAssertEqual(failure.localReport.cleanup, failure.cleanup)
      }
      XCTAssertTrue(material.cleanupStatus().complete)
      XCTAssertFalse(test.peer.established)
      XCTAssertEqual(test.fixture.base.root.snapshot().executionTails, baseline)
      try await test.environment.close()
      await test.store.waitPhysicalCleanup()
      XCTAssertEqual(test.fixture.base.root.snapshot().executionTails, 0)
    }

    func testFailedAttemptCleanupDoesNotIncludeHealthySessionOrSharedSQLiteStore() async throws {
      let test = try NativeSessionFixture(profile: .x25519, mode: .rejection, replacement: true)
      defer { test.cleanup() }
      let replacement = try XCTUnwrap(test.replacementInput)
      let healthyMaterial = try test.host.material(
        TransportPoolCredential(input: replacement),
        identity: TransportApplicationIdentity(test.client))
      let healthy = try await test.environment.connectMaterial(healthyMaterial)
      let failedMaterial = try await test.material()
      do {
        _ = try await test.environment.connectMaterial(failedMaterial)
        XCTFail("rejected attempt published a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertTrue(failure.cleanup.complete)
        XCTAssertFalse(failure.cleanup.cleanupIncomplete)
        XCTAssertEqual(failure.cleanup.pendingCallbacks, 0)
        XCTAssertEqual(failure.localReport.cleanup, failure.cleanup)
      }
      XCTAssertTrue(failedMaterial.cleanupStatus().complete)
      let environmentCleanup = await test.environment.cleanupStatus()
      XCTAssertFalse(environmentCleanup.complete)
      XCTAssertGreaterThan(environmentCleanup.pendingCallbacks, 0)
      let stream = try await healthy.openStream(kind: "example.echo")
      let payload = Data("healthy-after-failed-attempt".utf8)
      let written = try await stream.write(payload)
      let echoed = try await stream.read(maxBytes: payload.count)
      XCTAssertEqual(written, payload.count)
      XCTAssertEqual(echoed, payload)
      try await stream.close()
      try await healthy.close()
      try await test.environment.close()
      await test.store.waitPhysicalCleanup()
    }
    func testOriginalMTLSIssuanceAndTxBReachNativeReadyAfterSourceCloses() async throws {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile, pinned: true)
        defer { test.cleanup() }
        let identity = try V4ControlTestAuthority.Identity()
        let authority = NativeLiveAuthorityState(test: test, profile: profile)
        let issuance = try V4ControlTestAuthority(identity: identity) { path, body in
          try authority.issue(path, body: body)
        }
        defer { issuance.stop() }
        let activation = try V4ControlTestAuthority(identity: identity) { path, body in
          try authority.authorize(path, body: body)
        }
        defer { activation.stop() }
        let configuration = TransportLiveAuthoritySourceConfiguration(
          issuance: issuance.configuration(),
          activation: activation.configuration(), clientCertificate: test.input.clientCertificate,
          serverCertificate: test.input.serverCertificate, activationSigningKeyID: "activate")
        let source = try await test.environment.makeLiveAuthoritySource(
          configuration, identity: TransportApplicationIdentity(test.client))
        let material = try await source.acquire()
        source.close()
        let session = try await test.environment.connectMaterial(material)
        XCTAssertTrue(test.peer.established)
        XCTAssertEqual(issuance.requests, ["/issue/direct"])
        XCTAssertEqual(activation.requests, ["/live/authorize"])
        let stream = try await session.openStream(kind: "example.echo")
        let written = try await stream.write(Data([7, 8, 9]))
        let echoed = try await stream.read(maxBytes: 3)
        XCTAssertEqual(written, 3)
        XCTAssertEqual(echoed, Data([7, 8, 9]))
        do {
          _ = try await source.acquire()
          XCTFail("closed live Source issued a new lease")
        } catch {}
        try await stream.close()
        try await session.close()
      }
    }

    func testDefaultConnectAcquiresClosedPoolSourceOnceForBothNativeProfiles() async throws {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile)
        defer { test.cleanup() }
        let source = try await test.source()
        let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
        let session = try await connect(
          environment: test.environment, source: source,
          requirements: ConnectionRequirements(
            localConsumerTLS13Verification: true, applicationProfile: "transport"))
        XCTAssertTrue(test.peer.established)
        XCTAssertEqual(owner.acquisitionCount, 1)
        XCTAssertEqual(source.description, "Flowersec.ConnectionMaterialSource(<redacted>)")
        XCTAssertTrue(Mirror(reflecting: source).children.isEmpty)
        source.close()
        XCTAssertTrue(source.cleanupStatus().complete)
        do {
          _ = try await source.acquire()
          XCTFail("A closed source admitted another Acquire")
        } catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .closed) }
        XCTAssertEqual(owner.acquisitionCount, 1)
        // Closing the source affects future Acquire only. This Session keeps
        // the exact already captured material and native transport ownership.
        let stream = try await session.openStream(kind: "example.echo")
        let written = try await stream.write(Data([1, 2, 3]))
        XCTAssertEqual(written, 3)
        let echoed = try await stream.read(maxBytes: 16)
        XCTAssertEqual(echoed, Data([1, 2, 3]))
        try await stream.finish()
        try await session.close()
        try await test.environment.close()
      }
    }
    func testClosedPoolSourceRetainsCapturedGenerationAndRejectsIdentitySubstitution() async throws
    {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = try await test.source()
      let material = try await source.acquire()
      let original = try XCTUnwrap(material.owner as? V4DirectPoolMaterial)
      XCTAssertEqual(original.sourceGeneration, 1)
      XCTAssertEqual(original.identity.identityPublicKey, test.client.identityPublicKey)
      let wrong = try test.fixture.base.environment.generateIdentity(profile: .x25519)
      defer { wrong.close() }
      do {
        try source.replacePoolGeneration(
          [test.credential()], identity: TransportApplicationIdentity(wrong))
        XCTFail(
          "Publishing a credential with another key must fail before replacing the generation")
      } catch {}
      try source.replacePoolGeneration(
        [test.credential()], identity: TransportApplicationIdentity(test.client))
      let next = try await source.acquire()
      let nextOwner = try XCTUnwrap(next.owner as? V4DirectPoolMaterial)
      XCTAssertEqual(nextOwner.sourceGeneration, 2)
      XCTAssertEqual(nextOwner.sourceIncarnation, original.sourceIncarnation)
      XCTAssertEqual(original.sourceGeneration, 1)
      do {
        _ = try await source.acquire()
        XCTFail("The local finite pool cannot issue or top itself up")
      } catch { XCTAssertEqual(error as? ConnectionMaterialSourceError, .exhausted) }
      source.close()
      let session = try await test.environment.connectMaterial(material)
      XCTAssertTrue(test.peer.established)
      try await session.close()
      // Source generations are local snapshots, never additional once rights
      // for two records that refer to the same independently spendable lease.
      do {
        _ = try await test.environment.connectMaterial(next)
        XCTFail("A local generation granted another spend")
      } catch {}
      try await test.environment.close()
    }
    func testPoolSourceRotationCapturesMatchingNewKeyWithoutChangingOldMaterial() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = try await test.source()
      let oldMaterial = try await source.acquire()
      let oldOwner = try XCTUnwrap(oldMaterial.owner as? V4DirectPoolMaterial)
      let replacement = try test.fixture.base.environment.generateIdentity(profile: .x25519)
      defer { replacement.close() }
      func certificate(_ identity: V4LocalIdentity) -> [UInt64: V4CBORValue] {
        [
          3: NamespaceFixture.map([0: .uint(0), 1: .bytes(identity.dhPublicKey)]),
          4: .bytes(identity.identityPublicKey),
        ]
      }
      // The fixture issuer signs a distinct lease and its complete new
      // certificate pair. Local generation replacement grants no authority.
      let input = try test.fixture.input(
        source: .preauthorizedPool, indices: [0],
        client: certificate(replacement), server: certificate(test.server),
        artifact: [6: .bytes(Data(repeating: 51, count: 16))],
        activation: [5: .bytes(Data(repeating: 51, count: 16))])
      let credential = TransportPoolCredential(
        artifact: input.artifact,
        clientCertificate: input.clientCertificate, serverCertificate: input.serverCertificate,
        activationAuthorization: input.activation)
      try source.replacePoolGeneration(
        [credential], identity: TransportApplicationIdentity(replacement))
      let newMaterial = try await source.acquire()
      let newOwner = try XCTUnwrap(newMaterial.owner as? V4DirectPoolMaterial)
      XCTAssertEqual(newOwner.sourceGeneration, 2)
      XCTAssertEqual(oldOwner.sourceGeneration, 1)
      XCTAssertEqual(newOwner.identity.identityPublicKey, replacement.identityPublicKey)
      XCTAssertEqual(oldOwner.identity.identityPublicKey, test.client.identityPublicKey)
      XCTAssertEqual(try newOwner.plan.artifact.b("lease_id"), Data(repeating: 51, count: 16))
      XCTAssertEqual(try oldOwner.plan.artifact.b("lease_id"), Data(repeating: 30, count: 16))
      source.close()
      newMaterial.close()
      // Releasing the new source/material keeps the original key and lease
      // available to the original native establishment path.
      let session = try await test.environment.connectMaterial(oldMaterial)
      XCTAssertTrue(test.peer.established)
      try await session.close()
      try await test.environment.close()
    }
    func testClosedSourceProviderBindingAndRequirementsRefuseBeforeAcquire() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      let other = try NativeSessionFixture(profile: .x25519)
      defer {
        test.cleanup()
        other.cleanup()
      }
      let source = try await test.source()
      let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
      do {
        _ = try await other.environment.connect(source: source)
        XCTFail("A foreign provider/environment acquired the source")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .invalidMaterial)
        XCTAssertEqual(failure.connection.spendState, .unspent)
      }
      XCTAssertEqual(owner.acquisitionCount, 0)
      XCTAssertFalse(other.peer.established)
      do {
        _ = try await test.environment.connect(
          source: source, requirements: ConnectionRequirements(applicationProfile: "execution"))
        XCTFail("A source widened its signed application profile")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .unsupported)
        XCTAssertEqual(failure.connection.spendState, .unspent)
      }
      XCTAssertEqual(owner.acquisitionCount, 0)
      let session = try await test.environment.connect(source: source)
      XCTAssertEqual(owner.acquisitionCount, 1)
      XCTAssertTrue(test.peer.established)
      try await session.close()
      try await test.environment.close()
      try await other.environment.close()
    }

    func testControllerDefersPublicationUntilCandidateInitializationAndStopsOnUnknownFailure()
      async throws
    {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = try await test.source()
      let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
      let initializer = NativeHeldCandidateInitializer()
      let controller = try ConnectionController(
        environment: test.environment, source: source,
        initializeSession: { candidate in try await initializer.initialize(candidate) })
      await controller.start()
      while !(await initializer.started) {
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
      XCTAssertTrue(test.peer.established)
      let unpublished = await controller.snapshot()
      XCTAssertEqual(unpublished.state, .connecting)
      XCTAssertNil(unpublished.currentSession)
      XCTAssertEqual(owner.acquisitionCount, 1)
      // An application failure can follow an actual committed Register. The
      // controller cannot infer rollback from candidate transport cleanup.
      await initializer.releaseFailure()
      do {
        _ = try await controller.waitForSession()
        XCTFail("Failed initialization published or replayed a candidate")
      } catch {}
      let failed = await controller.snapshot()
      XCTAssertEqual(failed.state, .failed)
      XCTAssertEqual(failed.retryDisposition, .terminal)
      XCTAssertEqual(owner.acquisitionCount, 1)
      await controller.close()
      source.close()
      try await test.environment.close()
    }

    func testControllerAcquiresFreshMaterialAfterActualNativeDisconnect() async throws {
      let test = try NativeSessionFixture(profile: .x25519, replacement: true)
      defer { test.cleanup() }
      let source = try await test.source()
      let sourceOwner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
      let controller = try ConnectionController(environment: test.environment, source: source)
      do {
        await controller.start()
        let first = try await controller.waitForSession()
        let original = try XCTUnwrap(first as? V4NativeSession)
        let stream = try await first.openStream(kind: "example.echo")
        _ = try await stream.write(Data([99]))
        _ = try await stream.read(maxBytes: 1)
        try await test.peer.disconnect()
        let termination = await first.waitTermination()
        XCTAssertEqual(termination.error, .closed)
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while await controller.generation < 2 {
          guard ContinuousClock.now < deadline else { throw SessionError.timeout }
          try await ContinuousClock().sleep(for: .milliseconds(5))
        }
        let next = try await controller.captureSession()
        XCTAssertFalse((next as? V4NativeSession) === original)
        XCTAssertEqual(sourceOwner.acquisitionCount, 2)
        do {
          _ = try await stream.write(Data([100]))
          XCTFail("Old Stream moved to a replacement connection")
        } catch {}
        let replacement = try await next.openStream(kind: "example.echo")
        let written = try await replacement.write(Data([101]))
        let echoed = try await replacement.read(maxBytes: 1)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(echoed, Data([101]))
        try await replacement.close()
        await controller.close()
        source.close()
        try await test.environment.close()
      } catch {
        await controller.close()
        source.close()
        try? await test.environment.close()
        throw error
      }
    }

    func testExplicitReplacementPublishesFirstSessionWithoutRetirementPosition() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = try await test.source()
      let controller = try ConnectionController(environment: test.environment, source: source)
      do {
        let first = try await controller.replaceSession()
        XCTAssertTrue(first.currentSwitched)
        XCTAssertEqual(first.generation, 1)
        XCTAssertNil(first.previousSession)
        XCTAssertNil(first.retirement)
        let captured = try await controller.captureSession()
        XCTAssertTrue((captured as? V4NativeSession) === (first.currentSession as? V4NativeSession))
        await controller.close()
        source.close()
        try await test.environment.close()
      } catch {
        await controller.close()
        source.close()
        try? await test.environment.close()
        throw error
      }
    }

    func testExplicitReplacementAfterFirstInitializerFailureUsesFreshMaterialExactlyOnce()
      async throws
    {
      let test = try NativeSessionFixture(profile: .x25519, replacement: true)
      defer { test.cleanup() }
      let source = try await test.source()
      let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
      let initializer = NativeExplicitRecoveryInitializer()
      let controller = try ConnectionController(
        environment: test.environment, source: source,
        initializeSession: { candidate in try await initializer.initialize(candidate) })
      do {
        await controller.start()
        do {
          _ = try await controller.waitForSession()
          XCTFail("Unknown initialization was published")
        } catch {}
        let failed = await controller.snapshot()
        XCTAssertEqual(failed.state, .failed)
        XCTAssertNil(failed.currentSession)
        let retry = await controller.retryNow()
        XCTAssertFalse(retry)
        XCTAssertEqual(owner.acquisitionCount, 1)
        // The application's authority has resolved the original action. Only
        // this explicit call authorizes a new initialization on new material.
        let recovered = try await controller.replaceSession()
        XCTAssertNil(recovered.previousSession)
        XCTAssertNil(recovered.retirement)
        XCTAssertTrue(recovered.currentSwitched)
        XCTAssertEqual(owner.acquisitionCount, 2)
        let calls = await initializer.calls
        XCTAssertEqual(calls, 2)
        let stream = try await recovered.currentSession.openStream(kind: "example.echo")
        let written = try await stream.write(Data([97]))
        let echoed = try await stream.read(maxBytes: 1)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(echoed, Data([97]))
        try await stream.close()
        await controller.close()
        source.close()
        try await test.environment.close()
      } catch {
        await controller.close()
        source.close()
        try? await test.environment.close()
        throw error
      }
    }

    func testControllerReplacementPublishesOriginalCandidateAndRetainsOldNativeRouting()
      async throws
    {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile, replacement: true)
        defer { test.cleanup() }
        let source = try await test.source()
        let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
        let initializer = NativeReplacementInitializer()
        let controller = try ConnectionController(
          environment: test.environment, source: source,
          initializeSession: { candidate in try await initializer.initialize(candidate) })
        do {
          await controller.start()
          let initial = try await controller.waitForSession()
          let old = try XCTUnwrap(initial as? V4NativeSession)
          let oldStream = try await old.openStream(kind: "example.echo")
          let before = await controller.snapshot()
          let replacement = Task {
            try await controller.replaceSession(retirement: .retain(for: .seconds(1)))
          }
          try await initializer.waitForReplacement()
          let held = await controller.snapshot()
          do {
            _ = try await controller.captureSession()
            XCTFail("Initialization exposed old dispatch authority")
          } catch { XCTAssertEqual((error as? ConnectionControllerError)?.code, .notReady) }
          XCTAssertTrue((held.currentSession as? V4NativeSession) === old)
          XCTAssertEqual(held.generation, before.generation)
          XCTAssertEqual(owner.acquisitionCount, 2)
          XCTAssertTrue(test.peer.established)
          XCTAssertTrue(test.replacementPeer?.established == true)
          await initializer.release()
          let result = try await replacement.value
          let current = try XCTUnwrap(result.currentSession as? V4NativeSession)
          let capturedNew = try await controller.captureSession()
          XCTAssertTrue(result.currentSwitched)
          XCTAssertEqual(result.generation, before.generation + 1)
          XCTAssertTrue((result.previousSession as? V4NativeSession) === old)
          XCTAssertTrue((capturedNew as? V4NativeSession) === current)
          XCTAssertFalse(current === old)
          let retirement = try XCTUnwrap(result.retirement)
          let firstDeadline = retirement.progress().deadline
          let oldWritten = try await oldStream.write(Data([71, 72]))
          let oldEcho = try await oldStream.read(maxBytes: 2)
          XCTAssertEqual(oldWritten, 2)
          XCTAssertEqual(oldEcho, Data([71, 72]))
          let newStream = try await current.openStream(kind: "example.echo")
          let newWritten = try await newStream.write(Data([81, 82]))
          let newEcho = try await newStream.read(maxBytes: 2)
          XCTAssertEqual(newWritten, 2)
          XCTAssertEqual(newEcho, Data([81, 82]))
          XCTAssertEqual(retirement.progress().deadline, firstDeadline)
          XCTAssertEqual(owner.acquisitionCount, 2)
          let canceledWait = Task { try await retirement.wait() }
          canceledWait.cancel()
          do {
            _ = try await canceledWait.value
            XCTFail("Canceled retirement observation completed")
          } catch {}
          XCTAssertEqual(retirement.progress().deadline, firstDeadline)
          let retired = try await retirement.wait()
          XCTAssertEqual(retired.state, .closed)
          XCTAssertTrue(retired.cleanup.complete)
          XCTAssertEqual(retired.deadline, firstDeadline)
          do {
            _ = try await oldStream.write(Data([73]))
            XCTFail("An old handle followed the replacement Session")
          } catch {}
          let stillCurrent = try await controller.captureSession()
          XCTAssertTrue((stillCurrent as? V4NativeSession) === current)
          try await newStream.close()
          await controller.close()
          source.close()
          try await test.environment.close()
        } catch {
          await initializer.release()
          await controller.close()
          source.close()
          try? await test.environment.close()
          throw error
        }
      }
    }

    func testControllerReplacementCancellationBeforePublicationKeepsOriginalSessionAndAcquiresOnce()
      async throws
    {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile, replacement: true)
        defer { test.cleanup() }
        let source = try await test.source()
        let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
        let initializer = NativeReplacementInitializer()
        let controller = try ConnectionController(
          environment: test.environment, source: source,
          initializeSession: { candidate in try await initializer.initialize(candidate) })
        do {
          await controller.start()
          let initial = try await controller.waitForSession()
          let old = try XCTUnwrap(initial as? V4NativeSession)
          let stream = try await old.openStream(kind: "example.echo")
          let before = await controller.snapshot()
          let replacement = Task {
            try await controller.replaceSession(retirement: .retain(for: .seconds(1)))
          }
          try await initializer.waitForReplacement()
          let initializedCandidate = await initializer.replacementCandidate
          let candidate = try XCTUnwrap(initializedCandidate as? V4NativeSession)
          XCTAssertTrue(test.replacementPeer?.established == true)
          XCTAssertEqual(owner.acquisitionCount, 2)
          replacement.cancel()
          // Cancellation cannot pretend a noncooperative initializer returned.
          // Until that callback really exits, its candidate stays unpublished.
          let held = await controller.snapshot()
          XCTAssertTrue((held.currentSession as? V4NativeSession) === old)
          XCTAssertEqual(held.generation, before.generation)
          await initializer.release()
          do {
            _ = try await replacement.value
            XCTFail("Canceled replacement was published")
          } catch {}
          let after = await controller.snapshot()
          XCTAssertTrue((after.currentSession as? V4NativeSession) === old)
          XCTAssertEqual(after.generation, before.generation)
          XCTAssertEqual(owner.acquisitionCount, 2)
          let candidateEnd = await candidate.waitTermination()
          XCTAssertNotNil(candidateEnd.error)
          do {
            _ = try await candidate.openStream(kind: "example.echo")
            XCTFail("Canceled candidate retained its publication right")
          } catch {}
          let written = try await stream.write(Data([91, 92]))
          let echoed = try await stream.read(maxBytes: 2)
          XCTAssertEqual(written, 2)
          XCTAssertEqual(echoed, Data([91, 92]))
          await controller.close()
          source.close()
          try await test.environment.close()
        } catch {
          await initializer.release()
          await controller.close()
          source.close()
          try? await test.environment.close()
          throw error
        }
      }
    }

    func testControllerReplacementInitializerFailureClosesCandidateWithoutReplayOrPublication()
      async throws
    {
      for profile in V4CryptoProfile.allCases {
        let test = try NativeSessionFixture(profile: profile, replacement: true)
        defer { test.cleanup() }
        let source = try await test.source()
        let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
        let initializer = NativeReplacementInitializer(failOnRelease: true)
        let controller = try ConnectionController(
          environment: test.environment, source: source,
          initializeSession: { candidate in try await initializer.initialize(candidate) })
        do {
          await controller.start()
          let initial = try await controller.waitForSession()
          let old = try XCTUnwrap(initial as? V4NativeSession)
          let stream = try await old.openStream(kind: "example.echo")
          let before = await controller.snapshot()
          let replacement = Task {
            try await controller.replaceSession(retirement: .drain(timeout: .seconds(1)))
          }
          try await initializer.waitForReplacement()
          let initializedCandidate = await initializer.replacementCandidate
          let candidate = try XCTUnwrap(initializedCandidate as? V4NativeSession)
          XCTAssertEqual(owner.acquisitionCount, 2)
          let held = await controller.snapshot()
          XCTAssertTrue((held.currentSession as? V4NativeSession) === old)
          XCTAssertEqual(held.generation, before.generation)
          await initializer.release()
          do {
            _ = try await replacement.value
            XCTFail("Failed initializer published its candidate")
          } catch {}
          let failed = await controller.snapshot()
          XCTAssertEqual(failed.state, .failed)
          XCTAssertEqual(failed.retryDisposition, .terminal)
          XCTAssertTrue((failed.currentSession as? V4NativeSession) === old)
          XCTAssertEqual(failed.generation, before.generation)
          let automaticRetry = await controller.retryNow()
          XCTAssertFalse(automaticRetry)
          do {
            _ = try await controller.captureSession()
            XCTFail("Unknown initializer effects reopened old dispatch")
          } catch { XCTAssertEqual((error as? ConnectionControllerError)?.code, .notReady) }
          XCTAssertEqual(owner.acquisitionCount, 2)
          _ = await candidate.waitTermination()
          do {
            _ = try await candidate.openStream(kind: "example.echo")
            XCTFail("Failed candidate remained usable")
          } catch {}
          let written = try await stream.write(Data([93]))
          let echoed = try await stream.read(maxBytes: 1)
          XCTAssertEqual(written, 1)
          XCTAssertEqual(echoed, Data([93]))
          await controller.close()
          source.close()
          try await test.environment.close()
        } catch {
          await initializer.release()
          await controller.close()
          source.close()
          try? await test.environment.close()
          throw error
        }
      }
    }

    func testClientRegisteredHandlersReceiveNativeRPCAndNotify() async throws {
      try await registeredClientHandlers(useController: false)
    }

    func testControllerRegisteredHandlersReceiveNativeRPCAndNotifyAfterReplacement() async throws {
      try await registeredClientHandlers(useController: true)
    }

    func testControllerRetainsServerCloseTaskUntilItsOriginalTransportReturns() async throws {
      try await registeredClientHandlers(useController: true, holdServerClose: true)
    }

    private func registeredClientHandlers(useController: Bool, holdServerClose: Bool = false)
      async throws
    {
      let test = try NativeSessionFixture(
        profile: .x25519, mode: .bridge,
        replacement: useController, replacementMode: .bridge, services: true)
      defer { test.cleanup() }
      let corpus = try JSONDecoder().decode(
        V4JSON.self,
        from: Data(
          contentsOf:
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("testdata/transport_v4/corpus.json")))
      let environment = test.environment
      func service(_ vectorID: String, typeID: UInt64) async throws -> (
        ServiceDefinition, MethodDefinition, ServiceContract
      ) {
        let vector = try XCTUnwrap(corpus["vectors"].array?.first { $0["id"].text == vectorID })
        let canonical = try v4RuleHex(XCTUnwrap(vector["hex"].text))
        let original = try V4NamespaceDocument(
          canonical, schema: "ServiceContract", bytes: 8192,
          nodes: 1024, registry: V4NamespaceRegistry()
        ).root
        let distinct = V4Crypto.map(
          (0..<29).compactMap { id -> (UInt64, Data)? in
            if id == 1 { return (1, V4NamespaceValue.head(0, typeID)) }
            guard let field = original.optionalID(id) else { return nil }
            return (UInt64(id), Data(field.raw))
          })
        let contract = try await environment.captureServiceContract(distinct)
        let request = try MessageDefinition(
          schemaDigest: Data(repeating: 7, count: 32), revision: "1", maxMessageBytes: 1_048_576)
        let response =
          contract.shape == .notify
          ? nil
          : try MessageDefinition(
            schemaDigest: Data(repeating: 8, count: 32), revision: "1", maxMessageBytes: 1_048_576)
        let method = try MethodDefinition(
          MethodDefinitionOptions(
            typeID: contract.typeID, shape: contract.shape,
            semantics: contract.semantics, request: request, response: response,
            responseRevision: "1",
            requestMaxBytes: 1_048_576, minResponseLimitBytes: Int(contract.uint(9)),
            maxResponseBytes: Int(contract.uint(10)),
            streaming: contract.shape == .serverStreaming
              ? StreamingLimits(
                maxItemCount: UInt32(contract.uint(24)),
                maxPayloadBytes: contract.uint(25), maxDurationMS: contract.uint(26)) : nil))
        return (
          try ServiceDefinition(
            namespace: contract.namespace,
            methods: [ServiceMethod(name: "operation", method: method)]), method, contract
        )
      }
      let (unaryDefinition, unary, unaryContract) = try await service(
        "service_unary_transient", typeID: 1)
      let (notifyDefinition, notify, notifyContract) = try await service(
        "service_notify_observation", typeID: 2)
      let registry = try await test.environment.makeServiceRegistry(
        ServiceRegistryConfiguration(
          authority: unaryDefinition.namespace,
          queryBinding: ServiceContractQueryBinding(
            typeID: 12345, contractDigest: Data(repeating: 6, count: 32))))
      let caller = try ServiceServerCaller(
        subject: "server",
        identityDigest: NamespaceFixture.digest("certificate-digest", test.input.serverCertificate),
        executionAuthority: Data(repeating: 3, count: 32))
      let calls = NativeInboundServiceCalls()
      try registry.registerUnary(
        unary, in: unaryDefinition, contract: unaryContract, callers: [caller],
        requestCodec: BytesMessageCodec(definition: unary.options.request),
        responseCodec: BytesMessageCodec(definition: XCTUnwrap(unary.options.response))
      ) { _, _, value in
        await calls.recordUnary(value)
        return value
      }
      try registry.registerNotify(
        notify, in: notifyDefinition, contract: notifyContract, callers: [caller],
        codec: BytesMessageCodec(definition: notify.options.request)
      ) { _, _, value in
        await calls.recordNotify(value)
      }
      let heldTransport =
        holdServerClose ? V4ApplicationInputTransport(kind: "example.retired-close") : nil
      if let heldTransport {
        let (definition, method, contract) = try await service(
          "service_stream_transient", typeID: 3)
        try registry.registerStream(
          ServiceStreamBinding(method: method, kind: heldTransport.kind),
          in: definition, contract: contract, callers: [caller],
          requestCodec: BytesMessageCodec(definition: method.options.request),
          itemCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))
        ) { _, _, _, _ in
          XCTFail("An unselected cleanup target entered its application handler")
        }
        await heldTransport.holdFirstClose()
      }
      let source = try await test.source()
      let controller =
        useController
        ? try ConnectionController(environment: test.environment, source: source) : nil
      var sessions: [any Session] = []
      do {
        if let controller {
          await controller.start()
          sessions.append(try await controller.waitForSession())
        } else {
          sessions.append(try await test.environment.connect(source: source))
        }
        let peers = [test.peer] + (test.replacementPeer.map { [$0] } ?? [])
        for (index, peer) in peers.enumerated() {
          if index > 0 {
            let controller = try XCTUnwrap(controller)
            if let heldTransport {
              let old = try XCTUnwrap(sessions.first as? V4NativeSession)
              let channel = try XCTUnwrap(old.serviceChannel)
              let dispatcher = await channel.dynamicDispatcher
              let server = try XCTUnwrap(dispatcher as? V4ServiceServerSession)
              try server.adoptStream(
                id: UInt64.max - 1, kind: heldTransport.kind,
                source: heldTransport, facts: nil, readable: { false })
              let replacement = try await controller.replaceSession(
                retirement: .retain(for: .milliseconds(40)))
              let retirement = try XCTUnwrap(replacement.retirement)
              try await nativeManagementWait { await heldTransport.closeIsWaiting() }
              XCTAssertGreaterThan(server.physicalPending, 0)
              XCTAssertFalse(retirement.progress().cleanup.complete)
              do {
                _ = try await controller.replaceSession()
                XCTFail("Pending server close admitted another replacement")
              } catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
              let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
              XCTAssertEqual(owner.acquisitionCount, 2)
              await heldTransport.releaseClose()
              let completed = try await retirement.wait()
              XCTAssertTrue(completed.cleanup.complete)
              XCTAssertEqual(server.physicalPending, 0)
              sessions.append(try XCTUnwrap(replacement.currentSession))
            } else {
              let replacement = try await controller.replaceSession()
              sessions.append(try XCTUnwrap(replacement.currentSession))
            }
          }
          let payload = Data([UInt8(41 + index)])
          let wire = try V4ApplicationWireRegistry()
          let request = try V4ApplicationHeader(
            kind: "transient_unary_request",
            fields: [
              2: .uint(UInt64(unary.typeID)), 3: .uint(1), 5: .uint(11_000),
              6: .bytes(unaryContract.digest), 7: .uint(0), 8: .uint(try unaryContract.uint(10)),
            ], registry: wire)
          let rpc =
            try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded()
            + V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded()
          let stream = try await peer.openStream(
            kind: "flowersec.rpc.v4", payload: rpc, service: true)
          let response = try V4ApplicationHeader(
            kind: "transient_unary_response",
            fields: [
              2: .uint(UInt64(unary.typeID)), 3: .uint(1), 6: .bytes(unaryContract.digest),
            ], registry: wire)
          let expected =
            try V4RPCFragment(kind: .begin, serial: 1, replyTo: 1, payload: response.encoded())
            .encoded()
            + V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded()
          try await peer.waitInput(stream: stream, bytes: expected)
          let notification = try V4ApplicationHeader(
            kind: "observation_notify",
            fields: [
              2: .uint(UInt64(notify.typeID)), 3: .uint(1), 5: .uint(11_000),
              6: .bytes(notifyContract.digest),
            ], registry: wire
          ).encoded()
          try await peer.openStream(
            kind: "flowersec.notify.v4",
            payload:
              V4Crypto.integer(UInt64(notification.count), width: 2) + notification + payload,
            service: true)
          try await nativeManagementWait { await calls.notificationCount == index + 1 }
          XCTAssertNil(peer.error)
        }
        let expected = peers.indices.map { Data([UInt8(41 + $0)]) }
        let unaryValues = await calls.unaryValues
        let notifyValues = await calls.notifyValues
        XCTAssertEqual(unaryValues, expected)
        XCTAssertEqual(notifyValues, expected)
        if let controller { await controller.close() }
        for session in sessions { try await session.close() }
        source.close()
        registry.close()
        try await test.environment.close()
      } catch {
        await heldTransport?.releaseClose()
        if let controller { await controller.close() }
        for session in sessions { try? await session.close() }
        source.close()
        registry.close()
        try? await test.environment.close()
        throw error
      }
    }

    func testControllerRefusesSecondReplacementUntilOriginalRetiredNotificationCallbackExits()
      async throws
    {
      let test = try NativeSessionFixture(profile: .x25519, replacement: true, services: true)
      defer { test.cleanup() }
      let source = try await test.source()
      let owner = try XCTUnwrap(source.owner as? V4PoolMaterialSource)
      let controller = try ConnectionController(environment: test.environment, source: source)
      let hold = NativeRetiredNotificationHold()
      let corpus = try JSONDecoder().decode(
        V4JSON.self,
        from: Data(
          contentsOf:
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("testdata/transport_v4/corpus.json")))
      let vector = try XCTUnwrap(
        corpus["vectors"].array?.first { $0["id"].text == "service_notify_observation" })
      let hex = try XCTUnwrap(vector["hex"].text)
      var canonical = Data()
      var offset = hex.startIndex
      while offset < hex.endIndex {
        let end = hex.index(offset, offsetBy: 2)
        canonical.append(try XCTUnwrap(UInt8(hex[offset..<end], radix: 16)))
        offset = end
      }
      let contract = try ServiceContract(
        environment: test.fixture.base.environment, canonical: canonical)
      let message = try MessageDefinition(
        schemaDigest: Data(repeating: 7, count: 32), revision: "1", maxMessageBytes: 1_048_576)
      let method = try MethodDefinition(
        MethodDefinitionOptions(
          typeID: contract.typeID, shape: .notify,
          semantics: .observation, request: message, responseRevision: "1",
          requestMaxBytes: 1_048_576))
      let definition = try ServiceDefinition(
        namespace: contract.namespace, methods: [ServiceMethod(name: "changed", method: method)])
      let peer = try ServiceBindingTarget.Peer(
        subject: "server",
        identityDigest:
          NamespaceFixture.digest("certificate-digest", test.input.serverCertificate))
      let target = try ServiceBindingTarget(
        authority: "authority", tenant: "tenant", audience: "service",
        localSubject: "client", peers: [peer])
      let observer = try await controller.subscribeNotifications(
        method, in: definition, target: target,
        snapshot: ServiceContractSnapshot(contract: contract),
        codec: BytesMessageCodec(definition: message),
        observation: .currentOnly, options: NotificationSubscriptionOptions(),
        handler: { _, event in
          if case .notification(let bytes, _, _) = event { await hold.enter(bytes) }
        })
      do {
        await controller.start()
        let original = try await controller.waitForSession()
        let old = try XCTUnwrap(original as? V4NativeSession)
        let header = try V4ApplicationHeader(
          kind: "observation_notify",
          fields: [
            2: .uint(UInt64(method.typeID)),
            3: .uint(1), 5: .uint(20_000), 6: .bytes(contract.digest),
          ], registry: V4ApplicationWireRegistry()
        ).encoded()
        let frame = V4Crypto.integer(UInt64(header.count), width: 2) + header + Data([94])
        // The original peer publishes a real reserved notification stream over
        // the native encrypted channel; no synthetic callback count is installed.
        try await test.peer.openStream(kind: "flowersec.notify.v4", payload: frame, service: true)
        try await hold.waitForEntry()
        XCTAssertTrue(observer.observationStatus().callbackActive)
        let pendingCallbacks = await old.retirementPendingCallbacks()
        XCTAssertGreaterThan(pendingCallbacks, 0)
        let replacement = try await controller.replaceSession(
          retirement: .retain(for: .milliseconds(40)))
        let retirement = try XCTUnwrap(replacement.retirement)
        let deadline = retirement.progress().deadline
        let closingDeadline = ContinuousClock.now.advanced(by: .seconds(5))
        while retirement.progress().state != .closing {
          guard ContinuousClock.now < closingDeadline else { throw SessionError.timeout }
          try await ContinuousClock().sleep(for: .milliseconds(5))
        }
        XCTAssertFalse(retirement.progress().cleanup.complete)
        XCTAssertEqual(retirement.progress().deadline, deadline)
        let current = try XCTUnwrap(replacement.currentSession as? V4NativeSession)
        let currentStream = try await current.openStream(kind: "example.echo")
        let written = try await currentStream.write(Data([95]))
        let echoed = try await currentStream.read(maxBytes: 1)
        XCTAssertEqual(written, 1)
        XCTAssertEqual(echoed, Data([95]))
        do {
          _ = try await controller.replaceSession()
          XCTFail("Unretired original callback permitted a second replacement")
        } catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
        XCTAssertEqual(owner.acquisitionCount, 2)
        XCTAssertEqual(retirement.progress().deadline, deadline)
        let heldSnapshot = await controller.snapshot()
        XCTAssertEqual(heldSnapshot.generation, replacement.generation)
        XCTAssertTrue((heldSnapshot.currentSession as? V4NativeSession) === current)
        await hold.release()
        let retired = try await retirement.wait()
        XCTAssertTrue(retired.cleanup.complete)
        XCTAssertEqual(retired.deadline, deadline)
        let delivered = await hold.payloads
        XCTAssertEqual(delivered, [Data([94])])
        observer.close()
        try await currentStream.close()
        await controller.close()
        source.close()
        try await test.environment.close()
      } catch {
        await hold.release()
        observer.close()
        await controller.close()
        source.close()
        try? await test.environment.close()
        throw error
      }
    }

    func testPublicAcquireFailureProjectsTypedFactsAndCleanup() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = NativeCountingSource()
      do {
        _ = try await test.environment.connect(source: ConnectionMaterialSource(owner: source))
        XCTFail("failed Acquire published a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .connectionFailed)
        XCTAssertEqual(failure.connection.spendState, .unspent)
        XCTAssertEqual(failure.connection.admissionState, .notStarted)
        XCTAssertTrue(failure.cleanup.complete)
      }
      XCTAssertEqual(source.count, 1)
      try await test.environment.close()
    }

    func testPublicDeliveryCancellationProjectsAdmittedFactsAfterSessionCreation() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let material = try await test.material()
      let established = try await test.host.connectMaterial(
        material, requirements: ConnectionRequirements())
      let owner = NativeDelayedSessionOwner(session: established)
      let delivery = TransportEnvironment(owner: owner)
      let pending = Task { try await delivery.connectMaterial(material) }
      while !owner.waiting { await Task.yield() }
      pending.cancel()
      owner.release()
      do {
        _ = try await pending.value
        XCTFail("canceled public delivery published a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .connectionFailed)
        XCTAssertEqual(failure.connection.spendState, .spent)
        XCTAssertEqual(failure.connection.admissionState, .admitted)
        XCTAssertEqual(failure.connection.networkReady, .ready)
        XCTAssertEqual(failure.connection.applicationPublish, .failed)
        XCTAssertTrue(failure.cleanup.complete)
      }
      let termination = await established.waitTermination()
      XCTAssertEqual(termination.error, .closed)
      try await delivery.close()
      try await test.environment.close()
    }

    func testPublicDeliveryCloseProjectsAdmittedFactsAfterSessionCreation() async throws {
      let test = try NativeSessionFixture(profile: .p256)
      defer { test.cleanup() }
      let material = try await test.material()
      let established = try await test.host.connectMaterial(
        material, requirements: ConnectionRequirements())
      let owner = NativeDelayedSessionOwner(session: established)
      let delivery = TransportEnvironment(owner: owner)
      let pending = Task { try await delivery.connectMaterial(material) }
      while !owner.waiting { await Task.yield() }
      try await delivery.close()
      owner.release()
      do {
        _ = try await pending.value
        XCTFail("closed public delivery published a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .connectionFailed)
        XCTAssertEqual(failure.connection.spendState, .spent)
        XCTAssertEqual(failure.connection.admissionState, .admitted)
        XCTAssertEqual(failure.connection.networkReady, .ready)
        XCTAssertEqual(failure.connection.applicationPublish, .failed)
        XCTAssertTrue(failure.cleanup.complete)
      }
      let termination = await established.waitTermination()
      XCTAssertEqual(termination.error, .closed)
      try await test.environment.close()
    }

    func testMaterialCleanupRetainsEachOriginalLiveControlCallTail() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let material = try await test.material()
      let original = try XCTUnwrap(material.owner as? V4DirectPoolMaterial)
      let environment = test.fixture.base.environment
      try original.claim(in: environment)
      let storage = try environment.serviceOperationStorage(requestBytes: 1, responseBytes: 1)
      var observations: [(V4ControlHTTPCallCleanup, Flowersec.V4ResourceReference)] = []
      for phase in [
        V4DirectPoolMaterial.ControlCall.relayReady, .registeredPrepare, .relayPrepare, .authorize,
        .relayActivate,
      ] {
        let observation = try original.controlCall(phase)
        let tail = try storage.executionTail()
        observation.observeDriver(tail)
        observations.append((observation, tail))
        let body = try storage.executionTail()
        observation.observeResponse(body)
        observations.append((observation, body))
      }
      original.finish(success: false)
      XCTAssertFalse(material.cleanupStatus().complete)
      XCTAssertGreaterThanOrEqual(material.cleanupStatus().pendingCallbacks, 10)
      let bounded = try await material.waitCleanup()
      XCTAssertTrue(bounded.cleanupIncomplete)
      XCTAssertGreaterThanOrEqual(bounded.pendingCallbacks, 10)
      for (observation, tail) in observations {
        tail.release()
        observation.released()
      }
      _ = await original.waitPhysicalCleanup()
      XCTAssertTrue(material.cleanupStatus().complete)
      storage.release()
      try await test.environment.close()
    }

    func testPublicRequirementsRefuseBeforeSourceAcquire() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = NativeCountingSource()
      do {
        _ = try await test.environment.connect(
          source: ConnectionMaterialSource(owner: source),
          requirements: ConnectionRequirements(independentReliableReadProgress: true))
        XCTFail("WSS claimed independent stream read progress")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.code, .unsupported)
        XCTAssertEqual(failure.connection.spendState, .unspent)
        XCTAssertEqual(failure.connection.admissionState, .notStarted)
        XCTAssertTrue(failure.cleanup.complete)
      }
      XCTAssertEqual(source.count, 0)
      let diagnostics = await test.environment.diagnosticCounters()
      XCTAssertEqual(diagnostics[.connectionAttempts], 1)
      XCTAssertEqual(diagnostics[.connectionFailures], 1)
      try await test.environment.close()
    }
    func testClosedPublicConnectProjectsWithoutAcquiringOrConsumingMaterial() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = NativeCountingSource()
      let material = try await test.material()
      // This independent facade has no authority over the still-owned input.
      let closed = TransportEnvironment()
      try await closed.close()
      do {
        _ = try await closed.connect(source: ConnectionMaterialSource(owner: source))
        XCTFail("closed source connect published a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.retryDisposition, .terminal)
        XCTAssertEqual(failure.connection, .notStarted)
        XCTAssertTrue(failure.cleanup.complete)
      }
      do {
        _ = try await closed.connectMaterial(material)
        XCTFail("closed material connect published a Session")
      } catch {
        let failure = try XCTUnwrap(error as? ConnectError)
        XCTAssertEqual(failure.retryDisposition, .terminal)
        XCTAssertEqual(failure.connection, .notStarted)
        XCTAssertTrue(failure.cleanup.complete)
      }
      XCTAssertEqual(source.count, 0)
      XCTAssertFalse(material.cleanupStatus().complete)
      let session = try await test.environment.connectMaterial(material)
      try await session.close()
      try await test.environment.close()
    }
    func testEnvironmentCloseRetainsNoncooperativeSourceUntilActualCallbackExit() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = NativeHeldSource()
      let material = try await test.material()
      let baseline = test.fixture.base.root.snapshot().executionTails
      XCTAssertGreaterThan(baseline, 0)
      let connecting = Task {
        try await test.environment.connect(source: ConnectionMaterialSource(owner: source))
      }
      while !source.started { try await ContinuousClock().sleep(for: .milliseconds(5)) }
      XCTAssertEqual(test.fixture.base.root.snapshot().executionTails, baseline + 1)
      try await test.environment.close()
      let incomplete = await test.environment.cleanupStatus()
      XCTAssertTrue(incomplete.cleanupIncomplete)
      XCTAssertGreaterThanOrEqual(incomplete.pendingCallbacks, 1)
      source.complete(material)
      do {
        _ = try await connecting.value
        XCTFail("closed TransportEnvironment published source result")
      } catch {}
      await test.store.waitPhysicalCleanup()
      XCTAssertEqual(test.fixture.base.root.snapshot().executionTails, 0)
      XCTAssertTrue(material.cleanupStatus().complete)
      XCTAssertFalse(test.peer.established)
    }
    func testRevocationClosesNativePumpsAndFencesBufferedApplicationDelivery() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let stream = try await session.openStream(kind: "example.echo")
      let count = try await stream.write(Data([1]))
      XCTAssertEqual(count, 1)
      let state = test.fixture.state(leases: [
        NamespaceFixture.map([
          0: .bytes(Data(repeating: 5, count: 16)), 1: .bytes(Data(repeating: 30, count: 16)),
          2: .bytes(NamespaceFixture.digest("artifact-digest", test.input.artifact)),
          3: .uint(9), 4: .uint(1800),
        ])
      ])
      try await test.environment.refreshNamespace(
        authority: "authority",
        head: test.fixture.base.head(state: state, sequence: 2), state: state)
      do {
        _ = try await stream.read(maxBytes: 16)
        XCTFail("revoked bytes delivered")
      } catch {}
      try await session.close()
      try await test.environment.close()
    }
  }
  private actor NativeExplicitRecoveryInitializer {
    private(set) var calls = 0
    func initialize(_ candidate: any Session) async throws {
      calls += 1
      if calls == 1 { throw SessionError.operationFailed }
      try Task.checkCancellation()
    }
  }
  private actor NativeReplacementInitializer {
    private var calls = 0
    private var waiter: CheckedContinuation<Void, Never>?
    private let failOnRelease: Bool
    private(set) var replacementStarted = false
    private(set) var replacementCandidate: (any Session)?
    init(failOnRelease: Bool = false) { self.failOnRelease = failOnRelease }
    func initialize(_ candidate: any Session) async throws {
      calls += 1
      guard calls == 2 else { return }
      replacementCandidate = candidate
      replacementStarted = true
      await withCheckedContinuation { waiter = $0 }
      try Task.checkCancellation()
      if failOnRelease { throw SessionError.operationFailed }
    }
    func waitForReplacement() async throws {
      let deadline = ContinuousClock.now.advanced(by: .seconds(5))
      while !replacementStarted {
        guard ContinuousClock.now < deadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    func release() {
      waiter?.resume()
      waiter = nil
    }
  }
  private actor NativeRetiredNotificationHold {
    private var continuation: CheckedContinuation<Void, Never>?
    private var released = false
    private(set) var payloads: [Data] = []
    func enter(_ bytes: Data) async {
      payloads.append(bytes)
      if !released { await withCheckedContinuation { continuation = $0 } }
    }
    func waitForEntry() async throws {
      let deadline = ContinuousClock.now.advanced(by: .seconds(5))
      while payloads.isEmpty {
        guard ContinuousClock.now < deadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    func release() {
      released = true
      continuation?.resume()
      continuation = nil
    }
  }
  private actor NativeHeldCandidateInitializer {
    private(set) var started = false
    private var waiter: CheckedContinuation<Void, Never>?
    func initialize(_ candidate: any Session) async throws {
      started = true
      await withCheckedContinuation { waiter = $0 }
      throw SessionError.operationFailed
    }
    func releaseFailure() {
      waiter?.resume()
      waiter = nil
    }
  }

  private final class NativeDelayedSessionOwner: TransportEnvironmentOwner, @unchecked Sendable {
    private let lock = NSLock()
    private let session: any Session
    private var waiter: CheckedContinuation<any Session, Error>?
    init(session: any Session) { self.session = session }
    var waiting: Bool { lock.withLock { waiter != nil } }
    func connect(source: ConnectionMaterialSource, requirements: ConnectionRequirements)
      async throws -> any Session
    {
      try await next()
    }
    func connectMaterial(_ material: ConnectionMaterial, requirements: ConnectionRequirements)
      async throws -> any Session
    {
      try await next()
    }
    private func next() async throws -> any Session {
      try await withCheckedThrowingContinuation { continuation in
        lock.withLock { waiter = continuation }
      }
    }
    func release() {
      let continuation = lock.withLock {
        defer { waiter = nil }
        return waiter
      }
      continuation?.resume(returning: session)
    }
    func close() async throws {}
    func cleanupStatus() -> CleanupStatus { CleanupStatus(complete: true) }
  }

  private final class NativeCountingSource: ConnectionMaterialSourceOwner, @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    var count: Int { lock.withLock { calls } }
    func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
      lock.withLock { calls += 1 }
      throw SessionError.operationFailed
    }
    // The borrowed source can remain open or retain unrelated provider work;
    // neither belongs to the failed connection's already-returned Acquire.
    func cleanupStatus() -> CleanupStatus { CleanupStatus(complete: false, pendingCallbacks: 3) }
  }
  private final class NativeHeldSource: ConnectionMaterialSourceOwner, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ConnectionMaterial, Never>?
    var started: Bool { lock.withLock { continuation != nil } }
    func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
      await withCheckedContinuation { next in lock.withLock { continuation = next } }
    }
    func complete(_ material: ConnectionMaterial) {
      let next = lock.withLock {
        defer { continuation = nil }
        return continuation
      }
      next?.resume(returning: material)
    }
  }

  private final class NativeLiveAuthorityState: @unchecked Sendable {
    let test: NativeSessionFixture
    let profile: V4CryptoProfile
    init(test: NativeSessionFixture, profile: V4CryptoProfile) {
      self.test = test
      self.profile = profile
    }
    func issue(_ path: String, body: Data) throws -> Data {
      try test.fixture.base.environment.gate.withLock {
        guard path == "/issue/direct" else { throw TransportControlError.responseInvalid }
        var reader = V4PoolWireCursor(body, maximum: 1024)
        try reader.array(1)
        guard try reader.bytes(maximum: 32).count == 32 else {
          throw TransportControlError.responseInvalid
        }
        try reader.end()
        return test.input.artifact
      }
    }
    func authorize(_ path: String, body: Data) throws -> Data {
      try test.fixture.base.environment.gate.withLock {
        guard path == "/live/authorize" else { throw TransportControlError.responseInvalid }
        var reader = V4PoolWireCursor(body, maximum: 1024)
        try reader.array(13)
        guard try reader.text(maximum: 64) == "live-authorization-1",
          try reader.text(maximum: 128) == "tenant",
          try reader.text(maximum: 128) == "service",
          try reader.text(maximum: 128) == profile.rawValue,
          try reader.bytes(maximum: 16) == Data(repeating: 5, count: 16),
          try reader.bytes(maximum: 16) == Data(repeating: 30, count: 16)
        else { throw TransportControlError.responseInvalid }
        let attempt = try reader.bytes(maximum: 16)
        let registry = try V4NamespaceRegistry()
        let artifact = try V4NamespaceDocument(
          test.input.artifact, schema: "Artifact", bytes: 65_536, nodes: 16_384, registry: registry
        ).root
        guard attempt.count == 16, attempt.contains(where: { $0 != 0 }),
          try reader.bytes(maximum: 32) == artifact.digest("artifact_digest"),
          try reader.bytes(maximum: 32) == artifact.b("client_identity_digest"),
          try reader.bytes(maximum: 32) == artifact.b("server_identity_digest")
        else { throw TransportControlError.responseInvalid }
        try reader.array(3)
        guard try reader.uint() == 0,
          try reader.bytes(maximum: 16) == Data(repeating: 40, count: 16),
          try reader.bytes(maximum: 32) == test.fixture.routeDigest(0), try reader.uint() == 1500,
          try reader.uint() == 1
        else { throw TransportControlError.responseInvalid }
        try reader.end()
        // TxB binds the exact previously issued Artifact and certificate bytes.
        // Re-signing equal certificate fields need not reproduce their signatures.
        let activation = try NamespaceFixture.signed(
          [
            0: .uint(1), 1: .text("spend"), 2: .text("activate"), 3: .text("tenant"),
            4: .bytes(Data(repeating: 5, count: 16)), 5: .bytes(Data(repeating: 30, count: 16)),
            6: .bytes(try artifact.digest("artifact_digest")),
            7: .bytes(Data(repeating: 40, count: 16)), 8: .bytes(test.fixture.routeDigest(0)),
            9: .bytes(attempt), 10: .bytes(try artifact.b("client_identity_digest")),
            11: .bytes(try artifact.b("server_identity_digest")), 12: .text("service"),
            13: .uint(900), 14: .uint(1500), 15: .uint(1800),
          ], signature: 16, label: "activation_authorization/signature", seed: 13)
        let input = V4CredentialInput(
          artifact: test.input.artifact,
          clientCertificate: test.input.clientCertificate,
          serverCertificate: test.input.serverCertificate,
          activation: activation, source: .liveAuthority, candidateIndex: 0)
        let serverAdmission = try test.fixture.verify(input)
        let plan = try serverAdmission.directPoolPlan(
          in: test.fixture.base.environment, identity: test.client)
        test.peer.configure(plan: plan, admission: serverAdmission, identity: test.server)
        return input.activation
      }
    }
  }

  private actor NativeInboundServiceCalls {
    var unaryValues: [Data] = []
    var notifyValues: [Data] = []
    var notificationCount: Int { notifyValues.count }
    func recordUnary(_ value: Data) { unaryValues.append(value) }
    func recordNotify(_ value: Data) { notifyValues.append(value) }
  }

  private final class NativeSessionFixture {
    let fixture: CredentialFixture
    let client: V4LocalIdentity
    let server: V4LocalIdentity
    let input: V4CredentialInput
    let peer: NativeSessionPeer
    let listener: V4WebSocketTestServer
    let replacementListener: V4WebSocketTestServer?
    let replacementPeer: NativeSessionPeer?
    let replacementInput: V4CredentialInput?
    let directory: URL
    let backing: V4PoolStoreBacking
    let store: V4SQLitePoolStore
    let environment: TransportEnvironment
    let host: V4ClientEnvironment
    init(
      profile: V4CryptoProfile, mode: NativeSessionPeer.Mode = .echo, pinned: Bool = false,
      replacement: Bool = false, replacementMode: NativeSessionPeer.Mode = .echo,
      services: Bool = false, loopbackHTTP: Bool = false
    )
      throws
    {
      fixture = try CredentialFixture(profile: profile.rawValue, nativeResources: true)
      client = try fixture.base.environment.generateIdentity(profile: profile)
      server = try fixture.base.environment.generateIdentity(profile: profile)
      peer = NativeSessionPeer(mode: mode)
      let peer = peer
      listener = try V4WebSocketTestServer(
        subprotocol: loopbackHTTP ? "flowersec.local.v4" : "flowersec.direct.v4",
        loopbackHTTP: loopbackHTTP,
        certificateName: pinned ? "v4_pin_cert" : "self_signed_cert",
        keyName: pinned ? "v4_pin_key" : "self_signed_key",
        handler: { channel in
          peer.attach(channel)
          return peer
        })
      if loopbackHTTP {
        fixture.candidateCount = 1
        fixture.candidateLeg = NamespaceFixture.map([
          0: .uint(1), 1: .bytes(Data(repeating: 50, count: 16)), 2: .uint(1),
          3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text("127.0.0.1"),
          7: .uint(UInt64(listener.port)), 8: .text("/flowersec/v4/local"),
          10: .text("flowersec.local.v4"), 13: .text("http://127.0.0.1:\(listener.port)"),
        ])
      } else {
        fixture.candidateLeg = NamespaceFixture.map([
          0: .uint(0), 1: .bytes(Data(repeating: 50, count: 16)), 2: .uint(1),
          3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text("localhost"),
          7: .uint(UInt64(listener.port)),
          8: .text("/flowersec/v4/direct"), 9: .text("http/1.1"), 10: .text("flowersec.direct.v4"),
          11: pinned
            ? try V4PinTestFixture.policy(certificateName: "v4_pin_cert")
            : NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
        ])
      }
      func certificate(_ identity: V4LocalIdentity) -> [UInt64: V4CBORValue] {
        [
          3: NamespaceFixture.map([
            0: .uint(profile == .x25519 ? 0 : 1), 1: .bytes(identity.dhPublicKey),
          ]),
          4: .bytes(identity.identityPublicKey),
        ]
      }
      let sessionContract: [UInt64: V4CBORValue] =
        services
        ? [
          13: NamespaceFixture.map([
            0: .uint(1_048_576), 1: .uint(138), 2: .uint(8 << 20), 3: .uint(0),
            4: NamespaceFixture.map([0: .uint(1), 1: .uint(1000), 2: .uint(1000)]),
            5: .uint(1), 6: .uint(1),
          ])
        ] : [:]
      input = try fixture.input(
        source: .preauthorizedPool, indices: [0],
        client: certificate(client), server: certificate(server), artifact: sessionContract)
      let plan = try fixture.verify(input).directPoolPlan(
        in: fixture.base.environment, identity: client)
      let serverAdmission = try fixture.verify(input)
      peer.configure(plan: plan, admission: serverAdmission, identity: server)
      if replacement {
        let replacementPeer = NativeSessionPeer(mode: replacementMode)
        let replacementListener = try V4WebSocketTestServer(handler: { channel in
          replacementPeer.attach(channel)
          return replacementPeer
        })
        self.replacementPeer = replacementPeer
        self.replacementListener = replacementListener
        let originalLeg = fixture.candidateLeg
        fixture.candidateLeg = NamespaceFixture.map([
          0: .uint(0), 1: .bytes(Data(repeating: 60, count: 16)), 2: .uint(1),
          3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text("localhost"),
          7: .uint(UInt64(replacementListener.port)),
          8: .text("/flowersec/v4/direct"), 9: .text("http/1.1"), 10: .text("flowersec.direct.v4"),
          11: NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
        ])
        let replacementInput = try fixture.input(
          source: .preauthorizedPool, indices: [0],
          client: certificate(client), server: certificate(server),
          artifact: sessionContract.merging([
            6: .bytes(Data(repeating: 61, count: 16)), 7: .bytes(Data(repeating: 62, count: 32)),
          ]) { _, new in new },
          activation: [
            5: .bytes(Data(repeating: 61, count: 16)), 9: .bytes(Data(repeating: 63, count: 16)),
          ])
        self.replacementInput = replacementInput
        let replacementAdmission = try fixture.verify(replacementInput)
        let replacementPlan = try fixture.verify(replacementInput).directPoolPlan(
          in: fixture.base.environment, identity: client)
        replacementPeer.configure(
          plan: replacementPlan, admission: replacementAdmission, identity: server)
        fixture.candidateLeg = originalLeg
      } else {
        replacementPeer = nil
        replacementListener = nil
        replacementInput = nil
      }
      let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      directory = root.appendingPathComponent(
        ".flowersec/swift-native-session-\(UUID().uuidString)")
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      backing = try V4PoolStoreBacking(
        environment: fixture.base.environment, directory: directory,
        identity: V4PoolStoreIdentity(
          storeID: Data(repeating: 7, count: 16), generation: 1,
          tenant: "tenant", issuer: Data(repeating: 5, count: 16), spendAuthority: "spend",
          winnerAuthority: "winner"),
        maximumBytes: 1 << 20, maximumRows: 16, continuity: { _ in })
      store = try backing.open(create: true)
      let ca = try Data(
        contentsOf: Bundle.module.url(
          forResource: "self_signed_ca", withExtension: "pem",
          subdirectory: "Fixtures")!)
      var endpoints = [
        TransportEndpoint(
          hostname: loopbackHTTP ? "127.0.0.1" : "localhost", port: listener.port,
          numericAddress: "127.0.0.1")
      ]
      if let replacementListener {
        endpoints.append(
          TransportEndpoint(
            hostname: "localhost", port: replacementListener.port, numericAddress: "127.0.0.1"))
      }
      host = try V4ClientEnvironment(
        foundation: fixture.base.environment, namespaces: [fixture.base.owner!],
        credentials: fixture.configuration(),
        endpoints: endpoints,
        roots: pinned ? [] : [ca], backing: backing, store: store,
        provider: fixture.base.environment.clientProviderStorage(bytes: 1 << 20))
      environment = TransportEnvironment(owner: host)
    }
    func credential() -> TransportPoolCredential {
      TransportPoolCredential(
        artifact: input.artifact, clientCertificate: input.clientCertificate,
        serverCertificate: input.serverCertificate, activationAuthorization: input.activation)
    }
    func source() async throws -> ConnectionMaterialSource {
      var credentials = [credential()]
      if let replacementInput {
        credentials.append(TransportPoolCredential(input: replacementInput))
      }
      return try await environment.makePreauthorizedPoolSource(
        credentials, identity: TransportApplicationIdentity(client))
    }
    func material() async throws -> ConnectionMaterial {
      try await environment.preparePoolMaterial(
        TransportPoolCredential(
          artifact: input.artifact,
          clientCertificate: input.clientCertificate, serverCertificate: input.serverCertificate,
          activationAuthorization: input.activation),
        identity: TransportApplicationIdentity(client))
    }
    func cleanup() {
      fixture.base.environment.beginClose()
      listener.stop()
      replacementListener?.stop()
      try? FileManager.default.removeItem(at: directory)
      try? backing.retireRemovedFiles()
    }
  }

  private final class NativeSessionPeer: ChannelInboundHandler, V4HandshakeWriter,
    V4RecordPublisher,
    @unchecked Sendable
  {
    enum Mode { case echo, bridge, rejection, forgedRejection, holdAdmission }
    typealias InboundIn = WebSocketFrame
    typealias OutboundOut = WebSocketFrame
    private let lock = NSRecursiveLock()
    private let mode: Mode
    private var channel: (any Channel)?
    private var plan: V4DirectPoolPlan!
    private var admission: V4CredentialAdmission!
    private var identity: V4LocalIdentity!
    private var handshake: V4Handshake?
    private var core: V4ReliableSession?
    private var clientHello = Data()
    private var serverHello = Data()
    private var context = Data()
    private var fsb = Data()
    private var step = 0
    private var streams: [V4StreamHandle] = []
    private var terminal: Set<UInt64> = []
    private var localAwaiting: Set<UInt64> = []
    private var initialPayloads: [UInt64: Data] = [:]
    private var bridgeInputs: [UInt64: Data] = [:]
    private var bridgeEOFs: Set<UInt64> = []
    private var holdingBridgeInput = false
    private var holdingProtocol = false
    private var heldProtocol: [Data] = []
    private var failure: String?
    private var noiseCount = 0
    private var metadataInputs: [Data] = []
    private var holdingPongs = false
    private var pongs: [Data] = []
    var error: String? { lock.withLock { failure } }
    var noiseInputs: Int { lock.withLock { noiseCount } }
    var receivedMetadata: [Data] { lock.withLock { metadataInputs } }
    var established: Bool { lock.withLock { core != nil } }
    var epoch: UInt32? { lock.withLock { try? core?.epoch() } }
    init(mode: Mode) { self.mode = mode }
    var bridgeWindow: Int { lock.withLock { Int(plan.window) } }
    func holdBridgeInput() { lock.withLock { holdingBridgeInput = true } }
    var heldProtocolInputs: Int { lock.withLock { heldProtocol.count } }
    func holdProtocolInput() { lock.withLock { holdingProtocol = true } }
    func releaseProtocolInput() async throws {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      try await channel.eventLoop.submit { [self] in
        try lock.withLock {
          holdingProtocol = false
          let original = heldProtocol
          heldProtocol.removeAll()
          for wire in original { try input(wire) }
          try process()
        }
      }.get()
    }
    func holdPongs() { lock.withLock { holdingPongs = true } }
    func disconnect() async throws {
      if let channel = lock.withLock({ channel }) { try await channel.close().get() }
    }
    func waitClosed() async throws {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      try await channel.closeFuture.get()
    }
    func waitPongs(_ count: Int) async throws {
      let start = ContinuousClock.now
      while lock.withLock({ pongs.count < count }) {
        guard start.duration(to: .now) < .seconds(5) else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    func releasePongs() async throws {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      try await channel.eventLoop.submit { [self] in
        try lock.withLock {
          holdingPongs = false
          for pong in pongs { try raw(pong) }
          pongs.removeAll()
        }
      }.get()
    }
    func resetStreams() async throws {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      try await channel.eventLoop.submit { [self] in
        try lock.withLock {
          for stream in streams {
            try core!.reset(stream)
            terminal.insert(stream.number)
          }
          try process()
        }
      }.get()
    }
    func sendBridgePayload(toStream index: Int, bytes: Data, finish: Bool = false) async throws {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      try await channel.eventLoop.submit { [self] in
        try lock.withLock {
          guard mode == .bridge, streams.indices.contains(index), let core else {
            throw SessionError.operationFailed
          }
          let stream = streams[index]
          if !bytes.isEmpty { try core.write(stream, data: bytes, to: self) }
          if finish { try core.write(stream, data: Data(), fin: true, to: self) }
          try process()
        }
      }.get()
    }
    func waitBridgeInput(stream index: Int, bytes: Data, eof: Bool = false) async throws {
      let deadline = ContinuousClock.now.advanced(by: .seconds(5))
      while !lock.withLock({
        streams.indices.contains(index)
          && bridgeInputs[streams[index].number, default: Data()] == bytes
          && (!eof || bridgeEOFs.contains(streams[index].number))
      }) {
        guard ContinuousClock.now < deadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    func attach(_ channel: any Channel) { lock.withLock { self.channel = channel } }
    func configure(
      plan: V4DirectPoolPlan, admission: V4CredentialAdmission, identity: V4LocalIdentity
    ) {
      lock.withLock {
        self.plan = plan
        self.admission = admission
        self.identity = identity
      }
    }
    func waitAdmission() async throws {
      let start = ContinuousClock.now
      while lock.withLock({ step < 2 }) {
        guard start.duration(to: .now) < .seconds(5) else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      let frame = unwrapInboundIn(data)
      do { try lock.withLock { try input(Data(frame.unmaskedData.readableBytesView)) } } catch {
        lock.withLock { failure = "\(error)" }
        context.close(promise: nil)
      }
    }
    private func decode(_ bytes: Data, _ schema: String) throws -> V4NamespaceValue {
      try V4NamespaceDocument(
        bytes, schema: schema, bytes: 65536, nodes: 4096,
        registry: V4NamespaceRegistry(),
        context: ["activation_source_profile": admission.source.rawValue]
      ).root
    }
    private func input(_ wire: Data) throws {
      if step == 4 && holdingProtocol {
        heldProtocol.append(wire)
        return
      }
      guard wire.count > 8 else { throw V4CryptoFailure.authentication }
      let bytes = Data(wire.dropFirst(8))
      switch step {
      case 0:
        guard wire[4] == 1 else { throw V4CryptoFailure.phase }
        clientHello = bytes
        let hello = try decode(bytes, "ClientHello")
        var fields = try (0...7).map { (UInt64($0), Data(try hello.fieldID($0).raw)) }
        fields += [
          (8, V4Crypto.bytes(try V4Crypto.random(32))), (9, V4NamespaceValue.head(0, 0)),
          (10, V4NamespaceValue.head(0, 0)), (11, V4NamespaceValue.head(0, 1)),
          (12, V4Crypto.bytes(Data())),
        ]
        serverHello = V4Crypto.map(fields)
        context = try V4DirectEstablishment.context(
          plan, clientHello: clientHello, serverHello: serverHello)
        try send(1, serverHello)
        step = 1
      case 1:
        guard wire[4] == 2 else { throw V4CryptoFailure.phase }
        fsb = bytes
        step = 2
        if mode == .holdAdmission { return }
        let f = try decode(fsb, "FSB4")
        try f.verify("fsb_signature", publicKey: plan.client.b("ed25519_public_key"))
        let c = try decode(context, "TransportContext")
        var fields: [(UInt64, Data)] = [
          (0, V4NamespaceValue.head(0, (mode == .echo || mode == .bridge) ? 0 : 1)),
          (1, V4NamespaceValue.head(0, (mode == .echo || mode == .bridge) ? 0 : 1)),
          (2, V4NamespaceValue.head(0, (mode == .echo || mode == .bridge) ? 1 : 0)),
          (3, V4Crypto.bytes(try V4Crypto.random(32))),
          (4, V4Crypto.bytes(try f.digest("admission_binding"))),
          (5, V4Crypto.bytes(plan.credential.routeDigest)),
          (6, V4Crypto.bytes(try c.b("hello_transcript_digest"))), (7, V4NamespaceValue.head(0, 0)),
          (8, V4NamespaceValue.head(0, 1)),
          (9, V4Crypto.bytes(try c.digest("transport_context_digest"))),
          (10, V4Crypto.bytes(plan.credential.certificateDigests[0])),
          (11, V4Crypto.bytes(plan.credential.certificateDigests[1])),
          (12, V4Crypto.bytes(Data(plan.server.raw))),
        ]
        if mode != .echo && mode != .bridge {
          fields = fields.map {
            [UInt64(3), 4, 9, 10, 11].contains($0.0)
              ? ($0.0, V4Crypto.bytes(Data(repeating: 0, count: 32))) : $0
          }
        }
        fields.append(
          (
            13,
            V4Crypto.bytes(
              try identity.signHandshake(
                V4Crypto.domain("fsa4/signature", [V4Crypto.map(fields)]), in: plan.environment))
          ))
        var fsa = V4Crypto.map(fields)
        if mode == .forgedRejection { fsa[fsa.count - 1] ^= 1 }
        try send(3, fsa)
        if mode != .echo && mode != .bridge { return }
        handshake = try plan.environment.handshake(
          admission: admission, role: .server, identity: identity,
          input: V4HandshakeInput(
            artifact: Data(plan.artifact.raw), clientHello: clientHello,
            serverHello: serverHello, transportContext: context, fsb: fsb, fsa: fsa))
      case 2:
        guard wire[4] == 4, let handshake else { throw V4CryptoFailure.phase }
        noiseCount += 1
        try handshake.receiveNoise(bytes)
        try handshake.submitNoise(to: self)
        step = 3
      case 3:
        guard wire[4] == 5, let handshake else { throw V4CryptoFailure.phase }
        try handshake.receiveReady(bytes)
        try handshake.submitReady(to: self)
        core = try handshake.establish().makeSession()
        self.handshake = nil
        step = 4
      default:
        try core!.receive(wire)
        try process()
      }
    }
    private func process() throws {
      guard let core else { return }
      while let remote = try core.pendingOpen() {
        let pending = try core.pendingMetadata(remote)
        metadataInputs.append(try pending.metadata.withBytes { $0 })
        pending.metadata.close()
        try core.decideOpen(remote, decision: .accept(receiveWindow: plan.window), to: self)
        streams.append(remote)
      }
      for _ in 0..<32 { if try !core.poll(to: self) { break } }
      for stream in streams where !terminal.contains(stream.number) && !holdingBridgeInput {
        if localAwaiting.contains(stream.number), try core.phase(stream) == .accepted {
          try core.write(
            stream, data: initialPayloads.removeValue(forKey: stream.number) ?? Data([9]), to: self)
          localAwaiting.remove(stream.number)
        }
        switch try core.read(stream, maximum: 64) {
        case .data(let data):
          defer { data.close() }
          if mode == .bridge {
            bridgeInputs[stream.number, default: Data()].append(try data.withBytes { $0 })
          } else {
            try core.write(stream, data: data.withBytes { $0 }, to: self)
          }
          try core.replenish(stream, window: plan.window)
        case .eof:
          if mode == .bridge {
            bridgeEOFs.insert(stream.number)
          } else {
            try core.write(stream, data: Data(), fin: true, to: self)
          }
          terminal.insert(stream.number)
        case .aborted: terminal.insert(stream.number)
        case .pending: break
        }
      }
      for _ in 0..<32 { if try !core.poll(to: self) { break } }
    }
    func waitInput(stream: UInt64, bytes: Data) async throws {
      let deadline = ContinuousClock.now.advanced(by: .seconds(5))
      while !lock.withLock({ bridgeInputs[stream] == bytes }) {
        guard ContinuousClock.now < deadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(5))
      }
    }
    @discardableResult
    func openStream(
      metadata: Data = Data(), kind: String = "example.from-server", payload: Data = Data([9]),
      service: Bool = false
    ) async throws -> UInt64 {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      return try await channel.eventLoop.submit { [self] in
        try lock.withLock {
          let value = try core!.open(
            kind: kind, metadata: metadata, receiveWindow: service ? 16_384 : plan.window, to: self,
            service: service)
          streams.append(value)
          localAwaiting.insert(value.number)
          initialPayloads[value.number] = payload
          return value.number
        }
      }.get()
    }
    func publish(_ buffer: V4CryptoBuffer) throws {
      let bytes = try buffer.withBytes { $0 }
      if bytes[4] == 15, holdingPongs {
        pongs.append(bytes)
        return
      }
      try raw(bytes)
    }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws {
      try send(flight == .noise ? 4 : 5, buffer.withBytes { $0 })
    }
    private func send(_ type: UInt8, _ bytes: Data) throws {
      try raw(V4Crypto.integer(UInt64(bytes.count), width: 4) + Data([type, 0, 0, 0]) + bytes)
    }
    private func raw(_ bytes: Data) throws {
      guard let channel else { throw SessionError.closed }
      var buffer = channel.allocator.buffer(capacity: bytes.count)
      buffer.writeBytes(bytes)
      channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .binary, data: buffer), promise: nil)
    }
  }
#endif
