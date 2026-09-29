#if os(macOS) || os(iOS)
  import Crypto
  import Foundation
  import NIOCore
  import NIOWebSocket
  import XCTest

  @testable import Flowersec

  @MainActor
  final class TransportV4NativeSessionTests: XCTestCase {
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
      let namespace = TransportV4TrustNamespace(
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
        return TransportV4NamespaceSnapshot(response: V4Crypto.map(fields), state: state)
      }
      var configuration = TransportV4ClientConfiguration(
        tenant: "tenant", audience: "service",
        clientSubject: "client", serverSubject: "server", namespaces: [namespace],
        endpoints: [
          TransportV4Endpoint(hostname: "localhost", port: 443, numericAddress: "127.0.0.1")
        ],
        history: TransportV4PoolHistory(
          directory: directory, storeID: Data(repeating: 2, count: 16),
          generation: 1, artifactIssuerKeyID: Data(repeating: 5, count: 16),
          spendAuthority: "spend",
          winnerAuthority: "winner", create: true, checkContinuity: {}),
        trustedTime: {
          let elapsed = timeStart.duration(to: .now).components
          let milliseconds = UInt64(
            elapsed.seconds * 1000 + elapsed.attoseconds / 1_000_000_000_000_000)
          return TransportV4TrustedTime(
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
      var identity: TransportV4ApplicationIdentity? =
        try await environment.importApplicationIdentity(
          profile: .x25519,
          signingSeed: Data(repeating: 21, count: 32),
          noiseStaticPrivateKey: Data(repeating: 31, count: 32))
      let input = try fixture.input(source: .preauthorizedPool, indices: [0])
      var material: ConnectionMaterial? = try await environment.preparePoolMaterial(
        TransportV4PoolCredential(
          artifact: input.artifact, clientCertificate: input.clientCertificate,
          serverCertificate: input.serverCertificate, activationAuthorization: input.activation),
        identity: identity!)
      material?.close()
      material = nil
      var generated: TransportV4ApplicationIdentity? =
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
        } catch let error as TransportV4ConnectError {
          XCTAssertEqual(error, forged ? .securityFailed : .admissionRejected(code: 1))
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
    func testPublicSessionUsesSignedLeafPinAndPreservesBothDirectionsMetadata() async throws {
      let test = try NativeSessionFixture(profile: .p256, pinned: true)
      defer { test.cleanup() }
      let session = try await test.environment.connectMaterial(test.material())
      let metadata = try StreamMetadata(
        namespace: "acme/chat", version: .max,
        values: ["z": Data(), "aa": Data([0, 255]), "é": Data([1, 2, 3])])
      let stream = try await session.openStream(kind: "example.echo", metadata: metadata)
      XCTAssertEqual(test.peer.receivedMetadata, [try metadata.encodedV4()])
      let count = try await stream.write(Data([7, 8]))
      XCTAssertEqual(count, 2)
      let echoed = try await stream.read(maxBytes: 2)
      XCTAssertEqual(echoed, Data([7, 8]))
      let accepting = Task { try await session.acceptStream() }
      try await test.peer.openStream(metadata: metadata.encodedV4())
      let incoming = try await accepting.value
      XCTAssertEqual(incoming.metadata, metadata)
      XCTAssertEqual(try incoming.metadata.encodedV4(), try metadata.encodedV4())
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
      } catch let error as TransportV4LivenessError {
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
      try await test.environment.close()
      XCTAssertNil(test.peer.error)
    }
    func testCancelDuringNativeAdmissionJoinsOriginalSocketAndEndsMaterial() async throws {
      let test = try NativeSessionFixture(profile: .p256, mode: .holdAdmission)
      defer { test.cleanup() }
      let material = try await test.material()
      let connecting = Task { try await test.environment.connectMaterial(material) }
      try await test.peer.waitAdmission()
      connecting.cancel()
      do {
        _ = try await connecting.value
        XCTFail("canceled connection established")
      } catch {}
      XCTAssertTrue(material.cleanupStatus().complete)
      XCTAssertFalse(test.peer.established)
      XCTAssertEqual(test.fixture.base.root.snapshot().executionTails, 0)
      try await test.environment.close()
    }
    func testPublicRequirementsRefuseBeforeSourceAcquire() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = NativeCountingSource()
      do {
        _ = try await test.environment.connect(
          source: source,
          requirements: ConnectionRequirements(independentReliableReadProgress: true))
        XCTFail("WSS claimed independent stream read progress")
      } catch let error as TransportV4ConnectError { XCTAssertEqual(error, .unsupported) }
      XCTAssertEqual(source.count, 0)
      try await test.environment.close()
    }
    func testEnvironmentCloseRetainsNoncooperativeSourceUntilActualCallbackExit() async throws {
      let test = try NativeSessionFixture(profile: .x25519)
      defer { test.cleanup() }
      let source = NativeHeldSource()
      let material = try await test.material()
      let connecting = Task { try await test.environment.connect(source: source) }
      while !source.started { try await ContinuousClock().sleep(for: .milliseconds(5)) }
      XCTAssertEqual(test.fixture.base.root.snapshot().executionTails, 1)
      try await test.environment.close()
      let incomplete = await test.environment.cleanupStatus()
      XCTAssertTrue(incomplete.cleanupIncomplete)
      XCTAssertEqual(incomplete.pendingCallbacks, 1)
      source.complete(material)
      do {
        _ = try await connecting.value
        XCTFail("closed Environment published source result")
      } catch {}
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
  private final class NativeCountingSource: ConnectionMaterialSource, @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    var count: Int { lock.withLock { calls } }
    func acquire(_ requirements: ConnectionRequirements) async throws -> ConnectionMaterial {
      lock.withLock { calls += 1 }
      throw SessionError.operationFailed
    }
  }
  private final class NativeHeldSource: ConnectionMaterialSource, @unchecked Sendable {
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

  private final class NativeSessionFixture {
    let fixture: CredentialFixture
    let client: V4LocalIdentity
    let server: V4LocalIdentity
    let input: V4CredentialInput
    let peer: NativeSessionPeer
    let listener: V4WebSocketTestServer
    let directory: URL
    let backing: V4PoolStoreBacking
    let environment: TransportEnvironment
    let host: V4ClientEnvironment
    init(profile: V4CryptoProfile, mode: NativeSessionPeer.Mode = .echo, pinned: Bool = false)
      throws
    {
      fixture = try CredentialFixture(profile: profile.rawValue)
      client = try fixture.base.environment.generateIdentity(profile: profile)
      server = try fixture.base.environment.generateIdentity(profile: profile)
      peer = NativeSessionPeer(mode: mode)
      let peer = peer
      listener = try V4WebSocketTestServer(
        certificateName: pinned ? "v4_pin_cert" : "self_signed_cert",
        keyName: pinned ? "v4_pin_key" : "self_signed_key",
        handler: { channel in
          peer.attach(channel)
          return peer
        })
      fixture.candidateLeg = NamespaceFixture.map([
        0: .uint(0), 1: .bytes(Data(repeating: 50, count: 16)), 2: .uint(1),
        3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text("localhost"),
        7: .uint(UInt64(listener.port)),
        8: .text("/flowersec/v4/direct"), 9: .text("http/1.1"), 10: .text("flowersec.direct.v4"),
        11: pinned
          ? try V4PinTestFixture.policy(certificateName: "v4_pin_cert")
          : NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
      ])
      func certificate(_ identity: V4LocalIdentity) -> [UInt64: V4CBORValue] {
        [
          3: NamespaceFixture.map([
            0: .uint(profile == .x25519 ? 0 : 1), 1: .bytes(identity.dhPublicKey),
          ]),
          4: .bytes(identity.identityPublicKey),
        ]
      }
      input = try fixture.input(
        source: .preauthorizedPool, indices: [0],
        client: certificate(client), server: certificate(server))
      let plan = try fixture.verify(input).directPoolPlan(
        in: fixture.base.environment, identity: client)
      let serverAdmission = try fixture.verify(input)
      peer.configure(plan: plan, admission: serverAdmission, identity: server)
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
      let ca = try Data(
        contentsOf: Bundle.module.url(
          forResource: "self_signed_ca", withExtension: "pem",
          subdirectory: "Fixtures")!)
      host = try V4ClientEnvironment(
        foundation: fixture.base.environment, namespaces: [fixture.base.owner!],
        credentials: fixture.configuration(),
        endpoints: [
          TransportV4Endpoint(
            hostname: "localhost", port: listener.port, numericAddress: "127.0.0.1")
        ],
        roots: pinned ? [] : [ca], backing: backing, store: backing.open(create: true),
        provider: fixture.base.environment.clientProviderStorage(bytes: 1 << 20))
      environment = TransportEnvironment(owner: host)
    }
    func material() async throws -> ConnectionMaterial {
      try await environment.preparePoolMaterial(
        TransportV4PoolCredential(
          artifact: input.artifact,
          clientCertificate: input.clientCertificate, serverCertificate: input.serverCertificate,
          activationAuthorization: input.activation),
        identity: TransportV4ApplicationIdentity(client))
    }
    func cleanup() {
      fixture.base.environment.beginClose()
      listener.stop()
      try? FileManager.default.removeItem(at: directory)
      try? backing.retireRemovedFiles()
    }
  }

  private final class NativeSessionPeer: ChannelInboundHandler, V4HandshakeWriter,
    V4RecordPublisher,
    @unchecked Sendable
  {
    enum Mode { case echo, rejection, forgedRejection, holdAdmission }
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
    func holdPongs() { lock.withLock { holdingPongs = true } }
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
        context: ["activation_source_profile": "preauthorized_pool"]
      ).root
    }
    private func input(_ wire: Data) throws {
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
          (0, V4NamespaceValue.head(0, mode == .echo ? 0 : 1)),
          (1, V4NamespaceValue.head(0, mode == .echo ? 0 : 1)),
          (2, V4NamespaceValue.head(0, mode == .echo ? 1 : 0)),
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
        if mode != .echo {
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
        if mode != .echo { return }
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
      for stream in streams where !terminal.contains(stream.number) {
        if localAwaiting.contains(stream.number), try core.phase(stream) == .accepted {
          try core.write(stream, data: Data([9]), to: self)
          localAwaiting.remove(stream.number)
        }
        switch try core.read(stream, maximum: 64) {
        case .data(let data):
          defer { data.close() }
          try core.write(stream, data: data.withBytes { $0 }, to: self)
          try core.replenish(stream, window: plan.window)
        case .eof:
          try core.write(stream, data: Data(), fin: true, to: self)
          terminal.insert(stream.number)
        case .aborted: terminal.insert(stream.number)
        case .pending: break
        }
      }
      for _ in 0..<32 { if try !core.poll(to: self) { break } }
    }
    func openStream(metadata: Data = Data()) async throws {
      guard let channel = lock.withLock({ channel }) else { throw SessionError.closed }
      try await channel.eventLoop.submit { [self] in
        try lock.withLock {
          let value = try core!.open(
            kind: "example.from-server", metadata: metadata, receiveWindow: plan.window, to: self)
          streams.append(value)
          localAwaiting.insert(value.number)
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
