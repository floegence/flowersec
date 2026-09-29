#if os(macOS) || os(iOS)
  import Foundation
  import NIOCore
  import NIOHTTP1
  import NIOPosix
  import NIOSSL
  import NIOWebSocket
  import XCTest

  @testable import Flowersec

  @MainActor
  final class TransportV4WebSocketTests: XCTestCase {
    func route(
      _ fixture: CredentialFixture, port: Int, host: String = "localhost",
      tls: V4CBORValue = NamespaceFixture.map([0: .uint(0), 1: .bool(true)])
    ) throws
      -> V4WebSocketRoute
    {
      fixture.candidateLeg = NamespaceFixture.map([
        0: .uint(0), 1: .bytes(Data(repeating: 50, count: 16)), 2: .uint(1),
        3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text(host), 7: .uint(UInt64(port)),
        8: .text("/flowersec/v4/direct"), 9: .text("http/1.1"), 10: .text("flowersec.direct.v4"),
        11: tls,
      ])
      let input = try fixture.input(indices: [0])
      return try fixture.verify(input).webSocketRoute(in: fixture.base.environment)
    }
    func roots() throws -> [Data] {
      [
        try Data(
          contentsOf: Bundle.module.url(
            forResource: "self_signed_ca", withExtension: "pem", subdirectory: "Fixtures")!)
      ]
    }
    func testRealTLS13UpgradeBinaryPublicationAndEnvironmentClose() async throws {
      let server = try V4WebSocketTestServer()
      defer { server.stop() }
      let fixture = try CredentialFixture()
      let route = try route(fixture, port: server.port)
      let before = fixture.base.root.snapshot().used.sdkBytes
      var socket: V4PreparedWebSocket? = try await .prepare(
        route: route, numericAddress: "127.0.0.1", trustRootsPEM: roots())
      XCTAssertGreaterThan(fixture.base.root.snapshot().used.sdkBytes, before)
      var outgoing: V4CryptoBuffer? = try fixture.base.environment.cryptoBuffer(capacity: 3)
      try outgoing!.store(Data([1, 2, 3]))
      try socket!.publish(outgoing!)
      var incoming: V4CryptoBuffer? = try await socket!.receive()
      XCTAssertEqual(try incoming!.withBytes { $0 }, Data([1, 2, 3]))
      XCTAssertEqual(server.request?.uri, "/flowersec/v4/direct")
      XCTAssertEqual(server.request?.headers["host"], ["localhost:\(server.port)"])
      XCTAssertEqual(server.request?.headers["sec-websocket-protocol"], ["flowersec.direct.v4"])
      XCTAssertEqual(server.request?.headers["sec-websocket-extensions"], [])
      fixture.base.environment.beginClose()
      await socket!.waitClosed()
      XCTAssertThrowsError(try socket!.publish(outgoing!))
      XCTAssertThrowsError(try incoming!.withBytes { $0 })
      outgoing = nil
      incoming = nil
      socket = nil
    }
    func testTLSIdentityALPNAndUpgradeExtensionsFailBeforePublication() async throws {
      for mode in 0..<4 {
        let server = try V4WebSocketTestServer(
          alpn: mode == 1 ? ["http/1.0"] : ["http/1.1"],
          subprotocol: mode == 2 ? "wrong" : "flowersec.direct.v4", extensions: mode == 3)
        defer { server.stop() }
        let fixture = try CredentialFixture()
        let route = try route(
          fixture, port: server.port, host: mode == 0 ? "wrong.example" : "localhost")
        do {
          let socket = try await V4PreparedWebSocket.prepare(
            route: route, numericAddress: "127.0.0.1", trustRootsPEM: roots())
          socket.close()
          await socket.waitClosed()
          XCTFail("invalid TLS/upgrade accepted: mode \(mode)")
        } catch {}
      }
    }
    func testPreparationRefusesUntrustedCertificateAndNonNumericEndpoint() async throws {
      let server = try V4WebSocketTestServer()
      defer { server.stop() }
      let fixture = try CredentialFixture()
      let route = try route(fixture, port: server.port)
      for address in ["localhost", "127.0.0.1"] {
        do {
          let socket = try await V4PreparedWebSocket.prepare(route: route, numericAddress: address)
          socket.close()
          await socket.waitClosed()
          XCTFail("untrusted preparation accepted")
        } catch {}
      }
    }
    func testPendingReadCancellationClosesOriginalSocket() async throws {
      let server = try V4WebSocketTestServer()
      defer { server.stop() }
      let fixture = try CredentialFixture()
      let socket = try await V4PreparedWebSocket.prepare(
        route: route(fixture, port: server.port),
        numericAddress: "127.0.0.1", trustRootsPEM: roots())
      let task = Task { try await socket.receive() }
      task.cancel()
      do {
        _ = try await task.value
        XCTFail("canceled input succeeded")
      } catch {}
      await socket.waitClosed()
      let output = try fixture.base.environment.cryptoBuffer(capacity: 0)
      try output.store(Data())
      XCTAssertThrowsError(try socket.publish(output))
    }
    func testRawQuicCredentialCannotBecomeWebSocketRoute() throws {
      let fixture = try CredentialFixture()
      let admission = try fixture.verify(fixture.input())
      XCTAssertThrowsError(try admission.webSocketRoute(in: fixture.base.environment))
    }

    func testNativePinAcceptsExactLeafWithoutPKIOrSANAndKeepsOriginalWindow() async throws {
      // These certificates use the fixture's independent 1970 trusted interval.
      // Their CN deliberately differs from the signed route and they have no SAN.
      let server = try V4WebSocketTestServer(certificateName: "v4_pin_cert", keyName: "v4_pin_key")
      defer { server.stop() }
      let fixture = try CredentialFixture()
      let pin = try V4PinTestFixture.policy(certificateName: "v4_pin_cert", until: 1200)
      let socket = try await V4PreparedWebSocket.prepare(
        route: route(fixture, port: server.port, tls: pin),
        numericAddress: "127.0.0.1")
      let bytes = try fixture.base.environment.cryptoBuffer(capacity: 3)
      try bytes.store(Data([4, 5, 6]))
      try socket.publish(bytes)
      let echo = try await socket.receive()
      XCTAssertEqual(try echo.withBytes { $0 }, Data([4, 5, 6]))
      echo.close()
      fixture.base.source.advance(200)
      XCTAssertThrowsError(try socket.publish(bytes))
      await socket.waitClosed()
    }

    func testNativePinRejectsWrongDigestCertificateProfileAndInactiveSet() async throws {
      for certificateName in [
        "v4_pin_cert", "v4_pin_long_cert", "v4_pin_client_cert", "v4_pin_critical_cert",
      ] {
        let server = try V4WebSocketTestServer(
          certificateName: certificateName, keyName: "v4_pin_key")
        defer { server.stop() }
        let fixture = try CredentialFixture()
        let policy = try V4PinTestFixture.policy(
          certificateName: certificateName,
          wrongDigest: certificateName == "v4_pin_cert")
        do {
          let socket = try await V4PreparedWebSocket.prepare(
            route: route(fixture, port: server.port, tls: policy), numericAddress: "127.0.0.1")
          socket.close()
          await socket.waitClosed()
          XCTFail("invalid pin/profile accepted: \(certificateName)")
        } catch {}
        XCTAssertNil(server.request, "TLS refusal must precede HTTP upgrade")
      }
      let fixture = try CredentialFixture()
      let policy = try V4PinTestFixture.policy(certificateName: "v4_pin_cert", from: 1100)
      let server = try V4WebSocketTestServer(certificateName: "v4_pin_cert", keyName: "v4_pin_key")
      defer { server.stop() }
      do {
        _ = try await V4PreparedWebSocket.prepare(
          route: route(fixture, port: server.port, tls: policy),
          numericAddress: "127.0.0.1")
        XCTFail("future pin was active")
      } catch {}
      XCTAssertNil(server.request)
    }

    func testPinCaptureCannotAdoptFutureRotationOrWindowOutsideActualDER() throws {
      let fixture = try CredentialFixture()
      let future = try V4PinTestFixture.entry(
        certificateName: "v4_pin_cert", from: 1150, until: 1400)
      let wrong = NamespaceFixture.map([
        0: .bytes(Data(repeating: 0, count: 32)), 1: .uint(900),
        2: .uint(1300), 3: .text("x509v3-p256-14d"),
      ])
      let tls = NamespaceFixture.map([
        0: .uint(1), 1: .bool(true), 2: .uint(0), 3: .array([wrong, future]),
      ])
      let prepared = try V4PinnedTLS(route: route(fixture, port: 443, tls: tls))
      fixture.base.source.advance(150)
      XCTAssertThrowsError(try prepared.verify(V4PinTestFixture.certificate("v4_pin_cert")))
      let tooLong = try V4PinTestFixture.policy(
        certificateName: "v4_pin_cert", until: 8 * 86400 * 1000)
      let original = try V4PinnedTLS(route: route(fixture, port: 443, tls: tooLong))
      XCTAssertThrowsError(try original.verify(V4PinTestFixture.certificate("v4_pin_cert")))
    }
  }

  enum V4PinTestFixture {
    static func certificate(_ name: String) throws -> NIOSSLCertificate {
      try NIOSSLCertificate.fromPEMBytes(
        Array(
          Data(
            contentsOf: Bundle.module.url(
              forResource: name, withExtension: "pem", subdirectory: "Fixtures")!)))[0]
    }
    static func entry(
      certificateName: String, from: UInt64 = 900, until: UInt64 = 1400,
      wrongDigest: Bool = false
    ) throws -> V4CBORValue {
      let digest = try V4Crypto.hash(Data(certificate(certificateName).toDERBytes()))
      return NamespaceFixture.map([
        0: .bytes(wrongDigest ? Data(repeating: 99, count: 32) : digest),
        1: .uint(from), 2: .uint(until), 3: .text("x509v3-p256-14d"),
      ])
    }
    static func policy(
      certificateName: String, from: UInt64 = 900, until: UInt64 = 1400,
      wrongDigest: Bool = false
    ) throws -> V4CBORValue {
      try NamespaceFixture.map([
        0: .uint(1), 1: .bool(true), 2: .uint(0),
        3: .array([
          entry(
            certificateName: certificateName, from: from, until: until, wrongDigest: wrongDigest)
        ]),
      ])
    }
  }

  final class V4WebSocketTestServer: @unchecked Sendable {
    private let group: MultiThreadedEventLoopGroup
    private let listener: any Channel
    private let state: State
    var port: Int { listener.localAddress!.port! }
    var request: HTTPRequestHead? { state.lock.withLock { state.request } }
    private final class State: @unchecked Sendable {
      let lock = NSLock()
      var request: HTTPRequestHead?
      var children: [any Channel] = []
    }
    init(
      alpn: [String] = ["http/1.1"], subprotocol: String = "flowersec.direct.v4",
      extensions: Bool = false,
      certificateName: String = "self_signed_cert", keyName: String = "self_signed_key",
      handler: @escaping @Sendable (any Channel) -> any ChannelHandler = { _ in Echo() }
    ) throws {
      let certificate = Bundle.module.url(
        forResource: certificateName, withExtension: "pem", subdirectory: "Fixtures")!
      let key = Bundle.module.url(
        forResource: keyName, withExtension: "pem", subdirectory: "Fixtures")!
      var config = TLSConfiguration.makeServerConfiguration(
        certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(Data(contentsOf: certificate)))
          .map { .certificate($0) },
        privateKey: .privateKey(try NIOSSLPrivateKey(file: key.path, format: .pem)))
      config.minimumTLSVersion = .tlsv13
      config.maximumTLSVersion = .tlsv13
      config.applicationProtocols = alpn
      let ssl = try NIOSSLContext(configuration: config)
      group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
      let state = State()
      self.state = state
      listener = try ServerBootstrap(group: group).childChannelInitializer { channel in
        state.lock.withLock { state.children.append(channel) }
        let upgrader = NIOWebSocketServerUpgrader(
          maxFrameSize: 1_048_584, automaticErrorHandling: true,
          shouldUpgrade: { channel, request in
            state.lock.withLock { state.request = request }
            var headers = HTTPHeaders([("sec-websocket-protocol", subprotocol)])
            if extensions {
              headers.add(name: "sec-websocket-extensions", value: "permessage-deflate")
            }
            return channel.eventLoop.makeSucceededFuture(headers)
          },
          upgradePipelineHandler: { channel, _ in
            do {
              try channel.pipeline.syncOperations.addHandler(handler(channel))
              return channel.eventLoop.makeSucceededVoidFuture()
            } catch { return channel.eventLoop.makeFailedFuture(error) }
          })
        do {
          try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: ssl))
          return channel.pipeline.configureHTTPServerPipeline(
            withServerUpgrade: ([upgrader], { _ in }))
        } catch { return channel.eventLoop.makeFailedFuture(error) }
      }.bind(host: "127.0.0.1", port: 0).wait()
    }
    func stop() {
      for child in state.lock.withLock({ state.children }) { try? child.close().wait() }
      try? listener.close().wait()
      try? group.syncShutdownGracefully()
    }
    private final class Echo: ChannelInboundHandler, @unchecked Sendable {
      typealias InboundIn = NIOWebSocket.WebSocketFrame
      typealias OutboundOut = NIOWebSocket.WebSocketFrame
      func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let frame = unwrapInboundIn(data)
        context.writeAndFlush(
          wrapOutboundOut(WebSocketFrame(fin: true, opcode: .binary, data: frame.unmaskedData)),
          promise: nil)
      }
    }
  }
#endif
