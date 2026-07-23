import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOWebSocket
import XCTest

@testable import Flowersec

final class ConnectorV2Tests: XCTestCase {
  func testRealLocalWSSDirectEndToEnd() async throws {
    try await exerciseRealWSS(vectorIndex: 0)
  }

  func testRealLocalWSSTunnelBridgesTwoAdmittedLegsEndToEnd() async throws {
    let tls = try ConnectorTestTLS.load()
    let accepted = ConnectorAcceptedTransport()
    let source = try loadArtifactJSON(index: 1)
    let original = try parseArtifactV2(Data(source.utf8)).value
    let server = try await ConnectorWSSServer.start(
      tls: tls, selectedProtocol: "flowersec.tunnel.v2", accepted: accepted)
    let candidateURL = original.path.candidates.first(where: { $0.carrier == "websocket" })!.url
    let localURL = "wss://localhost:\(server.port)/flowersec/v2/tunnel"
    let clientRaw = source.replacingOccurrences(of: candidateURL, with: localURL)
    let serverRaw =
      clientRaw
      .replacingOccurrences(of: "\"role\":1", with: "\"role\":2")
      .replacingOccurrences(of: "endpoint-client", with: "endpoint-swap")
      .replacingOccurrences(of: "endpoint-server", with: "endpoint-client")
      .replacingOccurrences(of: "endpoint-swap", with: "endpoint-server")
    let clientArtifact = try parseArtifactV2(Data(clientRaw.utf8))
    let serverArtifact = try parseArtifactV2(Data(serverRaw.utf8))
    let clientSpend = ConnectorSpendCounter()
    let serverSpend = ConnectorSpendCounter()
    let options = ConnectorOptionsV2(
      connectTimeout: .seconds(5), trustRootsPEM: [tls.certificatePEM])
    let clientConnector = try ConnectorV2(
      lease: ArtifactLeaseV2(artifact: clientArtifact) { await clientSpend.commit() },
      options: options)
    let serverConnector = try ConnectorV2(
      lease: ArtifactLeaseV2(artifact: serverArtifact) { await serverSpend.commit() },
      options: options)
    async let bridgeResult: Void = Self.bridgeTunnelLegs(accepted: accepted)
    async let clientResult = clientConnector.connect()
    async let serverResult = serverConnector.connect()
    let (client, serverPeer) = try await (clientResult, serverResult)

    let outbound = try await client.openStream(kind: "tunnel-e2e")
    let inbound = try await serverPeer.acceptStream()
    _ = try await outbound.write(Data("through-tunnel".utf8))
    let received = try await inbound.stream.read(maxBytes: 64)
    XCTAssertEqual(received, Data("through-tunnel".utf8))
    try await outbound.closeWrite()
    let eof = try await inbound.stream.read(maxBytes: 1)
    XCTAssertNil(eof)
    let reverse = try await serverPeer.openStream(kind: "tunnel-reverse")
    let reverseInbound = try await client.acceptStream()
    _ = try await reverse.write(Data("back".utf8))
    let reverseReceived = try await reverseInbound.stream.read(maxBytes: 32)
    XCTAssertEqual(reverseReceived, Data("back".utf8))
    await client.close()
    await serverPeer.close()
    _ = try? await bridgeResult
    let clientSpendCount = await clientSpend.value()
    let serverSpendCount = await serverSpend.value()
    XCTAssertEqual(clientSpendCount, 1)
    XCTAssertEqual(serverSpendCount, 1)
    await server.close()
  }

  private static func bridgeTunnelLegs(accepted: ConnectorAcceptedTransport) async throws {
    let first = try await accepted.accept()
    let second = try await accepted.accept()
    let firstFSB2 = try await first.readBinary()
    let secondFSB2 = try await second.readBinary()
    let firstRole = try tunnelRole(firstFSB2)
    let secondRole = try tunnelRole(secondFSB2)
    guard Set([firstRole, secondRole]) == Set([1, 2]) else { throw ConnectorQueueError.invalid }
    let success = Data([70, 83, 65, 50, 2, 0, 0, 0])
    try await first.writeBinary(success)
    try await second.writeBinary(success)
    try await withThrowingTaskGroup(of: Void.self) { group in
      group.addTask { try await relay(from: first, to: second) }
      group.addTask { try await relay(from: second, to: first) }
      defer { group.cancelAll() }
      _ = try await group.next()
    }
  }

  private static func tunnelRole(_ fsb2: Data) throws -> Int {
    guard fsb2.count >= 12,
      let payload = try JSONSerialization.jsonObject(with: fsb2.dropFirst(12)) as? [String: Any],
      let role = payload["role"] as? Int
    else { throw ConnectorQueueError.invalid }
    return role
  }

  private static func relay(
    from source: ConnectorNIOBinaryTransport,
    to destination: ConnectorNIOBinaryTransport
  ) async throws {
    while !Task.isCancelled { try await destination.writeBinary(try await source.readBinary()) }
  }

  private func exerciseRealWSS(vectorIndex: Int) async throws {
    let tls = try ConnectorTestTLS.load()
    let accepted = ConnectorAcceptedTransport()
    let raw = try loadArtifactJSON(index: vectorIndex)
    let original = try parseArtifactV2(Data(raw.utf8)).value
    let expectedProtocol =
      original.path.kind == "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2"
    let server = try await ConnectorWSSServer.start(
      tls: tls, selectedProtocol: expectedProtocol, accepted: accepted)
    let rewritten = raw.replacingOccurrences(
      of: original.path.candidates.first(where: { $0.carrier == "websocket" })!.url,
      with: "wss://localhost:\(server.port)/flowersec/v2/\(original.path.kind)"
    )
    let artifact = try parseArtifactV2(Data(rewritten.utf8))
    let spend = ConnectorSpendCounter()
    let lease = ArtifactLeaseV2(artifact: artifact) { await spend.commit() }
    let connector = try ConnectorV2(
      lease: lease,
      options: ConnectorOptionsV2(connectTimeout: .seconds(5), trustRootsPEM: [tls.certificatePEM])
    )
    async let serverSession = Self.establishServerSession(artifact: artifact, accepted: accepted)
    async let clientSession = connector.connect()
    let (client, serverPeer) = try await (clientSession, serverSession)

    let outbound = try await client.openStream(kind: "wss-e2e")
    let inbound = try await serverPeer.acceptStream()
    _ = try await outbound.write(Data("client".utf8))
    let received = try await inbound.stream.read(maxBytes: 32)
    XCTAssertEqual(received, Data("client".utf8))
    try await outbound.closeWrite()
    let eof = try await inbound.stream.read(maxBytes: 1)
    XCTAssertNil(eof)
    let reverse = try await serverPeer.openStream(kind: "reverse")
    let reverseInbound = try await client.acceptStream()
    _ = try await reverse.write(Data("server".utf8))
    let reverseReceived = try await reverseInbound.stream.read(maxBytes: 32)
    XCTAssertEqual(reverseReceived, Data("server".utf8))
    await client.close()
    await serverPeer.close()
    let spendCount = await spend.value()
    let selectedProtocol = await accepted.protocolValue()
    XCTAssertEqual(spendCount, 1)
    XCTAssertEqual(selectedProtocol, expectedProtocol)
    await server.close()
  }

  private static func establishServerSession(
    artifact: ArtifactV2, accepted: ConnectorAcceptedTransport
  ) async throws -> TransportV2Session {
    let transport = try await accepted.accept()
    let fsb2 = try await transport.readBinary()
    try await transport.writeBinary(Data([70, 83, 65, 50, 2, 0, 0, 0]))
    let wire = artifact.value
    var preimage = Data("flowersec-v2-admission\0".utf8)
    preimage.append(fsb2)
    let binding = Data(SHA256.hash(data: preimage))
    let path: PathKind = wire.path.kind == "direct" ? .direct : .tunnel
    let carrier = WebSocketCarrierSessionV2(
      transport: transport, path: path, client: false,
      inboundCapacity: wire.session.maxInboundStreams + 2)
    let config = TransportV2SessionConfig(
      role: .server, path: path, channelID: wire.session.channelID,
      sessionContractHash: try decodeTest32(wire.session.contractHashBase64URL),
      suite: TransportCipherSuiteV2(rawValue: wire.session.defaultSuite)!,
      psk: try decodeTest32(wire.session.e2eePSKBase64URL),
      maxInboundStreams: wire.session.maxInboundStreams,
      idleTimeoutSeconds: wire.session.idleTimeoutSeconds,
      localAdmissionBinding: path == .direct ? binding : Data(repeating: 0, count: 32),
      peerAdmissionBinding: binding,
      localEndpointInstanceID: wire.path.expectedPeerEndpointInstanceID ?? "",
      expectedPeerEndpointInstanceID: wire.path.localEndpointInstanceID ?? ""
    )
    return try await TransportV2Session.establish(carrier: carrier, config: config)
  }

  func testWebSocketCarrierProvidesBidirectionalStreamsAndFIN() async throws {
    let pair = ConnectorBinaryPair()
    let client = WebSocketCarrierSessionV2(
      transport: pair.client, path: .direct, client: true, inboundCapacity: 3)
    let server = WebSocketCarrierSessionV2(
      transport: pair.server, path: .direct, client: false, inboundCapacity: 3)

    let outbound = try await client.openStream()
    let inbound = try await server.acceptStream()
    let written = try await outbound.write(Data("hello".utf8))
    let first = try await inbound.read(maxBytes: 2)
    let second = try await inbound.read(maxBytes: 8)
    XCTAssertEqual(written, 5)
    XCTAssertEqual(first, Data("he".utf8))
    XCTAssertEqual(second, Data("llo".utf8))
    try await outbound.closeWrite()
    let eof = try await inbound.read(maxBytes: 1)
    XCTAssertNil(eof)

    let reverse = try await server.openStream()
    let reverseInbound = try await client.acceptStream()
    let reverseWritten = try await reverse.write(Data("ok".utf8))
    let reverseRead = try await reverseInbound.read(maxBytes: 8)
    XCTAssertEqual(reverseWritten, 2)
    XCTAssertEqual(reverseRead, Data("ok".utf8))
    await client.close(code: 0, reason: "done")
    await server.close(code: 0, reason: "done")
  }

  func testConnectorRejectsInvalidPublicOptions() throws {
    let artifact = try loadArtifact()
    let lease = ArtifactLeaseV2(artifact: artifact) {}
    XCTAssertThrowsError(
      try ConnectorV2(
        lease: lease,
        options: ConnectorOptionsV2(origin: "http://example.com")
      )
    ) { XCTAssertEqual($0 as? ConnectErrorV2, .invalidOptions) }
  }

  func testConnectorCommitsSpendBeforeFSB2AndClosesAfterAdmissionReject() async throws {
    let artifact = try loadArtifact()
    let events = ConnectorEventRecorder()
    let lease = ArtifactLeaseV2(artifact: artifact) { await events.append("spend") }
    let transport = ConnectorAdmissionTransport(events: events)
    let connector = try ConnectorV2(
      lease: lease,
      options: ConnectorOptionsV2(),
      dial: { _, _, _ in
        await events.append("dial")
        return transport
      }
    )

    do {
      _ = try await connector.connect()
      XCTFail("admission rejection unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectErrorV2, .connectionFailed)
    }
    let recordedEvents = await events.values()
    XCTAssertEqual(recordedEvents, ["dial", "spend", "write", "read", "close"])
  }

  private func loadArtifact() throws -> ArtifactV2 {
    try parseArtifactV2(Data(loadArtifactJSON(index: 0).utf8))
  }

  private func loadArtifactJSON(index: Int) throws -> String {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("testdata/transport_v2/artifact_vectors.json")
    let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    let positive = root["positive"] as! [[String: Any]]
    return positive[index]["artifact_json"] as! String
  }
}

private struct ConnectorBinaryPair {
  let client: ConnectorMemoryBinaryTransport
  let server: ConnectorMemoryBinaryTransport

  init() {
    let clientQueue = ConnectorBinaryQueue()
    let serverQueue = ConnectorBinaryQueue()
    client = ConnectorMemoryBinaryTransport(inbound: clientQueue, outbound: serverQueue)
    server = ConnectorMemoryBinaryTransport(inbound: serverQueue, outbound: clientQueue)
  }
}

private actor ConnectorMemoryBinaryTransport: FlowersecBinaryTransport {
  private let inbound: ConnectorBinaryQueue
  private let outbound: ConnectorBinaryQueue

  init(inbound: ConnectorBinaryQueue, outbound: ConnectorBinaryQueue) {
    self.inbound = inbound
    self.outbound = outbound
  }

  func writeBinary(_ data: Data) async throws { await outbound.push(data) }
  func readBinary() async throws -> Data { try await inbound.next() }
  func close() async { await inbound.finish() }
}

private actor ConnectorBinaryQueue {
  private var values: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false

  func push(_ value: Data) {
    guard !closed else { return }
    if let waiter = waiters.first {
      waiters.removeFirst()
      waiter.resume(returning: value)
    } else {
      values.append(value)
    }
  }

  func next() async throws -> Data {
    if !values.isEmpty { return values.removeFirst() }
    if closed { throw ConnectorQueueError.closed }
    return try await withCheckedThrowingContinuation { waiters.append($0) }
  }

  func finish() {
    closed = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume(throwing: ConnectorQueueError.closed) }
  }
}

private enum ConnectorQueueError: Error { case closed, invalid }

private func decodeTest32(_ value: String) throws -> Data {
  var text = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  text += String(repeating: "=", count: (4 - text.count % 4) % 4)
  return try XCTUnwrap(Data(base64Encoded: text))
}

private actor ConnectorSpendCounter {
  private var count = 0
  func commit() { count += 1 }
  func value() -> Int { count }
}

private struct ConnectorTestTLS {
  let certificatePEM: Data
  let certificate: NIOSSLCertificate
  let privateKey: NIOSSLPrivateKey

  static func load() throws -> Self {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let resources = root.appendingPathComponent(
      ".build/checkouts/async-http-client/Tests/AsyncHTTPClientTests/Resources")
    let cert = try Data(contentsOf: resources.appendingPathComponent("self_signed_cert.pem"))
    let key = try Data(contentsOf: resources.appendingPathComponent("self_signed_key.pem"))
    return try Self(
      certificatePEM: cert,
      certificate: XCTUnwrap(NIOSSLCertificate.fromPEMBytes(Array(cert)).first),
      privateKey: NIOSSLPrivateKey(bytes: Array(key), format: .pem)
    )
  }
}

private actor ConnectorAcceptedTransport {
  private var values: [ConnectorNIOBinaryTransport] = []
  private var waiters: [CheckedContinuation<ConnectorNIOBinaryTransport, Error>] = []
  private var selectedProtocol: String?

  func deliver(_ transport: ConnectorNIOBinaryTransport, protocolValue: String?) {
    selectedProtocol = protocolValue
    if let waiter = waiters.first {
      waiters.removeFirst()
      waiter.resume(returning: transport)
    } else {
      values.append(transport)
    }
  }

  func accept() async throws -> ConnectorNIOBinaryTransport {
    if !values.isEmpty { return values.removeFirst() }
    return try await withCheckedThrowingContinuation { waiters.append($0) }
  }

  func protocolValue() -> String? { selectedProtocol }
}

private final class ConnectorWSSServer: @unchecked Sendable {
  let port: Int
  private let group: MultiThreadedEventLoopGroup
  private let channel: any Channel

  private init(port: Int, group: MultiThreadedEventLoopGroup, channel: any Channel) {
    self.port = port
    self.group = group
    self.channel = channel
  }

  static func start(
    tls material: ConnectorTestTLS,
    selectedProtocol: String,
    accepted: ConnectorAcceptedTransport
  ) async throws -> ConnectorWSSServer {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    var tls = TLSConfiguration.makeServerConfiguration(
      certificateChain: [.certificate(material.certificate)],
      privateKey: .privateKey(material.privateKey))
    tls.minimumTLSVersion = .tlsv13
    let context = try NIOSSLContext(configuration: tls)
    let channel = try await ServerBootstrap(group: group)
      .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        let upgrader = NIOWebSocketServerUpgrader(
          maxFrameSize: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12,
          shouldUpgrade: { channel, request in
            guard request.headers["sec-websocket-protocol"].contains(selectedProtocol) else {
              return channel.eventLoop.makeSucceededFuture(nil)
            }
            var headers = HTTPHeaders()
            headers.add(name: "sec-websocket-protocol", value: selectedProtocol)
            return channel.eventLoop.makeSucceededFuture(headers)
          },
          upgradePipelineHandler: { channel, request in
            let transport = ConnectorNIOBinaryTransport(channel: channel)
            let handler = ConnectorNIOWebSocketHandler(transport: transport)
            return channel.pipeline.addHandlers(
              NIOWebSocketFrameAggregator(
                minNonFinalFragmentSize: 1,
                maxAccumulatedFrameCount: 1024,
                maxAccumulatedFrameSize: FlowersecSDKDefaults.Yamux.maxFrameBytes + 12),
              handler
            ).map {
              Task {
                await accepted.deliver(
                  transport, protocolValue: request.headers.first(name: "sec-websocket-protocol"))
              }
            }
          })
        let upgrade: NIOHTTPServerUpgradeSendableConfiguration = (
          upgraders: [upgrader], completionHandler: { _ in }
        )
        do {
          try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
          return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgrade)
        } catch { return channel.eventLoop.makeFailedFuture(error) }
      }.bind(host: "127.0.0.1", port: 0).get()
    return ConnectorWSSServer(
      port: try XCTUnwrap(channel.localAddress?.port), group: group, channel: channel)
  }

  func close() async {
    try? await channel.close().get()
    try? await group.shutdownGracefully()
  }
}

private final class ConnectorNIOBinaryTransport: FlowersecBinaryTransport, @unchecked Sendable {
  private let channel: any Channel
  private let lock = NSLock()
  private var frames: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false

  init(channel: any Channel) { self.channel = channel }

  func writeBinary(_ data: Data) async throws {
    var buffer = channel.allocator.buffer(capacity: data.count)
    buffer.writeBytes(data)
    try await channel.writeAndFlush(WebSocketFrame(fin: true, opcode: .binary, data: buffer)).get()
  }

  func readBinary() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      lock.withLock {
        if closed {
          continuation.resume(throwing: ConnectorQueueError.closed)
        } else if !frames.isEmpty {
          continuation.resume(returning: frames.removeFirst())
        } else {
          waiters.append(continuation)
        }
      }
    }
  }

  func close() async {
    finish()
    try? await channel.close().get()
  }

  func receive(_ data: Data) {
    let waiter = lock.withLock { () -> CheckedContinuation<Data, Error>? in
      if let waiter = waiters.first {
        waiters.removeFirst()
        return waiter
      }
      frames.append(data)
      return nil
    }
    waiter?.resume(returning: data)
  }

  func finish() {
    let pending = lock.withLock { () -> [CheckedContinuation<Data, Error>] in
      guard !closed else { return [] }
      closed = true
      let pending = waiters
      waiters.removeAll()
      frames.removeAll()
      return pending
    }
    for waiter in pending { waiter.resume(throwing: ConnectorQueueError.closed) }
  }
}

private final class ConnectorNIOWebSocketHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = WebSocketFrame
  private let transport: ConnectorNIOBinaryTransport
  init(transport: ConnectorNIOBinaryTransport) { self.transport = transport }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    guard frame.opcode == .binary else {
      context.close(promise: nil)
      return
    }
    var payload = frame.unmaskedData
    transport.receive(payload.readData(length: payload.readableBytes) ?? Data())
  }
  func channelInactive(context: ChannelHandlerContext) {
    transport.finish()
    context.fireChannelInactive()
  }
  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    transport.finish()
    context.close(promise: nil)
  }
}

private actor ConnectorEventRecorder {
  private var events: [String] = []
  func append(_ event: String) { events.append(event) }
  func values() -> [String] { events }
}

private actor ConnectorAdmissionTransport: FlowersecBinaryTransport {
  private let events: ConnectorEventRecorder

  init(events: ConnectorEventRecorder) { self.events = events }

  func writeBinary(_ data: Data) async throws {
    XCTAssertEqual(data.prefix(4), Data("FSB2".utf8))
    await events.append("write")
  }

  func readBinary() async throws -> Data {
    await events.append("read")
    var response = Data("FSA2".utf8)
    response.append(contentsOf: [2, 1, 0, 8])
    response.append(Data("capacity".utf8))
    return response
  }

  func close() async { await events.append("close") }
}
