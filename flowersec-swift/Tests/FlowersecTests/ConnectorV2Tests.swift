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
  func testServerParityClientProfile() async throws {
    #if os(macOS)
      guard ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_READY_BASE64"] != nil else { throw XCTSkip("server parity input is supplied by the parity runner") }
      guard let encoded = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_READY_BASE64"],
        let data = Data(base64Encoded: encoded),
        let ready = try JSONSerialization.jsonObject(with: data) as? [String: Any],
        let artifactJSON = ready["artifact_json"] as? String,
        let trustPEM = ready["trust_pem"] as? String,
        let origin = ready["origin"] as? String,
        let path = ProcessInfo.processInfo.environment["FLOWERSEC_PARITY_PATH"],
        path == "direct" || path == "tunnel"
      else { throw XCTSkip("server parity input is supplied by the parity runner") }
      let artifact = try parseArtifact(Data(artifactJSON.utf8))
      let session = try await connect(
        lease: ArtifactLease(artifact: artifact) {},
        options: ConnectorOptions(origin: origin, connectTimeout: .seconds(5), trustRootsPEM: [Data(trustPEM.utf8)])
      )
      let echo: [String: String] = try await session.rpc.call(7001, ["value": "ping"], as: [String: String].self, timeout: .seconds(5))
      XCTAssertEqual(echo["value"], "ping")
      try await session.rpc.notify(7002, ["value": "notify"])
      let stream = try await session.openStream(kind: "parity.echo", metadata: try StreamMetadata(["cell": .string(path)]))
      _ = try await stream.write(Data("hello".utf8))
      try await stream.closeWrite()
      let echoed = try await stream.read(maxBytes: 32)
      XCTAssertEqual(echoed, Data("world".utf8))
      let reset = try await session.openStream(kind: "parity.reset")
      _ = try await reset.write(Data("reset".utf8))
      try await reset.closeWrite()
      do { _ = try await reset.read(maxBytes: 32); XCTFail("reset stream succeeded") } catch { }
      try await session.rekey()
      _ = try await session.probeLiveness()
      try await session.close()
    #else
      throw ConnectError.runtimeUnsupported
    #endif
  }

  func testConnectionControllerReplacesTerminatedGoWSSSessionWithoutReplay() async throws {
    let scenario = try connectionControllerScenario(named: "connect_and_replace_after_termination")
    XCTAssertEqual(scenario.sessions, ["session-1", "session-2"])
    XCTAssertEqual(scenario.replay, [])
    let firstPeer = try GoWSSPeer.start(path: "direct")
    defer { firstPeer.stop() }
    let secondPeer = try GoWSSPeer.start(path: "direct")
    defer { secondPeer.stop() }
    let firstArtifact = try goWSSArtifact(endpoint: firstPeer.endpoint, vectorIndex: 0)
    let secondArtifact = try goWSSArtifact(endpoint: secondPeer.endpoint, vectorIndex: 0)
    let source = ControllerGoWSSArtifactSource(artifacts: [firstArtifact, secondArtifact])
    let controller = try ConnectionController(
      source: source,
      options: ConnectorOptions(
        origin: "https://client.example",
        connectTimeout: .seconds(5),
        trustRootsPEM: [
          Data(firstPeer.endpoint.caPEM.utf8), Data(secondPeer.endpoint.caPEM.utf8),
        ]
      )
    )

    await controller.start()
    let firstSession = try await waitForControllerSession(
      controller,
      source: source,
      afterAcquisitions: 1
    )
    try await exerciseGoSession(firstSession)
    let staleStream = try await firstSession.openStream(kind: "must-not-migrate")
    let firstResult = firstPeer.finish()
    XCTAssertEqual(firstResult.status, 0, firstResult.stderr)
    _ = await firstSession.waitTermination()

    await XCTAssertThrowsErrorAsync(
      try await staleStream.write(Data("must-not-replay".utf8)))
    let secondSession = try await waitForControllerSession(
      controller,
      source: source,
      afterAcquisitions: 2
    )

    await XCTAssertThrowsErrorAsync(try await firstSession.openStream(kind: "must-not-migrate"))
    await XCTAssertThrowsErrorAsync(try await firstSession.rpc.notify(90, "must-not-replay"))
    try await exerciseGoSession(secondSession)
    await controller.close()
    let secondResult = secondPeer.finish()
    XCTAssertEqual(secondResult.status, 0, secondResult.stderr)
    let sourceCounts = await source.counts()
    XCTAssertEqual(sourceCounts.acquisitions, 2)
    XCTAssertEqual(sourceCounts.spends, 2)
  }

  func testRealLocalWSSDirectEndToEnd() async throws {
    try await exerciseRealWSS(vectorIndex: 0)
  }

  func testLoopbackPlaintextDirectRuntimeContract() async throws {
    let accepted = ConnectorAcceptedTransport()
    let raw = try loadArtifactJSON(index: 0)
    let original = try parseArtifact(Data(raw.utf8)).value
    let candidateURL = try XCTUnwrap(
      original.path.candidates.first(where: { $0.carrier == "websocket" })?.url)
    let server = try await ConnectorWSSServer.startPlaintext(
      selectedProtocol: "flowersec.direct.v2", accepted: accepted)
    let rewritten = try singleWebSocketArtifactJSON(
      raw: raw,
      candidateURL: candidateURL,
      replacementURL: "ws://127.0.0.1:\(server.port)/flowersec/v2/direct"
    )
    let artifact = try parseArtifact(Data(rewritten.utf8))
    let spend = ConnectorSpendCounter()
    let lease = ArtifactLease(artifact: artifact) { await spend.commit() }
    async let serverSession = Self.establishServerSession(artifact: artifact, accepted: accepted)
    async let clientSession = connect(
      lease: lease,
      options: ConnectorOptions(origin: "http://127.0.0.1:\(server.port)", connectTimeout: .seconds(5))
    )
    let (client, serverPeer) = try await (clientSession, serverSession)

    _ = try await client.probeLiveness()
    let outbound = try await client.openStream(kind: "loopback-direct")
    let inbound = try await serverPeer.acceptStream()
    _ = try await outbound.write(Data("client".utf8))
    let received = try await inbound.stream.read(maxBytes: 32)
    XCTAssertEqual(received, Data("client".utf8))
    try await outbound.closeWrite()
    let eof = try await inbound.stream.read(maxBytes: 1)
    XCTAssertNil(eof)
    try await client.close()
    try await serverPeer.close()
    let spendCount = await spend.value()
    let selectedProtocol = await accepted.protocolValue()
    XCTAssertEqual(spendCount, 1)
    XCTAssertEqual(selectedProtocol, "flowersec.direct.v2")
    await server.close()

    let tunnelRaw = try loadArtifactJSON(index: 1)
    let tunnel = try parseArtifact(Data(tunnelRaw.utf8)).value
    let tunnelCandidateURL = try XCTUnwrap(
      tunnel.path.candidates.first(where: { $0.carrier == "websocket" })?.url)
    let plaintextTunnel = try singleWebSocketArtifactJSON(
      raw: tunnelRaw,
      candidateURL: tunnelCandidateURL,
      replacementURL: "ws://127.0.0.1:\(server.port)/flowersec/v2/tunnel")
    XCTAssertThrowsError(try parseArtifact(Data(plaintextTunnel.utf8)))
    let nonLoopback = rewritten.replacingOccurrences(of: "127.0.0.1", with: "192.0.2.10")
    XCTAssertThrowsError(try parseArtifact(Data(nonLoopback.utf8)))
  }

  func testRealGoWSSDirectEndToEnd() async throws {
    try await exerciseGoWSS(path: "direct", vectorIndex: 0)
  }

  func testRealGoWSSTunnelEndToEnd() async throws {
    try await exerciseGoWSS(path: "tunnel", vectorIndex: 1)
  }

  func testRealLocalWSSTunnelBridgesTwoAdmittedLegsEndToEnd() async throws {
    let tls = try ConnectorTestTLS.load()
    let accepted = ConnectorAcceptedTransport()
    let source = try loadArtifactJSON(index: 1)
    let original = try parseArtifact(Data(source.utf8)).value
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
    let clientArtifact = try parseArtifact(Data(clientRaw.utf8))
    let serverArtifact = try parseArtifact(Data(serverRaw.utf8))
    let clientSpend = ConnectorSpendCounter()
    let serverSpend = ConnectorSpendCounter()
    let options = ConnectorOptions(
      connectTimeout: .seconds(5), trustRootsPEM: [tls.certificatePEM])
    let clientLease = ArtifactLease(artifact: clientArtifact) { await clientSpend.commit() }
    let serverLease = ArtifactLease(artifact: serverArtifact) { await serverSpend.commit() }
    async let bridgeResult: Void = Self.bridgeTunnelLegs(accepted: accepted)
    async let clientResult = connect(lease: clientLease, options: options)
    async let serverResult = connect(lease: serverLease, options: options)
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
    try await client.close()
    try await serverPeer.close()
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
    let original = try parseArtifact(Data(raw.utf8)).value
    let expectedProtocol =
      original.path.kind == "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2"
    let server = try await ConnectorWSSServer.start(
      tls: tls, selectedProtocol: expectedProtocol, accepted: accepted)
    let rewritten = raw.replacingOccurrences(
      of: original.path.candidates.first(where: { $0.carrier == "websocket" })!.url,
      with: "wss://localhost:\(server.port)/flowersec/v2/\(original.path.kind)"
    )
    let artifact = try parseArtifact(Data(rewritten.utf8))
    let spend = ConnectorSpendCounter()
    let lease = ArtifactLease(artifact: artifact) { await spend.commit() }
    let options = ConnectorOptions(
      connectTimeout: .seconds(5), trustRootsPEM: [tls.certificatePEM])
    async let serverSession = Self.establishServerSession(artifact: artifact, accepted: accepted)
    async let clientSession = connect(lease: lease, options: options)
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
    try await client.close()
    try await serverPeer.close()
    let spendCount = await spend.value()
    let selectedProtocol = await accepted.protocolValue()
    XCTAssertEqual(spendCount, 1)
    XCTAssertEqual(selectedProtocol, expectedProtocol)
    await server.close()
  }

  private static func establishServerSession(
    artifact: Artifact, accepted: ConnectorAcceptedTransport
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

    await XCTAssertThrowsErrorAsync(try await client.sendDatagram(Data())) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .datagramsUnavailable)
    }
    await XCTAssertThrowsErrorAsync(try await client.receiveDatagram(maxBytes: 1)) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .datagramsUnavailable)
    }

    let outbound = try await client.openStream()
    let inbound = try await server.acceptStream()
    let written = try await outbound.write(Data("hello".utf8))
    let first = try await inbound.read(maxBytes: 2)
    let second = try await inbound.read(maxBytes: 8)
    XCTAssertEqual(written, 5)
    XCTAssertEqual(first, Data("he".utf8))
    XCTAssertEqual(second, Data("llo".utf8))
    await XCTAssertThrowsErrorAsync(try await outbound.stopSending(code: 6)) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .stopSendingUnsupported)
    }
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

  func testWebSocketCarrierAbortSynchronouslyRejectsLateStreams() async throws {
    let pair = ConnectorBinaryPair()
    let client = WebSocketCarrierSessionV2(
      transport: pair.client, path: .direct, client: true, inboundCapacity: 1)
    let server = WebSocketCarrierSessionV2(
      transport: pair.server, path: .direct, client: false, inboundCapacity: 1)

    client.abort(code: 6, reason: "test abort")
    await XCTAssertThrowsErrorAsync(try await client.openStream()) {
      XCTAssertEqual($0 as? TransportV2CarrierError, .closed)
    }
    await server.close(code: 0, reason: "done")
  }

  func testConnectRejectsInvalidPublicOptions() async throws {
    let artifact = try loadArtifact()
    let lease = ArtifactLease(artifact: artifact) {}
    do {
      _ = try await connect(
        lease: lease,
        options: ConnectorOptions(origin: "http://example.com"))
      XCTFail("invalid public options unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .invalidOptions)
    }
  }

  func testConnectorCommitsSpendBeforeFSB2AndClosesAfterAdmissionReject() async throws {
    let artifact = try loadArtifact()
    let events = ConnectorEventRecorder()
    let lease = ArtifactLease(artifact: artifact) { await events.append("spend") }
    let connector = try SessionConnectorV2(
      lease: lease,
      options: ConnectorOptions(),
      runtime: ConnectorAdmissionRuntime(events: events)
    )

    do {
      _ = try await connector.connect()
      XCTFail("admission rejection unexpectedly established a session")
    } catch {
      XCTAssertEqual(error as? ConnectError, .connectionFailed)
    }
    let recordedEvents = await events.values()
    XCTAssertEqual(recordedEvents, ["dial", "spend", "write", "read", "close"])
  }

  private func loadArtifact() throws -> Artifact {
    try parseArtifact(Data(loadArtifactJSON(index: 0).utf8))
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

  private func singleWebSocketArtifactJSON(
    raw: String,
    candidateURL: String,
    replacementURL: String
  ) throws -> String {
    var wire = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any])
    var path = try XCTUnwrap(wire["path"] as? [String: Any])
    var candidates = try XCTUnwrap(path["candidates"] as? [[String: Any]])
    var candidate = try XCTUnwrap(candidates.first(where: { $0["url"] as? String == candidateURL }))
    candidate["url"] = replacementURL
    candidates = [candidate]
    path["candidates"] = candidates
    wire["path"] = path
    return String(
      data: try JSONSerialization.data(
        withJSONObject: wire, options: [.sortedKeys, .withoutEscapingSlashes]),
      encoding: .utf8
    )!
  }

  private func exerciseGoWSS(path: String, vectorIndex: Int) async throws {
    let process = Process()
    let output = Pipe()
    let errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["go", "run", "./internal/cmd/ts-session-peer", "--path", path]
    process.currentDirectoryURL = packageRoot().appendingPathComponent("flowersec-go")
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    defer {
      if process.isRunning {
        process.terminate()
        process.waitUntilExit()
      }
    }

    let endpoint = try JSONDecoder().decode(
      GoWSSEndpoint.self,
      from: readFirstLine(output.fileHandleForReading)
    )
    let source = try loadArtifactJSON(index: vectorIndex)
    var wire = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any])
    var pathObject = try XCTUnwrap(wire["path"] as? [String: Any])
    let candidates = try XCTUnwrap(pathObject["candidates"] as? [[String: Any]])
    var webSocket = try XCTUnwrap(candidates.first(where: { $0["id"] as? String == "w1" }))
    webSocket["url"] = endpoint.url
    pathObject["candidates"] = [webSocket]
    wire["path"] = pathObject
    let artifact = try parseArtifact(
      JSONSerialization.data(
        withJSONObject: wire, options: [.sortedKeys, .withoutEscapingSlashes])
    )
    let candidateSet = try AdmissionCodecV2.canonicalizeCandidates(artifact)
    XCTAssertEqual(candidateSet.candidates.map(\.normalizedURL), [endpoint.url])
    let clientStarted = ContinuousClock.now
    var clientOperation = "connect"
    do {
      let session = try await connect(
        lease: ArtifactLease(artifact: artifact) {},
        options: ConnectorOptions(
          origin: "https://client.example",
          connectTimeout: .seconds(5),
          trustRootsPEM: [Data(endpoint.caPEM.utf8)]
        )
      )

      clientOperation = "liveness"
      _ = try await session.probeLiveness()
      clientOperation = "open stream"
      let stream = try await session.openStream(kind: "interop.echo")
      clientOperation = "write initial payload"
      _ = try await stream.write(Data("hello-go".utf8))
      clientOperation = "read peer payloads"
      let greeting = try await readMessage(stream)
      let serverRekey = try await readMessage(stream)
      XCTAssertEqual(greeting, Data("hello-ts".utf8))
      XCTAssertEqual(serverRekey, Data("go-rekey-ok".utf8))
      clientOperation = "rekey"
      try await session.rekey()
      clientOperation = "write post-rekey payload"
      _ = try await stream.write(Data("ts-rekey-ok".utf8))
      clientOperation = "finish stream"
      try await stream.closeWrite()
      clientOperation = "read stream finish"
      let done = try await readMessage(stream)
      let eof = try await stream.read(maxBytes: 1)
      XCTAssertEqual(done, Data("done".utf8))
      XCTAssertNil(eof)
      try await session.close()
    } catch {
      process.waitUntilExit()
      let peerError = errors.fileHandleForReading.readDataToEndOfFile()
      throw GoWSSInteropError(
        client: error,
        clientDuration: clientStarted.duration(to: .now),
        clientOperation: clientOperation,
        peer: String(decoding: peerError, as: UTF8.self),
        peerExit: process.terminationStatus
      )
    }

    process.waitUntilExit()
    let peerError = errors.fileHandleForReading.readDataToEndOfFile()
    XCTAssertEqual(process.terminationStatus, 0, String(decoding: peerError, as: UTF8.self))
  }

  private func goWSSArtifact(endpoint: GoWSSEndpoint, vectorIndex: Int) throws -> Artifact {
    let source = try loadArtifactJSON(index: vectorIndex)
    var wire = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any])
    var pathObject = try XCTUnwrap(wire["path"] as? [String: Any])
    let candidates = try XCTUnwrap(pathObject["candidates"] as? [[String: Any]])
    var webSocket = try XCTUnwrap(candidates.first(where: { $0["id"] as? String == "w1" }))
    webSocket["url"] = endpoint.url
    pathObject["candidates"] = [webSocket]
    wire["path"] = pathObject
    return try parseArtifact(
      JSONSerialization.data(
        withJSONObject: wire, options: [.sortedKeys, .withoutEscapingSlashes])
    )
  }

  private func exerciseGoSession(_ session: any Session) async throws {
    _ = try await session.probeLiveness()
    let stream = try await session.openStream(kind: "interop.echo")
    _ = try await stream.write(Data("hello-go".utf8))
    let greeting = try await readMessage(stream)
    let serverRekey = try await readMessage(stream)
    XCTAssertEqual(greeting, Data("hello-ts".utf8))
    XCTAssertEqual(serverRekey, Data("go-rekey-ok".utf8))
    try await session.rekey()
    _ = try await stream.write(Data("ts-rekey-ok".utf8))
    try await stream.closeWrite()
    let done = try await readMessage(stream)
    let eof = try await stream.read(maxBytes: 1)
    XCTAssertEqual(done, Data("done".utf8))
    XCTAssertNil(eof)
  }

  private func waitForControllerSession(
    _ controller: ConnectionController,
    source: ControllerGoWSSArtifactSource,
    afterAcquisitions minimumAcquisitions: Int
  ) async throws -> any Session {
    let deadline = ContinuousClock.now + .seconds(5)
    while ContinuousClock.now < deadline {
      let snapshot = await controller.snapshot()
      if snapshot.state == .failed { throw ControllerGoWSSTestError.failed }
      let counts = await source.counts()
      if counts.acquisitions >= minimumAcquisitions,
        snapshot.state == .connected,
        let session = snapshot.currentSession
      {
        return session
      }
      try await Task.sleep(for: .milliseconds(1))
    }
    let snapshot = await controller.snapshot()
    let counts = await source.counts()
    throw ControllerGoWSSTestError.timeout(
      state: snapshot.state,
      attempt: snapshot.attempt,
      hasCurrentSession: snapshot.currentSession != nil,
      acquisitions: counts.acquisitions
    )
  }

  private func readMessage(_ stream: any ByteStream) async throws -> Data {
    let value = try await stream.read(maxBytes: 64)
    return try XCTUnwrap(value)
  }

  private func readFirstLine(_ handle: FileHandle) throws -> Data {
    var buffered = Data()
    while true {
      let chunk = try handle.read(upToCount: 1) ?? Data()
      guard !chunk.isEmpty else { throw ConnectorQueueError.closed }
      buffered.append(chunk)
      if chunk[0] == 0x0a { return buffered.dropLast() }
    }
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

private func XCTAssertThrowsErrorAsync<T>(
  _ expression: @autoclosure () async throws -> T,
  _ errorHandler: (any Error) -> Void = { _ in },
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    _ = try await expression()
    XCTFail("Expected expression to throw", file: file, line: line)
  } catch {
    errorHandler(error)
  }
}

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

private struct GoWSSEndpoint: Decodable {
  let url: String
  let caPEM: String

  enum CodingKeys: String, CodingKey {
    case url
    case caPEM = "ca_pem"
  }
}

private final class GoWSSPeer: @unchecked Sendable {
  let endpoint: GoWSSEndpoint
  private let process: Process
  private let errors: Pipe
  private var result: (status: Int32, stderr: String)?

  private init(process: Process, errors: Pipe, endpoint: GoWSSEndpoint) {
    self.process = process
    self.errors = errors
    self.endpoint = endpoint
  }

  static func start(path: String) throws -> GoWSSPeer {
    let process = Process()
    let output = Pipe()
    let errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["go", "run", "./internal/cmd/ts-session-peer", "--path", path]
    process.currentDirectoryURL = packageRoot().appendingPathComponent("flowersec-go")
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    do {
      let endpoint = try JSONDecoder().decode(
        GoWSSEndpoint.self,
        from: readEndpointLine(output.fileHandleForReading)
      )
      return GoWSSPeer(process: process, errors: errors, endpoint: endpoint)
    } catch {
      if process.isRunning {
        process.terminate()
        process.waitUntilExit()
      }
      throw error
    }
  }

  func finish() -> (status: Int32, stderr: String) {
    if let result { return result }
    process.waitUntilExit()
    let value = (
      status: process.terminationStatus,
      stderr: String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    )
    result = value
    return value
  }

  func stop() {
    if process.isRunning {
      process.terminate()
      process.waitUntilExit()
    }
  }

  private static func readEndpointLine(_ handle: FileHandle) throws -> Data {
    var buffered = Data()
    while true {
      let chunk = try handle.read(upToCount: 1) ?? Data()
      guard !chunk.isEmpty else { throw ControllerGoWSSTestError.peerClosed }
      if chunk[0] == 0x0a { return buffered }
      buffered.append(chunk)
    }
  }
}

private actor ControllerGoWSSArtifactSource: ArtifactSource {
  private var artifacts: [Artifact]
  private var acquisitions = 0
  private var spends = 0

  init(artifacts: [Artifact]) {
    self.artifacts = artifacts
  }

  func acquireArtifact() throws -> ArtifactLease {
    guard !artifacts.isEmpty else {
      throw ArtifactSourceFailure(disposition: .terminal)
    }
    acquisitions += 1
    let artifact = artifacts.removeFirst()
    return ArtifactLease(artifact: artifact) { await self.recordSpend() }
  }

  func counts() -> (acquisitions: Int, spends: Int) {
    (acquisitions, spends)
  }

  private func recordSpend() {
    spends += 1
  }
}

private enum ControllerGoWSSTestError: Error {
  case failed
  case peerClosed
  case timeout(
    state: ConnectionState,
    attempt: UInt64,
    hasCurrentSession: Bool,
    acquisitions: Int
  )
}

private struct GoWSSInteropError: LocalizedError {
  let client: any Error
  let clientDuration: Duration
  let clientOperation: String
  let peer: String
  let peerExit: Int32

  var errorDescription: String? {
    "Swift client \(clientOperation) failed after \(clientDuration): \(client); Go peer exit \(peerExit): \(peer.trimmingCharacters(in: .whitespacesAndNewlines))"
  }
}

private struct ConnectorTestTLS {
  let certificatePEM: Data
  let certificate: NIOSSLCertificate
  let privateKey: NIOSSLPrivateKey

  static func load() throws -> Self {
    let resources = try XCTUnwrap(Bundle.module.resourceURL?.appendingPathComponent("Fixtures"))
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
    try await startServer(tls: material, selectedProtocol: selectedProtocol, accepted: accepted)
  }

  static func startPlaintext(
    selectedProtocol: String,
    accepted: ConnectorAcceptedTransport
  ) async throws -> ConnectorWSSServer {
    try await startServer(tls: nil, selectedProtocol: selectedProtocol, accepted: accepted)
  }

  private static func startServer(
    tls material: ConnectorTestTLS?,
    selectedProtocol: String,
    accepted: ConnectorAcceptedTransport
  ) async throws -> ConnectorWSSServer {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let context: NIOSSLContext?
    if let material {
      var tls = TLSConfiguration.makeServerConfiguration(
        certificateChain: [.certificate(material.certificate)],
        privateKey: .privateKey(material.privateKey))
      tls.minimumTLSVersion = .tlsv13
      context = try NIOSSLContext(configuration: tls)
    } else {
      context = nil
    }
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
          if let context {
            try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
          }
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

private struct ConnectorAdmissionRuntime: RuntimeCarrierAdapterV2 {
  let capabilities = RuntimeCapabilitiesV2.macOS
  let events: ConnectorEventRecorder

  func validate(options: ConnectorOptions) throws {}

  func prepare(
    candidate: CanonicalCandidateV2,
    path: PathKind,
    role: SessionRoleV2,
    options: ConnectorOptions
  ) async throws -> any PreparedCarrierConnectionV2 {
    await events.append("dial")
    return ConnectorAdmissionConnection(events: events)
  }
}

private actor ConnectorAdmissionConnection: PreparedCarrierConnectionV2 {
  nonisolated let carrier = CarrierKind.webSocket
  private let events: ConnectorEventRecorder

  init(events: ConnectorEventRecorder) { self.events = events }

  func writeAdmission(_ data: Data) async throws {
    XCTAssertEqual(data.prefix(4), Data("FSB2".utf8))
    await events.append("write")
  }

  func readAdmission() async throws -> Data {
    await events.append("read")
    var response = Data("FSA2".utf8)
    response.append(contentsOf: [2, 1, 0, 8])
    response.append(Data("capacity".utf8))
    return response
  }

  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV2CarrierSession {
    throw ConnectorQueueError.invalid
  }

  func close() async { await events.append("close") }
}
