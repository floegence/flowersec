#if os(macOS)
import Foundation
import XCTest
@testable import Flowersec

private actor RelayTestStore {
  var records: [String: RelayAdmissionRecord] = [:]
  var spent: Set<String> = []
  var released: Set<String> = []
  let entered: AsyncStream<String>.Continuation
  let onRelease: @Sendable () async throws -> Void

  init(entered: AsyncStream<String>.Continuation, onRelease: @escaping @Sendable () async throws -> Void = {}) {
    self.entered = entered; self.onRelease = onRelease
  }

  func publish(_ artifact: Artifact) throws {
    let record = try RelayAdmissionRecord(artifact: artifact, authorityScope: "issuer.tenant")
    let encoded = try JSONEncoder().encode(record)
    let text = String(decoding: encoded, as: UTF8.self)
    XCTAssertFalse(text.contains(artifact.value.session.e2eePSKBase64URL))
    XCTAssertFalse(text.contains(artifact.value.path.token!))
    records[record.lookupKey] = try JSONDecoder().decode(RelayAdmissionRecord.self, from: encoded)
  }

  func grant(_ request: RelayAdmissionRequest) -> RelayAdmissionGrant? {
    guard let record = records[request.lookupKey] else { return nil }
    return RelayAdmissionGrant(reservingFor: record) { try await self.acquire(record.lookupKey) }
  }

  func acquire(_ key: String) throws -> ConnectionLease {
    guard spent.insert(key).inserted else { throw RelayAdmissionError.credentialReplay }
    entered.yield(key)
    return ConnectionLease { try await self.release(key) }
  }

  func release(_ key: String) async throws {
    try await onRelease()
    XCTAssertTrue(released.insert(key).inserted)
  }
}

final class WebSocketRelayTests: XCTestCase {
  private static let origin = "https://relay-test.example"
  private static func fixture(_ name: String) throws -> Data {
    try Data(contentsOf: Bundle.module.resourceURL!.appendingPathComponent("Fixtures/\(name)"))
  }

  private func listen(_ store: RelayTestStore, timeout: Duration = .seconds(5)) async throws -> WebSocketRelay {
    let ingress = WebSocketRelayIngress(bindAddress: "127.0.0.1", port: 0, allowedOrigins: [Self.origin],
      certificateChainPEM: try Self.fixture("self_signed_cert.pem"), privateKeyPEM: try Self.fixture("self_signed_key.pem"))
    return try await WebSocketRelay.listen(ingresses: [ingress, ingress], maxPendingLegs: 1, maxActivePairs: 1,
      admissionTimeout: .seconds(8), pairTimeout: timeout) { request in await store.grant(request) }
  }

  private func endpoint(_ port: Int) -> String { "wss://127.0.0.1:\(port)/flowersec/v5/tunnel" }

  private func artifact(_ port: Int, role: Int, token: String, peer: String? = nil, group: String = "group") throws -> Artifact {
    var root = try XCTUnwrap(JSONSerialization.jsonObject(with: TransportV3Tests.validArtifact()) as? [String: Any])
    root["path"] = ["kind": "tunnel", "listener_audience": "relay", "rendezvous_group_id": group, "role": role,
      "local_endpoint_instance_id": role == 1 ? "client" : "server", "expected_peer_endpoint_instance_id": peer ?? (role == 1 ? "server" : "client"),
      "token": token, "candidates": [["carrier": "websocket", "id": "a", "tls": ["mode":"ca"], "url": endpoint(port), "wire_profile": "flowersec-tunnel/5"]]] as [String: Any]
    return try parseArtifact(FlowersecJCSV3.encode(root))
  }

  private func socket(_ port: Int) async throws -> NIOWebSocketBinaryTransportV3 {
    try await NIOWebSocketBinaryTransportV3(socket: rawSocket(port))
  }

  private func rawSocket(_ port: Int) async throws -> any ProxyUpstreamWebSocket {
    let handler = try NativeTLSPolicyAdapterV3.makeCAClientHandlerFactory(serverHostname: "127.0.0.1", trustRootsPEM: [Self.fixture("self_signed_ca.pem")])
    return try await ProxyNIOWebSocketConnector.connect(url: XCTUnwrap(URL(string: endpoint(port))),
      headers: [ProxyHeader(name: "Origin", value: Self.origin), ProxyHeader(name: "Sec-WebSocket-Protocol", value: "flowersec.tunnel.v5")],
      maxFrameBytes: 262_156, timeout: .seconds(3), tlsHandler: handler)
  }

  private func response(_ port: Int, _ artifact: Artifact) async throws -> AdmissionResponseV3 {
    let socket = try await socket(port)
    do {
      try await socket.writeBinary(AdmissionCodecV3.encodeFSB5(artifact: artifact, chosenCandidateID: "a").frame)
      let response = try await AdmissionCodecV3.decodeFSA5(socket.readBinary())
      await socket.close(); return response
    } catch { await socket.close(); throw error }
  }

  func testTunnelOrderedCloseFromEachBusinessRole() async throws {
    let events = AsyncStream.makeStream(of: String.self), store = RelayTestStore(entered: events.continuation)
    let relay = try await listen(store)
    do {
      for actor in ["client", "server", "both"] {
        let client = try artifact(relay.ports[0], role: 1, token: "client-order-\(actor)", group: actor)
        let server = try artifact(relay.ports[1], role: 2, token: "server-order-\(actor)", group: actor)
        try await store.publish(client); try await store.publish(server)
        let options = ConnectorOptions(origin: Self.origin, connectTimeout: .seconds(5), trustRootsPEM: [try Self.fixture("self_signed_ca.pem")])
        async let left = connect(lease: ArtifactLease(artifact: client) {}, options: options)
        async let right = connect(lease: ArtifactLease(artifact: server) {}, options: options)
        let (clientSession, serverSession) = try await (left, right)
        switch actor {
        case "client": try await clientSession.close()
        case "server": try await serverSession.close()
        default:
          async let leftClose: Void = clientSession.close(), rightClose: Void = serverSession.close()
          _ = try await (leftClose, rightClose)
        }
        let leftResult = await clientSession.waitTermination(), rightResult = await serverSession.waitTermination()
        XCTAssertEqual(leftResult, SessionTermination(error: .closed), actor)
        XCTAssertEqual(rightResult, SessionTermination(error: .closed), actor)
      }
      await relay.close(); try await relay.waitClosedAndCheckReleases()
      let spent = await store.spent, released = await store.released
      XCTAssertEqual(spent.count, 6); XCTAssertEqual(released, spent)
    } catch { await relay.close(); throw error }
  }

  func testTunnelRejectsWrongReleaseAndMissingControlFIN() async throws {
    for mode in TunnelWireV3.Mode.allCases {
      let wire = TunnelWireV3(mode: mode)
      func config(_ server: Bool) -> TransportV3SessionConfig {
        var config = TransportV3SessionConfig(role: server ? .server : .client, path: .tunnel, channelID: "ordered",
          sessionContractHash: Data(repeating: 1, count: 32), suite: .chacha20Poly1305, psk: Data(repeating: 7, count: 32), maxInboundStreams: 8,
          idleTimeoutSeconds: 0, localAdmissionBinding: Data(repeating: server ? 2 : 1, count: 32),
          peerAdmissionBinding: Data(repeating: server ? 1 : 2, count: 32), localEndpointInstanceID: server ? "server" : "client",
          expectedPeerEndpointInstanceID: server ? "client" : "server")
        config.deadlines.closeFlush = .milliseconds(500)
        return config
      }
      func carrier(_ server: Bool) -> WebSocketCarrierSessionV3 {
        WebSocketCarrierSessionV3(transport: NIOWebSocketBinaryTransportV3(socket: TunnelSocketV3(server: server, wire: wire)),
          path: .tunnel, client: !server, inboundCapacity: 10)
      }
      async let left = TransportV3Session.establish(carrier: carrier(false), config: config(false))
      async let right = TransportV3Session.establish(carrier: carrier(true), config: config(true))
      let (clientCore, serverCore) = try await (left, right)
      let client: any Session = OpaqueSessionV3(clientCore), server: any Session = OpaqueSessionV3(serverCore)
      await wire.arm()
      if mode == .serverInitiates { try await server.close() }
      else if mode == .bothInitiate {
        async let leftClose: Void = client.close(), rightClose: Void = server.close()
        _ = try await (leftClose, rightClose)
      } else { try await client.close() }
      let clientResult = await client.waitTermination(), serverResult = await server.waitTermination()
      let fins = await wire.fins
      switch mode {
      case .normal, .serverInitiates, .bothInitiate:
        XCTAssertEqual(fins, [true, false], "\(mode)")
        XCTAssertEqual(clientResult, SessionTermination(error: .closed), "\(mode)")
        XCTAssertEqual(serverResult, clientResult, "\(mode)")
      case .noRelease:
        XCTAssertEqual(fins, [true, false], "\(mode)")
        XCTAssertEqual(clientResult, SessionTermination(error: .timeout), "\(mode)")
      case .serverFINWriteFailure:
        XCTAssertEqual(serverResult, SessionTermination(error: .operationFailed), "\(mode)")
        XCTAssertFalse(fins.contains(false), "\(mode)")
      case .damagedClientRecord:
        XCTAssertEqual(serverResult, SessionTermination(error: .operationFailed), "\(mode)")
        XCTAssertFalse(fins.contains(true), "\(mode)")
      case .reset, .trailing, .damagedRecord, .releaseInsteadOfFIN:
        XCTAssertEqual(clientResult, SessionTermination(error: .operationFailed), "\(mode)")
        XCTAssertFalse(fins.contains(false), "\(mode)")
      case .wrongCode, .wrongReason, .disconnect:
        XCTAssertEqual(fins, [true, false], "\(mode)")
        XCTAssertEqual(clientResult, SessionTermination(error: .operationFailed), "\(mode)")
      }
    }
  }

  func testRelayReleasesOnlyClientAfterBothControlFINs() async throws {
    let events = AsyncStream.makeStream(of: String.self), store = RelayTestStore(entered: events.continuation)
    let relay = try await listen(store)
    func next(_ socket: any ProxyUpstreamWebSocket) async throws -> ProxyWebSocketFrame {
      try await withThrowingTaskGroup(of: ProxyWebSocketFrame.self) { tasks in
        tasks.addTask { try await socket.receive() }
        tasks.addTask { try await Task.sleep(for: .seconds(1)); throw TransportV3SessionError.timeout }
        defer { tasks.cancelAll() }
        return try await tasks.next()!
      }
    }
    func binary(_ bytes: Data) -> ProxyWebSocketFrame { .init(operation: .binary, payload: bytes) }
    do {
      for mode in ["ordered", "client-first", "reset"] {
        let client = try artifact(relay.ports[0], role: 1, token: "client-replay-\(mode)", group: mode)
        let server = try artifact(relay.ports[1], role: 2, token: "server-replay-\(mode)", group: mode)
        try await store.publish(client); try await store.publish(server)
        let left = try await rawSocket(relay.ports[0]), right = try await rawSocket(relay.ports[1])
        try await left.send(binary(AdmissionCodecV3.encodeFSB5(artifact: client, chosenCandidateID: "a").frame))
        try await right.send(binary(AdmissionCodecV3.encodeFSB5(artifact: server, chosenCandidateID: "a").frame))
        let admitted = binary(Data("FSA5".utf8) + Data([5, 0, 0, 0]))
        let leftResponse = try await next(left), rightResponse = try await next(right)
        XCTAssertEqual(leftResponse, admitted); XCTAssertEqual(rightResponse, admitted)
        var control = Data([0,1,0,1,0,0,0,1,0,0,0,0])
        try await left.send(binary(control)); _ = try await next(right)
        control[3] = 2; try await right.send(binary(control)); _ = try await next(left)
        control[3] = 4
        if mode == "ordered" {
          var other = control; other[7] = 3
          try await left.send(binary(other)); let auxiliary = try await next(right); XCTAssertEqual(auxiliary, binary(other))
          for chunk in [Data(control.prefix(3)), Data(control.dropFirst(3))] {
            try await right.send(binary(chunk)); let forwarded = try await next(left); XCTAssertEqual(forwarded, binary(chunk))
          }
          let part = binary(Data(control.prefix(11)))
          try await left.send(part); let pending = try await next(right); XCTAssertEqual(pending, part)
          let last = binary(Data(control.suffix(1))); try await left.send(last)
          let final = try await next(right); XCTAssertEqual(final, last)
          let release = try await next(left)
          XCTAssertEqual(release, ProxyWebSocketFrame(operation: .close, payload: Data([0x0f, 0xa0]) + Data("session closed".utf8)))
          try await right.send(.init(operation: .ping, payload: Data([9])))
          let reply = try await next(right); XCTAssertEqual(reply, .init(operation: .pong, payload: Data([9])))
        } else {
          if mode == "reset" { control[3] = 8 }
          try await left.send(binary(control))
          do { let frame = try await next(left); XCTFail("Invalid FIN sequence returned \(frame.operation)") }
          catch TransportV3SessionError.timeout { XCTFail("Invalid FIN sequence did not close the carrier") }
          catch { }
        }
        await right.close(); await left.close()
      }
      await relay.close(); try await relay.waitClosedAndCheckReleases()
    } catch { await relay.close(); throw error }
  }

  func testIndependentIngressMirrorFirstRPCAndPhysicalCut() async throws {
    let events = AsyncStream.makeStream(of: String.self), store = RelayTestStore(entered: events.continuation)
    let relay = try await listen(store)
    do {
      let first = relay.ports[0], second = relay.ports[1]
      let client = try artifact(first, role: 1, token: "client-once-991"), server = try artifact(second, role: 2, token: "server-once-992")
      let wrongPeer = try artifact(second, role: 2, token: "wrong-peer-993", peer: "other")
      let excess = try artifact(first, role: 1, token: "pending-capacity-994", group: "other")
      for item in [client, server, wrongPeer, excess] { try await store.publish(item) }
      let wrong = try await response(second, client)
      XCTAssertEqual(wrong.reason, "invalid_credential")
      let forged = try artifact(first, role: 1, token: "client-once-991", group: "altered")
      let altered = try await response(first, forged)
      XCTAssertEqual(altered.reason, "invalid_credential")
      let initialSpent = await store.spent
      XCTAssertTrue(initialSpent.isEmpty)
      let roots = [try Self.fixture("self_signed_ca.pem")]
      var methods = RPCHandlers()
      try methods.register(7201, context: String.self) { (side: String, value: Int) in "\(side):\(value)" }
      let leftOptions = ConnectorOptions(origin: Self.origin, connectTimeout: .seconds(6), trustRootsPEM: roots, rpcHandlers: methods.bound(to: "left"))
      let rightOptions = ConnectorOptions(origin: Self.origin, connectTimeout: .seconds(6), trustRootsPEM: roots, rpcHandlers: methods.bound(to: "right"))
      async let left = connect(lease: ArtifactLease(artifact: client) {}, options: leftOptions)
      var iterator = events.stream.makeAsyncIterator(); _ = await iterator.next()
      let capacity = try await response(first, excess), mismatch = try await response(second, wrongPeer)
      XCTAssertEqual(capacity.reason, "capacity"); XCTAssertEqual(mismatch.reason, "pair_mismatch")
      async let right = connect(lease: ArtifactLease(artifact: server) {}, options: rightOptions)
      let (clientSession, serverSession) = try await (left, right)
      async let call = clientSession.rpc.call(7201, 41, as: String.self, timeout: .seconds(3))
      async let reverse = serverSession.rpc.call(7201, 42, as: String.self, timeout: .seconds(3))
      let replies = try await (call, reverse)
      XCTAssertEqual(replies.0, "right:41"); XCTAssertEqual(replies.1, "left:42")
      async let accepted = serverSession.acceptStream()
      let outbound = try await clientSession.openStream(kind: "relay.bytes"), inbound = try await accepted.stream
      let payload = Data("opaque stream through two independent entrances".utf8)
      _ = try await outbound.write(payload); try await outbound.closeWrite()
      let delivered = try await inbound.read(maxBytes: 128), forwardEOF = try await inbound.read(maxBytes: 128)
      XCTAssertEqual(delivered, payload); XCTAssertNil(forwardEOF)
      _ = try await inbound.write(Data([7])); try await inbound.closeWrite()
      let replyBytes = try await outbound.read(maxBytes: 128), reverseEOF = try await outbound.read(maxBytes: 128)
      XCTAssertEqual(replyBytes, Data([7])); XCTAssertNil(reverseEOF)
      let replay = try await response(first, client)
      XCTAssertEqual(replay, AdmissionResponseV3(status: .reject, reason: "credential_replay"))
      let other = try artifact(first, role: 1, token: "active-capacity-995", group: "active"), otherPeer = try artifact(second, role: 2, token: "active-capacity-996", group: "active")
      try await store.publish(other); try await store.publish(otherPeer)
      let waiting = try await socket(first)
      try await waiting.writeBinary(AdmissionCodecV3.encodeFSB5(artifact: other, chosenCandidateID: "a").frame)
      let otherKey = try RelayAdmissionRecord(artifact: other, authorityScope: "issuer.tenant").lookupKey
      while let key = await iterator.next(), key != otherKey { }
      let overActive = try await response(second, otherPeer)
      XCTAssertEqual(overActive, AdmissionResponseV3(status: .retryable, reason: "capacity"))
      let waitingResult = try await AdmissionCodecV3.decodeFSA5(waiting.readBinary())
      XCTAssertEqual(waitingResult, overActive)
      await waiting.close()
      await relay.close(); try await relay.waitClosedAndCheckReleases()
      _ = await clientSession.waitTermination(); _ = await serverSession.waitTermination()
      do { _ = try await clientSession.rpc.call(7201, 43, as: String.self, timeout: .seconds(1)); XCTFail("call succeeded after relay closed") } catch { }
      let spent = await store.spent, released = await store.released
      XCTAssertEqual(released, spent); XCTAssertEqual(spent.count, 6)
    } catch { await relay.close(); throw error }
  }

  func testTimeoutRejectsUnpairedLegAndShutdownJoinsRelease() async throws {
    let events = AsyncStream.makeStream(of: String.self), holding = AsyncStream.makeStream(of: Void.self)
    let started = XCTestExpectation(description: "lease release began"), ended = XCTestExpectation(description: "shutdown returned")
    let store = RelayTestStore(entered: events.continuation) {
      started.fulfill(); var iterator = holding.stream.makeAsyncIterator(); _ = await iterator.next()
      throw ArtifactLeaseError.releaseFailed
    }
    let relay = try await listen(store, timeout: .milliseconds(150))
    do {
      let leg = try artifact(relay.ports[0], role: 1, token: "pending-once-123")
      try await store.publish(leg)
      let rejected = try await response(relay.ports[0], leg)
      XCTAssertEqual(rejected, AdmissionResponseV3(status: .retryable, reason: "pair_timeout"))
      await fulfillment(of: [started], timeout: 3)
      let close = Task { await relay.close(); ended.fulfill() }
      let result = await XCTWaiter.fulfillment(of: [ended], timeout: 0.1)
      XCTAssertEqual(result, .timedOut)
      holding.continuation.finish(); await close.value
      do { try await relay.waitClosedAndCheckReleases(); XCTFail("release failure was lost") }
      catch ArtifactLeaseError.releaseFailed { }
    } catch { holding.continuation.finish(); await relay.close(); throw error }
  }

  func testPreSuccessBinaryCannotEnterNextPair() async throws {
    let events = AsyncStream.makeStream(of: String.self), released = XCTestExpectation(description: "premature sender reclaimed")
    let store = RelayTestStore(entered: events.continuation) { released.fulfill() }
    let relay = try await listen(store)
    do {
      let client = try artifact(relay.ports[0], role: 1, token: "premature-111")
      try await store.publish(client)
      let leg = try await socket(relay.ports[0])
      try await leg.writeBinary(AdmissionCodecV3.encodeFSB5(artifact: client, chosenCandidateID: "a").frame)
      var iterator = events.stream.makeAsyncIterator(); _ = await iterator.next()
      try await leg.writeBinary(Data([1]))
      do { _ = try await leg.readBinary(); XCTFail("unexpected response after premature data") } catch { }
      await fulfillment(of: [released], timeout: 2)
      await leg.close(); await relay.close(); try await relay.waitClosedAndCheckReleases()
    } catch { await relay.close(); throw error }
  }
}

private struct TunnelSocketV3: ProxyUpstreamWebSocket {
  let server: Bool
  let wire: TunnelWireV3
  let selectedProtocol: String? = nil
  func send(_ frame: ProxyWebSocketFrame) async throws { try await wire.send(frame, server: server) }
  func receive() async throws -> ProxyWebSocketFrame { try await wire.queue(server).receive() }
  func close() async { wire.queue(server).finish(TransportV3CarrierError.closed) }
}

private actor TunnelWireV3 {
  enum Mode: CaseIterable { case normal, serverInitiates, bothInitiate, wrongCode, wrongReason, disconnect, noRelease, reset, trailing, damagedRecord, damagedClientRecord, releaseInsteadOfFIN, serverFINWriteFailure }
  private let mode: Mode
  private nonisolated let clientQueue = ProxyWebSocketInboundState(maxBufferedBytes: 1 << 20)
  private nonisolated let serverQueue = ProxyWebSocketInboundState(maxBufferedBytes: 1 << 20)
  private var armed = false
  private var firstWrites = Set<Bool>()
  private var otherWriter: CheckedContinuation<Void, Never>?
  private var clientRecords = 0
  private(set) var fins: [Bool] = []
  init(mode: Mode) { self.mode = mode }
  func arm() { armed = true }
  nonisolated func queue(_ server: Bool) -> ProxyWebSocketInboundState { server ? serverQueue : clientQueue }

  func send(_ frame: ProxyWebSocketFrame, server: Bool) async throws {
    if frame.operation == .close { return }
    let peer = queue(!server)
    var bytes = frame.payload
    guard armed, frame.operation == .binary, bytes.count >= 12, bytes.readUInt32BE(at: 4) == 1 else {
      _ = peer.push(frame); return
    }
    if bytes[1] == 0, mode == .bothInitiate, firstWrites.insert(server).inserted {
      if firstWrites.count == 1 { await withCheckedContinuation { otherWriter = $0 } }
      else { otherWriter?.resume(); otherWriter = nil }
    }
    if bytes[1] == 0, !server { clientRecords += 1 }
    if bytes[1] == 0, (server && mode == .damagedRecord) || (!server && mode == .damagedClientRecord && clientRecords == 2), bytes.count > 12 {
      bytes[bytes.count - 1] ^= 1
      _ = peer.push(ProxyWebSocketFrame(operation: .binary, payload: bytes)); return
    }
    guard bytes.readUInt16BE(at: 2) & 4 != 0 else { _ = peer.push(frame); return }
    fins.append(server)
    let release = ProxyWebSocketFrame(operation: .close, payload: Data(mode == .wrongCode ? [0x0f, 0xa1] : [0x0f, 0xa0]) + Data((mode == .wrongReason ? "peer closed" : "session closed").utf8))
    if server {
      switch mode {
      case .serverFINWriteFailure: throw TransportV3CarrierError.streamReset
      case .reset:
        bytes[3] = 8; _ = peer.push(ProxyWebSocketFrame(operation: .binary, payload: bytes)); return
      case .trailing:
        bytes[1] = 0; bytes[11] = 1; bytes.append(42)
        _ = peer.push(ProxyWebSocketFrame(operation: .binary, payload: bytes)); return
      case .releaseInsteadOfFIN: _ = peer.push(release); return
      default: break
      }
    }
    _ = peer.push(frame)
    if !server {
      if mode == .disconnect { clientQueue.finish(TransportV3CarrierError.closed) }
      else if mode != .noRelease { _ = clientQueue.push(release) }
    }
  }
}
#endif
