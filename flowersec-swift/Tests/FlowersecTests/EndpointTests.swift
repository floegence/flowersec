import Foundation
import XCTest
@testable import Flowersec

final class EndpointTests: XCTestCase {
  private struct Ping: Codable, Sendable { var value: String }
  private struct Pong: Codable, Sendable, Equatable { var value: String; var ok: Bool }

  func testResolvedDirectEndpointServesRPC() async throws {
    let pair = BinaryTransportPair()
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let committed = Flag()
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-endpoint-test",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
    let options = ConnectOptions(liveness: .disabled)

    async let endpoint = Endpoint.acceptDirectResolved(
      transport: pair.server,
      resolver: { initInfo in
        XCTAssertEqual(initInfo.channelID, info.channelID)
        XCTAssertEqual(initInfo.suite, info.defaultSuite)
        return DirectEndpointCredential(
          channelID: initInfo.channelID,
          suite: initInfo.suite,
          psk: psk,
          initExpiresAtUnixS: expiresAt,
          commitAuthenticated: { await committed.set() }
        )
      }
    )
    async let client = Flowersec.establishConnection(
      info,
      transport: pair.client,
      options: options,
      path: .direct,
      idleTimeout: nil
    )

    let session = try await endpoint
    let wasCommitted = await committed.value
    XCTAssertTrue(wasCommitted)
    let router = RPCRouter()
    await router.register(77) { (ping: Ping) in
      Pong(value: ping.value, ok: true)
    }
    let serveTask = Task { try await session.serveRPC(router: router) }
    let connected = try await client
    let response: Pong = try await connected.rpc.call(77, Ping(value: "hello"))
    XCTAssertEqual(response, Pong(value: "hello", ok: true))

    await connected.close()
    await session.close()
    serveTask.cancel()
    _ = try? await serveTask.value
  }

  func testGeneratedTypedRPCClientAndServerRoundTrip() async throws {
    let pair = BinaryTransportPair()
    let psk = try Data.secureRandom(count: 32)
    let expiresAt = Int64(Date().timeIntervalSince1970) + 60
    let info = DirectConnectInfo(
      wsURL: URL(string: "wss://127.0.0.1/direct")!,
      channelID: "swift-generated-rpc-test",
      psk: psk,
      channelInitExpiresAtUnixS: expiresAt,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )

    async let endpoint = Endpoint.acceptDirectResolved(
      transport: pair.server,
      resolver: { initInfo in
        DirectEndpointCredential(
          channelID: initInfo.channelID,
          suite: initInfo.suite,
          psk: psk,
          initExpiresAtUnixS: expiresAt
        )
      }
    )
    async let client = Flowersec.establishConnection(
      info,
      transport: pair.client,
      options: ConnectOptions(liveness: .disabled),
      path: .direct,
      idleTimeout: nil
    )

    let session = try await endpoint
    let handler = GeneratedDemoHandler()
    let router = RPCRouter()
    await registerWireDemoDemo(router: router, handler: handler)
    let serveTask = Task { try await session.serveRPC(router: router) }
    let connected = try await client
    let demo = WireDemoDemoClient(rpc: connected.rpc)

    let response = try await demo.ping(WireDemoPingRequest())
    XCTAssertTrue(response.ok)

    try await demo.notifyHello(WireDemoHelloNotify(hello: "typed hello"))
    let notification = await handler.nextHello()
    XCTAssertEqual(notification, "typed hello")

    await connected.close()
    await session.close()
    serveTask.cancel()
    _ = try? await serveTask.value
  }
}

private actor GeneratedDemoHandler: WireDemoDemoHandler {
  private var notifications: [String] = []
  private var waiters: [CheckedContinuation<String, Never>] = []

  func ping(_ request: WireDemoPingRequest) async throws -> WireDemoPingResponse {
    WireDemoPingResponse(ok: true)
  }

  func hello(_ payload: WireDemoHelloNotify) async {
    if waiters.isEmpty {
      notifications.append(payload.hello)
    } else {
      waiters.removeFirst().resume(returning: payload.hello)
    }
  }

  func nextHello() async -> String {
    if !notifications.isEmpty {
      return notifications.removeFirst()
    }
    return await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }
}

private actor Flag {
  private var stored = false
  var value: Bool { stored }
  func set() { stored = true }
}

private struct BinaryTransportPair {
  let client: TestBinaryTransport
  let server: TestBinaryTransport

  init() {
    let clientInbound = PacketPipe()
    let serverInbound = PacketPipe()
    client = TestBinaryTransport(inbound: clientInbound, outbound: serverInbound)
    server = TestBinaryTransport(inbound: serverInbound, outbound: clientInbound)
  }
}

private struct TestBinaryTransport: FlowersecBinaryTransport {
  let inbound: PacketPipe
  let outbound: PacketPipe

  func writeBinary(_ data: Data) async throws {
    try await outbound.send(data)
  }

  func readBinary() async throws -> Data {
    try await inbound.receive()
  }

  func close() async {
    await inbound.close()
    await outbound.close()
  }
}

private actor PacketPipe {
  private var packets: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false

  func send(_ data: Data) throws {
    guard !closed else { throw FlowersecError.closed() }
    if waiters.isEmpty {
      packets.append(data)
    } else {
      waiters.removeFirst().resume(returning: data)
    }
  }

  func receive() async throws -> Data {
    if !packets.isEmpty { return packets.removeFirst() }
    guard !closed else { throw FlowersecError.closed() }
    return try await withCheckedThrowingContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    for waiter in waiters { waiter.resume(throwing: FlowersecError.closed()) }
    waiters.removeAll()
    packets.removeAll()
  }
}
