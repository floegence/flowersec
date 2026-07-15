#if os(macOS)
import Foundation
import XCTest

@testable import Flowersec

final class RustInteropTests: XCTestCase {
  func testSwiftClientInteroperatesWithRustEndpointRPCStreamLivenessAndProxy() async throws {
    let harness = try RustHarness.start()
    defer { harness.stop() }
    let ready = try harness.readReady()
    XCTAssertEqual(ready.v, 1)
    XCTAssertEqual(ready.event, "ready")

    let client = try await Flowersec.connectDirect(
      ready.directInfo,
      options: ConnectOptions(
        origin: "https://app.example.com",
        transportSecurityPolicy: .allowPlaintextForLoopback,
        liveness: .disabled
      )
    )
    defer { Task { await client.close() } }

    let notification = expectation(description: "Rust typed notification")
    let demo = WireDemoDemoClient(rpc: client.rpc)
    let subscription = demo.onHello { payload in
      XCTAssertEqual(payload.hello, "world")
      notification.fulfill()
    }
    let response = try await demo.ping(WireDemoPingRequest())
    XCTAssertTrue(response.ok)
    await fulfillment(of: [notification], timeout: 2)
    subscription.cancel()

    let echo = try await client.openStream(kind: "echo")
    let echoPayload = Data("swift-rust-stream".utf8)
    try await echo.write(echoPayload)
    let echoed = try await echo.readExact(echoPayload.count)
    XCTAssertEqual(echoed, echoPayload)
    await echo.close()
    _ = try await client.probeLiveness(timeout: .seconds(2))

    let proxy = try ProxyClient(route: client)
    let http = try await proxy.request(.get("/http"))
    XCTAssertEqual(http.status, 200)
    XCTAssertEqual(http.body, Data("flowersec-rust-proxy-ok".utf8))

    let webSocket = try await proxy.openWebSocket(path: "/ws")
    let webSocketPayload = Data("swift-rust-websocket".utf8)
    try await webSocket.send(
      ProxyWebSocketFrame(operation: .text, payload: webSocketPayload)
    )
    let received = try await webSocket.receive()
    XCTAssertEqual(
      received,
      ProxyWebSocketFrame(operation: .text, payload: webSocketPayload)
    )
    try await webSocket.close(reason: "done")
    await client.close()
  }

  func testSwiftClientInteroperatesWithRustEndpointThroughTunnel() async throws {
    let goHarness = try GoExternalHarness.start()
    defer { goHarness.stop() }
    let grants = try goHarness.readReady()
    let rustHarness = try RustHarness.start(serverGrant: grants.grantServer)
    defer { rustHarness.stop() }
    let attaching = try rustHarness.readEvent()
    XCTAssertEqual(attaching.v, 1)
    XCTAssertEqual(attaching.event, "attaching")

    let client = try await Flowersec.connectTunnel(
      grants.grantClient,
      options: ConnectOptions(
        origin: "https://app.redeven.com",
        transportSecurityPolicy: .allowPlaintextForLoopback,
        liveness: .disabled
      )
    )
    defer { Task { await client.close() } }
    try await exercise(client)
  }

  private func exercise(_ client: FlowersecClient) async throws {
    let notification = expectation(description: "Rust tunnel typed notification")
    let demo = WireDemoDemoClient(rpc: client.rpc)
    let subscription = demo.onHello { payload in
      XCTAssertEqual(payload.hello, "world")
      notification.fulfill()
    }
    let response = try await demo.ping(WireDemoPingRequest())
    XCTAssertTrue(response.ok)
    await fulfillment(of: [notification], timeout: 2)
    subscription.cancel()

    let echo = try await client.openStream(kind: "echo")
    let echoPayload = Data("swift-rust-tunnel".utf8)
    try await echo.write(echoPayload)
    let echoed = try await echo.readExact(echoPayload.count)
    XCTAssertEqual(echoed, echoPayload)
    await echo.close()
    _ = try await client.probeLiveness(timeout: .seconds(2))

    let proxy = try ProxyClient(route: client)
    let http = try await proxy.request(.get("/http"))
    XCTAssertEqual(http.status, 200)
    XCTAssertEqual(http.body, Data("flowersec-rust-proxy-ok".utf8))
    await client.close()
  }
}

private struct RustHarnessReady: Decodable {
  var v: Int
  var event: String
  var directInfo: DirectConnectInfo

  enum CodingKeys: String, CodingKey {
    case v
    case event
    case directInfo = "direct_info"
  }
}

private struct HarnessEvent: Decodable {
  var v: Int
  var event: String
}

private struct GoExternalReady: Decodable {
  var grantClient: ChannelInitGrant
  var grantServer: ChannelInitGrant

  enum CodingKeys: String, CodingKey {
    case grantClient = "grant_client"
    case grantServer = "grant_server"
  }
}

private final class RustHarness: @unchecked Sendable {
  private let process: Process
  private let output: FileHandle

  private init(process: Process, output: FileHandle) {
    self.process = process
    self.output = output
  }

  static func start(serverGrant: ChannelInitGrant? = nil) throws -> RustHarness {
    let repoRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["cargo", "run", "--quiet", "--example", "interop_harness"]
    if let serverGrant {
      let data = try JSONEncoder().encode(serverGrant)
      guard let json = String(data: data, encoding: .utf8) else {
        throw CocoaError(.fileWriteInapplicableStringEncoding)
      }
      process.arguments?.append(contentsOf: ["--", "--tunnel-grant-json", json])
    }
    process.currentDirectoryURL = repoRoot.appendingPathComponent("flowersec-rust")
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.standardError
    try process.run()
    return RustHarness(process: process, output: output.fileHandleForReading)
  }

  func readReady() throws -> RustHarnessReady {
    try readLine(RustHarnessReady.self)
  }

  func readEvent() throws -> HarnessEvent {
    try readLine(HarnessEvent.self)
  }

  private func readLine<Value: Decodable>(_ type: Value.Type) throws -> Value {
    var line = Data()
    while true {
      let byte = output.readData(ofLength: 1)
      guard !byte.isEmpty else {
        throw FlowersecError.closed()
      }
      if byte[byte.startIndex] == 0x0A { break }
      line.append(byte)
    }
    return try JSONDecoder().decode(type, from: line)
  }

  func stop() {
    if process.isRunning {
      process.terminate()
      process.waitUntilExit()
    }
    try? output.close()
  }
}

private final class GoExternalHarness: @unchecked Sendable {
  private let process: Process
  private let output: FileHandle

  private init(process: Process, output: FileHandle) {
    self.process = process
    self.output = output
  }

  static func start() throws -> GoExternalHarness {
    let repoRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = [
      "go", "run", "./internal/cmd/flowersec-e2e-harness", "-external-server",
    ]
    process.currentDirectoryURL = repoRoot.appendingPathComponent("flowersec-go")
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.standardError
    try process.run()
    return GoExternalHarness(process: process, output: output.fileHandleForReading)
  }

  func readReady() throws -> GoExternalReady {
    var line = Data()
    while true {
      let byte = output.readData(ofLength: 1)
      guard !byte.isEmpty else { throw FlowersecError.closed() }
      if byte[byte.startIndex] == 0x0A { break }
      line.append(byte)
    }
    return try JSONDecoder().decode(GoExternalReady.self, from: line)
  }

  func stop() {
    if process.isRunning {
      process.terminate()
      process.waitUntilExit()
    }
    try? output.close()
  }
}
#endif
