#if os(macOS)
import Foundation
import XCTest

@testable import Flowersec

final class GoInteropTests: XCTestCase {
  func testSwiftClientInteroperatesWithGoDirectTunnelRPCStreamLivenessAndProxy() async throws {
    let harness = try GoHarness.start()
    defer { harness.stop() }
    let ready = try harness.readReady()

    let direct = try await Flowersec.connectDirect(
      ready.directInfo,
      options: connectOptions()
    )
    try await exercise(direct, path: .direct)

    let artifact = try await Controlplane.requestConnectArtifact(
      ArtifactRequestOptions(
        baseURL: ready.controlplaneBaseURL,
        endpointID: "swift-go-interop",
        traceID: "trace-swift-go-interop",
        allowLoopbackHTTP: true
      )
    )
    XCTAssertEqual(artifact.metadata.correlation?.traceID, "trace-swift-go-interop")
    let tunnel = try await Flowersec.connect(artifact, options: connectOptions())
    try await exercise(tunnel, path: .tunnel)
  }

  private func connectOptions() -> ConnectOptions {
    ConnectOptions(
      origin: "https://interop.flowersec.test",
      transportSecurityPolicy: .allowPlaintextForLoopback,
      liveness: .disabled
    )
  }

  private func exercise(_ client: FlowersecClient, path: FlowersecPath) async throws {
    let notification = expectation(description: "Go typed notification on \(path.rawValue)")
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
    let echoPayload = Data("swift-go-stream".utf8)
    try await echo.write(echoPayload)
    let echoed = try await echo.readExact(echoPayload.count)
    XCTAssertEqual(echoed, echoPayload)
    await echo.close()

    _ = try await client.probeLiveness(timeout: .seconds(2))

    let proxy = try ProxyClient(route: client)
    let http = try await proxy.request(.get("/http"))
    XCTAssertEqual(http.status, 200)
    XCTAssertEqual(http.body, Data("flowersec-go-proxy-ok".utf8))

    let webSocket = try await proxy.openWebSocket(path: "/ws")
    let webSocketPayload = Data("swift-go-websocket".utf8)
    try await webSocket.send(ProxyWebSocketFrame(operation: .text, payload: webSocketPayload))
    let received = try await webSocket.receive()
    XCTAssertEqual(
      received,
      ProxyWebSocketFrame(operation: .text, payload: webSocketPayload)
    )
    try await webSocket.close(reason: "done")

    await client.close()
  }
}

private struct GoHarnessReady: Decodable {
  var directInfo: DirectConnectInfo
  var controlplaneBaseURL: URL

  enum CodingKeys: String, CodingKey {
    case directInfo = "direct_info"
    case controlplaneBaseURL = "controlplane_base_url"
  }
}

private final class GoHarness: @unchecked Sendable {
  private let process: Process
  private let output: FileHandle

  private init(process: Process, output: FileHandle) {
    self.process = process
    self.output = output
  }

  static func start() throws -> GoHarness {
    let repoRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let process = Process()
    let output = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["go", "run", "./internal/cmd/flowersec-e2e-harness"]
    process.currentDirectoryURL = repoRoot.appendingPathComponent("flowersec-go")
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output
    process.standardError = FileHandle.standardError
    try process.run()
    return GoHarness(process: process, output: output.fileHandleForReading)
  }

  func readReady() throws -> GoHarnessReady {
    var line = Data()
    while true {
      let byte = output.readData(ofLength: 1)
      guard !byte.isEmpty else {
        throw FlowersecError.closed()
      }
      if byte[byte.startIndex] == 0x0A { break }
      line.append(byte)
    }
    return try JSONDecoder().decode(GoHarnessReady.self, from: line)
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
