import Foundation
import XCTest

@testable import Flowersec

final class ProxyTests: XCTestCase {
  func testHTTPClientAndServerRoundTripWithSecurityPolicy() async throws {
    let recorder = ProxyHTTPRecorder()
    let contract = ProxyContractOptions(
      blockedResponseHeaders: ["set-cookie"],
      forbiddenCookieNamePrefixes: ["product-"]
    )
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        contract: contract
      ),
      httpExecutor: { request in
        await recorder.record(request)
        return ProxyHTTPUpstreamResponse(
          status: 201,
          headers: [
            ProxyHeader(name: "content-type", value: "text/plain"),
            ProxyHeader(name: "set-cookie", value: "session=upstream; Path=/"),
            ProxyHeader(name: "x-not-allowed", value: "secret"),
          ],
          body: Data("created".utf8)
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let route = ProxyTestRoute(server: server)
    let client = try ProxyClient(route: route, options: contract)

    let response = try await client.request(
      ProxyHTTPRequest(
        method: "POST",
        path: "/api/items?draft=1",
        headers: [
          ProxyHeader(name: "Content-Type", value: "application/json"),
          ProxyHeader(name: "Authorization", value: "Bearer product-secret"),
          ProxyHeader(name: "Cookie", value: "app=1; product-auth=hidden; theme=dark"),
        ],
        externalOrigin: "https://workspace.example.test",
        timeout: .milliseconds(250),
        body: Data("{\"name\":\"item\"}".utf8)
      )
    )

    XCTAssertEqual(response.status, 201)
    XCTAssertEqual(response.body, Data("created".utf8))
    XCTAssertEqual(response.headers, [ProxyHeader(name: "content-type", value: "text/plain")])
    let recordedRequest = await recorder.request()
    let upstream = try XCTUnwrap(recordedRequest)
    XCTAssertEqual(upstream.url.absoluteString, "http://127.0.0.1:8080/api/items?draft=1")
    XCTAssertEqual(upstream.body, Data("{\"name\":\"item\"}".utf8))
    XCTAssertEqual(upstream.timeout, .milliseconds(250))
    XCTAssertNil(upstream.headers.first { $0.name == "authorization" })
    XCTAssertEqual(
      upstream.headers.first { $0.name == "cookie" }?.value,
      "app=1; theme=dark"
    )
    XCTAssertEqual(upstream.headers.first { $0.name == "host" }?.value, "workspace.example.test")
    XCTAssertEqual(upstream.headers.first { $0.name == "x-forwarded-proto" }?.value, "https")
  }

  func testHTTPRejectsConflictingExternalOrigin() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173"
      ),
      httpExecutor: { _ in throw ProxyError.upstream("must not execute") },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let client = try ProxyClient(route: ProxyTestRoute(server: server))
    do {
      _ = try await client.request(
        ProxyHTTPRequest(
          method: "GET",
          path: "/",
          headers: [ProxyHeader(name: "origin", value: "https://other.example.test")],
          externalOrigin: "https://workspace.example.test"
        )
      )
      XCTFail("Expected conflicting origins to fail")
    } catch let error as ProxyError {
      guard case .remote(let code, _) = error else {
        return XCTFail("Unexpected proxy error: \(error)")
      }
      XCTAssertEqual(code, "invalid_request_meta")
    }
  }

  func testWebSocketClientAndServerRoundTripAllOperations() async throws {
    let upstream = ProxyTestUpstreamWebSocket(selectedProtocol: "chat")
    let recorder = ProxyWebSocketHeaderRecorder()
    let contract = ProxyContractOptions(forbiddenCookieNames: ["product-auth"])
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "https://workspace.example.test",
        contract: contract
      ),
      httpExecutor: { _ in throw ProxyError.upstream("not used") },
      webSocketFactory: { url, headers, maxBytes, _ in
        await recorder.record(url: url, headers: headers, maxBytes: maxBytes)
        return upstream
      }
    )
    let client = try ProxyClient(route: ProxyTestRoute(server: server), options: contract)
    let socket = try await client.openWebSocket(
      path: "/socket?room=1",
      headers: [
        ProxyHeader(name: "sec-websocket-protocol", value: "chat, superchat"),
        ProxyHeader(name: "cookie", value: "app=1; product-auth=hidden"),
        ProxyHeader(name: "origin", value: "https://attacker.example.test"),
      ]
    )
    XCTAssertEqual(socket.selectedProtocol, "chat")

    try await socket.send(ProxyWebSocketFrame(operation: .text, payload: Data("hello".utf8)))
    let textFrame = try await socket.receive()
    XCTAssertEqual(
      textFrame,
      ProxyWebSocketFrame(operation: .text, payload: Data("hello".utf8))
    )
    try await socket.send(ProxyWebSocketFrame(operation: .binary, payload: Data([1, 2, 3])))
    let binaryFrame = try await socket.receive()
    XCTAssertEqual(
      binaryFrame,
      ProxyWebSocketFrame(operation: .binary, payload: Data([1, 2, 3]))
    )
    try await socket.send(ProxyWebSocketFrame(operation: .ping, payload: Data("p".utf8)))
    let pongFrame = try await socket.receive()
    XCTAssertEqual(
      pongFrame,
      ProxyWebSocketFrame(operation: .pong, payload: Data("p".utf8))
    )
    try await socket.close(code: 1000, reason: "done")
    await upstream.waitForSent(.close)

    let recordedWebSocket = await recorder.value()
    let observed = try XCTUnwrap(recordedWebSocket)
    XCTAssertEqual(observed.url.absoluteString, "ws://127.0.0.1:8080/socket?room=1")
    XCTAssertEqual(observed.maxBytes, FlowersecSDKDefaults.Proxy.maxWSFrameBytes)
    XCTAssertEqual(
      observed.headers.first { $0.name == "origin" }?.value,
      "https://workspace.example.test"
    )
    XCTAssertEqual(observed.headers.first { $0.name == "cookie" }?.value, "app=1")
    XCTAssertEqual(
      observed.headers.first { $0.name == "sec-websocket-protocol" }?.value,
      "chat, superchat"
    )
    let sent = await upstream.sentFrames()
    XCTAssertTrue(sent.contains(ProxyWebSocketFrame(operation: .ping, payload: Data("p".utf8))))
    XCTAssertEqual(sent.last?.operation, .close)
  }

  func testServerRejectsDisallowedUpstreamHost() throws {
    XCTAssertThrowsError(
      try ProxyServer(
        options: ProxyServerOptions(
          upstream: URL(string: "http://10.0.0.8:8080")!,
          upstreamOrigin: "http://127.0.0.1:5173"
        )
      )
    )
  }

  func testCookieJarPreservesSameNameCookiesByPath() {
    var jar = ProxyCookieJar()
    jar.capture(
      requestPath: "/admin/login",
      headers: [
        ProxyHeader(name: "set-cookie", value: "session=root; Path=/"),
        ProxyHeader(name: "set-cookie", value: "session=admin; Path=/admin"),
      ]
    )
    XCTAssertEqual(
      jar.requestHeader(for: "/admin/users")?.value,
      "session=admin; session=root"
    )
    XCTAssertEqual(jar.requestHeader(for: "/administrator")?.value, "session=root")
  }

  func testClientRejectsBodyOverLimitBeforeOpeningStream() async throws {
    let route = ProxyCountingRoute()
    let client = try ProxyClient(
      route: route,
      options: ProxyContractOptions(maxBodyBytes: 4)
    )
    do {
      _ = try await client.request(
        ProxyHTTPRequest(method: "POST", path: "/", body: Data(repeating: 1, count: 5))
      )
      XCTFail("Expected the body limit")
    } catch let error as ProxyError {
      XCTAssertEqual(error, .bodyTooLarge)
    }
    let openCount = await route.count()
    XCTAssertEqual(openCount, 0)
  }
}

private final class ProxyTestRoute: ProxyStreamRoute, @unchecked Sendable {
  private let server: ProxyServer

  init(server: ProxyServer) { self.server = server }

  func openStream(kind: String) async throws -> any FlowersecByteStream {
    let pair = ProxyDuplexStream.makePair()
    Task { [server] in
      try? await server.serveStream(kind: kind, stream: pair.server)
    }
    return pair.client
  }
}

private final class ProxyCountingRoute: ProxyStreamRoute, @unchecked Sendable {
  private let state = ProxyCountingRouteState()

  func openStream(kind: String) async throws -> any FlowersecByteStream {
    await state.increment()
    throw ProxyError.stream("not available")
  }

  func count() async -> Int { await state.count() }
}

private actor ProxyCountingRouteState {
  private var value = 0
  func increment() { value += 1 }
  func count() -> Int { value }
}

private final class ProxyDuplexStream: FlowersecByteStream, @unchecked Sendable {
  private let state: ProxyDuplexState
  private let side: Int

  private init(state: ProxyDuplexState, side: Int) {
    self.state = state
    self.side = side
  }

  static func makePair() -> (client: ProxyDuplexStream, server: ProxyDuplexStream) {
    let state = ProxyDuplexState()
    return (
      ProxyDuplexStream(state: state, side: 0),
      ProxyDuplexStream(state: state, side: 1)
    )
  }

  func write(_ data: Data) async throws { try await state.write(from: side, data: data) }
  func readExact(_ length: Int) async throws -> Data { try await state.read(side: side, length: length) }
  func close() async { await state.close(side: side) }
}

private actor ProxyDuplexState {
  private var buffers = [Data(), Data()]
  private var closed = [false, false]
  private var waiters = [[CheckedContinuation<Void, Never>](), []]

  func write(from side: Int, data: Data) throws {
    let peer = 1 - side
    guard !closed[side], !closed[peer] else { throw ProxyError.stream("duplex stream closed") }
    buffers[peer].append(data)
    resume(peer)
  }

  func read(side: Int, length: Int) async throws -> Data {
    while buffers[side].count < length {
      guard !closed[side] else { throw ProxyError.stream("duplex stream closed") }
      await withCheckedContinuation { waiters[side].append($0) }
    }
    let data = Data(buffers[side].prefix(length))
    buffers[side].removeFirst(length)
    return data
  }

  func close(side: Int) {
    closed[side] = true
    closed[1 - side] = true
    resume(0)
    resume(1)
  }

  private func resume(_ side: Int) {
    let current = waiters[side]
    waiters[side].removeAll()
    for waiter in current { waiter.resume() }
  }
}

private actor ProxyHTTPRecorder {
  private var value: ProxyHTTPUpstreamRequest?
  func record(_ request: ProxyHTTPUpstreamRequest) { value = request }
  func request() -> ProxyHTTPUpstreamRequest? { value }
}

private actor ProxyWebSocketHeaderRecorder {
  struct Value: Sendable {
    var url: URL
    var headers: [ProxyHeader]
    var maxBytes: Int
  }

  private var recorded: Value?

  func record(url: URL, headers: [ProxyHeader], maxBytes: Int) {
    recorded = Value(url: url, headers: headers, maxBytes: maxBytes)
  }

  func value() -> Value? { recorded }
}

private actor ProxyTestUpstreamWebSocket: ProxyUpstreamWebSocket {
  nonisolated let selectedProtocol: String?
  private var sent: [ProxyWebSocketFrame] = []
  private var incoming: [ProxyWebSocketFrame] = []
  private var waiters: [CheckedContinuation<ProxyWebSocketFrame, any Error>] = []
  private var sentWaiters: [ProxyWebSocketOperation: [CheckedContinuation<Void, Never>]] = [:]
  private var closed = false

  init(selectedProtocol: String?) { self.selectedProtocol = selectedProtocol }

  func send(_ frame: ProxyWebSocketFrame) {
    sent.append(frame)
    let operationWaiters = sentWaiters.removeValue(forKey: frame.operation) ?? []
    for waiter in operationWaiters { waiter.resume() }
    let response: ProxyWebSocketFrame
    switch frame.operation {
    case .ping:
      response = ProxyWebSocketFrame(operation: .pong, payload: frame.payload)
    default:
      response = frame
    }
    if waiters.isEmpty { incoming.append(response) }
    else { waiters.removeFirst().resume(returning: response) }
  }

  func receive() async throws -> ProxyWebSocketFrame {
    if !incoming.isEmpty { return incoming.removeFirst() }
    if closed { throw ProxyError.stream("test WebSocket closed") }
    return try await withCheckedThrowingContinuation { waiters.append($0) }
  }

  func close() {
    closed = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume(throwing: ProxyError.stream("test WebSocket closed")) }
  }

  func sentFrames() -> [ProxyWebSocketFrame] { sent }

  func waitForSent(_ operation: ProxyWebSocketOperation) async {
    if sent.contains(where: { $0.operation == operation }) { return }
    await withCheckedContinuation { sentWaiters[operation, default: []].append($0) }
  }
}
