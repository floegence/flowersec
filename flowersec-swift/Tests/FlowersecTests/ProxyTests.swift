import Foundation
import XCTest

@testable import Flowersec

final class ProxyTests: XCTestCase {
  func testProxyServerDefaultsTo64ConcurrentStreams() {
    XCTAssertEqual(
      ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173"
      ).maxConcurrentStreams,
      64
    )
  }

  func testHTTPErrorResponseAllowsOmittedHeaders() throws {
    let data = Data(
      #"{"v":1,"request_id":"request-1","ok":false,"error":{"code":"request_body_too_large","message":"too large"}}"#.utf8
    )
    let response = try JSONDecoder().decode(ProxyHTTPResponseMeta.self, from: data)
    XCTAssertFalse(response.ok)
    XCTAssertEqual(response.headers, [])
    XCTAssertEqual(response.error?.code, "request_body_too_large")
  }

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
        let body = try await request.body.collect()
        await recorder.record(request, body: body)
        return ProxyHTTPUpstreamResponse(
          status: 201,
          headers: [
            ProxyHeader(name: "content-type", value: "text/plain"),
            ProxyHeader(name: "set-cookie", value: "session=upstream; Path=/"),
            ProxyHeader(name: "x-not-allowed", value: "secret"),
          ],
          contentLength: 7,
          body: { write in try await write(Data("created".utf8)) }
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
    let recorded = await recorder.request()
    let recordedRequest = try XCTUnwrap(recorded)
    let upstream = recordedRequest.request
    XCTAssertEqual(upstream.url.absoluteString, "http://127.0.0.1:8080/api/items?draft=1")
    XCTAssertEqual(recordedRequest.body, Data("{\"name\":\"item\"}".utf8))
    XCTAssertEqual(upstream.timeout, .milliseconds(250))
    XCTAssertNil(upstream.headers.first { $0.name == "authorization" })
    XCTAssertEqual(
      upstream.headers.first { $0.name == "cookie" }?.value,
      "app=1; theme=dark"
    )
    XCTAssertEqual(upstream.headers.first { $0.name == "host" }?.value, "workspace.example.test")
    XCTAssertEqual(upstream.headers.first { $0.name == "x-forwarded-proto" }?.value, "https")
  }

  func testHTTPStreamsRequestChunkBeforeTerminatorAndAllowsEarlyResponse() async throws {
    let firstChunkSeen = expectation(description: "upstream received the first request chunk")
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173"
      ),
      httpExecutor: { request in
        var body = request.body.makeAsyncIterator()
        let first = try await body.next()
        XCTAssertEqual(first, Data("first".utf8))
        firstChunkSeen.fulfill()
        return ProxyHTTPUpstreamResponse(
          status: 202,
          headers: [],
          contentLength: 2,
          body: { write in try await write(Data("ok".utf8)) }
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let pair = ProxyDuplexStream.makePair()
    let serverTask = Task {
      try await server.serveStream(kind: ProxyProtocol.http1Kind, stream: pair.server)
    }

    try await ProxyFraming.writeJSON(
      ProxyHTTPRequestMeta(requestID: "streaming-request", method: "POST", path: "/", headers: []),
      to: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    try await pair.client.write(proxyBodyFrame(Data("first".utf8)))

    await fulfillment(of: [firstChunkSeen], timeout: 1)
    let response = try await ProxyFraming.readJSON(
      ProxyHTTPResponseMeta.self,
      from: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    XCTAssertTrue(response.ok)
    XCTAssertEqual(response.status, 202)
    let responseChunk = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertEqual(responseChunk, Data("ok".utf8))
    let responseEnd = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertNil(responseEnd)
    _ = try await serverTask.value
  }

  func testHTTPStreamsResponseMetadataAndFirstChunkBeforeUpstreamCompletes() async throws {
    let bodyGate = ProxyTestGate()
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173"
      ),
      httpExecutor: { _ in
        ProxyHTTPUpstreamResponse(
          status: 200,
          headers: [ProxyHeader(name: "content-type", value: "text/plain")],
          contentLength: nil,
          body: { write in
            try await write(Data("first".utf8))
            await bodyGate.wait()
            try await write(Data("second".utf8))
          }
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let pair = ProxyDuplexStream.makePair()
    let serverTask = Task {
      try await server.serveStream(kind: ProxyProtocol.http1Kind, stream: pair.server)
    }
    try await proxyWriteRequest(metaID: "streaming-response", body: Data(), to: pair.client)

    let response = try await ProxyFraming.readJSON(
      ProxyHTTPResponseMeta.self,
      from: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    XCTAssertTrue(response.ok)
    let firstChunk = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertEqual(firstChunk, Data("first".utf8))

    await bodyGate.open()
    let secondChunk = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertEqual(secondChunk, Data("second".utf8))
    let responseEnd = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertNil(responseEnd)
    _ = try await serverTask.value
  }

  func testHTTPKnownOversizedResponseReturnsStructuredErrorBeforeMetadata() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        contract: ProxyContractOptions(maxBodyBytes: 4)
      ),
      httpExecutor: { _ in
        ProxyHTTPUpstreamResponse(
          status: 200,
          headers: [],
          contentLength: 5,
          body: { _ in XCTFail("oversized known body must not be consumed") }
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let pair = ProxyDuplexStream.makePair()
    let serverTask = Task {
      try await server.serveStream(kind: ProxyProtocol.http1Kind, stream: pair.server)
    }
    try await proxyWriteRequest(metaID: "known-overflow", body: Data(), to: pair.client)

    let response = try await ProxyFraming.readJSON(
      ProxyHTTPResponseMeta.self,
      from: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    XCTAssertFalse(response.ok)
    XCTAssertEqual(response.error?.code, "response_body_too_large")
    let responseEnd = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertNil(responseEnd)
    _ = try await serverTask.value
  }

  func testHTTPUnknownOversizedRequestReturnsStructuredErrorBeforeResponse() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        contract: ProxyContractOptions(maxChunkBytes: 4, maxBodyBytes: 5)
      ),
      httpExecutor: { request in
        _ = try await request.body.collect()
        return ProxyHTTPUpstreamResponse(
          status: 200,
          headers: [],
          contentLength: 0,
          body: { _ in }
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let pair = ProxyDuplexStream.makePair()
    let serverTask = Task {
      try await server.serveStream(kind: ProxyProtocol.http1Kind, stream: pair.server)
    }
    try await ProxyFraming.writeJSON(
      ProxyHTTPRequestMeta(requestID: "request-overflow", method: "POST", path: "/", headers: []),
      to: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    try await pair.client.write(proxyBodyFrame(Data("four".utf8)))
    try await pair.client.write(proxyBodyFrame(Data("xx".utf8)))

    let response = try await ProxyFraming.readJSON(
      ProxyHTTPResponseMeta.self,
      from: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    XCTAssertFalse(response.ok)
    XCTAssertEqual(response.error?.code, "request_body_too_large")
    let responseEnd = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertNil(responseEnd)
    _ = try await serverTask.value
  }

  func testHTTPUnknownOversizedResponseResetsAfterMetadataWithoutSecondError() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        contract: ProxyContractOptions(maxChunkBytes: 4, maxBodyBytes: 5)
      ),
      httpExecutor: { _ in
        ProxyHTTPUpstreamResponse(
          status: 200,
          headers: [],
          contentLength: nil,
          body: { write in
            try await write(Data("four".utf8))
            try await write(Data("more".utf8))
          }
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let pair = ProxyDuplexStream.makePair()
    let serverTask = Task {
      try await server.serveStream(kind: ProxyProtocol.http1Kind, stream: pair.server)
    }
    try await proxyWriteRequest(metaID: "unknown-overflow", body: Data(), to: pair.client)

    let response = try await ProxyFraming.readJSON(
      ProxyHTTPResponseMeta.self,
      from: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    XCTAssertTrue(response.ok)
    let firstChunk = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertEqual(firstChunk, Data("four".utf8))
    do {
      _ = try await pair.client.readExact(4)
      XCTFail("overflow must reset instead of writing a second response frame")
    } catch {
      let wasReset = await pair.client.wasPeerReset()
      XCTAssertTrue(wasReset)
    }
    _ = try? await serverTask.value
  }

  func testHTTPFramingFailureAfterMetadataResetsStream() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        contract: ProxyContractOptions(maxChunkBytes: 4, maxBodyBytes: 8)
      ),
      httpExecutor: { request in
        var requestBody = request.body.makeAsyncIterator()
        let firstRequestChunk = try await requestBody.next()
        XCTAssertEqual(firstRequestChunk, Data("good".utf8))
        let remainingBody = request.body
        return ProxyHTTPUpstreamResponse(
          status: 200,
          headers: [],
          contentLength: nil,
          body: { write in
            try await write(Data("ok".utf8))
            var iterator = remainingBody.makeAsyncIterator()
            _ = try await iterator.next()
          }
        )
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let pair = ProxyDuplexStream.makePair()
    let serverTask = Task {
      try await server.serveStream(kind: ProxyProtocol.http1Kind, stream: pair.server)
    }
    try await ProxyFraming.writeJSON(
      ProxyHTTPRequestMeta(requestID: "late-framing-error", method: "POST", path: "/", headers: []),
      to: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    try await pair.client.write(proxyBodyFrame(Data("good".utf8)))
    try await pair.client.write(proxyBodyFrame(Data("large".utf8)))

    let response = try await ProxyFraming.readJSON(
      ProxyHTTPResponseMeta.self,
      from: pair.client,
      maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
    )
    XCTAssertTrue(response.ok)
    let firstChunk = try await proxyReadBodyChunk(from: pair.client)
    XCTAssertEqual(firstChunk, Data("ok".utf8))
    do {
      _ = try await pair.client.readExact(4)
      XCTFail("late request framing failure must reset the stream")
    } catch {
      let wasReset = await pair.client.wasPeerReset()
      XCTAssertTrue(wasReset)
    }
    _ = try? await serverTask.value
  }

  func testConcurrentStreamLimitResetsImmediatelyAndReleasesPermit() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        maxConcurrentStreams: 1
      ),
      httpExecutor: { _ in throw ProxyError.upstream("not used") },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let first = ProxyBlockingStream()
    let firstTask = Task {
      await server.serveAcceptedStream(
        EndpointStream(kind: ProxyProtocol.http1Kind, stream: first)
      )
    }
    await first.waitUntilRead()

    let second = ProxyBlockingStream()
    await server.serveAcceptedStream(
      EndpointStream(kind: ProxyProtocol.http1Kind, stream: second)
    )
    let secondWasReset = await second.wasReset()
    XCTAssertTrue(secondWasReset)

    await first.unblock()
    _ = await firstTask.value
    let third = ProxyBlockingStream()
    let thirdTask = Task {
      await server.serveAcceptedStream(
        EndpointStream(kind: ProxyProtocol.http1Kind, stream: third)
      )
    }
    await third.waitUntilRead()
    let thirdWasReset = await third.wasReset()
    XCTAssertFalse(thirdWasReset)
    await third.unblock()
    _ = await thirdTask.value
  }

  func testCancelingAcceptedStreamResetsAndReleasesPermit() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173",
        maxConcurrentStreams: 1
      ),
      httpExecutor: { _ in throw ProxyError.upstream("not used") },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let canceled = ProxyBlockingStream()
    let canceledTask = Task {
      await server.serveAcceptedStream(
        EndpointStream(kind: ProxyProtocol.http1Kind, stream: canceled)
      )
    }
    await canceled.waitUntilRead()
    canceledTask.cancel()

    var canceledWasReset = false
    for _ in 0..<50 {
      canceledWasReset = await canceled.wasReset()
      if canceledWasReset { break }
      try await Task.sleep(for: .milliseconds(10))
    }
    if !canceledWasReset { await canceled.unblock() }
    XCTAssertTrue(canceledWasReset)
    _ = await canceledTask.value

    let next = ProxyBlockingStream()
    let nextTask = Task {
      await server.serveAcceptedStream(
        EndpointStream(kind: ProxyProtocol.http1Kind, stream: next)
      )
    }
    await next.waitUntilRead()
    let nextWasReset = await next.wasReset()
    XCTAssertFalse(nextWasReset)
    await next.unblock()
    _ = await nextTask.value
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

  func testHTTPUsesTypedUpstreamTimeoutClassification() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173"
      ),
      httpExecutor: { _ in
        throw ProxyUpstreamFailure(.timeout, message: "typed timeout")
      },
      webSocketFactory: { _, _, _, _ in throw ProxyError.upstream("not used") }
    )
    let client = try ProxyClient(route: ProxyTestRoute(server: server))

    do {
      _ = try await client.request(ProxyHTTPRequest(method: "GET", path: "/"))
      XCTFail("Expected upstream timeout")
    } catch let error as ProxyError {
      guard case .remote(let code, _) = error else {
        return XCTFail("Unexpected proxy error: \(error)")
      }
      XCTAssertEqual(code, "timeout")
    }
  }

  func testWebSocketUsesTypedRejectionClassification() async throws {
    let server = try ProxyServer(
      options: ProxyServerOptions(
        upstream: URL(string: "http://127.0.0.1:8080")!,
        upstreamOrigin: "http://127.0.0.1:5173"
      ),
      httpExecutor: { _ in throw ProxyError.upstream("not used") },
      webSocketFactory: { _, _, _, _ in
        throw ProxyUpstreamFailure(.rejected, message: "typed rejection")
      }
    )
    let client = try ProxyClient(route: ProxyTestRoute(server: server))

    do {
      _ = try await client.openWebSocket(path: "/socket")
      XCTFail("Expected upstream rejection")
    } catch let error as ProxyError {
      guard case .remote(let code, _) = error else {
        return XCTFail("Unexpected proxy error: \(error)")
      }
      XCTAssertEqual(code, "upstream_ws_rejected")
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
  func reset() async throws { await state.reset(side: side) }
  func wasPeerReset() async -> Bool { await state.wasReset(side: 1 - side) }
}

private actor ProxyDuplexState {
  private var buffers = [Data(), Data()]
  private var closed = [false, false]
  private var reset = [false, false]
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

  func reset(side: Int) {
    reset[side] = true
    close(side: side)
  }

  func wasReset(side: Int) -> Bool { reset[side] }

  private func resume(_ side: Int) {
    let current = waiters[side]
    waiters[side].removeAll()
    for waiter in current { waiter.resume() }
  }
}

private actor ProxyTestGate {
  private var openState = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if openState { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func open() {
    openState = true
    let current = waiters
    waiters.removeAll()
    current.forEach { $0.resume() }
  }
}

private actor ProxyBlockingStream: FlowersecByteStream {
  private var readStarted = false
  private var readWaiters: [CheckedContinuation<Void, Never>] = []
  private var unblockWaiters: [CheckedContinuation<Void, Never>] = []
  private var unblocked = false
  private var resetState = false

  func write(_ data: Data) async throws {}

  func readExact(_ length: Int) async throws -> Data {
    readStarted = true
    let current = readWaiters
    readWaiters.removeAll()
    current.forEach { $0.resume() }
    if !unblocked {
      await withCheckedContinuation { unblockWaiters.append($0) }
    }
    throw ProxyError.stream("blocking test stream released")
  }

  func close() async { unblock() }

  func reset() async throws {
    resetState = true
    unblock()
  }

  func waitUntilRead() async {
    if readStarted { return }
    await withCheckedContinuation { readWaiters.append($0) }
  }

  func unblock() {
    unblocked = true
    let current = unblockWaiters
    unblockWaiters.removeAll()
    current.forEach { $0.resume() }
  }

  func wasReset() -> Bool { resetState }
}

private func proxyBodyFrame(_ body: Data) -> Data {
  var frame = Data()
  frame.appendUInt32BE(UInt32(body.count))
  frame.append(body)
  return frame
}

private func proxyWriteRequest(
  metaID: String,
  body: Data,
  to stream: any FlowersecByteStream
) async throws {
  try await ProxyFraming.writeJSON(
    ProxyHTTPRequestMeta(requestID: metaID, method: "POST", path: "/", headers: []),
    to: stream,
    maxBytes: FlowersecSDKDefaults.Proxy.maxJSONFrameBytes
  )
  try await ProxyFraming.writeBody(body, to: stream, options: ProxyContractOptions())
}

private func proxyReadBodyChunk(from stream: any FlowersecByteStream) async throws -> Data? {
  let header = try await stream.readExact(4)
  let length = Int(header.readUInt32BE(at: 0))
  if length == 0 { return nil }
  return try await stream.readExact(length)
}

private actor ProxyHTTPRecorder {
  struct Value: Sendable {
    var request: ProxyHTTPUpstreamRequest
    var body: Data
  }

  private var value: Value?
  func record(_ request: ProxyHTTPUpstreamRequest, body: Data) {
    value = Value(request: request, body: body)
  }
  func request() -> Value? { value }
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
