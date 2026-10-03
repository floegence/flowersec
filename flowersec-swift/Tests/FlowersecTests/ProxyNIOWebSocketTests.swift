#if os(macOS) || os(iOS)

import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOWebSocket
import XCTest

@testable import Flowersec

final class ProxyNIOWebSocketTests: XCTestCase {
  func testConnectCompletesSuccessfulUpgrade() async throws {
    let fixtures = Bundle.module.resourceURL!.appendingPathComponent("Fixtures")
    let pem = try Data(contentsOf: fixtures.appendingPathComponent("self_signed_cert.pem"))
    let certificate = try XCTUnwrap(NIOSSLCertificate.fromPEMBytes(Array(pem)).first)
    let ca = try NIOSSLCertificate.fromPEMFile(fixtures.appendingPathComponent("self_signed_ca.pem").path)
    let key = try NIOSSLPrivateKey(
      file: fixtures.appendingPathComponent("self_signed_key.pem").path, format: .pem)
    let configuration = TLSConfiguration.makeServerConfiguration(
      certificateChain: [.certificate(certificate)], privateKey: .privateKey(key))
    let tlsContext = try NIOSSLContext(configuration: configuration)
    for mode in ["direct", "http", "tls-ca", "tls-untrusted", "tls-wrong-host", "tls-wrong-pin"] {
      let tls = mode.hasPrefix("tls-")
      let rejects = ["tls-untrusted", "tls-wrong-host", "tls-wrong-pin"].contains(mode)
      let server = try LocalWebSocketServer(
        behavior: .upgrade(
          selectedProtocol: "flowersec-test", initialPayloads: [], closeAfterPayloads: false),
        tlsContext: tls ? tlsContext : nil)
      defer { server.stop() }
      let path = mode == "direct" ? "/socket?token=test" : "/flowersec/v3/direct"
      let host = mode == "tls-wrong-host" ? "wrong.invalid" : "localhost"
      let endpoint = URL(
        string: "\(tls ? "wss" : "ws")://\(tls ? host : "127.0.0.1"):\(server.port)\(path)")!
      let port = Int(server.port)
      let dial: TLSChannelProvider.Connect = { initialize in
        try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
          .channelInitializer(initialize).connect(host: "127.0.0.1", port: port).get()
      }
      let provider =
        mode == "http" ? try HTTPDirectChannelProvider(endpoint: endpoint, connect: dial) : nil
      let tlsProvider =
        tls
        ? try TLSChannelProvider(
          origin: URL(string: "https://\(host):\(server.port)")!, connect: dial) : nil
      let policy: TransportSecurityPolicyV3
      if mode == "tls-wrong-pin" {
        policy = .pin(serverName: host, activeLeafDERSHA256: [Data(repeating: 1, count: 32)])
      } else {
        policy = .ca(
          serverName: host, rootsSource: mode == "tls-untrusted" ? .platform : .configured)
      }
      let handler =
        tls
        ? try NativeTLSPolicyAdapterV3.makeClientHandlerFactory(
          policy: policy, serverHostname: host, configuredRoots: ca) : nil
      do {
        let socket = try await ProxyNIOWebSocketConnector.connect(
          url: endpoint,
          headers: [ProxyHeader(name: "Sec-WebSocket-Protocol", value: "flowersec-test")],
          maxFrameBytes: 64, timeout: .seconds(2), tlsHandler: handler,
          channelProvider: provider, tlsChannelProvider: tlsProvider)
        XCTAssertFalse(rejects, "\(mode) must reject TLS")
        XCTAssertEqual(socket.selectedProtocol, "flowersec-test")
        let request = try XCTUnwrap(server.request)
        XCTAssertEqual(request.uri, path)
        XCTAssertEqual(request.protocolHeader, "flowersec-test")
        await socket.close()
      } catch {
        guard rejects else { XCTFail("\(mode): \(error)"); continue }
        XCTAssertTrue((error as? ProxyUpstreamFailure)?.tlsLocated == true, "\(mode): \(error)")
        XCTAssertNil(server.request, "TLS rejection must precede HTTP delivery")
      }
    }
  }

  func testConnectReportsRejectedUpgrade() async throws {
    let server = try LocalWebSocketServer(behavior: .reject(status: 403, reason: "Forbidden"))
    defer { server.stop() }

    do {
      _ = try await ProxyNIOWebSocketConnector.connect(
        url: URL(string: "ws://127.0.0.1:\(server.port)/socket")!,
        headers: [],
        maxFrameBytes: 64,
        timeout: .seconds(1)
      )
      XCTFail("expected the rejected upgrade to fail")
    } catch let failure as ProxyUpstreamFailure {
      guard case .rejected = failure.kind else {
        return XCTFail("unexpected upstream failure kind: \(failure.kind)")
      }
      XCTAssertEqual(failure.message, "WebSocket upgrade rejected with 403")
    }
  }

  func testConnectTimesOutWhenUpgradeDoesNotRespond() async throws {
    let server = try LocalWebSocketServer(behavior: .stall)
    defer { server.stop() }

    let started = ContinuousClock.now
    do {
      _ = try await ProxyNIOWebSocketConnector.connect(
        url: URL(string: "ws://127.0.0.1:\(server.port)/socket")!,
        headers: [],
        maxFrameBytes: 64,
        timeout: .milliseconds(100)
      )
      XCTFail("expected the upgrade to time out")
    } catch let failure as ProxyUpstreamFailure {
      guard case .timeout = failure.kind else {
        return XCTFail("unexpected upstream failure kind: \(failure.kind)")
      }
      XCTAssertEqual(failure.message, "WebSocket upgrade timed out")
    }
    XCTAssertLessThan(started.duration(to: .now), .seconds(1))
  }

  func testConnectFailsWhenPeerClosesBeforeUpgradeResponseWithoutTimeout() async throws {
    let server = try LocalWebSocketServer(behavior: .closeBeforeResponse)
    defer { server.stop() }

    let completion = expectation(description: "connection completed")
    let result = AsyncTestResult<any ProxyUpstreamWebSocket>()
    let connection = Task {
      do {
        let socket = try await ProxyNIOWebSocketConnector.connect(
          url: URL(string: "ws://127.0.0.1:\(server.port)/socket")!,
          headers: [],
          maxFrameBytes: 64,
          timeout: nil
        )
        await result.set(.success(socket))
      } catch {
        await result.set(.failure(error))
      }
      completion.fulfill()
    }

    await fulfillment(of: [completion], timeout: 0.5)
    guard let outcome = await result.value else {
      connection.cancel()
      return XCTFail("connection remained pending after the peer closed")
    }
    switch outcome {
    case .success(let socket):
      await socket.close()
      XCTFail("connection unexpectedly succeeded")
    case .failure(let error):
      guard let failure = error as? ProxyUpstreamFailure else {
        return XCTFail("unexpected error: \(error)")
      }
      guard case .dial = failure.kind else {
        return XCTFail("unexpected upstream failure kind: \(failure.kind)")
      }
    }
  }

  func testConnectionPreservesFrameOrderWhenPeerClosesImmediately() async throws {
    let payloads = (0..<8_192).map { Data("frame-\($0)".utf8) }
    let server = try LocalWebSocketServer(
      behavior: .upgrade(
        selectedProtocol: nil,
        initialPayloads: payloads,
        closeAfterPayloads: true
      )
    )
    defer { server.stop() }

    let socket = try await ProxyNIOWebSocketConnector.connect(
      url: URL(string: "ws://127.0.0.1:\(server.port)/socket")!,
      headers: [],
      maxFrameBytes: FlowersecSDKDefaults.Proxy.maxWSFrameBytes,
      timeout: .seconds(1)
    )
    defer { Task { await socket.close() } }

    var received: [Data] = []
    do {
      for _ in payloads {
        received.append(try await socket.receive().payload)
      }
    } catch {
      XCTFail("connection closed after \(received.count) of \(payloads.count) frames: \(error)")
    }
    XCTAssertEqual(received, payloads)
  }

  func testConnectionClosesWhenBufferedInboundFramesExceedBudget() async throws {
    let payloads = (0..<96).map { Data(repeating: UInt8($0), count: 4) }
    let server = try LocalWebSocketServer(
      behavior: .upgrade(
        selectedProtocol: nil,
        initialPayloads: payloads,
        closeAfterPayloads: false
      )
    )
    defer { server.stop() }

    let socket = try await ProxyNIOWebSocketConnector.connect(
      url: URL(string: "ws://127.0.0.1:\(server.port)/socket")!,
      headers: [],
      maxFrameBytes: 4,
      timeout: .seconds(1)
    )
    defer { Task { await socket.close() } }

    try await Task.sleep(for: .milliseconds(100))
    var received: [Data] = []
    var terminalError: (any Error)?
    while received.count < payloads.count {
      do {
        received.append(try await socket.receive().payload)
      } catch {
        terminalError = error
        break
      }
    }
    XCTAssertFalse(received.isEmpty)
    XCTAssertLessThan(received.count, payloads.count)
    XCTAssertEqual(received, Array(payloads.prefix(received.count)))
    XCTAssertEqual(
      terminalError as? ProxyError,
      .stream("Upstream WebSocket receive buffer exceeded")
    )
  }

  func testConnectionEnforcesInboundAndOutboundFrameSize() async throws {
    let server = try LocalWebSocketServer(
      behavior: .upgrade(
        selectedProtocol: nil,
        initialPayloads: [Data("large".utf8)],
        closeAfterPayloads: false
      )
    )
    defer { server.stop() }

    let socket = try await ProxyNIOWebSocketConnector.connect(
      url: URL(string: "ws://127.0.0.1:\(server.port)/socket")!,
      headers: [],
      maxFrameBytes: 4,
      timeout: .seconds(1)
    )
    defer { Task { await socket.close() } }

    do {
      try await socket.send(ProxyWebSocketFrame(operation: .binary, payload: Data("large".utf8)))
      XCTFail("expected the outbound frame limit to reject the payload")
    } catch let error as ProxyError {
      XCTAssertEqual(error, .frameTooLarge)
    }

    do {
      _ = try await socket.receive()
      XCTFail("expected the inbound frame limit to close the connection")
    } catch {
      XCTAssertTrue(error is ProxyError)
    }
  }
}

private final class LocalWebSocketServer: @unchecked Sendable {
  enum Behavior: Sendable {
    case upgrade(
      selectedProtocol: String?,
      initialPayloads: [Data],
      closeAfterPayloads: Bool
    )
    case reject(status: Int, reason: String)
    case stall
    case closeBeforeResponse
  }

  let port: UInt16

  private let group: MultiThreadedEventLoopGroup
  private let serverChannel: any Channel
  private let state: LocalWebSocketServerState
  private let lock = NSLock()
  private var stopped = false

  var request: LocalWebSocketRequest? { state.request }

  init(behavior: Behavior, tlsContext: NIOSSLContext? = nil) throws {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let state = LocalWebSocketServerState()
    do {
      let channel = try ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.backlog, value: 1)
        .childChannelInitializer { channel in
          state.setChildChannel(channel)
          let tls =
            tlsContext.map { channel.pipeline.addHandler(NIOSSLServerHandler(context: $0)) }
            ?? channel.eventLoop.makeSucceededVoidFuture()
          return tls.flatMap {
            configureWebSocketTestChannel(channel, behavior: behavior, state: state)
          }
        }
        .bind(host: "127.0.0.1", port: 0)
        .wait()
      guard let port = channel.localAddress?.port else {
        try channel.close().wait()
        try group.syncShutdownGracefully()
        throw LocalWebSocketServerError.missingPort
      }
      self.group = group
      self.serverChannel = channel
      self.state = state
      self.port = UInt16(port)
    } catch {
      try? group.syncShutdownGracefully()
      throw error
    }
  }

  deinit {
    stop()
  }

  func stop() {
    let shouldStop = lock.withLock {
      guard !stopped else { return false }
      stopped = true
      return true
    }
    guard shouldStop else { return }
    try? state.childChannel?.close().wait()
    try? serverChannel.close().wait()
    try? group.syncShutdownGracefully()
  }
}

private struct LocalWebSocketRequest: Sendable {
  let uri: String
  let protocolHeader: String?
}

private final class LocalWebSocketServerState: @unchecked Sendable {
  private let lock = NSLock()
  private var capturedRequest: LocalWebSocketRequest?
  private var capturedChildChannel: (any Channel)?

  var request: LocalWebSocketRequest? {
    lock.withLock { capturedRequest }
  }

  var childChannel: (any Channel)? {
    lock.withLock { capturedChildChannel }
  }

  func capture(_ head: HTTPRequestHead) {
    lock.withLock {
      capturedRequest = LocalWebSocketRequest(
        uri: head.uri,
        protocolHeader: head.headers.first(name: "sec-websocket-protocol")
      )
    }
  }

  func setChildChannel(_ channel: any Channel) {
    lock.withLock { capturedChildChannel = channel }
  }
}

private enum LocalWebSocketServerError: Error {
  case missingPort
}

private func configureWebSocketTestChannel(
  _ channel: any Channel,
  behavior: LocalWebSocketServer.Behavior,
  state: LocalWebSocketServerState
) -> EventLoopFuture<Void> {
  switch behavior {
  case .upgrade(let selectedProtocol, let initialPayloads, let closeAfterPayloads):
    let upgrader = NIOWebSocketServerUpgrader(
      maxFrameSize: 1_024,
      automaticErrorHandling: true,
      shouldUpgrade: { channel, head in
        state.capture(head)
        var headers = HTTPHeaders()
        if let selectedProtocol {
          headers.add(name: "sec-websocket-protocol", value: selectedProtocol)
        }
        return channel.eventLoop.makeSucceededFuture(headers)
      },
      upgradePipelineHandler: { channel, _ in
        var writes = channel.eventLoop.makeSucceededVoidFuture()
        for payload in initialPayloads {
          writes = writes.flatMap {
            var buffer = channel.allocator.buffer(capacity: payload.count)
            buffer.writeBytes(payload)
            return channel.writeAndFlush(
              WebSocketFrame(fin: true, opcode: .text, data: buffer)
            )
          }
        }
        return closeAfterPayloads ? writes.flatMap { channel.close() } : writes
      }
    )
    let configuration: NIOHTTPServerUpgradeSendableConfiguration = (
      upgraders: [upgrader],
      completionHandler: { _ in }
    )
    return channel.pipeline.configureHTTPServerPipeline(
      withServerUpgrade: configuration
    )
  case .reject(let status, let reason):
    return channel.pipeline.configureHTTPServerPipeline().flatMap {
      channel.pipeline.addHandler(
        LocalHTTPResponseHandler(
          state: state,
          response: HTTPResponseStatus(statusCode: status, reasonPhrase: reason)
        )
      )
    }
  case .stall:
    return channel.pipeline.configureHTTPServerPipeline().flatMap {
      channel.pipeline.addHandler(LocalHTTPResponseHandler(state: state, response: nil))
    }
  case .closeBeforeResponse:
    return channel.pipeline.configureHTTPServerPipeline().flatMap {
      channel.pipeline.addHandler(
        LocalHTTPResponseHandler(state: state, response: nil, closeWithoutResponse: true)
      )
    }
  }
}

private final class LocalHTTPResponseHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = HTTPServerRequestPart
  typealias OutboundOut = HTTPServerResponsePart

  private let state: LocalWebSocketServerState
  private let response: HTTPResponseStatus?
  private let closeWithoutResponse: Bool

  init(
    state: LocalWebSocketServerState,
    response: HTTPResponseStatus?,
    closeWithoutResponse: Bool = false
  ) {
    self.state = state
    self.response = response
    self.closeWithoutResponse = closeWithoutResponse
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch unwrapInboundIn(data) {
    case .head(let head):
      state.capture(head)
    case .end:
      if closeWithoutResponse {
        context.close(promise: nil)
        return
      }
      guard let response else { return }
      var headers = HTTPHeaders()
      headers.add(name: "content-length", value: "0")
      context.write(
        wrapOutboundOut(
          .head(HTTPResponseHead(version: .http1_1, status: response, headers: headers))
        ),
        promise: nil
      )
      context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    case .body:
      break
    }
  }
}

private actor AsyncTestResult<Value: Sendable> {
  private(set) var value: Result<Value, any Error>?

  func set(_ value: Result<Value, any Error>) {
    self.value = value
  }
}

#endif
