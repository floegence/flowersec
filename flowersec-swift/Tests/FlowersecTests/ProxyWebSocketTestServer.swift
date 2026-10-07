#if os(macOS) || os(iOS)
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOWebSocket
@testable import Flowersec

/// Independent native WebSocket peer. Tests control each data and Close frame;
/// a successful write never fabricates the peer's reply or socket retirement.
final class ProxyWebSocketTestServer: @unchecked Sendable {
  private let gate = NSLock()
  private var listener: (any Channel)?
  private var client: (any Channel)?
  private var received: [ProxyWebSocketFrame] = []
  private var receivedBytes = 0
  private var closed = false
  private var failed = false
  private var portValue = 0
  var port: Int { gate.withLock { portValue } }

  static func start() async throws -> ProxyWebSocketTestServer {
    let state = ProxyWebSocketTestServer()
    let listener = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
      .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        state.gate.withLock { state.client = channel }
        let upgrader = NIOWebSocketServerUpgrader(maxFrameSize: 65_536, automaticErrorHandling: true,
          shouldUpgrade: { channel, _ in channel.eventLoop.makeSucceededFuture(HTTPHeaders()) },
          upgradePipelineHandler: { channel, _ in channel.pipeline.addHandler(ProxyWebSocketTestFrames(state)) })
        let configuration: NIOHTTPServerUpgradeSendableConfiguration = (upgraders: [upgrader], completionHandler: { _ in })
        return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: configuration)
      }
      .bind(host: "127.0.0.1", port: 0).get()
    guard let port = listener.localAddress?.port else {
      try? await listener.close().get(); throw SessionError.operationFailed
    }
    state.gate.withLock { state.listener = listener; state.portValue = port }
    return state
  }
  fileprivate func accept(_ value: WebSocketFrame) -> Bool {
    let operation: ProxyWebSocketOperation
    switch value.opcode {
    case .text: operation = .text
    case .binary: operation = .binary
    case .connectionClose: operation = .close
    case .ping: operation = .ping
    case .pong: operation = .pong
    default: gate.withLock { failed = true }; return false
    }
    let payload = Data(value.unmaskedData.readableBytesView)
    return gate.withLock {
      guard received.count < 16, payload.count <= 65_536 - receivedBytes else { failed = true; return false }
      received.append(ProxyWebSocketFrame(operation: operation, payload: payload)); receivedBytes += payload.count
      return true
    }
  }
  fileprivate func didClose() { gate.withLock { closed = true } }
  fileprivate func didFail() { gate.withLock { failed = true } }
  func send(_ operation: ProxyWebSocketOperation, _ payload: Data) async throws {
    guard let channel = gate.withLock({ client }), payload.count <= 65_536 else { throw SessionError.closed }
    let opcode: WebSocketOpcode
    switch operation {
    case .text: opcode = .text
    case .binary: opcode = .binary
    case .close: opcode = .connectionClose
    case .ping: opcode = .ping
    case .pong: opcode = .pong
    }
    try await channel.eventLoop.submit {
      var data = channel.allocator.buffer(capacity: payload.count); data.writeBytes(payload)
      return channel.writeAndFlush(WebSocketFrame(fin: true, opcode: opcode, data: data))
    }.flatMap { $0 }.get()
  }
  func waitInput(_ expected: [ProxyWebSocketFrame]) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while true {
      let state = gate.withLock { (received, failed) }
      guard !state.1 else { throw SessionError.operationFailed }
      if state.0 == expected { return }
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await Task.sleep(for: .milliseconds(5))
    }
  }
  func waitClosed() async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !gate.withLock({ closed }) {
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await Task.sleep(for: .milliseconds(5))
    }
  }
  func close() async {
    let channels = gate.withLock { (client, listener) }
    try? await channels.0?.close().get(); try? await channels.1?.close().get()
  }
}

private final class ProxyWebSocketTestFrames: ChannelInboundHandler {
  typealias InboundIn = WebSocketFrame
  private let state: ProxyWebSocketTestServer
  init(_ state: ProxyWebSocketTestServer) { self.state = state }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    if !state.accept(unwrapInboundIn(data)) { context.close(promise: nil) }
  }
  func channelInactive(context: ChannelHandlerContext) { state.didClose(); context.fireChannelInactive() }
  func errorCaught(context: ChannelHandlerContext, error: any Error) { state.didFail(); context.close(promise: nil) }
}

/// An application wrapper holds an entered callback after its real native read.
/// Cancellation cannot claim that callback exited before the application releases it.
final class ProxyWebSocketReceiveHold: @unchecked Sendable {
  private let gate = NSLock()
  private var entered = false
  private var released = false
  private var continuation: CheckedContinuation<Void, Never>?
  func hold() async {
    await withCheckedContinuation { next in
      let complete = gate.withLock {
        entered = true
        if released { return true }
        continuation = next; return false
      }
      if complete { next.resume() }
    }
  }
  func waitEntered() async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while !gate.withLock({ entered }) {
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await Task.sleep(for: .milliseconds(5))
    }
  }
  func release() {
    let original = gate.withLock { released = true; let value = continuation; continuation = nil; return value }
    original?.resume()
  }
}
struct ProxyHeldNativeUpstream: ProxyUpstream {
  let original: NativeProxyUpstream
  let hold: ProxyWebSocketReceiveHold
  func send(_ request: HTTPProxyRequest) async throws -> HTTPProxyResponse { try await original.send(request) }
  func openWebSocket(path: String, headers: [HTTPProxyField]) async throws -> any ProxyUpstreamSocket {
    ProxyHeldNativeSocket(original: try await original.openWebSocket(path: path, headers: headers), hold: hold)
  }
}
private struct ProxyHeldNativeSocket: ProxyUpstreamSocket {
  let original: any ProxyUpstreamSocket
  let hold: ProxyWebSocketReceiveHold
  var selectedProtocol: Data? { original.selectedProtocol }
  func send(_ message: ProxyWebSocketMessage) async throws { try await original.send(message) }
  func receive() async throws -> ProxyWebSocketMessage {
    let value = try await original.receive(); await hold.hold(); return value
  }
  func close() async { await original.close() }
}
#endif
