import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOWebSocket

protocol ProxyUpstreamWebSocket: Sendable {
  var selectedProtocol: String? { get }
  func send(_ frame: ProxyWebSocketFrame) async throws
  func receive() async throws -> ProxyWebSocketFrame
  func close() async
}

typealias ProxyUpstreamWebSocketFactory = @Sendable (
  URL, [ProxyHeader], Int, Duration?
) async throws -> any ProxyUpstreamWebSocket

enum ProxyNIOWebSocketConnector {
  static func connect(
    url: URL,
    headers: [ProxyHeader],
    maxFrameBytes: Int,
    timeout: Duration?
  ) async throws -> any ProxyUpstreamWebSocket {
    guard let scheme = url.scheme?.lowercased(), scheme == "ws" || scheme == "wss",
      let host = url.host
    else { throw ProxyError.invalidConfiguration("invalid WebSocket upstream URL") }
    let port = url.port ?? (scheme == "wss" ? 443 : 80)
    let group = MultiThreadedEventLoopGroup.singleton
    let timeoutMilliseconds = try timeout.map(proxyDurationMilliseconds)
    let upgrade = NIOPromiseBox(group.any().makePromise(of: Void.self))
    let socket = NIOPromiseBox(group.any().makePromise(of: NIOProxyUpstreamWebSocket.self))
    let authority = url.port == nil ? host : "\(host):\(port)"
    let path = url.path.isEmpty ? "/" : url.path
    let requestHeaders = HTTPHeaders(headers.map { ($0.name, $0.value) })

    var bootstrap = ClientBootstrap(group: group)
    if let timeout {
      bootstrap = bootstrap.connectTimeout(.milliseconds(try proxyDurationMilliseconds(timeout)))
    }
    bootstrap = bootstrap.channelInitializer { channel in
      let requestHandler = ProxyWebSocketUpgradeRequestHandler(
        authority: authority,
        path: path,
        query: url.query,
        headers: requestHeaders,
        upgrade: upgrade
      )
      let requestHandlerBox = NIOLoopBound(requestHandler, eventLoop: channel.eventLoop)
      let upgrader = NIOWebSocketClientUpgrader(
        maxFrameSize: maxFrameBytes,
        automaticErrorHandling: true,
        upgradePipelineHandler: { channel, response in
          let state = ProxyWebSocketInboundState()
          let connection = NIOProxyUpstreamWebSocket(
            channel: channel,
            state: state,
            selectedProtocol: response.headers.first(name: "sec-websocket-protocol"),
            maxFrameBytes: maxFrameBytes
          )
          let handler = ProxyRawWebSocketHandler(state: state)
          do {
            try channel.pipeline.syncOperations.addHandler(
              NIOWebSocketFrameAggregator(
                minNonFinalFragmentSize: 1,
                maxAccumulatedFrameCount: 1024,
                maxAccumulatedFrameSize: maxFrameBytes
              )
            )
            try channel.pipeline.syncOperations.addHandler(handler)
            socket.promise.succeed(connection)
            return channel.eventLoop.makeSucceededVoidFuture()
          } catch {
            return channel.eventLoop.makeFailedFuture(error)
          }
        }
      )
      let upgradeConfiguration: NIOHTTPClientUpgradeConfiguration = (
        upgraders: [upgrader],
        completionHandler: { _ in
          upgrade.promise.succeed(())
          channel.pipeline.removeHandler(requestHandlerBox.value, promise: nil)
        }
      )
      do {
        if scheme == "wss" {
          let context = try NIOSSLContext(configuration: .makeClientConfiguration())
          try channel.pipeline.syncOperations.addHandler(
            NIOSSLClientHandler(context: context, serverHostname: host)
          )
        }
        try channel.pipeline.syncOperations.addHTTPClientHandlers(
          leftOverBytesStrategy: .forwardBytes,
          withClientUpgrade: upgradeConfiguration
        )
        try channel.pipeline.syncOperations.addHandler(requestHandlerBox.value)
        return channel.eventLoop.makeSucceededVoidFuture()
      } catch {
        return channel.eventLoop.makeFailedFuture(error)
      }
    }

    let channel: any Channel
    do {
      channel = try await bootstrap.connect(host: host, port: port).get()
    } catch let error as ChannelError {
      if case .connectTimeout = error {
        throw ProxyUpstreamFailure(.timeout, error)
      }
      throw ProxyUpstreamFailure(.dial, error)
    } catch {
      throw ProxyUpstreamFailure(.dial, error)
    }
    let scheduledTimeout = timeoutMilliseconds.map { milliseconds in
      group.any().scheduleTask(in: .milliseconds(milliseconds)) {
        upgrade.promise.fail(
          ProxyUpstreamFailure(.timeout, message: "WebSocket upgrade timed out")
        )
      }
    }
    do {
      try await upgrade.promise.futureResult.get()
      scheduledTimeout?.cancel()
      return try await socket.promise.futureResult.get()
    } catch {
      scheduledTimeout?.cancel()
      let operation = error as? ProxyUpstreamFailure ?? ProxyUpstreamFailure(.dial, error)
      do {
        try await channel.close().get()
      } catch {
        throw ProxyUpstreamFailure(
          operation.kind,
          message: "\(operation.localizedDescription); channel close failed: \(error.localizedDescription)"
        )
      }
      throw operation
    }
  }
}

private final class NIOPromiseBox<Value: Sendable>: @unchecked Sendable {
  let promise: EventLoopPromise<Value>

  init(_ promise: EventLoopPromise<Value>) {
    self.promise = promise
  }
}

private final class ProxyWebSocketUpgradeRequestHandler: ChannelInboundHandler,
  RemovableChannelHandler, @unchecked Sendable
{
  typealias InboundIn = HTTPClientResponsePart
  typealias OutboundOut = HTTPClientRequestPart

  private let authority: String
  private let path: String
  private let query: String?
  private let headers: HTTPHeaders
  private let upgrade: NIOPromiseBox<Void>
  private var sent = false

  init(
    authority: String,
    path: String,
    query: String?,
    headers: HTTPHeaders,
    upgrade: NIOPromiseBox<Void>
  ) {
    self.authority = authority
    self.path = path
    self.query = query
    self.headers = headers
    self.upgrade = upgrade
  }

  func handlerAdded(context: ChannelHandlerContext) {
    if context.channel.isActive { sendRequest(context: context) }
  }

  func channelActive(context: ChannelHandlerContext) {
    sendRequest(context: context)
    context.fireChannelActive()
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let response = unwrapInboundIn(data)
    if case .head(let head) = response {
      upgrade.promise.fail(
        ProxyUpstreamFailure(
          .rejected,
          message: "WebSocket upgrade rejected with \(head.status.code)"
        )
      )
    }
    if case .end = response { context.close(promise: nil) }
  }

  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    upgrade.promise.fail(error)
    context.close(promise: nil)
  }

  private func sendRequest(context: ChannelHandlerContext) {
    guard !sent else { return }
    sent = true
    var headers = headers
    headers.replaceOrAdd(name: "host", value: authority)
    let uri = query.map { "\(path)?\($0)" } ?? path
    context.write(
      wrapOutboundOut(
        .head(
          HTTPRequestHead(
            version: .http1_1,
            method: .GET,
            uri: uri,
            headers: headers
          )
        )
      ),
      promise: nil
    )
    context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
  }
}

private final class ProxyRawWebSocketHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = NIOWebSocket.WebSocketFrame
  private let state: ProxyWebSocketInboundState

  init(state: ProxyWebSocketInboundState) {
    self.state = state
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    let operation: ProxyWebSocketOperation
    switch frame.opcode {
    case .text: operation = .text
    case .binary: operation = .binary
    case .connectionClose: operation = .close
    case .ping: operation = .ping
    case .pong: operation = .pong
    default:
      context.close(promise: nil)
      return
    }
    let payload = Data(frame.unmaskedData.readableBytesView)
    Task { await state.push(ProxyWebSocketFrame(operation: operation, payload: payload)) }
  }

  func channelInactive(context: ChannelHandlerContext) {
    Task { await state.finish(ProxyError.stream("Upstream WebSocket closed")) }
    context.fireChannelInactive()
  }

  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    Task { await state.finish(ProxyError.upstream(error.localizedDescription)) }
    context.close(promise: nil)
  }
}

private actor ProxyWebSocketInboundState {
  private var frames: [ProxyWebSocketFrame] = []
  private var waiters: [CheckedContinuation<ProxyWebSocketFrame, any Error>] = []
  private var failure: (any Error)?

  func push(_ frame: ProxyWebSocketFrame) {
    guard failure == nil else { return }
    if waiters.isEmpty { frames.append(frame) }
    else { waiters.removeFirst().resume(returning: frame) }
  }

  func receive() async throws -> ProxyWebSocketFrame {
    if !frames.isEmpty { return frames.removeFirst() }
    if let failure { throw failure }
    return try await withCheckedThrowingContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func finish(_ error: any Error) {
    guard failure == nil else { return }
    failure = error
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume(throwing: error) }
  }
}

private final class NIOProxyUpstreamWebSocket: ProxyUpstreamWebSocket, @unchecked Sendable {
  let selectedProtocol: String?
  private let channel: any Channel
  private let state: ProxyWebSocketInboundState
  private let maxFrameBytes: Int

  init(
    channel: any Channel,
    state: ProxyWebSocketInboundState,
    selectedProtocol: String?,
    maxFrameBytes: Int
  ) {
    self.channel = channel
    self.state = state
    self.selectedProtocol = selectedProtocol
    self.maxFrameBytes = maxFrameBytes
  }

  func send(_ frame: ProxyWebSocketFrame) async throws {
    guard frame.payload.count <= maxFrameBytes else { throw ProxyError.frameTooLarge }
    let operation: WebSocketOpcode
    switch frame.operation {
    case .text: operation = .text
    case .binary: operation = .binary
    case .close: operation = .connectionClose
    case .ping: operation = .ping
    case .pong: operation = .pong
    }
    var buffer = channel.allocator.buffer(capacity: frame.payload.count)
    buffer.writeBytes(frame.payload)
    var generator = SystemRandomNumberGenerator()
    let nioFrame = NIOWebSocket.WebSocketFrame(
      fin: true,
      opcode: operation,
      maskKey: WebSocketMaskingKey.random(using: &generator),
      data: buffer
    )
    do { try await channel.writeAndFlush(nioFrame).get() }
    catch { throw ProxyError.upstream(error.localizedDescription) }
  }

  func receive() async throws -> ProxyWebSocketFrame {
    try await state.receive()
  }

  func close() async {
    try? await channel.close().get()
  }
}
