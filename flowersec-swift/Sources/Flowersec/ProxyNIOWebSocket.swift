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
    timeout: Duration?,
    trustRoots: [NIOSSLCertificate]? = nil
  ) async throws -> any ProxyUpstreamWebSocket {
    guard let scheme = url.scheme?.lowercased(), scheme == "ws" || scheme == "wss",
      let host = url.host
    else { throw ProxyError.invalidConfiguration("invalid WebSocket upstream URL") }
    let port = url.port ?? (scheme == "wss" ? 443 : 80)
    let group = MultiThreadedEventLoopGroup.singleton
    let timeoutMilliseconds = try timeout.map(proxyDurationMilliseconds)
    let connection = NIOPromiseBox(
      group.any().makePromise(of: NIOProxyUpstreamWebSocket.self)
    )
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
        connection: connection
      )
      let requestHandlerBox = NIOLoopBound(requestHandler, eventLoop: channel.eventLoop)
      let upgrader = NIOWebSocketClientUpgrader(
        maxFrameSize: maxFrameBytes,
        automaticErrorHandling: true,
        upgradePipelineHandler: { channel, response in
          let state = ProxyWebSocketInboundState(
            maxBufferedBytes: proxyWebSocketInboundBufferBytes(maxFrameBytes: maxFrameBytes)
          )
          let socket = NIOProxyUpstreamWebSocket(
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
            connection.succeed(socket)
            return channel.eventLoop.makeSucceededVoidFuture()
          } catch {
            connection.fail(error)
            return channel.eventLoop.makeFailedFuture(error)
          }
        }
      )
      let upgradeConfiguration: NIOHTTPClientUpgradeConfiguration = (
        upgraders: [upgrader],
        completionHandler: { _ in
          channel.pipeline.removeHandler(requestHandlerBox.value, promise: nil)
        }
      )
      do {
        if scheme == "wss" {
          var tls = TLSConfiguration.makeClientConfiguration()
          tls.minimumTLSVersion = .tlsv13
          if let trustRoots { tls.trustRoots = .certificates(trustRoots) }
          let context = try NIOSSLContext(configuration: tls)
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
        connection.fail(
          ProxyUpstreamFailure(.timeout, message: "WebSocket upgrade timed out")
        )
      }
    }
    do {
      let socket = try await connection.promise.futureResult.get()
      scheduledTimeout?.cancel()
      return socket
    } catch {
      scheduledTimeout?.cancel()
      let operation = error as? ProxyUpstreamFailure ?? ProxyUpstreamFailure(.dial, error)
      try? await channel.close().get()
      throw operation
    }
  }
}

private func proxyWebSocketInboundBufferBytes(maxFrameBytes: Int) -> Int {
  let (scaled, overflow) = maxFrameBytes.multipliedReportingOverflow(by: 64)
  return max(
    maxFrameBytes,
    min(
      overflow ? FlowersecSDKDefaults.Proxy.maxBodyBytes : scaled,
      FlowersecSDKDefaults.Proxy.maxBodyBytes
    )
  )
}

private final class NIOPromiseBox<Value: Sendable>: @unchecked Sendable {
  let promise: EventLoopPromise<Value>
  private let lock = NSLock()
  private var completed = false

  init(_ promise: EventLoopPromise<Value>) {
    self.promise = promise
  }

  func succeed(_ value: Value) {
    guard beginCompletion() else { return }
    promise.succeed(value)
  }

  func fail(_ error: any Error) {
    guard beginCompletion() else { return }
    promise.fail(error)
  }

  private func beginCompletion() -> Bool {
    lock.withLock {
      guard !completed else { return false }
      completed = true
      return true
    }
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
  private let connection: NIOPromiseBox<NIOProxyUpstreamWebSocket>
  private var sent = false

  init(
    authority: String,
    path: String,
    query: String?,
    headers: HTTPHeaders,
    connection: NIOPromiseBox<NIOProxyUpstreamWebSocket>
  ) {
    self.authority = authority
    self.path = path
    self.query = query
    self.headers = headers
    self.connection = connection
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
      connection.fail(
        ProxyUpstreamFailure(
          .rejected,
          message: "WebSocket upgrade rejected with \(head.status.code)"
        )
      )
    }
    if case .end = response { context.close(promise: nil) }
  }

  func channelInactive(context: ChannelHandlerContext) {
    connection.fail(
      ProxyUpstreamFailure(
        .dial,
        message: "WebSocket connection closed before the upgrade response"
      )
    )
    context.fireChannelInactive()
  }

  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    connection.fail(error)
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
    if !state.push(ProxyWebSocketFrame(operation: operation, payload: payload)) {
      context.close(promise: nil)
    }
  }

  func channelInactive(context: ChannelHandlerContext) {
    state.finish(ProxyError.stream("Upstream WebSocket closed"))
    context.fireChannelInactive()
  }

  func errorCaught(context: ChannelHandlerContext, error: any Error) {
    state.finish(ProxyError.upstream(error.localizedDescription))
    context.close(promise: nil)
  }
}

private final class ProxyWebSocketInboundState: @unchecked Sendable {
  private struct BufferedFrame {
    let frame: ProxyWebSocketFrame
    let bytes: Int
  }

  private let lock = NSLock()
  private let maxBufferedBytes: Int
  private var frames: [BufferedFrame] = []
  private var bufferedBytes = 0
  private var waiters: [CheckedContinuation<ProxyWebSocketFrame, any Error>] = []
  private var failure: (any Error)?

  init(maxBufferedBytes: Int) {
    self.maxBufferedBytes = maxBufferedBytes
  }

  func push(_ frame: ProxyWebSocketFrame) -> Bool {
    var waiter: CheckedContinuation<ProxyWebSocketFrame, any Error>?
    let frameBytes = max(1, frame.payload.count)
    let accepted = lock.withLock { () -> Bool in
      guard failure == nil else { return false }
      if !waiters.isEmpty {
        waiter = waiters.removeFirst()
        return true
      }
      guard frameBytes <= maxBufferedBytes - bufferedBytes else {
        failure = ProxyError.stream("Upstream WebSocket receive buffer exceeded")
        return false
      }
      frames.append(BufferedFrame(frame: frame, bytes: frameBytes))
      bufferedBytes += frameBytes
      return true
    }
    waiter?.resume(returning: frame)
    return accepted
  }

  func receive() async throws -> ProxyWebSocketFrame {
    return try await withCheckedThrowingContinuation { continuation in
      var frame: ProxyWebSocketFrame?
      var terminalError: (any Error)?
      lock.withLock {
        if !frames.isEmpty {
          let buffered = frames.removeFirst()
          bufferedBytes -= buffered.bytes
          frame = buffered.frame
        } else if let failure {
          terminalError = failure
        } else {
          waiters.append(continuation)
        }
      }
      if let frame {
        continuation.resume(returning: frame)
      } else if let terminalError {
        continuation.resume(throwing: terminalError)
      }
    }
  }

  func finish(_ error: any Error) {
    let current = lock.withLock { () -> [CheckedContinuation<ProxyWebSocketFrame, any Error>] in
      guard failure == nil else { return [] }
      failure = error
      let current = waiters
      waiters.removeAll()
      return current
    }
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
