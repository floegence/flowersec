#if os(macOS) || os(iOS)
import Foundation
import NIOCore
import NIOPosix
@testable import Flowersec

/// Local native peer with a real output half-close and a finite input budget.
/// The SDK under test owns the client descriptor; this peer is independent.
final class DuplexTCPTestServer: @unchecked Sendable {
  private let gate = NSLock()
  private var listener: (any Channel)?
  private var client: (any Channel)?
  private var received = Data()
  private var eof = false
  private var failure = false
  private var portValue = 0
  var port: Int { gate.withLock { portValue } }
  var input: Data { gate.withLock { received } }
  var inputEOF: Bool { gate.withLock { eof } }

  static func start() async throws -> DuplexTCPTestServer {
    let state = DuplexTCPTestServer()
    let listener = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
      .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
      .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
      .childChannelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 1024))
      .childChannelInitializer { channel in
        state.gate.withLock { state.client = channel }
        return channel.pipeline.addHandler(DuplexTCPTestFrames(state))
      }
      .bind(host: "127.0.0.1", port: 0).get()
    guard let port = listener.localAddress?.port else {
      try? await listener.close().get()
      throw SessionError.operationFailed
    }
    state.gate.withLock { state.listener = listener; state.portValue = port }
    return state
  }
  fileprivate func accept(_ bytes: ByteBuffer) -> Bool {
    gate.withLock {
      guard received.count + bytes.readableBytes <= 65_536 else { failure = true; return false }
      received.append(contentsOf: bytes.readableBytesView)
      return true
    }
  }
  fileprivate func halfClosed() { gate.withLock { eof = true } }
  fileprivate func failed() { gate.withLock { failure = true } }

  func waitInput(_ expected: Data, eof: Bool = false) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while true {
      let state = gate.withLock { (received, self.eof, failure) }
      guard !state.2 else { throw SessionError.operationFailed }
      if state.0 == expected, !eof || state.1 { return }
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }
  func send(_ bytes: Data, finish: Bool = false) async throws {
    guard let channel = gate.withLock({ client }) else { throw SessionError.closed }
    if !bytes.isEmpty {
      let future = channel.eventLoop.submit {
        var buffer = channel.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return channel.writeAndFlush(buffer)
      }.flatMap { $0 }
      try await future.get()
    }
    if finish { try await channel.close(mode: .output).get() }
  }
  func close() async {
    let channels = gate.withLock { (client, listener) }
    try? await channels.0?.close().get()
    try? await channels.1?.close().get()
  }
}

private final class DuplexTCPTestFrames: ChannelInboundHandler {
  typealias InboundIn = ByteBuffer
  private let state: DuplexTCPTestServer
  init(_ state: DuplexTCPTestServer) { self.state = state }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    if !state.accept(unwrapInboundIn(data)) { context.close(promise: nil) }
  }
  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let event = event as? ChannelEvent, case .inputClosed = event { state.halfClosed() }
    else { context.fireUserInboundEventTriggered(event) }
  }
  func errorCaught(context: ChannelHandlerContext, error: Error) {
    state.failed(); context.close(promise: nil)
  }
}
#endif
