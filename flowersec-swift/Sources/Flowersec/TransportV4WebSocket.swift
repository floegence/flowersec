#if os(macOS) || os(iOS)
  import Foundation
  import NIOCore
  import NIOHTTP1
  import NIOPosix
  import NIOSSL
  import NIOTLS
  import NIOWebSocket

  enum V4WebSocketFailure: Error, Sendable { case policy, upgrade, closed, capacity, canceled }

  // This provider prepares a dedicated native connection only. The private
  // constructor requires the actual TLS and HTTP upgrade path; it cannot mint
  // once-spend, a READY owner or a public Session. CA and pin policies come
  // only from the original authenticated candidate.
  final class V4PreparedWebSocket: @unchecked Sendable, V4HandshakeWriter, V4RecordPublisher {
    private let state: V4WebSocketState
    private init(_ state: V4WebSocketState) { self.state = state }

    static func prepare(
      route: V4WebSocketRoute, numericAddress: String,
      trustRootsPEM: [Data] = []
    ) async throws -> V4PreparedWebSocket {
      try route.check()
      guard numericAddress.utf8.count <= 64, trustRootsPEM.count <= 16,
        trustRootsPEM.reduce(0, { $0 + $1.count }) <= 262_144
      else { throw V4WebSocketFailure.policy }
      let endpoint = try SocketAddress(ipAddress: numericAddress, port: route.port)
      if let literal = try? SocketAddress(ipAddress: route.host, port: route.port),
        literal != endpoint
      {
        throw V4WebSocketFailure.policy
      }
      // DNS names retain their original TLS/HTTP identity while a trusted local
      // deployment chooses one numeric endpoint; this owner never starts DNS.
      guard (try? SocketAddress(ipAddress: route.host, port: route.port)) == nil else {
        throw V4WebSocketFailure.policy
      }
      var tls = TLSConfiguration.makeClientConfiguration()
      tls.minimumTLSVersion = .tlsv13
      tls.maximumTLSVersion = .tlsv13
      tls.certificateVerification = route.pins == nil ? .fullVerification : .noHostnameVerification
      tls.applicationProtocols = ["http/1.1"]
      if !trustRootsPEM.isEmpty {
        let roots = try trustRootsPEM.flatMap { try NIOSSLCertificate.fromPEMBytes(Array($0)) }
        guard !roots.isEmpty, roots.count <= 16 else { throw V4WebSocketFailure.policy }
        tls.trustRoots = .certificates(roots)
      }
      // SSL context creation can perform local trust-store I/O. Its admitted
      // native footprint is charged before construction and the callback tail.
      let charge = try route.environment.nativeConnectionStorage(maximumFrame: route.maximumFrame)
      let ssl = try NIOSSLContext(configuration: tls)
      let group = MultiThreadedEventLoopGroup.singleton
      let loop = group.any()
      let state = try V4WebSocketState(route: route, charge: charge, loop: loop)
      try route.environment.registerNativeConnection(state)
      let bootstrap = ClientBootstrap(group: group).connectTimeout(.seconds(10))
        .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 0)
        .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
        .channelOption(
          ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384)
        )
        .channelInitializer { channel in
          do {
            try state.attach(channel)
            let request = V4WebSocketUpgrade(state: state)
            let requestBox = NIOLoopBound(request, eventLoop: channel.eventLoop)
            let upgrader = NIOWebSocketClientUpgrader(
              maxFrameSize: route.maximumFrame + 8,
              automaticErrorHandling: true,
              upgradePipelineHandler: { channel, response in
                do {
                  try state.acceptUpgrade(response)
                  try channel.pipeline.syncOperations.addHandler(
                    NIOWebSocketFrameAggregator(
                      minNonFinalFragmentSize: 1, maxAccumulatedFrameCount: 1024,
                      maxAccumulatedFrameSize: route.maximumFrame + 8))
                  try channel.pipeline.syncOperations.addHandler(V4WebSocketFrames(state: state))
                  state.prepared()
                  return channel.eventLoop.makeSucceededVoidFuture()
                } catch {
                  state.fail(error)
                  return channel.eventLoop.makeFailedFuture(error)
                }
              })
            var limits = NIOHTTPDecoderLimitConfiguration()
            limits.maxHeaderFieldCount = 64
            limits.maxHeaderFieldSize = 4096
            limits.maxHeaderListSize = 16_384
            let tlsHandler: NIOSSLClientHandler
            if route.pins != nil {
              // This replaces PKI acceptance only. NIOSSL still verifies the
              // TLS 1.3 CertificateVerify/Finished proof on this native socket.
              tlsHandler = try NIOSSLClientHandler(
                context: ssl, serverHostname: route.host,
                customVerificationCallback: { certificates, promise in
                  do {
                    guard (1...16).contains(certificates.count), let leaf = certificates.first
                    else {
                      throw V4WebSocketFailure.policy
                    }
                    try state.verifyPinned(leaf)
                    promise.succeed(.certificateVerified)
                  } catch { promise.succeed(.failed) }
                })
            } else {
              tlsHandler = try NIOSSLClientHandler._makeSSLClientHandler(
                context: ssl, serverHostname: route.host,
                additionalPeerCertificateVerificationCallback: { certificate, channel in
                  guard V4NativeWebSocketTLS.matchesDNS(certificate, host: route.host) else {
                    return channel.eventLoop.makeFailedFuture(V4WebSocketFailure.policy)
                  }
                  do { try route.check() } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                  }
                  return channel.eventLoop.makeSucceededVoidFuture()
                })
            }
            try channel.pipeline.syncOperations.addHandler(tlsHandler)
            try channel.pipeline.syncOperations.addHTTPClientHandlers(
              leftOverBytesStrategy: .forwardBytes, decoderLimitConfiguration: limits,
              withClientUpgrade: (
                [upgrader],
                { _ in
                  channel.pipeline.removeHandler(requestBox.value, promise: nil)
                }
              ))
            try channel.pipeline.syncOperations.addHandler(request)
            return channel.eventLoop.makeSucceededVoidFuture()
          } catch {
            state.fail(error)
            return channel.eventLoop.makeFailedFuture(error)
          }
        }
      return try await withTaskCancellationHandler {
        do {
          _ = try await bootstrap.connect(to: endpoint).get()
          try await state.ready.futureResult.get()
          try state.check()
          if Task.isCancelled { throw V4WebSocketFailure.canceled }
          return V4PreparedWebSocket(state)
        } catch {
          state.fail(error)
          throw error
        }
      } onCancel: {
        state.cancel()
      }
    }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws { try publish(buffer) }
    func publish(_ buffer: V4CryptoBuffer) throws { try state.publish(buffer, opcode: .binary) }
    func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws {
      try state.publish(buffer, opcode: .binary, completion: completion)
    }
    func receive() async throws -> V4CryptoBuffer { try await state.receive() }
    func consumePool(using store: V4SQLitePoolStore) throws -> V4ConsumedWebSocket {
      do { return try store.consume(state.claimPool()) } catch {
        state.fail(error)
        throw error
      }
    }
    func close() { state.close() }
    func waitClosed() async { await state.waitClosed() }
    deinit { state.closePreparationAlias() }
  }

  private enum V4NativeWebSocketTLS {
    static func matchesDNS(_ certificate: NIOSSLCertificate, host: String) -> Bool {
      let target = host.lowercased().split(separator: ".", omittingEmptySubsequences: false)
      guard !target.isEmpty, target.allSatisfy({ !$0.isEmpty }) else { return false }
      for name in certificate._subjectAlternativeNames() where name.nameType == .dnsName {
        let bytes = name.contents.withUnsafeBufferPointer(Array.init)
        guard bytes.allSatisfy({ (33...126).contains($0) }) else { continue }
        let presented = String(decoding: bytes, as: UTF8.self).lowercased()
          .split(separator: ".", omittingEmptySubsequences: false)
        if presented == target { return true }
        if presented.count == target.count, presented.count >= 3, presented.first == "*",
          !target[0].hasPrefix("xn--"), presented.dropFirst() == target.dropFirst()
        {
          return true
        }
      }
      return false
    }
  }

  // Only the original completed native preparation can create this one-use
  // owner. Taking it permanently fences I/O through the preparation alias.
  final class V4PreparedPoolClaim: @unchecked Sendable {
    fileprivate let state: V4WebSocketState
    let environment: V4EnvironmentFoundation
    let facts: V4PoolSpendFacts
    let operationID: Data
    let carrierID: Data
    fileprivate init(_ state: V4WebSocketState) throws {
      self.state = state
      environment = state.route.environment
      facts = try state.route.credential.poolSpendFacts(in: environment)
      operationID = try V4Crypto.random(16)
      carrierID = try V4Crypto.random(16)
    }
    func check() throws { try state.checkAccess(self) }
    func publish(_ input: V4CryptoBuffer) throws {
      try state.publish(input, opcode: .binary, access: self)
    }
    func publish(_ input: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws {
      try state.publish(input, opcode: .binary, access: self, completion: completion)
    }
    func receive() async throws -> V4CryptoBuffer { try await state.receive(access: self) }
    func flush() async throws { try await state.flush(access: self) }
    func writable() throws -> Bool { try state.writable(access: self) }
    func wakeup(_ action: (@Sendable () -> Void)?) { state.setWakeup(action) }
    func recordCompletion(_ action: (@Sendable () throws -> Void)?) {
      state.setRecordCompletion(action)
    }
    func promote() throws { try state.promote(access: self) }
    func close() { state.close() }
    func waitClosed() async { await state.waitClosed() }
    deinit { state.close() }
  }

  private final class V4WebSocketState: V4NativeConnectionLifecycle, @unchecked Sendable {
    let route: V4WebSocketRoute
    let ready: EventLoopPromise<Void>
    private let charge: V4CryptoReservation
    private let lock: NSRecursiveLock
    private let eventLoop: any EventLoop
    private let pin: V4PinnedTLS?
    private let deadline: V4LocalWorkWindow
    private var channel: (any Channel)?
    private var physicalClose: EventLoopFuture<Void>?
    private var timer: Scheduled<Void>?
    private var queue: [V4CryptoBuffer] = []
    private var waiter: CheckedContinuation<V4CryptoBuffer, any Error>?
    private var writeWaiter: CheckedContinuation<Void, any Error>?
    private var wakeup: (@Sendable () -> Void)?
    private var recordCompletion: (@Sendable () throws -> Void)?
    private var failure: (any Error)?
    private var readyCompleted = false
    private var upgraded = false
    private var tlsFinished = false
    private var pendingWrites = 0
    private var consumptionStarted = false
    private weak var poolClaim: V4PreparedPoolClaim?
    private var established = false
    init(route: V4WebSocketRoute, charge: V4CryptoReservation, loop: any EventLoop) throws {
      self.route = route
      self.charge = charge
      self.lock = route.environment.gate
      eventLoop = loop
      pin = try route.pins == nil ? nil : V4PinnedTLS(route: route)
      deadline = try V4LocalWorkWindow(clock: route.environment.clock, durationMS: 10_000)
      ready = loop.makePromise(of: Void.self)
      queue.reserveCapacity(2)
      timer = loop.scheduleTask(in: .seconds(10)) { [self] in fail(V4TimeFailure.expired) }
    }
    func check() throws {
      try lock.withLock {
        if let failure { throw failure }
        try charge.check()
        try pin?.check(required: tlsFinished)
        if established {
          try route.credential.checkSessionAuthorization(in: route.environment)
        } else {
          try route.check()
          try deadline.check()
        }
        guard !upgraded || channel?.isActive == true else { throw V4WebSocketFailure.closed }
      }
    }
    func attach(_ channel: any Channel) throws {
      try lock.withLock {
        try check()
        guard self.channel == nil else { throw V4WebSocketFailure.policy }
        self.channel = channel
        physicalClose = channel.closeFuture
      }
    }
    func verifyPinned(_ certificate: NIOSSLCertificate) throws {
      guard let pin else { throw V4WebSocketFailure.policy }
      try pin.verify(certificate)
    }
    func checkAccess(_ claim: V4PreparedPoolClaim?) throws {
      try lock.withLock {
        try check()
        guard !consumptionStarted || (claim != nil && poolClaim === claim) else {
          throw V4CryptoFailure.phase
        }
      }
    }
    func claimPool() throws -> V4PreparedPoolClaim {
      try lock.withLock {
        try check()
        guard upgraded, !consumptionStarted, pendingWrites == 0, waiter == nil,
          queue.isEmpty, route.credential.source == .preauthorizedPool
        else { throw V4CryptoFailure.phase }
        let claim = try V4PreparedPoolClaim(self)
        consumptionStarted = true
        poolClaim = claim
        return claim
      }
    }
    func promote(access: V4PreparedPoolClaim) throws {
      try lock.withLock {
        try checkAccess(access)
        guard !established, pendingWrites == 0 else { throw V4CryptoFailure.phase }
        established = true
        deadline.cancel()
        timer?.cancel()
        timer = nil
      }
    }
    func writable(access: V4PreparedPoolClaim) throws -> Bool {
      try lock.withLock {
        try checkAccess(access)
        return pendingWrites < 2
      }
    }
    func setWakeup(_ action: (@Sendable () -> Void)?) { lock.withLock { wakeup = action } }
    func setRecordCompletion(_ action: (@Sendable () throws -> Void)?) {
      lock.withLock { recordCompletion = action }
    }
    func flush(access: V4PreparedPoolClaim) async throws {
      try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          do {
            try lock.withLock {
              try checkAccess(access)
              guard writeWaiter == nil else { throw V4WebSocketFailure.capacity }
              if pendingWrites == 0 { continuation.resume() } else { writeWaiter = continuation }
            }
          } catch { continuation.resume(throwing: error) }
        }
      } onCancel: {
        self.cancel()
      }
    }
    func tls(_ event: TLSUserEvent) throws {
      try lock.withLock {
        try check()
        guard case .handshakeCompleted(let negotiated) = event,
          negotiated == "http/1.1", !tlsFinished
        else { throw V4WebSocketFailure.policy }
        try pin?.check(required: true)
        tlsFinished = true
      }
    }
    func acceptUpgrade(_ response: HTTPResponseHead) throws {
      try lock.withLock {
        try check()
        guard tlsFinished, !upgraded, response.status == .switchingProtocols,
          response.headers["sec-websocket-protocol"] == [route.subprotocol],
          response.headers["sec-websocket-extensions"].isEmpty
        else { throw V4WebSocketFailure.upgrade }
        upgraded = true
      }
    }
    func prepared() {
      lock.withLock {
        guard failure == nil, upgraded, !readyCompleted else { return }
        readyCompleted = true
        ready.succeed(())
      }
    }
    func fail(_ error: any Error) {
      var socket: (any Channel)?
      var waiting: CheckedContinuation<V4CryptoBuffer, any Error>?
      var writing: CheckedContinuation<Void, any Error>?
      lock.withLock {
        guard failure == nil else { return }
        failure = error
        if !readyCompleted {
          readyCompleted = true
          ready.fail(error)
        }
        socket = channel
        channel = nil
        waiting = waiter
        waiter = nil
        writing = writeWaiter
        writeWaiter = nil
        for buffer in queue { buffer.close() }
        queue.removeAll()
        timer?.cancel()
        timer = nil
        deadline.cancel()
        charge.seal()
        wakeup?()
        wakeup = nil
        recordCompletion = nil
      }
      waiting?.resume(throwing: error)
      writing?.resume(throwing: error)
      socket?.close(promise: nil)
    }
    func close() { fail(V4WebSocketFailure.closed) }
    func cancel() {
      // Swift cancellation holds the task status lock. Defer the bounded
      // native close to avoid taking the owner gate while a completion resumes.
      eventLoop.execute { self.fail(V4WebSocketFailure.canceled) }
    }
    func closePreparationAlias() {
      lock.withLock { if !consumptionStarted { close() } }
    }
    func waitClosed() async {
      let closing = lock.withLock { physicalClose }
      if let closing { try? await closing.get() }
    }
    func publish(
      _ input: V4CryptoBuffer, opcode: WebSocketOpcode,
      access: V4PreparedPoolClaim? = nil, completion: (@Sendable (Bool) -> Void)? = nil
    ) throws {
      var enqueued = false
      do {
        try lock.withLock {
          try checkAccess(access)
          guard upgraded, let channel, pendingWrites < 2 else { throw V4WebSocketFailure.capacity }
          // Keep the original charged buffer through the actual NIO completion.
          let bytes = try input.withBytes { $0 }
          guard bytes.count <= route.maximumFrame + 8 else { throw V4WebSocketFailure.capacity }
          var data = channel.allocator.buffer(capacity: bytes.count)
          data.writeBytes(bytes)
          var generator = SystemRandomNumberGenerator()
          let frame = NIOWebSocket.WebSocketFrame(
            fin: true, opcode: opcode,
            maskKey: WebSocketMaskingKey.random(using: &generator), data: data)
          pendingWrites += 1
          enqueued = true
          channel.writeAndFlush(frame).whenComplete { [self, input] result in
            _ = input
            lock.withLock {
              pendingWrites -= 1
              switch result {
              case .success: completion?(true)
              case .failure: completion?(false)
              }
              if case .success = result {
                do {
                  try check()
                  // Record activity is ordered with Session gates before any
                  // waiter wakes. Native Ping/Pong and enqueue never qualify.
                  if established && opcode == .binary { try recordCompletion?() }
                } catch { fail(error) }
              }
              if pendingWrites == 0, let waiting = writeWaiter {
                writeWaiter = nil
                switch result {
                case .success: waiting.resume()
                case .failure(let error): waiting.resume(throwing: error)
                }
              }
              wakeup?()
            }
            if case .failure(let error) = result { fail(error) }
          }
        }
      } catch {
        if !enqueued { completion?(false) }
        fail(error)
        throw error
      }
    }
    func receive(access: V4PreparedPoolClaim? = nil) async throws -> V4CryptoBuffer {
      try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          do {
            try lock.withLock {
              try checkAccess(access)
              guard waiter == nil else { throw V4WebSocketFailure.capacity }
              if Task.isCancelled { throw V4WebSocketFailure.canceled }
              if !queue.isEmpty {
                continuation.resume(returning: queue.removeFirst())
              } else {
                waiter = continuation
              }
            }
          } catch { continuation.resume(throwing: error) }
        }
      } onCancel: {
        self.cancel()
      }
    }
    func input(_ frame: NIOWebSocket.WebSocketFrame) throws {
      try lock.withLock {
        try check()
        guard frame.fin, frame.maskKey == nil, !frame.rsv1, !frame.rsv2, !frame.rsv3,
          frame.data.readableBytes <= route.maximumFrame + 8
        else { throw V4WebSocketFailure.policy }
        if frame.opcode == .pong { return }
        if frame.opcode == .connectionClose { throw V4WebSocketFailure.closed }
        guard frame.opcode == .binary || frame.opcode == .ping else {
          throw V4WebSocketFailure.policy
        }
        if frame.opcode == .ping, frame.data.readableBytes > 125 { throw V4WebSocketFailure.policy }
        guard frame.opcode == .ping || waiter != nil || queue.count < 2 else {
          throw V4WebSocketFailure.capacity
        }
        let buffer = try route.environment.cryptoBuffer(
          capacity: frame.data.readableBytes,
          delivery: { [self] in try check() })
        try buffer.store(Data(frame.data.readableBytesView))
        if frame.opcode == .ping {
          try publish(buffer, opcode: .pong, access: poolClaim)
          return
        }
        if let waiter {
          self.waiter = nil
          waiter.resume(returning: buffer)
        } else {
          queue.append(buffer)
        }
      }
    }
  }

  private final class V4WebSocketUpgrade: ChannelInboundHandler, RemovableChannelHandler,
    @unchecked Sendable
  {
    typealias InboundIn = HTTPClientResponsePart
    typealias OutboundOut = HTTPClientRequestPart
    private let state: V4WebSocketState
    private var sent = false
    init(state: V4WebSocketState) { self.state = state }
    func handlerAdded(context: ChannelHandlerContext) {
      if context.channel.isActive { request(context) }
    }
    func channelActive(context: ChannelHandlerContext) {
      request(context)
      context.fireChannelActive()
    }
    private func request(_ context: ChannelHandlerContext) {
      guard !sent else { return }
      sent = true
      do {
        try state.check()
        let route = state.route
        var headers = HTTPHeaders([
          ("host", "\(route.host):\(route.port)"),
          ("sec-websocket-protocol", route.subprotocol),
        ])
        if let origin = route.origin { headers.add(name: "origin", value: origin) }
        context.write(
          wrapOutboundOut(
            .head(
              HTTPRequestHead(
                version: .http1_1, method: .GET,
                uri: route.path, headers: headers))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
      } catch { state.fail(error) }
    }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
      if let event = event as? TLSUserEvent {
        do { try state.tls(event) } catch { state.fail(error) }
      }
      context.fireUserInboundEventTriggered(event)
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      state.fail(V4WebSocketFailure.upgrade)
    }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { state.fail(error) }
    func channelInactive(context: ChannelHandlerContext) {
      state.close()
      context.fireChannelInactive()
    }
  }
  private final class V4WebSocketFrames: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NIOWebSocket.WebSocketFrame
    private let state: V4WebSocketState
    init(state: V4WebSocketState) { self.state = state }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      do { try state.input(unwrapInboundIn(data)) } catch { state.fail(error) }
    }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { state.fail(error) }
    func channelInactive(context: ChannelHandlerContext) {
      state.close()
      context.fireChannelInactive()
    }
  }
#endif
