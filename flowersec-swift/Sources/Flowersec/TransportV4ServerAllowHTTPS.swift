#if os(macOS) || os(iOS)
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import Security

/// An independently configured mutual TLS endpoint. The exact authority client
/// certificate is pinned before any server-allow body reaches the recipient.
public struct TransportServerAllowHTTPSConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let numericAddress: String
  public let port: Int
  public let serverTLS: NativeListenerTLSConfiguration
  public let authorityClientCertificateDER: Data
  public let timeoutMilliseconds: UInt64
  public init(numericAddress: String, port: Int, serverTLS: NativeListenerTLSConfiguration,
    authorityClientCertificateDER: Data, timeoutMilliseconds: UInt64 = 10_000) {
    self.numericAddress = numericAddress; self.port = port; self.serverTLS = serverTLS
    self.authorityClientCertificateDER = authorityClientCertificateDER; self.timeoutMilliseconds = timeoutMilliseconds
  }
  public var description: String { "Flowersec.ServerAllowHTTPSConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

// The native write completion, rather than an HTTP receive or serialized
// receipt, publishes the still-original prepared material into its Source.
final class V4ServerAllowAcknowledgement: @unchecked Sendable {
  let check: @Sendable () throws -> Void
  private let written: @Sendable () throws -> Void
  private let gate = NSLock()
  private var used = false
  init(check: @escaping @Sendable () throws -> Void, written: @escaping @Sendable () throws -> Void) {
    self.check = check; self.written = written
  }
  func completeWrite() throws {
    try gate.withLock { guard !used else { throw V4CryptoFailure.phase }; try check(); used = true; try written() }
  }
}

// One native HTTP request has one completion observation. The original ACK
// owner may attach before preparation finishes; failure and disconnect follow
// the same physical retirement path as a successfully written acknowledgement.
final class V4ServerAllowRequestCleanup: @unchecked Sendable {
  private let gate = NSLock()
  private var completion: (@Sendable () -> Void)?
  private var completed = false
  func observeCompletion(_ operation: @escaping @Sendable () -> Void) {
    let immediate = gate.withLock {
      if completed { return true }
      precondition(completion == nil)
      completion = operation
      return false
    }
    if immediate { operation() }
  }
  func complete() {
    let operation = gate.withLock { () -> (@Sendable () -> Void)? in
      guard !completed else { return nil }
      completed = true
      defer { completion = nil }
      return completion
    }
    operation?()
  }
}

final class V4ServerAllowHTTPS: V4NativeConnectionLifecycle, @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  let configuration: TransportServerAllowHTTPSConfiguration
  let receive: @Sendable (Data) async throws -> V4ServerAllowAcknowledgement
  let requestPaths: Set<String>
  let maximumRequestBytes: Int
  let minimumRequestIntervalMS: UInt64
  let receiveAtPath: (@Sendable (String, Data) async throws -> V4ServerAllowAcknowledgement)?
  let receiveWithCleanup: (@Sendable (Data, V4ServerAllowRequestCleanup) async throws -> V4ServerAllowAcknowledgement)?
  private let storage: V4CryptoReservation
  private let cleanupJoin: V4CleanupJoin
  private let cleanupEvents = V4SessionEvents(maximum: 4)
  private var listener: (any Channel)?
  private var active: V4ServerAllowHTTPCall?
  private var starting = false
  private var listenerJoined = true
  private var closed = false
  private var lastRequest: V4ClockMark?
  init(environment: V4EnvironmentFoundation, configuration: TransportServerAllowHTTPSConfiguration,
    requestPaths: Set<String> = ["/tunnel/server-allow"], maximumRequestBytes: Int = 10_326, minimumRequestIntervalMS: UInt64 = 100,
    receiveAtPath: (@Sendable (String, Data) async throws -> V4ServerAllowAcknowledgement)? = nil,
    receiveWithCleanup: (@Sendable (Data, V4ServerAllowRequestCleanup) async throws -> V4ServerAllowAcknowledgement)? = nil,
    receive: @escaping @Sendable (Data) async throws -> V4ServerAllowAcknowledgement) throws {
    let c = configuration
    guard !requestPaths.isEmpty, requestPaths.count <= 4, requestPaths.allSatisfy({ $0.hasPrefix("/tunnel/") && $0.utf8.count <= 64 }),
      (1...24_576).contains(maximumRequestBytes) else { throw TransportControlError.invalidConfiguration }
    guard (1...65535).contains(c.port), (1...30_000).contains(c.timeoutMilliseconds),
      (try? SocketAddress(ipAddress: c.numericAddress, port: c.port)) != nil,
      (1...65_536).contains(c.serverTLS.certificateChainPEM.count), (1...16_384).contains(c.serverTLS.privateKeyPEM.count),
      (1...16_384).contains(c.authorityClientCertificateDER.count) else { throw TransportControlError.invalidConfiguration }
    self.environment = environment; self.configuration = c; self.receive = receive
    self.requestPaths = requestPaths; self.maximumRequestBytes = maximumRequestBytes; self.minimumRequestIntervalMS = minimumRequestIntervalMS; self.receiveAtPath = receiveAtPath
    self.receiveWithCleanup = receiveWithCleanup
    storage = try environment.serverAllowHTTPSStorage(bytes: c.serverTLS.certificateChainPEM.count + c.serverTLS.privateKeyPEM.count + c.authorityClientCertificateDER.count)
    cleanupJoin = try V4CleanupJoin(environment: environment)
    _ = try NIOSSLCertificate(bytes: Array(c.authorityClientCertificateDER), format: .der)
    try environment.registerNativeConnection(self)
  }
  func start() async throws {
    try await withTaskCancellationHandler(operation: {
      try await startPhysical()
    }, onCancel: { [weak self] in
      // Bind may be suspended in NIO while no Channel has been published yet.
      // Close seals the owner immediately; startPhysical then closes any late
      // bound channel before returning, so cancellation cannot leak a listener
      // or publish a usable server after the caller has gone away.
      self?.close()
    })
  }
  private func startPhysical() async throws {
    try environment.gate.withLock {
      guard !closed, !starting, listener == nil else { throw TransportControlError.closed }
      try storage.check(); starting = true
    }
    defer { environment.gate.withLock { starting = false }; cleanupEvents.signal() }
    do {
      let bound = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
        .serverChannelOption(ChannelOptions.backlog, value: 1)
        .serverChannelOption(ChannelOptions.autoRead, value: false)
        .serverChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
        .serverChannelInitializer { [self] channel in
          do {
            let tail = try storage.executionTail()
            environment.gate.withLock { listener = channel; listenerJoined = false }
            channel.closeFuture.whenComplete { [self] _ in
              environment.gate.withLock { listener = nil; listenerJoined = true }; tail.release(); cleanupEvents.signal()
            }
            try environment.gate.withLock { guard !closed else { throw TransportControlError.closed }; try storage.check() }
            return channel.eventLoop.makeSucceededVoidFuture()
          } catch { channel.close(promise: nil); return channel.eventLoop.makeFailedFuture(error) }
        }
        .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
        .childChannelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384))
        .childChannelInitializer { [self] channel in
          do {
            let call = try environment.gate.withLock { () throws -> V4ServerAllowHTTPCall in
              guard !closed, let active else { throw TransportControlError.closed }; return active
            }
            return try call.attach(channel)
          } catch { channel.close(promise: nil); return channel.eventLoop.makeFailedFuture(error) }
        }
        .bind(to: SocketAddress(ipAddress: configuration.numericAddress, port: configuration.port)).get()
      do {
        try environment.gate.withLock { guard !closed, listener === bound else { throw TransportControlError.closed }; try arm() }
      } catch {
        // Close can win while bind is suspended, before the initializer has
        // published the listener. Always retire the returned physical channel
        // and wait for its close tail before propagating cancellation.
        bound.close(promise: nil)
        try? await bound.closeFuture.get()
        throw error
      }
    } catch { close(); throw error }
  }
  private func arm() throws {
    guard !closed, active == nil, let listener else { return }
    try storage.check()
    // One physical child slot is prepaid before accepting a socket. No
    // continuous autoRead or callback queue can allocate extra TLS owners.
    active = try V4ServerAllowHTTPCall(owner: self)
    listener.read()
  }
  func admitRequest() throws {
    try environment.gate.withLock {
      guard !closed else { throw TransportControlError.closed }; try storage.check()
      let now = try environment.clock.mark()
      if let lastRequest {
        guard now.sameEra(as: lastRequest), now.milliseconds >= lastRequest.milliseconds,
          try environment.clock.profile.elapsed(now.milliseconds - lastRequest.milliseconds).lowerMS >= minimumRequestIntervalMS
        else { throw TransportControlError.busy }
      }
      lastRequest = now
    }
  }
  fileprivate func retire(_ call: V4ServerAllowHTTPCall) {
    environment.gate.withLock {
      guard active === call else { return }; active = nil
      do { try arm() } catch { close() }
    }
    cleanupEvents.signal()
  }
  func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true
      cleanupJoin.beginClose()
      listener?.close(promise: nil); active?.close(); storage.seal()
    }
    cleanupEvents.signal()
  }
  func cleanupStatus() -> CleanupStatus {
    cleanupJoin.status(physicalCleanupStatus())
  }
  private func physicalCleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let count = (starting ? 1 : 0) + (listenerJoined ? 0 : 1) + (active == nil ? 0 : 1)
      return CleanupStatus(complete: closed && count == 0, cleanupIncomplete: closed && count != 0, pendingCallbacks: UInt64(count))
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    try await cleanupJoin.wait { [self] in await waitPhysicalCleanup() }
    return cleanupStatus()
  }
  func waitPhysicalCleanup() async {
    while true {
      let revision = cleanupEvents.revision
      if physicalCleanupStatus().complete { return }
      try? await cleanupEvents.wait(after: revision)
    }
  }
  deinit { close() }
}

fileprivate final class V4ServerAllowHTTPCall: @unchecked Sendable {
  private let owner: V4ServerAllowHTTPS
  private let storage: V4CryptoReservation
  private let tail: V4ResourceReference
  private let requestCleanup = V4ServerAllowRequestCleanup()
  private var gate: NSRecursiveLock { owner.environment.gate }
  private var channel: (any Channel)?
  private var channelJoined = true
  private var timerJoined = true
  private var writeJoined = true
  private var task: Task<Void, Never>?
  private var timer: Scheduled<Void>?
  private var window: V4LocalWorkWindow?
  private var peerVerified = false
  private var authenticated = false
  private var path: String?
  private var expected: Int?
  private var body = Data()
  private var ended = false
  private var closed = false
  private var retired = false
  init(owner: V4ServerAllowHTTPS) throws {
    self.owner = owner
    storage = try owner.environment.controlHTTPCallStorage(maximumBytes: 1, requestBytes: owner.maximumRequestBytes)
    tail = try storage.executionTail()
    body.reserveCapacity(owner.maximumRequestBytes)
  }
  func attach(_ channel: any Channel) throws -> EventLoopFuture<Void> {
    try gate.withLock {
      guard !closed, self.channel == nil else { throw TransportControlError.closed }
      self.channel = channel; channelJoined = false
    }
    channel.closeFuture.whenComplete { [self] _ in gate.withLock { self.channel = nil; channelJoined = true }; retireIfJoined() }
    do {
      let c = owner.configuration
      window = try V4LocalWorkWindow(clock: owner.environment.clock, durationMS: c.timeoutMilliseconds)
      let certificates = try NIOSSLCertificate.fromPEMBytes(Array(c.serverTLS.certificateChainPEM))
      guard (1...8).contains(certificates.count) else { throw TransportControlError.invalidConfiguration }
      var config = TLSConfiguration.makeServerConfiguration(certificateChain: certificates.map { .certificate($0) },
        privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(c.serverTLS.privateKeyPEM), format: .pem)))
      config.minimumTLSVersion = .tlsv13; config.maximumTLSVersion = .tlsv13
      config.applicationProtocols = ["http/1.1"]; config.certificateVerification = .noHostnameVerification
      config.trustRoots = .certificates([try NIOSSLCertificate(bytes: Array(c.authorityClientCertificateDER), format: .der)])
      // A fresh context prevents a ticket from another connection from
      // bypassing this connection's independently pinned client identity.
      let tls = try NIOSSLContext(configuration: config)
      let handler = NIOSSLServerHandler(context: tls, customVerificationCallback: { [self] certificates, promise in
        do { try verifyPeer(certificates); promise.succeed(.certificateVerified) }
        catch { promise.succeed(.failed) }
      })
      var limits = NIOHTTPDecoderLimitConfiguration()
      limits.maxHeaderFieldCount = 32; limits.maxHeaderFieldSize = 1024; limits.maxHeaderListSize = 8192
      try channel.pipeline.syncOperations.addHandler(handler)
      let pipeline = channel.pipeline.configureHTTPServerPipeline(withPipeliningAssistance: false, withErrorHandling: true,
        withDecoderLimitConfiguration: limits)
      return pipeline.flatMapThrowing { [self] in
        try channel.pipeline.syncOperations.addHandler(V4ServerAllowHTTPHandler(owner: self))
        let timerTail = try storage.executionTail()
        gate.withLock { timerJoined = false }
        let timer = channel.eventLoop.scheduleTask(in: .milliseconds(Int64(c.timeoutMilliseconds))) { [self] in close() }
        gate.withLock { self.timer = timer }
        timer.futureResult.whenComplete { [self] _ in timerTail.release(); gate.withLock { timerJoined = true }; retireIfJoined() }
      }
    } catch { close(); throw error }
  }
  private func check() throws {
    guard !closed else { throw TransportControlError.closed }
    try storage.check(); try window?.check()
  }
  private func verifyPeer(_ certificates: [NIOSSLCertificate]) throws {
    try gate.withLock {
      try check()
      guard !peerVerified, (1...8).contains(certificates.count) else { throw V4CryptoFailure.authentication }
      let encoded = try certificates.map { Data(try $0.toDERBytes()) }
      guard encoded.first == owner.configuration.authorityClientCertificateDER,
        encoded.reduce(0, { $0 + $1.count }) <= 131_072 else { throw V4CryptoFailure.authentication }
      let chain = try encoded.map { bytes in
        guard let value = SecCertificateCreateWithData(nil, bytes as CFData) else { throw V4CryptoFailure.authentication }; return value
      }
      let sample = owner.environment.clock.sample()
      guard let interval = sample.interval, let leaf = certificates.first else { throw sample.failure ?? V4TimeFailure.unavailable }
      guard leaf.notValidBefore >= 0, leaf.notValidAfter > leaf.notValidBefore,
        UInt64(leaf.notValidAfter) <= UInt64.max / 1000,
        UInt64(leaf.notValidBefore) * 1000 <= interval.lowerMS, interval.upperMS < UInt64(leaf.notValidAfter) * 1000
      else { throw V4CryptoFailure.authentication }
      var trust: SecTrust?
      guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateSSL(false, nil), &trust) == errSecSuccess, let trust,
        SecTrustSetAnchorCertificates(trust, [chain[0]] as CFArray) == errSecSuccess,
        SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
        SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { throw V4CryptoFailure.authentication }
      for milliseconds in [interval.lowerMS, interval.upperMS] {
        guard SecTrustSetVerifyDate(trust, Date(timeIntervalSince1970: Double(milliseconds) / 1000) as CFDate) == errSecSuccess,
          SecTrustEvaluateWithError(trust, nil) else { throw V4CryptoFailure.authentication }
      }
      try check(); peerVerified = true
    }
  }
  func tlsCompleted(_ event: TLSUserEvent) throws {
    try gate.withLock {
      try check()
      guard !authenticated, peerVerified, case .handshakeCompleted(let protocolName) = event, protocolName == "http/1.1" else {
        throw V4CryptoFailure.authentication
      }
      authenticated = true
    }
  }
  func receive(_ part: HTTPServerRequestPart) throws {
    try gate.withLock {
      try check()
      guard authenticated, peerVerified, !ended else { throw V4CryptoFailure.authentication }
      switch part {
      case .head(let head):
        try owner.admitRequest()
        let lengths = head.headers["content-length"]
        guard expected == nil, head.method == .POST, owner.requestPaths.contains(head.uri), head.version == .http1_1,
          head.headers["content-type"] == ["application/cbor"], lengths.count == 1,
          let count = Int(lengths[0]), String(count) == lengths[0], (1...owner.maximumRequestBytes).contains(count),
          ["transfer-encoding", "content-encoding", "cookie", "authorization", "trailer", "expect", "upgrade"].allSatisfy({ head.headers[$0].isEmpty })
        else { throw TransportControlError.responseInvalid }
        expected = count; path = head.uri
      case .body(let buffer):
        guard let expected, body.count <= expected, buffer.readableBytes <= expected - body.count else { throw TransportControlError.responseInvalid }
        body.append(contentsOf: buffer.readableBytesView)
      case .end(let trailers):
        guard trailers == nil, let expected, body.count == expected, let channel else { throw TransportControlError.responseInvalid }
        guard let path else { throw TransportControlError.responseInvalid }
        ended = true; let bytes = body
        let taskTail = try storage.executionTail()
        let operation = Task { [self] in
          defer { taskTail.release(); gate.withLock { task = nil }; retireIfJoined() }
          do {
            try Task.checkCancellation(); try gate.withLock { try check() }
            let acknowledgement: V4ServerAllowAcknowledgement
            if let receive = owner.receiveAtPath { acknowledgement = try await receive(path, bytes) }
            else if let receive = owner.receiveWithCleanup { acknowledgement = try await receive(bytes, requestCleanup) }
            else { acknowledgement = try await owner.receive(bytes) }
            try Task.checkCancellation(); try gate.withLock { try check() }; try acknowledgement.check()
            // No second request or body can occupy the original slot while
            // publication and the final native ACK write remain unfinished.
            let writeTail = try storage.executionTail()
            gate.withLock { writeJoined = false }
            let write = channel.eventLoop.submit { [self] () throws -> EventLoopFuture<Void> in
              try gate.withLock { try check() }; try acknowledgement.check()
              let promise = channel.eventLoop.makePromise(of: Void.self)
              let headers = HTTPHeaders([("Content-Type", "application/cbor"), ("Cache-Control", "no-store"),
                ("Content-Length", "1"), ("Connection", "close")])
              channel.write(HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)), promise: nil)
              var body = channel.allocator.buffer(capacity: 1); body.writeInteger(UInt8(0xf5))
              channel.write(HTTPServerResponsePart.body(.byteBuffer(body)), promise: nil)
              channel.writeAndFlush(HTTPServerResponsePart.end(nil), promise: promise)
              return promise.futureResult.flatMapThrowing { [self] in
                try gate.withLock { try check() }; try acknowledgement.completeWrite()
              }
            }.flatMap { $0 }
            write.whenComplete { [self] _ in writeTail.release(); gate.withLock { writeJoined = true }; retireIfJoined() }
            try await write.get()
            close()
          } catch { close() }
        }
        task = operation
      }
    }
  }
  func close() {
    gate.withLock {
      guard !closed else { return }; closed = true; window?.cancel(); task?.cancel(); timer?.cancel(); timer = nil
      channel?.close(promise: nil); storage.seal()
    }
    retireIfJoined()
  }
  private func retireIfJoined() {
    let joined = gate.withLock { () -> Bool in
      guard closed, channelJoined, timerJoined, writeJoined, task == nil, !retired else { return false }
      retired = true; return true
    }
    if joined { tail.release(); owner.retire(self); requestCleanup.complete() }
  }
  deinit { tail.release() }
}

private final class V4ServerAllowHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = HTTPServerRequestPart
  private let owner: V4ServerAllowHTTPCall
  init(owner: V4ServerAllowHTTPCall) { self.owner = owner }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    do { try owner.receive(unwrapInboundIn(data)) } catch { owner.close() }
  }
  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
      do { try owner.tlsCompleted(event) } catch { owner.close() }
    }
    context.fireUserInboundEventTriggered(event)
  }
  func channelInactive(context: ChannelHandlerContext) { owner.close(); context.fireChannelInactive() }
  func errorCaught(context: ChannelHandlerContext, error: Error) { owner.close() }
}
#endif
