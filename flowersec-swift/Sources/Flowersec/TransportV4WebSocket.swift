#if os(macOS) || os(iOS)
  import Foundation
  import Darwin
  import NIOCore
  import NIOHTTP1
  import NIOPosix
  import NIOSSL
  import NIOTLS
  import NIOWebSocket

  enum V4WebSocketFailure: Error, Sendable { case policy, upgrade, closed, connectionLost, capacity, canceled }

  // This provider prepares a dedicated native connection only. The private
  // constructor requires the signed native network or loopback HTTP upgrade path; it cannot mint
  // once-spend, a READY owner or a public Session. CA and pin policies come
  // only from the original authenticated candidate.
  final class V4PreparedWebSocket: @unchecked Sendable, V4HandshakeWriter, V4RecordPublisher, V4TunnelAuthenticationCarrier {
    private let state: V4WebSocketState
    private init(_ state: V4WebSocketState) { self.state = state }

    static func prepare(
      route: V4WebSocketRoute, numericAddress: String,
      trustRootsPEM: [Data] = [], handoff: (any V4ControllerHandoffReservation)? = nil, prepaidNative: V4CryptoReservation? = nil
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
      // Network routes retain their original DNS or numeric certificate
      // identity. Only signed local routes omit the TLS handler.
      let numericIdentity = V4CredentialText.addressBytes(route.host)
      if !route.requiresTLS {
        guard let address = endpoint.ipAddress, V4CredentialText.isLoopbackAddress(address),
          V4CredentialText.isLoopbackAddress(route.host)
        else { throw V4WebSocketFailure.policy }
      }
      // Admit native construction and callback ownership before SSL context or
      // HTTP pipeline allocation, including the explicitly signed local path.
      let charge: V4CryptoReservation
      if let prepaidNative {
        guard prepaidNative.environment === route.environment, handoff == nil else { throw V4ResourceFailure.owner }
        try prepaidNative.check(); charge = prepaidNative
      } else if let handoff { charge = try handoff.takeNativeConnection(in: route.environment, maximumFrame: route.maximumFrame) }
      else { charge = try route.environment.nativeConnectionStorage(maximumFrame: route.maximumFrame) }
      let ssl: NIOSSLContext?
      if route.requiresTLS {
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.minimumTLSVersion = .tlsv13
        tls.maximumTLSVersion = .tlsv13
        tls.certificateVerification = route.pins == nil && numericIdentity == nil ? .fullVerification : .noHostnameVerification
        tls.applicationProtocols = ["http/1.1"]
        if !trustRootsPEM.isEmpty {
          let roots = try trustRootsPEM.flatMap { try NIOSSLCertificate.fromPEMBytes(Array($0)) }
          guard !roots.isEmpty, roots.count <= 16 else { throw V4WebSocketFailure.policy }
          tls.trustRoots = .certificates(roots)
        }
        ssl = try NIOSSLContext(configuration: tls)
      } else { ssl = nil }
      let group = MultiThreadedEventLoopGroup.singleton
      let loop = group.any()
      let state = try V4WebSocketState(route: route, charge: charge, loop: loop)
      try route.environment.registerNativeConnection(state)
      let bootstrap = ClientBootstrap(group: group).connectTimeout(.milliseconds(FlowersecSDKDefaults.Transport.connectTimeoutMilliseconds))
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
                  return try V4WebSocketDemandDecoder.install(on: channel, state: state).map { state.prepared() }
                } catch {
                  state.fail(error)
                  return channel.eventLoop.makeFailedFuture(error)
                }
              })
            var limits = NIOHTTPDecoderLimitConfiguration()
            limits.maxHeaderFieldCount = 64
            limits.maxHeaderFieldSize = 4096
            limits.maxHeaderListSize = 16_384
            if let ssl {
              let tlsHandler: NIOSSLClientHandler
              if route.pins != nil {
                // This replaces PKI acceptance only. NIOSSL still verifies the
                // TLS 1.3 CertificateVerify/Finished proof on this native socket.
                tlsHandler = try NIOSSLClientHandler(
                  context: ssl, serverHostname: numericIdentity == nil ? route.host : nil,
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
                  context: ssl, serverHostname: numericIdentity == nil ? route.host : nil,
                  additionalPeerCertificateVerificationCallback: { certificate, channel in
                    guard V4NativeWebSocketTLS.matchesIdentity(certificate, host: route.host) else {
                      return channel.eventLoop.makeFailedFuture(V4WebSocketFailure.policy)
                    }
                    do { try route.check() } catch {
                      return channel.eventLoop.makeFailedFuture(error)
                    }
                    return channel.eventLoop.makeSucceededVoidFuture()
                  })
              }
              try channel.pipeline.syncOperations.addHandler(tlsHandler)
            }
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
          await state.waitClosed()
          throw error
        }
      } onCancel: {
        state.cancel()
      }
    }
    static func listen(route: V4WebSocketRoute, numericAddress: String,
      tls: NativeListenerTLSConfiguration?, handoff: (any V4ControllerHandoffReservation)? = nil, prepaidNative: V4CryptoReservation? = nil,
      onListening: (@Sendable () async throws -> Void)? = nil) async throws -> V4PreparedWebSocket {
      try route.check()
      guard !route.isDialer else { throw V4WebSocketFailure.policy }
      let address = try SocketAddress(ipAddress: numericAddress, port: route.port)
      if let literal = try? SocketAddress(ipAddress: route.host, port: route.port) {
        guard literal == address else { throw V4WebSocketFailure.policy }
      }
      if !route.requiresTLS {
        guard V4CredentialText.isLoopbackAddress(numericAddress) else { throw V4WebSocketFailure.policy }
      }
      if let prepaidNative {
        guard prepaidNative.environment === route.environment, handoff == nil else { throw V4ResourceFailure.owner }
        try prepaidNative.check()
      }
      let charge = try prepaidNative ?? handoff?.takeNativeConnection(in: route.environment, maximumFrame: route.maximumFrame)
        ?? route.environment.nativeConnectionStorage(maximumFrame: route.maximumFrame, listener: true)
      let ssl: NIOSSLContext?
      if route.requiresTLS {
        guard let tls, (1...262_144).contains(tls.certificateChainPEM.count),
          (1...65_536).contains(tls.privateKeyPEM.count) else { throw V4WebSocketFailure.policy }
        let certificates = try NIOSSLCertificate.fromPEMBytes(Array(tls.certificateChainPEM))
        guard (1...16).contains(certificates.count), let leaf = certificates.first,
          V4NativeWebSocketTLS.matchesIdentity(leaf, host: route.host) else { throw V4WebSocketFailure.policy }
        var configuration = TLSConfiguration.makeServerConfiguration(certificateChain: certificates.map { .certificate($0) },
          privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(tls.privateKeyPEM), format: .pem)))
        configuration.minimumTLSVersion = .tlsv13; configuration.maximumTLSVersion = .tlsv13
        configuration.applicationProtocols = ["http/1.1"]
        ssl = try NIOSSLContext(configuration: configuration)
      } else { ssl = nil }
      let group = MultiThreadedEventLoopGroup.singleton
      let state = try V4WebSocketState(route: route, charge: charge, loop: group.any())
      try route.environment.registerNativeConnection(state)
      let listener: any Channel
      do {
        listener = try await ServerBootstrap(group: group).serverChannelOption(ChannelOptions.backlog, value: 1)
        .serverChannelOption(ChannelOptions.autoRead, value: false)
        .serverChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
        .serverChannelInitializer { channel in
          do { try state.attachListener(channel); return channel.eventLoop.makeSucceededVoidFuture() }
          catch { state.fail(error); return channel.eventLoop.makeFailedFuture(error) }
        }
        .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
        .childChannelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384))
        .childChannelInitializer { channel in
          do {
            try state.attach(channel)
            if let ssl { try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: ssl)) }
            try channel.pipeline.syncOperations.addHandler(V4WebSocketListenerEvents(state: state))
            let upgrade = NIOWebSocketServerUpgrader(maxFrameSize: route.maximumFrame + 8, automaticErrorHandling: true,
              shouldUpgrade: { channel, request in
                do {
                  try state.active(channel); try state.acceptServerUpgrade(request)
                  return channel.eventLoop.makeSucceededFuture(HTTPHeaders([("sec-websocket-protocol", route.subprotocol)]))
                } catch { state.fail(error); return channel.eventLoop.makeFailedFuture(error) }
              }, upgradePipelineHandler: { channel, _ in
                do {
                  try channel.pipeline.syncOperations.addHandler(NIOWebSocketFrameAggregator(minNonFinalFragmentSize: 1,
                    maxAccumulatedFrameCount: 1024, maxAccumulatedFrameSize: route.maximumFrame + 8))
                  try channel.pipeline.syncOperations.addHandler(V4WebSocketFrames(state: state))
                  return try V4WebSocketDemandDecoder.install(on: channel, state: state).map { state.prepared() }
                } catch { state.fail(error); return channel.eventLoop.makeFailedFuture(error) }
              })
            return channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: ([upgrade], { _ in }))
          } catch { channel.close(promise: nil); return channel.eventLoop.makeFailedFuture(error) }
        }.bind(to: address).get()
      } catch { state.fail(error); await state.waitClosed(); throw error }
      // One explicit read accepts at most one child; no callback queue can
      // create further native sockets beyond this original reservation.
      listener.read()
      do {
        return try await withTaskCancellationHandler {
          if let onListening { try await onListening(); try state.check() }
          try await state.ready.futureResult.get()
          try state.check(); try Task.checkCancellation()
          listener.close(promise: nil); try await listener.closeFuture.get()
          return V4PreparedWebSocket(state)
        } onCancel: { state.cancel(); listener.close(promise: nil) }
      } catch {
        state.fail(error); listener.close(promise: nil); try? await listener.closeFuture.get(); await state.waitClosed(); throw error
      }
    }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws { try publish(buffer) }
    func publish(_ buffer: V4CryptoBuffer) throws { try state.publish(buffer, opcode: .binary) }
    func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws {
      try state.publish(buffer, opcode: .binary, completion: completion)
    }
    func receive() async throws -> V4CryptoBuffer { try await state.receive() }
    func flush() async throws { try await state.flush(access: nil) }
    func consumePool(using store: V4SQLitePoolStore) throws -> V4ConsumedWebSocket {
      do { return try store.consume(state.claimPool()) } catch {
        state.fail(error)
        throw error
      }
    }
    func consumeLive() throws -> V4ConsumedWebSocket {
      do { return try V4ConsumedWebSocket.live(state.claimLive()) }
      catch { state.fail(error); throw error }
    }
    func consumeLiveServer(registration: V4LiveServerRegistration, fsb: Data, context: Data) throws -> V4ConsumedWebSocket {
      do { return try registration.consume(state.claimLive(), fsb: fsb, context: context) }
      catch { state.fail(error); throw error }
    }
    func observeClosed(_ action: @escaping @Sendable () -> Void) throws { try state.observeClosed(action) }
    func cleanupStatus() -> CleanupStatus { state.cleanupStatus() }
    func check() throws { try state.check() }
    var tunnelCarrierIdentity: AnyObject { state }
    func claimTunnelChallenge(credential: V4CredentialAdmission) throws -> (Data, Data) {
      try state.claimTunnelChallenge(credential: credential, access: nil)
    }
    func relayChallenge() throws -> (Data, Data) { try state.relayChallenge() }
    func promoteRelay(_ activation: V4RelayActivation) throws { try state.promoteRelay(activation) }
    func close() { state.close() }
    func waitClosed() async { await state.waitClosed() }
    func waitPhysicalCleanup() async { await state.waitPhysicalCleanup() }
    deinit { state.closePreparationAlias() }
  }

  enum V4NativeWebSocketTLS {
    static func matchesIdentity(_ certificate: NIOSSLCertificate, host: String) -> Bool {
      if let address = V4CredentialText.addressBytes(host) {
        return certificate._subjectAlternativeNames().contains { name in
          guard name.nameType == .ipAddress else { return false }
          return name.contents.withUnsafeBufferPointer { Data($0).elementsEqual(address) }
        }
      }
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
    let facts: V4PoolSpendFacts?
    let localRole: V4CryptoRole
    let operationID: Data
    let carrierID: Data
    fileprivate init(_ state: V4WebSocketState, live: Bool = false) throws {
      self.state = state
      environment = state.route.environment
      localRole = state.route.credential.localRole
      if live {
        try state.route.credential.checkLiveActivationComplete(in: environment)
        facts = nil
      } else { facts = try state.route.credential.poolSpendFacts(in: environment) }
      operationID = try V4Crypto.random(16)
      carrierID = try V4Crypto.random(16)
    }
    var originalCredential: V4CredentialAdmission { state.route.credential }
    func check() throws { try state.checkAccess(self) }
    var tunnelCarrierIdentity: AnyObject { state }
    func claimTunnelChallenge(credential: V4CredentialAdmission) throws -> (Data, Data) {
      try state.claimTunnelChallenge(credential: credential, access: self)
    }
    func publish(_ input: V4CryptoBuffer) throws {
      try state.publish(input, opcode: .binary, access: self)
    }
    func publish(_ input: V4CryptoBuffer, admissionCheck: () throws -> Void) throws {
      try state.publish(input, opcode: .binary, access: self, admissionCheck: admissionCheck)
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
    func cleanupStatus() -> CleanupStatus { state.cleanupStatus() }
    func waitClosed() async { await state.waitClosed() }
    deinit { state.close() }
  }

  private final class V4WebSocketState: V4NativeConnectionLifecycle, @unchecked Sendable {
    let route: V4WebSocketRoute
    let ready: EventLoopPromise<Void>
    let incarnation: Data
    let hopChallenge: Data
    private let charge: V4CryptoReservation
    private let lock: NSRecursiveLock
    private let eventLoop: any EventLoop
    private let pin: V4PinnedTLS?
    private let deadline: V4LocalWorkWindow
    private let cleanupEvents = V4SessionEvents(maximum: 2)
    private var channel: (any Channel)?
    private var physicalClose: EventLoopFuture<Void>?
    private var listenerChannel: (any Channel)?
    private var listenerClose: EventLoopFuture<Void>?
    private var listenerJoined = true
    private var physicalJoined = true
    private var closeObserved = false
    private var timer: Scheduled<Void>?
    private var queue: [V4CryptoBuffer] = []
    private var waiter: CheckedContinuation<V4CryptoBuffer, any Error>?
    private var writeWaiter: CheckedContinuation<Void, any Error>?
    private var wakeup: (@Sendable () -> Void)?
    private var inputWakeup: (@Sendable () -> Void)?
    private var recordCompletion: (@Sendable () throws -> Void)?
    private var failure: (any Error)?
    private var readyCompleted = false
    private var upgraded = false
    private var tlsFinished = false
    private var physicalReady = false
    private var pendingWrites = 0
    private var consumptionStarted = false
    private var tunnelHopClaimed = false
    private weak var poolClaim: V4PreparedPoolClaim?
    private var established = false
    init(route: V4WebSocketRoute, charge: V4CryptoReservation, loop: any EventLoop) throws {
      self.route = route
      self.charge = charge
      incarnation = try V4Crypto.random(16)
      hopChallenge = try V4Crypto.random(32)
      guard incarnation.contains(where: { $0 != 0 }), hopChallenge.contains(where: { $0 != 0 })
      else { throw V4CryptoFailure.key }
      self.lock = route.environment.gate
      eventLoop = loop
      pin = try !route.isDialer || route.pins == nil ? nil : V4PinnedTLS(route: route)
      deadline = try V4LocalWorkWindow(clock: route.environment.clock, durationMS: FlowersecSDKDefaults.Transport.handshakeTimeoutMilliseconds)
      ready = loop.makePromise(of: Void.self)
      queue.reserveCapacity(2)
      timer = loop.scheduleTask(in: .milliseconds(Int64(FlowersecSDKDefaults.Transport.handshakeTimeoutMilliseconds))) { [self] in fail(V4TimeFailure.expired) }
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
        guard !upgraded || channel?.isActive == true else { throw V4WebSocketFailure.connectionLost }
      }
    }
    func attachListener(_ channel: any Channel) throws {
      try lock.withLock {
        try check()
        guard !route.isDialer, listenerChannel == nil else { throw V4WebSocketFailure.policy }
        let tail = try charge.executionTail()
        listenerChannel = channel; listenerClose = channel.closeFuture; listenerJoined = false
        channel.closeFuture.whenComplete { [self, tail] _ in
          lock.withLock { listenerJoined = true }
          tail.release(); cleanupEvents.signal(); withExtendedLifetime(self) {}
        }
      }
    }
    func attach(_ channel: any Channel) throws {
      try lock.withLock {
        try check()
        guard self.channel == nil else { throw V4WebSocketFailure.policy }
        let tail = try charge.executionTail()
        self.channel = channel
        physicalClose = channel.closeFuture; physicalJoined = false
        channel.closeFuture.whenComplete { [self, tail] _ in
          lock.withLock { physicalJoined = true }
          tail.release(); cleanupEvents.signal(); withExtendedLifetime(self) {}
        }
      }
    }
    func active(_ channel: any Channel) throws {
      try lock.withLock {
        try check()
        guard self.channel === channel else { throw V4WebSocketFailure.policy }
        if !route.requiresTLS {
          guard let remote = channel.remoteAddress, let address = remote.ipAddress,
            V4CredentialText.isLoopbackAddress(address),
            (route.isDialer ? remote : channel.localAddress) == (try SocketAddress(ipAddress: route.host, port: route.port))
          else { throw V4WebSocketFailure.policy }
        }
        physicalReady = true
      }
    }
    func claimTunnelChallenge(credential: V4CredentialAdmission, access: V4PreparedPoolClaim?) throws -> (Data, Data) {
      try lock.withLock {
        try checkAccess(access)
        guard !tunnelHopClaimed, upgraded, credential === route.credential,
          credential.pathKind == 1, !route.isRelay else { throw V4CryptoFailure.phase }
        tunnelHopClaimed = true
        return (incarnation, hopChallenge)
      }
    }
    func relayChallenge() throws -> (Data, Data) {
      try lock.withLock {
        try check(); guard route.isRelay, upgraded, !established else { throw V4CryptoFailure.phase }
        return (incarnation, hopChallenge)
      }
    }
    func promoteRelay(_ activation: V4RelayActivation) throws {
      try lock.withLock {
        try check(); guard route.isRelay, upgraded, !established, pendingWrites == 0 else { throw V4CryptoFailure.phase }
        try activation.claim(route)
        established = true; deadline.cancel(); timer?.cancel(); timer = nil
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
    // A physical relay dialer sends its HELLO first. The original client
    // listener may buffer that one flight before its activated claim is taken.
    // Transfer only that bounded initial flight with the same carrier owner;
    // authentication still happens after original consumption in HOP_AUTH.
    private func permitsQueuedRelayHello() throws -> Bool {
      guard route.credential.localRole == .client, route.credential.pathKind == 1,
        !route.isDialer, queue.count == 1, let first = queue.first else { return false }
      return try first.withBytes { bytes in
        bytes.count > 11 && bytes.count <= 10_354
          && V4Crypto.number(bytes.prefix(4)) == bytes.count - 8
          && bytes[4] == 16 && bytes[5..<8] == Data([0, 0, 0])
        // The closed canonical HELLO map starts with phase = 0.
          && bytes[8..<11] == Data([0xa4, 0x00, 0x00])
      }
    }
    func claimPool() throws -> V4PreparedPoolClaim {
      try lock.withLock {
        try check()
        guard upgraded, !consumptionStarted, pendingWrites == 0, waiter == nil,
          try (queue.isEmpty || permitsQueuedRelayHello()), route.credential.source == .preauthorizedPool
        else { throw V4CryptoFailure.phase }
        let claim = try V4PreparedPoolClaim(self)
        consumptionStarted = true
        poolClaim = claim
        return claim
      }
    }
    func claimLive() throws -> V4PreparedPoolClaim {
      try lock.withLock {
        try check()
        guard upgraded, !consumptionStarted, pendingWrites == 0, waiter == nil,
          try (queue.isEmpty || permitsQueuedRelayHello()), route.credential.source == .liveAuthority else { throw V4CryptoFailure.phase }
        let claim = try V4PreparedPoolClaim(self, live: true)
        consumptionStarted = true; poolClaim = claim; return claim
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
    func setInputWakeup(_ action: (@Sendable () -> Void)?) { lock.withLock { inputWakeup = action } }
    var acceptsInput: Bool {
      lock.withLock { failure == nil && (waiter != nil || queue.count < (route.isRelay ? 1 : 2)) }
    }
    func setRecordCompletion(_ action: (@Sendable () throws -> Void)?) {
      lock.withLock { recordCompletion = action }
    }
    func flush(access: V4PreparedPoolClaim?) async throws {
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
        guard route.requiresTLS, case .handshakeCompleted(let negotiated) = event,
          negotiated == "http/1.1", !tlsFinished
        else { throw V4WebSocketFailure.policy }
        if route.isDialer { try pin?.check(required: true) }
        tlsFinished = true
      }
    }
    func acceptServerUpgrade(_ request: HTTPRequestHead) throws {
      try lock.withLock {
        try check()
        guard physicalReady, !route.isDialer, (!route.requiresTLS || tlsFinished), !upgraded,
          request.method == .GET, request.uri == route.path,
          request.headers["sec-websocket-protocol"] == [route.subprotocol],
          request.headers["sec-websocket-extensions"].isEmpty,
          (request.headers["origin"].isEmpty ? route.allowAbsentOrigin :
            request.headers["origin"].count == 1 && route.allowedOrigins.contains(request.headers["origin"][0]))
        else { throw V4WebSocketFailure.upgrade }
        upgraded = true
      }
    }
    func acceptUpgrade(_ response: HTTPResponseHead) throws {
      try lock.withLock {
        try check()
        guard physicalReady, (!route.requiresTLS || tlsFinished), !upgraded, response.status == .switchingProtocols,
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
    func fail(_ originalError: any Error) {
      // Only native transport evidence has reconnect semantics. TLS policy,
      // record authentication and framing failures retain their terminal error.
      let error: any Error
      if let io = originalError as? IOError,
        [ECONNRESET, ECONNABORTED, EPIPE, ENOTCONN, ETIMEDOUT].contains(io.errnoCode) {
        error = V4WebSocketFailure.connectionLost
      } else if let tls = originalError as? NIOSSLError, case .uncleanShutdown = tls {
        error = V4WebSocketFailure.connectionLost
      } else { error = originalError }
      var listener: (any Channel)?
      var socket: (any Channel)?
      var waiting: CheckedContinuation<V4CryptoBuffer, any Error>?
      var writing: CheckedContinuation<Void, any Error>?
      lock.withLock {
        guard failure == nil else { return }
        if let tls = originalError as? NIOSSLError {
          if case .uncleanShutdown = tls {} else { charge.environment.root.diagnosticCounters.increment(.tlsRefusals) }
        }
        failure = error
        if !readyCompleted {
          readyCompleted = true
          ready.fail(error)
        }
        socket = channel
        channel = nil
        listener = listenerChannel
        listenerChannel = nil
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
        inputWakeup = nil
        recordCompletion = nil
      }
      listener?.close(promise: nil)
      waiting?.resume(throwing: error)
      writing?.resume(throwing: error)
      if let socket {
        // The terminal owner has sealed input and failed pending operations.
        // Abort the underlying socket: a TLS close_notify exchange requires
        // peer input that this bounded demand owner no longer admits. Waiting
        // for that exchange would hold physical cleanup until its own timeout.
        socket.pipeline.context(handlerType: NIOSSLHandler.self).whenComplete { result in
          switch result {
          case .success(let context): context.close(promise: nil)
          case .failure: socket.close(promise: nil)
          }
        }
      }
      cleanupEvents.signal()
    }
    func close() { fail(V4WebSocketFailure.closed) }
    func providerClosed() { fail(V4WebSocketFailure.connectionLost) }
    func cancel() {
      // Swift cancellation holds the task status lock. Defer the bounded
      // native close to avoid taking the owner gate while a completion resumes.
      eventLoop.execute { self.fail(V4WebSocketFailure.canceled) }
    }
    func closePreparationAlias() {
      lock.withLock { if !consumptionStarted { close() } }
    }
    func observeClosed(_ action: @escaping @Sendable () -> Void) throws {
      try lock.withLock {
        guard !closeObserved, let physicalClose else { throw V4CryptoFailure.phase }
        let tail = try charge.executionTail(); closeObserved = true
        physicalClose.whenComplete { _ in action(); tail.release() }
      }
    }
    func cleanupStatus() -> CleanupStatus {
      lock.withLock {
        let count = (listenerJoined ? 0 : 1) + (physicalJoined ? 0 : 1) + pendingWrites
        return CleanupStatus(complete: failure != nil && count == 0, cleanupIncomplete: failure != nil && count != 0,
          pendingCallbacks: UInt64(count))
      }
    }
    func waitClosed() async {
      let closing = lock.withLock { (listenerClose, physicalClose) }
      if let listener = closing.0 { try? await listener.get() }
      if let socket = closing.1 { try? await socket.get() }
      if cleanupStatus().complete { route.environment.retireNativeConnection(self) }
    }
    func waitPhysicalCleanup() async {
      while true {
        let revision = cleanupEvents.revision
        if cleanupStatus().complete { route.environment.retireNativeConnection(self); return }
        try? await cleanupEvents.wait(after: revision)
      }
    }
    func publish(
      _ input: V4CryptoBuffer, opcode: WebSocketOpcode,
      access: V4PreparedPoolClaim? = nil, completion: (@Sendable (Bool) -> Void)? = nil,
      admissionCheck: () throws -> Void = {}
    ) throws {
      var enqueued = false
      do {
        let (channel, tail) = try lock.withLock { () throws -> (any Channel, V4ResourceReference) in
          try checkAccess(access)
          guard upgraded, let value = self.channel, pendingWrites < 2 else { throw V4WebSocketFailure.capacity }
          let tail = try charge.executionTail()
          pendingWrites += 1
          return (value, tail)
        }
        var retainedByCompletion = false
        defer {
          if !retainedByCompletion {
            lock.withLock { pendingWrites -= 1 }
            tail.release()
            cleanupEvents.signal()
          }
        }
        let bytes = try input.withBytes { $0 }
        guard bytes.count <= route.maximumFrame + 8 else { throw V4WebSocketFailure.capacity }
        var data = channel.allocator.buffer(capacity: bytes.count)
        data.writeBytes(bytes)
        var generator = SystemRandomNumberGenerator()
        let frame = NIOWebSocket.WebSocketFrame(
          fin: true, opcode: opcode,
          maskKey: route.isDialer ? WebSocketMaskingKey.random(using: &generator) : nil, data: data)
        // This short claim is the publication linearization point. A later
        // Close cannot cancel physical provider work already owned by this tail.
        try lock.withLock {
          try checkAccess(access); try admissionCheck()
          guard self.channel === channel else { throw V4WebSocketFailure.closed }
          enqueued = true
          retainedByCompletion = true
          // The event-loop enqueue preserves gate claim order. Actual provider
          // submission runs after this short critical section has returned.
          channel.eventLoop.execute { [self, input, tail] in
          channel.writeAndFlush(frame).whenComplete { [self, input, tail] result in
            defer { tail.release(); cleanupEvents.signal() }
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
              inputWakeup?()
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
        guard frame.fin, (route.isDialer ? frame.maskKey == nil : frame.maskKey != nil), !frame.rsv1, !frame.rsv2, !frame.rsv3,
          frame.data.readableBytes <= route.maximumFrame + 8
        else { throw V4WebSocketFailure.policy }
        if frame.opcode == .pong { return }
        if frame.opcode == .connectionClose { throw V4WebSocketFailure.connectionLost }
        guard frame.opcode == .binary || frame.opcode == .ping else {
          throw V4WebSocketFailure.policy
        }
        if frame.opcode == .ping, frame.data.readableBytes > 125 { throw V4WebSocketFailure.policy }
        guard frame.opcode == .ping || waiter != nil || queue.count < (route.isRelay ? 1 : 2) else {
          throw V4WebSocketFailure.capacity
        }
        let payload = frame.unmaskedData
        let buffer = try route.environment.cryptoBuffer(
          capacity: payload.readableBytes,
          delivery: { [self] in try check() })
        try buffer.store(Data(payload.readableBytesView))
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

  // Keep undecoded bytes in the prepaid carrier buffer and pause native reads
  // whenever both original record positions are occupied. One TCP/TLS read may
  // contain many WebSocket frames, so maxMessagesPerRead alone is insufficient.
  final class V4WebSocketDemandDecoder: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = NIOWebSocket.WebSocketFrame
    private let acceptsInput: @Sendable () -> Bool
    private let fail: @Sendable (any Error) -> Void
    private let closed: @Sendable () -> Void
    private let decoder: WebSocketFrameDecoder
    private let loop: any EventLoop
    private let maximumBytes: Int
    private var context: ChannelHandlerContext?
    private var buffered = ByteBuffer()
    private var readPending = false
    private var pumping = false
    private var inputEnded = false
    private init(maximumFrame: Int, loop: any EventLoop, acceptsInput: @escaping @Sendable () -> Bool,
      fail: @escaping @Sendable (any Error) -> Void, closed: @escaping @Sendable () -> Void) {
      self.acceptsInput = acceptsInput; self.fail = fail; self.closed = closed; self.loop = loop
      decoder = WebSocketFrameDecoder(maxFrameSize: maximumFrame)
      maximumBytes = maximumFrame + 14 + 16_384
    }
    fileprivate static func install(on channel: any Channel, state: V4WebSocketState) throws -> EventLoopFuture<Void> {
      try install(on: channel, maximumFrame: state.route.maximumFrame + 8,
        acceptsInput: { state.acceptsInput }, fail: { state.fail($0) }, closed: { state.providerClosed() },
        installWakeup: { state.setInputWakeup($0) })
    }
    static func install(on channel: any Channel, maximumFrame: Int, drainOnEOF: Bool = false,
      acceptsInput: @escaping @Sendable () -> Bool, fail: @escaping @Sendable (any Error) -> Void,
      closed: @escaping @Sendable () -> Void,
      installWakeup: (@escaping @Sendable () -> Void) -> Void) throws -> EventLoopFuture<Void> {
      let old = try channel.pipeline.syncOperations.context(handlerType: ByteToMessageHandler<WebSocketFrameDecoder>.self)
      let demand = V4WebSocketDemandDecoder(maximumFrame: maximumFrame, loop: channel.eventLoop,
        acceptsInput: acceptsInput, fail: fail, closed: closed)
      try channel.pipeline.syncOperations.addHandler(demand, position: .after(old.handler))
      installWakeup { [weak demand] in demand?.resume() }
      // A proxy must drain complete frames already read before reporting EOF.
      // Keep the pipeline alive while its bounded demand buffer is consumed.
      let halfClosure = drainOnEOF
        ? channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        : channel.eventLoop.makeSucceededVoidFuture()
      let stopped = halfClosure.flatMap { channel.setOption(ChannelOptions.autoRead, value: false) }
      let removed = channel.pipeline.syncOperations.removeHandler(context: old)
      return stopped.and(removed).map { _ in demand.resume() }
    }
    func handlerAdded(context: ChannelHandlerContext) { self.context = context }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      var bytes = unwrapInboundIn(data)
      guard bytes.readableBytes <= maximumBytes - buffered.readableBytes else {
        fail(V4WebSocketFailure.capacity); return
      }
      buffered.writeBuffer(&bytes)
      pump(context)
    }
    func channelReadComplete(context: ChannelHandlerContext) {
      readPending = false; pump(context); context.fireChannelReadComplete()
    }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
      if let event = event as? ChannelEvent, case .inputClosed = event {
        inputEnded = true; readPending = false; pump(context)
      } else { context.fireUserInboundEventTriggered(event) }
    }
    func channelInactive(context: ChannelHandlerContext) {
      self.context = nil
      // A decoded frame can synchronously close the downstream pipeline while
      // decode still borrows buffered inout. Its pump clears after that borrow.
      if !pumping { buffered.clear() }
      closed(); context.fireChannelInactive()
    }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { fail(error) }
    private func resume() {
      loop.execute { [self] in if let context { pump(context) } }
    }
    private func pump(_ context: ChannelHandlerContext) {
      guard !pumping, self.context != nil else { return }; pumping = true
      defer {
        pumping = false
        if self.context == nil { buffered.clear() }
      }
      do {
        while self.context != nil, acceptsInput(), buffered.readableBytes > 0 {
          if try decoder.decode(context: context, buffer: &buffered) == .needMoreData { break }
        }
        guard self.context != nil else { return }
        buffered.discardReadBytes()
        if inputEnded {
          // decode may need more bytes for a final incomplete frame. Complete
          // frames have already been delivered; EOF ends that partial frame.
          if acceptsInput() || buffered.readableBytes == 0 {
            closed(); context.close(promise: nil)
          }
        } else if acceptsInput(), !readPending { readPending = true; context.read() }
      } catch { fail(error) }
    }
  }

  private final class V4WebSocketListenerEvents: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    let state: V4WebSocketState
    init(state: V4WebSocketState) { self.state = state }
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
      if let tls = event as? TLSUserEvent, case .handshakeCompleted = tls { do { try state.tls(tls) } catch { state.fail(error) } }
      context.fireUserInboundEventTriggered(event)
    }
    func channelInactive(context: ChannelHandlerContext) { state.providerClosed(); context.fireChannelInactive() }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { state.fail(error) }
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
        try state.active(context.channel)
        let route = state.route
        var headers = HTTPHeaders([
          ("host", "\(route.host.contains(":") ? "[\(route.host)]" : route.host):\(route.port)"),
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
      if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
        do { try state.tls(event) } catch { state.fail(error) }
      }
      context.fireUserInboundEventTriggered(event)
    }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      state.fail(V4WebSocketFailure.upgrade)
    }
    func errorCaught(context: ChannelHandlerContext, error: any Error) { state.fail(error) }
    func channelInactive(context: ChannelHandlerContext) {
      state.providerClosed()
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
      state.providerClosed()
      context.fireChannelInactive()
    }
  }
#endif
