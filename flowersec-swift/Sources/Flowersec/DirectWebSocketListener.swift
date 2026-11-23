#if os(macOS) || os(iOS)
import Crypto
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOWebSocket

/// Lookup hints only. The listener verifies the entire incoming admission against the returned artifact.
public struct DirectAdmissionRequest: Sendable {
  public let channelID: String
  public let candidateID: String
  public let origin: String
  public let remoteAddress: String
}

public struct DirectAdmissionGrant: Sendable {
  let artifact: Artifact
  let handlers: RPCHandlers
  let consume: @Sendable () async throws -> ConnectionLease?

  /// Supply the trusted issuer's artifact. The transaction must check current authority, expiry,
  /// and single use atomically, including across competing candidates and restarts. An uncertain
  /// commit must remain spent. Neither this grant nor a successful admission implies ongoing access.
  public init(artifact: Artifact, handlers: RPCHandlers = RPCHandlers(),
              consume: @escaping @Sendable () async throws -> Void) {
    self.artifact = artifact
    self.handlers = handlers
    self.consume = { try await consume(); return nil }
  }

  public init(reservingFor artifact: Artifact, handlers: RPCHandlers = RPCHandlers(),
              acquireConnectionLease: @escaping @Sendable () async throws -> ConnectionLease) {
    self.artifact = artifact
    self.handlers = handlers
    self.consume = acquireConnectionLease
  }
}

/// A v5 Direct WSS listener. No invitation is required to bind the socket.
public final class DirectWebSocketListener: Sendable {
  public typealias Authorize = @Sendable (DirectAdmissionRequest) async throws -> DirectAdmissionGrant?
  public typealias OnSession = @Sendable (any Session, DirectAdmissionRequest) async throws -> Void

  private let server: any Channel
  private let children: DirectChildrenV3
  public let port: Int

  private init(_ server: any Channel, port: Int, children: DirectChildrenV3) {
    self.server = server
    self.port = port
    self.children = children
  }

  /// `endpoint` is the public WSS URL in issued artifacts. When omitted, the actual local socket
  /// address of each accepted connection determines the endpoint; a Host header never selects it.
  /// `onSession` owns the application workflow until it returns. Closing the listener cancels it.
  public static func listen(bindAddress: String, port: Int, endpoint: String? = nil,
                            allowedOrigins: Set<String>, certificateChainPEM: Data, privateKeyPEM: Data,
                            maxConnections: Int = 512, admissionTimeout: Duration = .seconds(10),
                            rpcFrameLimits: RPCFrameLimits = .standard, maxConcurrentRPCRequests: Int = 32,
                            authorize: @escaping Authorize,
                            onSession: @escaping OnSession) async throws -> DirectWebSocketListener {
    guard maxConnections > 0, maxConcurrentRPCRequests > 0 else { throw ConnectError.invalidOptions }
    let children = DirectChildrenV3(maximum: maxConnections)
    let server = try await BoundWebSocketIngressV3.bind(kind: "direct", bindAddress: bindAddress, port: port,
      endpoint: endpoint, allowedOrigins: allowedOrigins, certificateChainPEM: certificateChainPEM,
      privateKeyPEM: privateKeyPEM, admissionTimeout: admissionTimeout, children: children) { leg in
        let config = DirectWSSConfigV3(endpoint: leg.endpoint, leafHash: leg.leafHash, frameLimits: rpcFrameLimits,
          maxConcurrentRequests: maxConcurrentRPCRequests, authorize: authorize, onSession: onSession)
        try await config.serve(socket: leg.socket, origin: leg.origin, address: leg.address,
          deadline: leg.deadline, established: leg.established)
      }
    guard let boundPort = server.localAddress?.port else { try? await server.close().get(); throw ConnectError.connectionFailed }
    return DirectWebSocketListener(server, port: boundPort, children: children)
  }

  public func close() async {
    let drain = children.shutdown()
    try? await server.close().get()
    try? await server.closeFuture.get()
    await drain.value
  }

  public func waitClosed() async {
    try? await server.closeFuture.get()
    await children.shutdown().value
  }

  public func waitClosedAndCheckReleases() async throws {
    await waitClosed()
    try children.checkReleases()
  }
}

struct BoundWebSocketLegV3: Sendable {
  let socket: any ProxyUpstreamWebSocket
  let channel: any Channel
  let origin: String
  let address: String
  let endpoint: String
  let leaf: NIOSSLCertificate
  let leafHash: Data
  let deadline: ContinuousClock.Instant
  let established: @Sendable () -> Void
}

enum BoundWebSocketIngressV3 {
  static func bind(kind: String, bindAddress: String, port: Int, endpoint: String?, allowedOrigins: Set<String>,
                   certificateChainPEM: Data, privateKeyPEM: Data, admissionTimeout: Duration, children: DirectChildrenV3,
                   serve: @escaping @Sendable (BoundWebSocketLegV3) async throws -> Void) async throws -> any Channel {
    guard (0...65535).contains(port), !allowedOrigins.isEmpty,
          admissionTimeout > .zero, admissionTimeout <= .seconds(3600),
          allowedOrigins.allSatisfy({ origin in
            guard let u = URLComponents(string: origin) else { return false }
            return ["http", "https"].contains(u.scheme) && u.host != nil && u.path.isEmpty &&
              u.user == nil && u.password == nil && u.query == nil && u.fragment == nil
          })
    else { throw ConnectError.invalidOptions }
    if let endpoint, try ArtifactCodecV3.normalizeURL(endpoint, carrier: "websocket", kind: kind) != endpoint {
      throw ConnectError.invalidOptions
    }
    let chain = try NIOSSLCertificate.fromPEMBytes(Array(certificateChainPEM))
    guard let leaf = chain.first else { throw ConnectError.invalidOptions }
    let key = try NIOSSLPrivateKey(bytes: Array(privateKeyPEM), format: .pem)
    var tls = TLSConfiguration.makeServerConfiguration(certificateChain: chain.map { .certificate($0) },
                                                       privateKey: .privateKey(key))
    tls.minimumTLSVersion = .tlsv13
    tls.maximumTLSVersion = .tlsv13
    tls.applicationProtocols = ["http/1.1"]
    _ = try NIOSSLContext(configuration: tls)
    let tlsConfig = tls, leafHash = Data(SHA256.hash(data: try leaf.toDERBytes()))
    let path = kind == "direct" ? TransportV3Contract.directWebSocketPath : TransportV3Contract.tunnelWebSocketPath
    return try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
      .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        let target: String
        if let endpoint { target = endpoint }
        else {
          guard let ip = channel.localAddress?.ipAddress, let port = channel.localAddress?.port else { return channel.close() }
          let host = ip.contains(":") ? "[\(ip)]" : ip
          target = "wss://\(host)\(port == 443 ? "" : ":\(port)")\(path)"
        }
        guard let url = URL(string: target), let host = url.host else { return channel.close() }
        return WebSocketIngressConfigV3(tls: tlsConfig, endpoint: target, path: path, tunnel: kind == "tunnel",
          authority: ProxyNIOWebSocketConnector.requestAuthority(url: url, host: host, port: url.port ?? 443),
          origins: allowedOrigins, leaf: leaf, leafHash: leafHash, timeout: admissionTimeout, serve: serve).install(channel, children: children)
      }
      .bind(to: SocketAddress(ipAddress: bindAddress, port: port)).get()
  }
}

private struct WebSocketIngressConfigV3: Sendable {
  let tls: TLSConfiguration
  let endpoint: String
  let path: String
  let tunnel: Bool
  let authority: String
  let origins: Set<String>
  let leaf: NIOSSLCertificate
  let leafHash: Data
  let timeout: Duration
  let serve: @Sendable (BoundWebSocketLegV3) async throws -> Void

  func install(_ channel: any Channel, children: DirectChildrenV3) -> EventLoopFuture<Void> {
    guard children.add(channel) else { return channel.close() }
    let deadline = ContinuousClock.now.advanced(by: timeout)
    let components = timeout.components
    let nanoseconds = components.seconds * 1_000_000_000 + components.attoseconds / 1_000_000_000
    let timer = channel.eventLoop.scheduleTask(in: .nanoseconds(nanoseconds)) { channel.close(promise: nil) }
    channel.closeFuture.whenComplete { _ in timer.cancel(); children.channelClosed(channel) }
    let proto = tunnel ? TransportV3Contract.tunnelWebSocketSubprotocol : TransportV3Contract.directWebSocketSubprotocol
    let maximum = FlowersecSDKDefaults.Yamux.maxFrameBytes + 12
    let upgrader = NIOWebSocketServerUpgrader(maxFrameSize: maximum, shouldUpgrade: { ch, head in
      let headers = head.headers
      guard head.method == .GET, head.version == .http1_1, head.uri == path,
            headers["host"].count == 1, headers["host"][0].caseInsensitiveCompare(authority) == .orderedSame,
            headers["origin"].count == 1, origins.contains(headers["origin"][0]),
            headers["sec-websocket-version"] == ["13"], headers["sec-websocket-protocol"] == [proto],
            headers["sec-websocket-key"].count == 1, let key = Data(base64Encoded: headers["sec-websocket-key"][0]),
            key.count == 16, key.base64EncodedString() == headers["sec-websocket-key"][0]
      else { ch.close(promise: nil); return ch.eventLoop.makeSucceededFuture(nil) }
      return ch.eventLoop.makeSucceededFuture(HTTPHeaders([("sec-websocket-protocol", proto)]))
    }, upgradePipelineHandler: { ch, head in
      let state = ProxyWebSocketInboundState(maxBufferedBytes: proxyWebSocketInboundBufferBytes(maxFrameBytes: maximum),
        maxBufferedFrames: tunnel ? 1024 : .max)
      do {
        try ch.pipeline.syncOperations.addHandler(DirectClientFrameRuleV3())
        if tunnel { try ch.pipeline.syncOperations.addHandler(RelayAdmissionFrameGate()) }
        try ch.pipeline.syncOperations.addHandler(NIOWebSocketFrameAggregator(minNonFinalFragmentSize: 1,
          maxAccumulatedFrameCount: 1024, maxAccumulatedFrameSize: maximum))
        try ch.pipeline.syncOperations.addHandler(ProxyRawWebSocketHandler(state: state))
        let socket = NIOProxyUpstreamWebSocket(channel: ch, state: state, selectedProtocol: proto,
                                               maxFrameBytes: maximum, maskOutbound: false)
        let worker = children.startWorker(ch) {
          guard let address = ch.remoteAddress else { return }
          try await serve(BoundWebSocketLegV3(socket: socket, channel: ch, origin: head.headers["origin"][0],
            address: address.description, endpoint: endpoint, leaf: leaf, leafHash: leafHash,
            deadline: deadline, established: { timer.cancel() }))
        }
        guard let worker else { return ch.close() }
        ch.closeFuture.whenComplete { _ in worker.cancel() }
        return ch.eventLoop.makeSucceededVoidFuture()
      } catch { return ch.eventLoop.makeFailedFuture(error) }
    })
    do {
      // A fresh context per connection shares neither a ticket key nor a session cache with any other leg.
      try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: NIOSSLContext(configuration: tls)))
      let reject = DirectRejectHTTPV3()
      try channel.pipeline.syncOperations.configureHTTPServerPipeline(withPipeliningAssistance: false,
        withServerUpgrade: ([upgrader], { ctx in ctx.pipeline.removeHandler(reject, promise: nil) }))
      try channel.pipeline.syncOperations.addHandler(reject)
      return channel.eventLoop.makeSucceededVoidFuture()
    } catch { return channel.eventLoop.makeFailedFuture(error) }
  }

}

private struct DirectWSSConfigV3: Sendable {
  let endpoint: String
  let leafHash: Data
  let frameLimits: RPCFrameLimits
  let maxConcurrentRequests: Int
  let authorize: DirectWebSocketListener.Authorize
  let onSession: DirectWebSocketListener.OnSession

  func serve(socket: any ProxyUpstreamWebSocket, origin: String, address: String, deadline: ContinuousClock.Instant,
             established: @Sendable () -> Void) async throws {
    let (session, request) = try await acceptSession(socket: socket, origin: origin, address: address, deadline: deadline)
    do {
      try checkDeadline(deadline)
      established()
      try await onSession(session, request)
    } catch {
      try await Task { try await session.close() }.value
      throw error
    }
    try await Task { try await session.close() }.value
  }

  private func checkDeadline(_ deadline: ContinuousClock.Instant) throws {
    try Task.checkCancellation()
    guard ContinuousClock.now < deadline else { throw ConnectError.timeout }
  }

  private func acceptSession(socket: any ProxyUpstreamWebSocket, origin: String, address: String,
                             deadline: ContinuousClock.Instant) async throws -> (OpaqueSessionV3, DirectAdmissionRequest) {
    let transport = NIOWebSocketBinaryTransportV3(socket: socket)
    let admission = try AdmissionCodecV3.decodeFSB5(try await transport.readBinary())
    guard admission.pathKind == "direct" else { throw ConnectError.artifactInvalid }
    let request = DirectAdmissionRequest(channelID: admission.channelID, candidateID: admission.chosenCandidateID,
                                         origin: origin, remoteAddress: address)
    try checkDeadline(deadline)
    let config: TransportV3SessionConfig
    var reservation: ConnectionLease?
    do {
      guard let grant = try await authorize(request) else { throw ConnectError.artifactInvalid }
      let artifact = grant.artifact
      func checkAuthority() throws {
        try checkDeadline(deadline)
        let now = UInt64(max(0, Date().timeIntervalSince1970))
        guard artifact.value.path.kind == "direct", artifact.value.session.initExpireAtUnixSeconds > now,
              let candidate = artifact.canonicalCandidates.first(where: { $0.id == request.candidateID }),
              candidate.carrier == "websocket", candidate.normalizedURL == endpoint,
              (try candidate.activePinHashes(at: now))?.contains(leafHash) ?? true
        else { throw ConnectError.artifactInvalid }
      }
      try checkAuthority()
      let expected = try AdmissionCodecV3.encodeFSB5(artifact: artifact, chosenCandidateID: request.candidateID)
      guard expected.admissionBinding == admission.admissionBinding else { throw ConnectError.artifactInvalid }
      config = try SessionConnectorV3.sessionConfig(artifact: artifact.value, path: .direct, role: .server,
        admissionBinding: expected.admissionBinding, handlers: grant.handlers, frameLimits: frameLimits,
        maxConcurrentRequests: maxConcurrentRequests)
      reservation = try await grant.consume()
      try checkAuthority()
    } catch {
      let reason = Data("authorization_denied".utf8)
      var frame = Data("FSA5".utf8) + Data([5, 1, 0, UInt8(reason.count)])
      frame.append(reason)
      try? await transport.writeBinary(frame)
      await transport.close()
      try await reservation?.finish()
      throw error
    }
    do {
      try await transport.writeBinary(Data("FSA5".utf8) + Data([5, 0, 0, 0]))
      let carrier = WebSocketCarrierSessionV3(transport: transport, path: .direct, client: false,
                                              inboundCapacity: config.maxInboundStreams + 2)
      let establishedSession = try await TransportV3Session.establish(carrier: carrier, config: config, connectionLease: reservation)
      return (OpaqueSessionV3(establishedSession), request)
    } catch {
      await transport.close()
      try await reservation?.finish()
      throw error
    }
  }
}

final class DirectChildrenV3: @unchecked Sendable {
  private let lock = NSLock()
  private var shutdownTask: Task<Void, Never>?
  private var channels: [ObjectIdentifier: any Channel] = [:]
  private var closedWithWorker: Set<ObjectIdentifier> = []
  private var workers: [ObjectIdentifier: Task<Void, Error>] = [:]
  private var releaseFailed = false
  func checkReleases() throws {
    if lock.withLock({ releaseFailed }) { throw ArtifactLeaseError.releaseFailed }
  }
  let maximum: Int
  init(maximum: Int) { self.maximum = maximum }
  func add(_ channel: any Channel) -> Bool {
    lock.withLock {
      guard shutdownTask == nil, channels.count < maximum else { return false }
      channels[ObjectIdentifier(channel)] = channel
      return true
    }
  }
  func startWorker(_ channel: any Channel, run: @escaping @Sendable () async throws -> Void) -> Task<Void, Error>? {
    lock.withLock {
      let id = ObjectIdentifier(channel)
      guard shutdownTask == nil, channels[id] != nil, workers[id] == nil else { return nil }
      let worker = Task {
        defer { channel.close(promise: nil); workerFinished(channel) }
        try Task.checkCancellation()
        do { try await run() } catch ArtifactLeaseError.releaseFailed {
          lock.withLock { releaseFailed = true }
          throw ArtifactLeaseError.releaseFailed
        }
      }
      workers[id] = worker
      return worker
    }
  }
  func channelClosed(_ channel: any Channel) {
    lock.withLock {
      let id = ObjectIdentifier(channel)
      if workers[id] == nil { channels.removeValue(forKey: id) } else { closedWithWorker.insert(id) }
    }
  }
  private func workerFinished(_ channel: any Channel) {
    lock.withLock {
      let id = ObjectIdentifier(channel)
      workers.removeValue(forKey: id)
      if closedWithWorker.remove(id) != nil { channels.removeValue(forKey: id) }
    }
  }
  func shutdown() -> Task<Void, Never> {
    lock.withLock {
      if let shutdownTask { return shutdownTask }
      let accepted = Array(channels.values)
      let active = Array(workers.values)
      let drain = Task {
        for worker in active { worker.cancel() }
        for channel in accepted { channel.close(promise: nil) }
        for channel in accepted { try? await channel.closeFuture.get() }
        for worker in active { _ = await worker.result }
      }
      shutdownTask = drain
      return drain
    }
  }
}

private final class DirectRejectHTTPV3: ChannelInboundHandler, RemovableChannelHandler, Sendable {
  typealias InboundIn = HTTPServerRequestPart
  func channelRead(context: ChannelHandlerContext, data: NIOAny) { context.close(promise: nil) }
}

private final class DirectClientFrameRuleV3: ChannelInboundHandler, Sendable {
  typealias InboundIn = WebSocketFrame
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    guard frame.maskKey != nil, !frame.rsv1, !frame.rsv2, !frame.rsv3 else { context.close(promise: nil); return }
    context.fireChannelRead(data)
  }
}
#endif
