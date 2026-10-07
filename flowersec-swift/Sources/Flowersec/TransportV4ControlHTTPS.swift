#if os(macOS) || os(iOS)
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import Security

/// Independently supplied control-plane identity and routing. The TLS client
/// key authorizes a service call; it never becomes an Artifact signing key.
public struct TransportControlHTTPSConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let endpoint: TransportEndpoint
  public let basePath: String
  public let trustRootsPEM: [Data]
  public let clientCertificatePEM: Data
  public let clientPrivateKeyPEM: Data
  public let maximumConcurrentRequests: Int
  public let timeoutMilliseconds: UInt64
  public init(endpoint: TransportEndpoint, basePath: String = "",
    trustRootsPEM: [Data], clientCertificatePEM: Data, clientPrivateKeyPEM: Data,
    maximumConcurrentRequests: Int = 2, timeoutMilliseconds: UInt64 = 10_000) {
    self.endpoint = endpoint; self.basePath = basePath; self.trustRootsPEM = trustRootsPEM
    self.clientCertificatePEM = clientCertificatePEM; self.clientPrivateKeyPEM = clientPrivateKeyPEM
    self.maximumConcurrentRequests = maximumConcurrentRequests; self.timeoutMilliseconds = timeoutMilliseconds
  }
  public var description: String { "Flowersec.ControlHTTPSConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

/// Original server-leg permission and independently installed HTTPS sender.
/// A successful durable pool consume is required before this sender is used.
public struct TransportPoolServerAllowConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let control: TransportControlHTTPSConfiguration
  public let recipient: Data
  public let incarnation: Data
  public let serverGrant: Data
  public init(control: TransportControlHTTPSConfiguration, recipient: Data, incarnation: Data, serverGrant: Data) {
    self.control = control; self.recipient = recipient; self.incarnation = incarnation; self.serverGrant = serverGrant
  }
  var input: V4PoolServerAllowInput {
    V4PoolServerAllowInput(grant: serverGrant, recipient: recipient, incarnation: incarnation, control: control)
  }
  public var description: String { "Flowersec.PoolServerAllowConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

public enum TransportControlError: String, Error, Sendable {
  case invalidConfiguration = "control_configuration"
  case responseInvalid = "control_response_invalid"
  case unavailable = "control_unavailable"
  case busy = "control_busy"
  case canceled
  case closed
}

// Observes one request's original slots without borrowing another reference or
// retaining its native driver. A later call on the same provider is unrelated.
final class V4ControlHTTPCallCleanup: @unchecked Sendable {
  private let gate = NSLock()
  private let events = V4SessionEvents(maximum: 4)
  private var driver: V4ResourceReference?
  private var response: V4ResourceReference?
  func observeDriver(_ reference: V4ResourceReference) { gate.withLock { driver = reference } }
  func observeResponse(_ reference: V4ResourceReference) { gate.withLock { response = reference } }
  func released() { events.signal() }
  func waitPhysicalCleanup() async {
    while true {
      let revision = events.revision
      if cleanupStatus().complete { return }
      try? await events.wait(after: revision)
    }
  }
  func cleanupStatus() -> CleanupStatus {
    let references = gate.withLock { (driver, response) }
    var pending: UInt64 = 0
    if let driver = references.0, (try? driver.checkRetained()) != nil { pending += 1 }
    if let response = references.1, (try? response.checkRetained()) != nil { pending += 1 }
    return CleanupStatus(complete: pending == 0, pendingCallbacks: pending)
  }
}

// Counts only actual driver/body ownership. This holder never retains the
// provider, request check, material or result that it measures.
fileprivate final class V4ControlHTTPSLifetime: @unchecked Sendable {
  private let gate = NSLock()
  let events = V4SessionEvents(maximum: 4)
  private var drivers = 0
  private var views = 0
  func driverStarted() { gate.withLock { drivers += 1 } }
  func driverEnded() { gate.withLock { drivers -= 1 }; events.signal() }
  func viewStarted() { gate.withLock { views += 1 } }
  func viewEnded() { gate.withLock { views -= 1 }; events.signal() }
  var pending: Int { gate.withLock { drivers + views } }
}

// Keep the original response charge even when Foundation stores a small Data
// inline. The no-copy deallocator also owns this lease for shared large views.
// Consumers retain the envelope through parsing and installing their own data.
fileprivate final class V4ControlHTTPResponseLease: @unchecked Sendable {
  private let storage: V4CryptoReservation
  private let transport: V4CryptoReservation
  private let custody: V4ResourceCustody?
  private let tail: V4ResourceReference
  private let lifetime: V4ControlHTTPSLifetime
  private let cleanup: V4ControlHTTPCallCleanup?
  init(storage: V4CryptoReservation, transport: V4CryptoReservation, custody: V4ResourceCustody?,
    lifetime: V4ControlHTTPSLifetime, cleanup: V4ControlHTTPCallCleanup?) throws {
    tail = try storage.executionTail()
    self.storage = storage; self.transport = transport; self.custody = custody; self.lifetime = lifetime
    self.cleanup = cleanup
    lifetime.viewStarted()
    cleanup?.observeResponse(tail)
  }
  deinit { tail.release(); lifetime.viewEnded(); cleanup?.released() }
}
final class V4ControlHTTPResponse: @unchecked Sendable {
  private(set) var bytes: Data
  private let lease: V4ControlHTTPResponseLease
  fileprivate init(bytes: Data, lease: V4ControlHTTPResponseLease) { self.bytes = bytes; self.lease = lease }
  deinit { bytes.resetBytes(in: 0..<bytes.count) }
}

/// One immutable native TLS assembly, shared by issuance and activation calls.
/// Every physical call has its own connection, bounded body, deadline and tail.
final class V4ControlHTTPS: V4NativeConnectionLifecycle, @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  private let storage: V4CryptoReservation
  private let configuration: TransportControlHTTPSConfiguration
  private let tls: NIOSSLContext
  private let anchors: [SecCertificate]
  private let lifetime = V4ControlHTTPSLifetime()
  private var active: [UUID: V4ControlHTTPCall] = [:]
  private var closed = false
  init(environment: V4EnvironmentFoundation, configuration: TransportControlHTTPSConfiguration) throws {
    let c = configuration; let endpoint = c.endpoint
    guard (1...8).contains(c.maximumConcurrentRequests), (1...30_000).contains(c.timeoutMilliseconds),
      endpoint.hostname.utf8.count <= 253, !endpoint.hostname.isEmpty,
      (V4CredentialText.addressBytes(endpoint.hostname) != nil ||
        (endpoint.hostname.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d || $0 == 0x2e }) &&
        endpoint.hostname.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-") }))),
      (1...65535).contains(endpoint.port),
      (try? SocketAddress(ipAddress: endpoint.numericAddress, port: endpoint.port)) != nil,
      c.basePath.utf8.count <= 256, c.basePath.isEmpty || (c.basePath.hasPrefix("/") && !c.basePath.hasSuffix("/")),
      c.basePath.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f && ![0x3f, 0x23, 0x25, 0x5c].contains($0) }),
      (1...16).contains(c.trustRootsPEM.count), c.trustRootsPEM.reduce(0, { $0 + $1.count }) <= 262_144,
      (1...65_536).contains(c.clientCertificatePEM.count), (1...16_384).contains(c.clientPrivateKeyPEM.count)
    else { throw TransportControlError.invalidConfiguration }
    if let literal = try? SocketAddress(ipAddress: endpoint.hostname, port: endpoint.port) {
      guard literal == (try SocketAddress(ipAddress: endpoint.numericAddress, port: endpoint.port))
      else { throw TransportControlError.invalidConfiguration }
    }
    storage = try environment.controlHTTPSStorage(bytes: c.trustRootsPEM.reduce(0, { $0 + $1.count }) + c.clientCertificatePEM.count + c.clientPrivateKeyPEM.count)
    self.environment = environment; self.configuration = c
    var config = TLSConfiguration.makeClientConfiguration()
    config.minimumTLSVersion = .tlsv13; config.maximumTLSVersion = .tlsv13
    config.certificateVerification = V4CredentialText.addressBytes(endpoint.hostname) == nil ? .fullVerification : .noHostnameVerification
    config.applicationProtocols = ["http/1.1"]
    let roots = try c.trustRootsPEM.flatMap { try NIOSSLCertificate.fromPEMBytes(Array($0)) }
    let certificates = try NIOSSLCertificate.fromPEMBytes(Array(c.clientCertificatePEM))
    guard (1...16).contains(roots.count), (1...8).contains(certificates.count) else { throw TransportControlError.invalidConfiguration }
    anchors = try roots.map { certificate in
      guard let value = SecCertificateCreateWithData(nil, Data(try certificate.toDERBytes()) as CFData) else { throw TransportControlError.invalidConfiguration }
      return value
    }
    config.trustRoots = .certificates(roots)
    config.certificateChain = certificates.map { .certificate($0) }
    config.privateKey = .privateKey(try NIOSSLPrivateKey(bytes: Array(c.clientPrivateKeyPEM), format: .pem))
    tls = try NIOSSLContext(configuration: config)
    try environment.registerNativeConnection(self)
  }
  func post(path: String, body: Data, maximumResponseBytes: Int, allowApplicationError: Bool = false, requestContentType: String = "application/cbor", responseContentType: String = "application/cbor",
    custody: V4ResourceCustody? = nil, cleanup: V4ControlHTTPCallCleanup? = nil,
    check: @escaping @Sendable () throws -> Void) async throws -> V4ControlHTTPResponse {
    let prepared = try prepare(path: path, body: body, maximumResponseBytes: maximumResponseBytes,
      allowApplicationError: allowApplicationError, requestContentType: requestContentType,
      responseContentType: responseContentType, custody: custody, cleanup: cleanup, check: check)
    return try await prepared.run()
  }
  // Captures the native driver's original backing and a provider position
  // before an irreversible operation. Preparing performs no network I/O.
  func prepare(path: String, body: Data, maximumResponseBytes: Int, allowApplicationError: Bool = false,
    requestContentType: String = "application/cbor", responseContentType: String = "application/cbor",
    custody: V4ResourceCustody? = nil, cleanup: V4ControlHTTPCallCleanup? = nil,
    check: @escaping @Sendable () throws -> Void) throws -> V4PreparedControlHTTPCall {
    let originalCheck: @Sendable () throws -> Void = { [environment] in
      try custody?.check(in: environment); try check()
    }
    let id = UUID()
    let call = try environment.gate.withLock {
      guard !closed else { throw TransportControlError.closed }
      try storage.check(); try originalCheck()
      guard active.count < configuration.maximumConcurrentRequests,
        path.hasPrefix("/"), path.utf8.count <= 128, ["application/cbor", "application/json"].contains(requestContentType),
        ["application/cbor", "application/json"].contains(responseContentType), (1...524_288).contains(body.count),
        (1...524_288).contains(maximumResponseBytes) else { throw TransportControlError.busy }
      let reservation = try environment.controlHTTPCallStorage(maximumBytes: maximumResponseBytes, requestBytes: body.count, custody: custody)
      let call = try V4ControlHTTPCall(environment: environment, configuration: configuration,
        tls: tls, anchors: anchors, path: configuration.basePath + path, body: body,
        maximum: maximumResponseBytes, requestContentType: requestContentType, responseContentType: responseContentType,
        allowApplicationError: allowApplicationError, storage: reservation, transportStorage: storage,
        custody: custody, lifetime: lifetime, cleanup: cleanup, check: originalCheck)
      active[id] = call; return call
    }
    return V4PreparedControlHTTPCall(call: call) { [self] in
      environment.gate.withLock { active.removeValue(forKey: id) }; lifetime.events.signal()
    }
  }
  func close() {
    environment.gate.withLock { closed = true; for call in active.values { call.close() } }
    lifetime.events.signal()
  }
  func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let pending = max(active.count, lifetime.pending)
      return CleanupStatus(complete: closed && pending == 0, pendingCallbacks: UInt64(pending))
    }
  }
  func waitCleanup() async throws -> CleanupStatus {
    while true {
      let revision = lifetime.events.revision
      let status = cleanupStatus()
      if status.complete { return status }
      try await lifetime.events.wait(after: revision)
    }
  }
  func waitPhysicalCleanup() async {
    while true {
      let revision = lifetime.events.revision
      if cleanupStatus().complete { return }
      try? await lifetime.events.wait(after: revision)
    }
  }
  deinit { close() }
}

struct V4ControlApplicationError: Error, Sendable { let payload: V4ControlHTTPResponse }

final class V4PreparedControlHTTPCall: @unchecked Sendable {
  private let gate = NSLock()
  private let call: V4ControlHTTPCall
  private let release: @Sendable () -> Void
  private var used = false
  fileprivate init(call: V4ControlHTTPCall, release: @escaping @Sendable () -> Void) {
    self.call = call; self.release = release
  }
  func run() async throws -> V4ControlHTTPResponse {
    try gate.withLock {
      guard !used else { throw TransportControlError.busy }; used = true
    }
    defer { release() }
    return try await call.run()
  }
  deinit { call.close(); release() }
}

private final class V4ControlHTTPCall: @unchecked Sendable {
  let loop: any EventLoop
  let reply: EventLoopPromise<V4ControlHTTPResponse>
  private let environment: V4EnvironmentFoundation
  private let storage: V4CryptoReservation
  private let tail: V4ResourceReference
  private let transportStorage: V4CryptoReservation
  private let custody: V4ResourceCustody?
  private let lifetime: V4ControlHTTPSLifetime
  private let cleanup: V4ControlHTTPCallCleanup?
  private let configuration: TransportControlHTTPSConfiguration
  private let tls: NIOSSLContext
  private let anchors: [SecCertificate]
  private let path: String
  private var body: Data
  private let maximum: Int
  private let requestContentType: String
  private let responseContentType: String
  private let allowApplicationError: Bool
  private var applicationError = false
  private let check: @Sendable () throws -> Void
  private let gate = NSLock()
  private var channel: (any Channel)?
  private var failure: Error?
  private var finished = false
  private var sent = false
  private var expected: Int?
  private var response = Data()
  private var timer: Scheduled<Void>?
  init(environment: V4EnvironmentFoundation, configuration: TransportControlHTTPSConfiguration,
    tls: NIOSSLContext, anchors: [SecCertificate], path: String, body: Data, maximum: Int, requestContentType: String, responseContentType: String, allowApplicationError: Bool,
    storage: V4CryptoReservation, transportStorage: V4CryptoReservation, custody: V4ResourceCustody?, lifetime: V4ControlHTTPSLifetime, cleanup: V4ControlHTTPCallCleanup?, check: @escaping @Sendable () throws -> Void) throws {
    tail = try storage.executionTail()
    self.transportStorage = transportStorage; self.custody = custody; self.lifetime = lifetime; self.cleanup = cleanup
    self.environment = environment; self.configuration = configuration; self.tls = tls
    self.anchors = anchors; self.path = path
    self.body = body.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
    self.maximum = maximum; self.requestContentType = requestContentType; self.responseContentType = responseContentType; self.allowApplicationError = allowApplicationError; self.storage = storage; self.check = check
    loop = MultiThreadedEventLoopGroup.singleton.any(); reply = loop.makePromise(of: V4ControlHTTPResponse.self)
    response.reserveCapacity(maximum)
    lifetime.driverStarted()
    cleanup?.observeDriver(tail)
  }
  func run() async throws -> V4ControlHTTPResponse {
    try environment.gate.withLock { try storage.check(); try check() }
    if Task.isCancelled { throw TransportControlError.canceled }
    // The final native handler owns this call after the awaiting task returns.
    // Its deinit releases the original execution tail and TLS prepayment.
    let endpoint = configuration.endpoint
    let bootstrap = ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
      .connectTimeout(.milliseconds(Int64(configuration.timeoutMilliseconds)))
      .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
      .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384))
      .channelInitializer { [self] channel in
        do {
          try environment.gate.withLock { try storage.check(); try check(); try gate.withLock { if let failure { throw failure }; self.channel = channel } }
          let handler = try NIOSSLClientHandler(context: tls, serverHostname: V4CredentialText.addressBytes(endpoint.hostname) == nil ? endpoint.hostname : nil,
            customVerificationCallback: { [self] certificates, promise in
              do { try verifyPeer(certificates); promise.succeed(.certificateVerified) }
              catch { promise.succeed(.failed) }
            })
          var limits = NIOHTTPDecoderLimitConfiguration()
          limits.maxHeaderFieldCount = 64; limits.maxHeaderFieldSize = 4096; limits.maxHeaderListSize = 16_384
          try channel.pipeline.syncOperations.addHandler(handler)
          try channel.pipeline.syncOperations.addHTTPClientHandlers(leftOverBytesStrategy: .dropBytes, decoderLimitConfiguration: limits)
          try channel.pipeline.syncOperations.addHandler(V4ControlHTTPHandler(owner: self))
          return channel.eventLoop.makeSucceededVoidFuture()
        } catch { fail(error); return channel.eventLoop.makeFailedFuture(error) }
      }
    return try await withTaskCancellationHandler {
      timer = loop.scheduleTask(in: .milliseconds(Int64(configuration.timeoutMilliseconds))) { [self] in fail(TransportControlError.unavailable) }
      do {
        let connection = try await bootstrap.connect(to: SocketAddress(ipAddress: endpoint.numericAddress, port: endpoint.port)).get()
        let result = try await reply.futureResult.get()
        connection.close(promise: nil); _ = try? await connection.closeFuture.get()
        gate.withLock { channel = nil }
        timer?.cancel(); timer = nil
        try storage.check(); try check()
        if Task.isCancelled { throw TransportControlError.canceled }
        if applicationError { throw V4ControlApplicationError(payload: result) }
        return result
      } catch {
        fail(error)
        let connected = gate.withLock { channel }
        if let connected { _ = try? await connected.closeFuture.get() }
        gate.withLock { channel = nil }
        timer?.cancel(); timer = nil
        if Task.isCancelled { throw TransportControlError.canceled }
        if let application = error as? V4ControlApplicationError { throw application }
        if let control = error as? TransportControlError { throw control }
        throw TransportControlError.unavailable
      }
    } onCancel: { self.close() }
  }
  private func verifyPeer(_ certificates: [NIOSSLCertificate]) throws {
    guard (1...16).contains(certificates.count) else { throw TransportControlError.responseInvalid }
    let encoded = try certificates.map { Data(try $0.toDERBytes()) }
    guard encoded.reduce(0, { $0 + $1.count }) <= 262_144 else { throw TransportControlError.responseInvalid }
    let chain = try encoded.map { bytes in
      guard let certificate = SecCertificateCreateWithData(nil, bytes as CFData) else { throw TransportControlError.responseInvalid }
      return certificate
    }
    let now = try environment.gate.withLock { () throws -> V4TimeInterval in
      try storage.check(); try check()
      let sample = environment.clock.sample()
      guard let interval = sample.interval else { throw sample.failure ?? V4TimeFailure.unavailable }
      return interval
    }
    var trust: SecTrust?
    let host = configuration.endpoint.hostname
    let numeric = V4CredentialText.addressBytes(host) != nil
    if numeric {
      guard V4NativeWebSocketTLS.matchesIdentity(certificates[0], host: host) else { throw TransportControlError.responseInvalid }
    }
    let policy = SecPolicyCreateSSL(true, numeric ? nil : host as CFString)
    guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess, let trust,
      SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { throw TransportControlError.responseInvalid }
    for milliseconds in [now.lowerMS, now.upperMS] {
      let date = Date(timeIntervalSince1970: Double(milliseconds) / 1000)
      guard SecTrustSetVerifyDate(trust, date as CFDate) == errSecSuccess,
        SecTrustEvaluateWithError(trust, nil) else { throw TransportControlError.responseInvalid }
    }
    try storage.check(); try check()
  }
  func authenticated(context: ChannelHandlerContext, event: TLSUserEvent) throws {
    try environment.gate.withLock { try storage.check(); try check(); try gate.withLock {
      if let failure { throw failure }
      guard !sent, case .handshakeCompleted(let negotiated) = event, negotiated == "http/1.1" else { throw TransportControlError.responseInvalid }
      sent = true
      let endpoint = configuration.endpoint
      let authority = endpoint.hostname.contains(":") ? "[\(endpoint.hostname)]" : endpoint.hostname
      let host = endpoint.port == 443 ? authority : "\(authority):\(endpoint.port)"
      let headers = HTTPHeaders([("Host", host), ("Accept", responseContentType), ("Content-Type", requestContentType),
        ("Content-Length", String(body.count)), ("Cache-Control", "no-store"), ("Connection", "close")])
      let head = HTTPRequestHead(version: .http1_1, method: .POST, uri: path, headers: headers)
      var buffer = context.channel.allocator.buffer(capacity: body.count); buffer.writeBytes(body)
      try storage.check(); try check()
      context.write(NIOAny(HTTPClientRequestPart.head(head)), promise: nil)
      context.write(NIOAny(HTTPClientRequestPart.body(.byteBuffer(buffer))), promise: nil)
      context.writeAndFlush(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
    } }
  }
  func receive(_ part: HTTPClientResponsePart) throws {
    try environment.gate.withLock { try storage.check(); try check(); try gate.withLock {
      if let failure { throw failure }
      guard sent, !finished else { throw TransportControlError.responseInvalid }
      switch part {
      case .head(let head):
        let lengths = head.headers["content-length"]
        guard expected == nil, (head.status == .ok || (allowApplicationError && head.status == .conflict)), head.version == .http1_1,
          head.headers["content-type"] == [responseContentType], lengths.count == 1,
          let length = Int(lengths[0]), String(length) == lengths[0], (1...maximum).contains(length),
          head.headers["transfer-encoding"].isEmpty, head.headers["content-encoding"].isEmpty,
          head.headers["trailer"].isEmpty, head.headers["set-cookie"].isEmpty
        else { throw TransportControlError.responseInvalid }
        expected = length; applicationError = head.status == .conflict
      case .body(let bytes):
        guard let expected, bytes.readableBytes <= expected - response.count else { throw TransportControlError.responseInvalid }
        response.append(contentsOf: bytes.readableBytesView)
      case .end(let trailers):
        guard trailers == nil, let expected, response.count == expected else { throw TransportControlError.responseInvalid }
        let result = try ownedResponse()
        finished = true; reply.succeed(result)
      }
    } }
  }
  private func ownedResponse() throws -> V4ControlHTTPResponse {
    // Both the response envelope and any shared Data backing retain the same
    // original lease. Foundation's inline representation cannot refund it.
    let lease = try V4ControlHTTPResponseLease(storage: storage, transport: transportStorage,
      custody: custody, lifetime: lifetime, cleanup: cleanup)
    let pointer = UnsafeMutableRawPointer.allocate(byteCount: response.count, alignment: 1)
    response.withUnsafeBytes { bytes in
      pointer.copyMemory(from: bytes.baseAddress!, byteCount: bytes.count)
    }
    let bytes = Data(bytesNoCopy: pointer, count: response.count,
      deallocator: .custom { [lease] pointer, count in
        pointer.initializeMemory(as: UInt8.self, repeating: 0, count: count)
        pointer.deallocate()
        withExtendedLifetime(lease) {}
      })
    return V4ControlHTTPResponse(bytes: bytes, lease: lease)
  }
  func fail(_ error: Error) {
    let pending = gate.withLock { () -> (Bool, (any Channel)?) in
      if failure == nil {
        if let tls = error as? NIOSSLError {
          if case .uncleanShutdown = tls {} else { environment.root.diagnosticCounters.increment(.tlsRefusals) }
        }
        failure = error
      }
      let pending = !finished
      finished = true
      return (pending, channel)
    }
    if pending.0 { reply.fail(error) }
    pending.1?.close(promise: nil)
  }
  func close() { fail(TransportControlError.canceled) }
  deinit {
    body.resetBytes(in: 0..<body.count)
    response.resetBytes(in: 0..<response.count)
    tail.release()
    lifetime.driverEnded()
    cleanup?.released()
  }
}
private final class V4ControlHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = HTTPClientResponsePart
  let owner: V4ControlHTTPCall
  init(owner: V4ControlHTTPCall) { self.owner = owner }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    do { try owner.receive(unwrapInboundIn(data)) } catch { owner.fail(error) }
  }
  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
      do { try owner.authenticated(context: context, event: event) } catch { owner.fail(error) }
    }
    context.fireUserInboundEventTriggered(event)
  }
  func errorCaught(context: ChannelHandlerContext, error: Error) { owner.fail(error) }
  func channelInactive(context: ChannelHandlerContext) { owner.fail(TransportControlError.unavailable); context.fireChannelInactive() }
}
#endif
