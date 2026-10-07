#if os(macOS) || os(iOS)
import Foundation
import NIOCore
import NIOPosix
import NIOSSL

public struct ProxyForwardingPolicy: Sendable {
  public var extraRequestHeaders: [String] = []
  public var extraResponseHeaders: [String] = []
  public var blockedResponseHeaders: [String] = []
  public var extraWebSocketHeaders: [String] = []
  public var forbiddenCookieNames: [String] = []
  public var forbiddenCookieNamePrefixes: [String] = []
  public var allowedExternalOrigins: [String] = []
  public init() {}
  fileprivate var options: ProxyForwardingOptions {
    ProxyForwardingOptions(extraRequestHeaders: extraRequestHeaders, extraResponseHeaders: extraResponseHeaders,
      blockedResponseHeaders: blockedResponseHeaders, extraWebSocketHeaders: extraWebSocketHeaders,
      forbiddenCookieNames: forbiddenCookieNames, forbiddenCookieNamePrefixes: forbiddenCookieNamePrefixes)
  }
}

/// A fixed HTTP origin and explicit numeric endpoint. Relative request paths
/// cannot choose a different authority, redirect target or TLS identity.
public struct NativeProxyUpstreamConfiguration: Sendable {
  public let origin: URL
  public let numericAddress: String
  public let trustRootsPEM: [Data]
  public let limits: ProxyClientLimits
  public let timeoutMilliseconds: UInt32
  public let forwardingPolicy: ProxyForwardingPolicy
  public init(origin: URL, numericAddress: String, trustRootsPEM: [Data] = [],
    limits: ProxyClientLimits, timeoutMilliseconds: UInt32 = 30_000,
    forwardingPolicy: ProxyForwardingPolicy = ProxyForwardingPolicy()) {
    self.origin = origin; self.numericAddress = numericAddress; self.trustRootsPEM = trustRootsPEM
    self.limits = limits; self.timeoutMilliseconds = timeoutMilliseconds; self.forwardingPolicy = forwardingPolicy
  }
  public init(origin: URL, numericAddress: String, trustRootsPEM: [Data] = [],
    timeoutMilliseconds: UInt32 = 30_000, forwardingPolicy: ProxyForwardingPolicy = ProxyForwardingPolicy()) throws {
    self.init(origin: origin, numericAddress: numericAddress, trustRootsPEM: trustRootsPEM,
      limits: try ProxyClientLimits(), timeoutMilliseconds: timeoutMilliseconds, forwardingPolicy: forwardingPolicy)
  }
}

public final class NativeProxyUpstream: ProxyUpstream, @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let configuration: NativeProxyUpstreamConfiguration
  private let policy: ProxyHeaderPolicy
  private let persistentStorage: V4CryptoReservation
  private let allowedExternalOrigins: Set<String>
  private var cookies = ProxyCookieJar()
  init(environment: V4EnvironmentFoundation, configuration: NativeProxyUpstreamConfiguration) throws {
    let c = configuration
    guard let host = c.origin.host, ["http", "https"].contains(c.origin.scheme ?? ""),
      c.origin.user == nil, c.origin.password == nil, c.origin.query == nil, c.origin.fragment == nil,
      c.origin.path.isEmpty || c.origin.path == "/", host.utf8.count <= 253,
      (1...FlowersecSDKDefaults.Proxy.maximumTimeoutMilliseconds).contains(c.timeoutMilliseconds), c.numericAddress.utf8.count <= 64,
      c.trustRootsPEM.count <= 16, c.trustRootsPEM.reduce(0, { $0 + $1.count }) <= 262_144
    else { throw ProxyClientFailure.configurationCapacity }
    _ = try SocketAddress(ipAddress: c.numericAddress, port: c.origin.port ?? (c.origin.scheme == "https" ? 443 : 80))
    let names = [c.forwardingPolicy.extraRequestHeaders, c.forwardingPolicy.extraResponseHeaders,
      c.forwardingPolicy.blockedResponseHeaders, c.forwardingPolicy.extraWebSocketHeaders,
      c.forwardingPolicy.forbiddenCookieNames, c.forwardingPolicy.forbiddenCookieNamePrefixes,
      c.forwardingPolicy.allowedExternalOrigins]
    guard names.reduce(0, { $0 + $1.count }) <= 256,
      names.reduce(0, { $0 + $1.reduce(0, { $0 + $1.utf8.count }) }) <= 65_536 else {
      throw ProxyClientFailure.configurationCapacity
    }
    persistentStorage = try environment.nativeProxyUpstreamStorage()
    self.environment = environment; self.configuration = c
    policy = try ProxyHeaderPolicy(options: c.forwardingPolicy.options)
    allowedExternalOrigins = try Set(c.forwardingPolicy.allowedExternalOrigins.map(proxyNormalizedOrigin))
  }
  public func send(_ request: HTTPProxyRequest) async throws -> HTTPProxyResponse {
    try persistentStorage.check(); try Task.checkCancellation()
    let limits = configuration.limits
    try V4ProxyWire.boundFields(request.headers, maximum: limits.maximumMetadataBytes)
    try V4ProxyWire.boundFields(request.trailers, maximum: limits.maximumMetadataBytes)
    let length = try V4ProxyWire.inspect(request.headers); try V4ProxyWire.trailers(request.trailers)
    guard request.method.utf8.count <= limits.maximumMetadataBytes,
      request.path.utf8.count <= limits.maximumMetadataBytes,
      (request.externalOrigin?.utf8.count ?? 0) <= limits.maximumMetadataBytes,
      V4ProxyWire.path(request.path), V4ProxyWire.token(Data(request.method.utf8)),
      request.body.count <= limits.maximumBodyBytes, length == nil || length == UInt64(request.body.count) else {
      throw ProxyClientFailure.protocolFailure
    }
    let storage = try environment.nativeProxyConnectionStorage(limits: limits)
    let tail = try storage.executionTail(); defer { tail.release(); storage.seal() }
    var headers = try filtered(request.headers, direction: 0)
    if let external = request.externalOrigin {
      let origin = try proxyNormalizedOrigin(external)
      guard allowedExternalOrigins.contains(origin), request.headers.allSatisfy({ field in
        field.name.lowercased() != "origin" || String(data: field.value, encoding: .ascii) == origin
      }), let scheme = URL(string: origin)?.scheme else { throw ProxyClientFailure.protocolFailure }
      if !headers.contains(where: { $0.name.lowercased() == "x-forwarded-proto" }) {
        headers.append(try HTTPProxyField(name: "x-forwarded-proto", value: scheme))
      }
    }
    try V4ProxyWire.boundFields(headers, maximum: limits.maximumMetadataBytes)
    _ = try V4ProxyWire.inspect(headers)
    let local = HTTPProxyRequest(method: request.method, path: request.path, headers: headers, body: request.body,
      trailers: request.trailers, externalOrigin: request.externalOrigin, timeoutMilliseconds: request.timeoutMilliseconds)
    let timeout = min(request.timeoutMilliseconds ?? configuration.timeoutMilliseconds, configuration.timeoutMilliseconds)
    let connection = try V4NativeHTTPProxyConnection(environment: environment, configuration: configuration,
      storage: storage, request: local, timeout: max(1, timeout))
    try environment.registerNativeConnection(connection)
    do {
      let response = try await connection.run()
      try storage.check(); try Task.checkCancellation()
      let responseFields = try filtered(response.headers, direction: 1)
      try environment.gate.withLock {
        try persistentStorage.check()
        try cookies.captureBounded(requestPath: request.path, headers: responseFields.compactMap { field in
          String(data: field.value, encoding: .isoLatin1).map { ProxyHeader(name: field.name, value: $0) }
        })
      }
      return HTTPProxyResponse(status: response.status, headers: responseFields, body: response.body, trailers: response.trailers)
    } catch { connection.close(); await connection.waitClosed(); throw error }
  }
  public func openWebSocket(path: String, headers: [HTTPProxyField]) async throws -> any ProxyUpstreamSocket {
    try persistentStorage.check(); try Task.checkCancellation()
    try V4ProxyWire.boundFields(headers, maximum: configuration.limits.maximumMetadataBytes)
    _ = try V4ProxyWire.inspect(headers)
    guard path.utf8.count <= configuration.limits.maximumMetadataBytes,
      V4ProxyWire.path(path), var components = URLComponents(url: configuration.origin, resolvingAgainstBaseURL: false) else {
      throw ProxyClientFailure.protocolFailure
    }
    let storage = try environment.nativeProxyConnectionStorage(limits: configuration.limits)
    let tail = try storage.executionTail()
    var ownsTail = true
    let dial = V4ProxyNativeDial()
    do {
      try environment.registerNativeConnection(dial)
      components.scheme = components.scheme == "https" ? "wss" : "ws"
      let parts = path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
      components.percentEncodedPath = String(parts[0]); components.percentEncodedQuery = parts.count == 2 ? String(parts[1]) : nil
      guard let url = components.url else { throw ProxyClientFailure.protocolFailure }
      let filtered = try filtered(headers, direction: 2).filter { $0.name.lowercased() != "origin" }
      var values = try filtered.map { field -> ProxyHeader in
        guard let value = String(data: field.value, encoding: .utf8) else { throw ProxyClientFailure.protocolFailure }
        return ProxyHeader(name: field.name, value: value)
      }
      if let stored = environment.gate.withLock({ cookies.requestHeader(for: path) }),
        let cookie = policy.filterWebSocket([stored]).first,
        !values.contains(where: { $0.name.lowercased() == "cookie" }) {
        values.append(cookie)
      }
      values.append(ProxyHeader(name: "origin", value: try proxyNormalizedOrigin(configuration.origin.absoluteString)))
      guard values.count <= 128,
        values.reduce(0, { $0 + $1.name.utf8.count + $1.value.utf8.count }) <= configuration.limits.maximumMetadataBytes else {
        throw ProxyClientFailure.resourceExhausted
      }
      let tls = try makeTLSHandler()
      let socket = try await ProxyNIOWebSocketConnector.connect(url: url, headers: values,
        maxFrameBytes: configuration.limits.maximumWebSocketFrameBytes,
        timeout: .milliseconds(Int64(configuration.timeoutMilliseconds)), tlsHandler: tls,
        numericAddress: configuration.numericAddress, lifetime: dial)
      try storage.check(); try Task.checkCancellation()
      let captured = V4NativeProxySocket(socket: socket, dial: dial, storage: storage, tail: tail, limits: configuration.limits)
      ownsTail = false
      do { try environment.registerNativeConnection(captured) }
      catch { await captured.close(); throw error }
      return captured
    } catch {
      dial.close(); await dial.waitClosed()
      if ownsTail { tail.release(); storage.seal() }
      throw error
    }
  }
  private func makeTLSHandler() throws -> ProxyTLSClientHandler? {
    guard configuration.origin.scheme == "https", let host = configuration.origin.host else { return nil }
    let ssl = try proxyTLSContext(host: host, roots: configuration.trustRootsPEM)
    return ProxyTLSClientHandler { try proxyTLSHandler(context: ssl, host: host) }
  }
  private func filtered(_ fields: [HTTPProxyField], direction: Int) throws -> [HTTPProxyField] {
    _ = try V4ProxyWire.inspect(fields)
    var nominated = Set<String>()
    for field in fields where field.name.lowercased() == "connection" {
      guard let value = String(data: field.value, encoding: .ascii) else { throw ProxyClientFailure.protocolFailure }
      for part in value.split(separator: ",", omittingEmptySubsequences: false) {
        let name = part.trimmingCharacters(in: .whitespaces).lowercased()
        guard V4ProxyWire.token(Data(name.utf8)) else { throw ProxyClientFailure.protocolFailure }
        nominated.insert(name)
      }
    }
    return try fields.compactMap { field in
      // Content-Length is a validated framing fact even when Connection names
      // it. Content coding and all field values remain opaque octets.
      if field.name.lowercased() == "content-length" { return field }
      guard !nominated.contains(field.name.lowercased()) else { return nil }
      guard let value = String(data: field.value, encoding: .isoLatin1) else { throw ProxyClientFailure.protocolFailure }
      let input = [ProxyHeader(name: field.name, value: value)]
      let allowed = direction == 0 ? policy.filterRequest(input) : direction == 1 ? policy.filterResponse(input) : policy.filterWebSocket(input)
      guard let filtered = allowed.first, let bytes = filtered.value.data(using: .isoLatin1) else { return nil }
      return try HTTPProxyField(name: field.name, value: bytes)
    }
  }
}

private func proxyTLSContext(host: String, roots: [Data]) throws -> NIOSSLContext {
  var tls = TLSConfiguration.makeClientConfiguration()
  tls.minimumTLSVersion = .tlsv13; tls.maximumTLSVersion = .tlsv13
  tls.applicationProtocols = ["http/1.1"]
  tls.certificateVerification = V4CredentialText.addressBytes(host) == nil ? .fullVerification : .noHostnameVerification
  if !roots.isEmpty {
    let certificates = try roots.flatMap { try NIOSSLCertificate.fromPEMBytes(Array($0)) }
    guard (1...16).contains(certificates.count) else { throw ProxyClientFailure.configurationCapacity }
    tls.trustRoots = .certificates(certificates)
  }
  return try NIOSSLContext(configuration: tls)
}
private func proxyTLSHandler(context: NIOSSLContext, host: String) throws -> NIOSSLClientHandler {
  try NIOSSLClientHandler._makeSSLClientHandler(context: context,
    serverHostname: V4CredentialText.addressBytes(host) == nil ? host : nil,
    additionalPeerCertificateVerificationCallback: { certificate, channel in
      guard V4NativeWebSocketTLS.matchesIdentity(certificate, host: host) else {
        return channel.eventLoop.makeFailedFuture(ProxyClientFailure.protocolFailure)
      }
      return channel.eventLoop.makeSucceededVoidFuture()
    })
}

private final class V4NativeProxySocket: ProxyUpstreamSocket, V4NativeConnectionLifecycle, @unchecked Sendable {
  private let socket: any ProxyUpstreamWebSocket
  private let dial: V4ProxyNativeDial
  private let storage: V4CryptoReservation
  private let tail: V4ResourceReference
  private let limits: ProxyClientLimits
  private let gate = NSLock()
  private var closing: Task<Void, Never>?
  private var sending = false
  private var receiving = false
  var selectedProtocol: Data? { socket.selectedProtocol.map { Data($0.utf8) } }
  init(socket: any ProxyUpstreamWebSocket, dial: V4ProxyNativeDial, storage: V4CryptoReservation,
    tail: V4ResourceReference, limits: ProxyClientLimits) {
    self.socket = socket; self.dial = dial; self.storage = storage; self.tail = tail; self.limits = limits
  }
  func send(_ message: ProxyWebSocketMessage) async throws {
    try gate.withLock {
      guard closing == nil, !sending else { throw ProxyClientFailure.resourceExhausted }
      sending = true
    }
    defer { gate.withLock { sending = false } }
    let callback = try storage.executionTail(); defer { callback.release() }
    try storage.check(); try Task.checkCancellation()
    let frame: ProxyWebSocketFrame
    switch message {
    case .text(let bytes): frame = .init(operation: .text, payload: bytes)
    case .binary(let bytes): frame = .init(operation: .binary, payload: bytes)
    case .close(let bytes): frame = .init(operation: .close, payload: bytes)
    case .ping(let bytes): frame = .init(operation: .ping, payload: bytes)
    case .pong(let bytes): frame = .init(operation: .pong, payload: bytes)
    }
    try V4ProxyWire.webSocket(frame.operation.rawValue, bytes: frame.payload, limits: limits)
    try await socket.send(frame)
  }
  func receive() async throws -> ProxyWebSocketMessage {
    try gate.withLock {
      guard closing == nil, !receiving else { throw ProxyClientFailure.resourceExhausted }
      receiving = true
    }
    defer { gate.withLock { receiving = false } }
    let callback = try storage.executionTail(); defer { callback.release() }
    try storage.check(); try Task.checkCancellation()
    let frame = try await socket.receive(); try storage.check()
    try V4ProxyWire.webSocket(frame.operation.rawValue, bytes: frame.payload, limits: limits)
    switch frame.operation {
    case .text: return .text(frame.payload)
    case .binary: return .binary(frame.payload)
    case .close: return .close(frame.payload)
    case .ping: return .ping(frame.payload)
    case .pong: return .pong(frame.payload)
    }
  }
  private func beginClose() -> Task<Void, Never> {
    gate.withLock {
      if let closing { return closing }
      let closing = Task { [socket, dial, tail, storage] in
        dial.close(); await socket.close(); await dial.waitClosed(); tail.release(); storage.seal()
      }
      self.closing = closing; return closing
    }
  }
  func close() { _ = beginClose() }
  func close() async { await beginClose().value }
  deinit {
    let owned = gate.withLock { closing != nil }
    if !owned {
      Task { [socket, dial, tail, storage] in
        dial.close(); await socket.close(); await dial.waitClosed(); tail.release(); storage.seal()
      }
    }
  }
}

// The native upstream parser keeps field values as octets. It handles HTTP/1
// Content-Length, chunked coding with independent trailers, and EOF-delimited
// bodies without collapsing duplicate fields or decoding content coding.
private final class V4NativeHTTPProxyConnection: V4NativeConnectionLifecycle, @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let configuration: NativeProxyUpstreamConfiguration
  private let storage: V4CryptoReservation
  private let request: HTTPProxyRequest
  private let timeout: UInt32
  // Environment close invokes this owner while holding the resource gate.
  // Use that same gate for NIO callbacks and their storage checks so close
  // and response publication have one atomic boundary and no inverted lock.
  private var gate: NSRecursiveLock { environment.gate }
  private let ready: EventLoopPromise<HTTPProxyResponse>
  private var channel: (any Channel)?
  private var closeFuture: EventLoopFuture<Void>?
  private var timer: Scheduled<Void>?
  private var completed = false
  private var pending = Data()
  private var status: Int?
  private var headers: [HTTPProxyField] = []
  private var body = Data()
  private var trailers: [HTTPProxyField] = []
  private var remaining: Int?
  private var chunked = false
  private var chunkRemaining: Int?
  private var readingTrailers = false
  private var informational = 0
  init(environment: V4EnvironmentFoundation, configuration: NativeProxyUpstreamConfiguration,
    storage: V4CryptoReservation, request: HTTPProxyRequest, timeout: UInt32) throws {
    self.environment = environment; self.configuration = configuration; self.storage = storage
    self.request = request; self.timeout = timeout
    ready = MultiThreadedEventLoopGroup.singleton.any().makePromise(of: HTTPProxyResponse.self)
  }
  func run() async throws -> HTTPProxyResponse {
    let c = configuration; let group = MultiThreadedEventLoopGroup.singleton
    let host = c.origin.host!; let port = c.origin.port ?? (c.origin.scheme == "https" ? 443 : 80)
    let ssl: NIOSSLContext?
    if c.origin.scheme == "https" { ssl = try proxyTLSContext(host: host, roots: c.trustRootsPEM) }
    else { ssl = nil }
    try gate.withLock {
      guard !completed else { throw ProxyClientFailure.closed }
      timer = ready.futureResult.eventLoop.scheduleTask(in: .milliseconds(Int64(timeout))) { [self] in
        fail(ProxyUpstreamFailure(.timeout, message: "The configured upstream deadline expired"))
      }
    }
    let bootstrap = ClientBootstrap(group: group).connectTimeout(.milliseconds(min(Int64(timeout), FlowersecSDKDefaults.Transport.connectTimeoutMilliseconds)))
      .channelOption(ChannelOptions.maxMessagesPerRead, value: 1)
      .channelOption(ChannelOptions.recvAllocator, value: FixedSizeRecvByteBufferAllocator(capacity: 16_384))
      .channelInitializer { channel in
        do {
          try self.attach(channel)
          if let ssl { try channel.pipeline.syncOperations.addHandler(proxyTLSHandler(context: ssl, host: host)) }
          try channel.pipeline.syncOperations.addHandler(V4NativeHTTPProxyHandler(owner: self))
          return channel.eventLoop.makeSucceededVoidFuture()
        } catch { self.fail(error); return channel.eventLoop.makeFailedFuture(error) }
      }
    return try await withTaskCancellationHandler {
      do {
        _ = try await bootstrap.connect(to: SocketAddress(ipAddress: c.numericAddress, port: port)).get()
        let response = try await ready.futureResult.get()
        await waitClosed(); try storage.check(); try Task.checkCancellation(); return response
      } catch { fail(error); await waitClosed(); throw error }
    } onCancel: { self.close() }
  }
  private func attach(_ channel: any Channel) throws {
    try gate.withLock {
      guard !completed, self.channel == nil else { throw ProxyClientFailure.closed }
      try storage.check(); self.channel = channel; closeFuture = channel.closeFuture
    }
  }
  func connected(_ context: ChannelHandlerContext) throws {
    try gate.withLock {
      guard !completed else { throw ProxyClientFailure.closed }
      try storage.check()
      let host = configuration.origin.host!
      let port = configuration.origin.port ?? (configuration.origin.scheme == "https" ? 443 : 80)
      let authority = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
      var wire = Data("\(request.method) \(request.path) HTTP/1.1\r\nHost: \(authority)\r\nConnection: close\r\n".utf8)
      let chunkedRequest = !request.trailers.isEmpty
      for field in request.headers where field.name.lowercased() != "host" && field.name.lowercased() != "connection" {
        if chunkedRequest && field.name.lowercased() == "content-length" { continue }
        wire.append(Data(field.name.utf8)); wire.append(Data(": ".utf8)); wire.append(field.value); wire.append(Data("\r\n".utf8))
      }
      if chunkedRequest {
        wire.append(Data("Transfer-Encoding: chunked\r\n\r\n".utf8))
        if !request.body.isEmpty { wire.append(Data("\(String(request.body.count, radix: 16))\r\n".utf8)); wire.append(request.body); wire.append(Data("\r\n".utf8)) }
        wire.append(Data("0\r\n".utf8))
        for trailer in request.trailers { wire.append(Data("\(trailer.name): ".utf8)); wire.append(trailer.value); wire.append(Data("\r\n".utf8)) }
        wire.append(Data("\r\n".utf8))
      } else {
        if !request.headers.contains(where: { $0.name.lowercased() == "content-length" }) { wire.append(Data("Content-Length: \(request.body.count)\r\n".utf8)) }
        wire.append(Data("\r\n".utf8)); wire.append(request.body)
      }
      var buffer = context.channel.allocator.buffer(capacity: wire.count); buffer.writeBytes(wire)
      context.writeAndFlush(NIOAny(buffer)).whenFailure { [self] in fail($0) }
    }
  }
  func input(_ bytes: Data) throws {
    try gate.withLock {
      guard !completed else { return }; try storage.check()
      guard pending.count + bytes.count <= configuration.limits.maximumBodyBytes + configuration.limits.maximumMetadataBytes + 65_536 else {
        throw ProxyClientFailure.resourceExhausted
      }
      pending.append(bytes)
      try parse()
    }
  }
  private func parse() throws {
    let limits = configuration.limits
    if status == nil {
      while true {
        guard let end = pending.range(of: Data("\r\n\r\n".utf8)) else {
          guard pending.count <= limits.maximumMetadataBytes else { throw ProxyClientFailure.resourceExhausted }; return
        }
        guard pending.distance(from: pending.startIndex, to: end.lowerBound) <= limits.maximumMetadataBytes else {
          throw ProxyClientFailure.resourceExhausted
        }
        let head = Data(pending[..<end.lowerBound]); pending.removeSubrange(..<end.upperBound)
        let lineEnd = head.range(of: Data("\r\n".utf8))
        let statusBytes = head[..<(lineEnd?.lowerBound ?? head.endIndex)]
        let line = String(decoding: statusBytes, as: UTF8.self).split(separator: " ", maxSplits: 2)
        guard line.count >= 2, line[0] == "HTTP/1.1" || line[0] == "HTTP/1.0", line[1].utf8.count == 3, let code = Int(line[1]), (100...599).contains(code) else {
          throw ProxyClientFailure.protocolFailure
        }
        let fields = try decodeFields(lineEnd.map { Data(head[$0.upperBound...]) } ?? Data())
        if code < 200 {
          informational += 1; guard code != 101, informational <= 4 else { throw ProxyClientFailure.protocolFailure }; continue
        }
        status = code
        let transfers = fields.filter { $0.name.lowercased() == "transfer-encoding" }
        let lengths = fields.filter { $0.name.lowercased() == "content-length" }
        guard transfers.isEmpty || lengths.isEmpty else { throw ProxyClientFailure.protocolFailure }
        if !transfers.isEmpty {
          guard transfers.count == 1, String(data: transfers[0].value, encoding: .ascii)?.lowercased() == "chunked" else { throw ProxyClientFailure.protocolFailure }
          chunked = true
        }
        headers = fields.filter { $0.name.lowercased() != "transfer-encoding" && $0.name.lowercased() != "trailer" }
        let length = try V4ProxyWire.inspect(headers)
        if request.method == "HEAD" || code == 204 || code == 304 { complete(); return }
        if let length { guard length <= UInt64(limits.maximumBodyBytes) else { throw ProxyClientFailure.resourceExhausted }; remaining = Int(length) }
        break
      }
    }
    if chunked {
      while true {
        if readingTrailers {
          if pending.starts(with: Data("\r\n".utf8)) { pending.removeFirst(2); complete(); return }
          guard let end = pending.range(of: Data("\r\n\r\n".utf8)) else {
            guard pending.count <= limits.maximumMetadataBytes else { throw ProxyClientFailure.resourceExhausted }; return
          }
          trailers = try decodeFields(Data(pending[..<end.lowerBound])); try V4ProxyWire.trailers(trailers)
          pending.removeSubrange(..<end.upperBound); complete(); return
        }
        if chunkRemaining == nil {
          guard let end = pending.range(of: Data("\r\n".utf8)) else {
            guard pending.count <= 4096 else { throw ProxyClientFailure.protocolFailure }; return
          }
          let raw = pending[..<end.lowerBound]
          guard raw.count <= 4096, V4ProxyWire.fieldValue(Data(raw)),
            let size = raw.split(separator: 59, maxSplits: 1, omittingEmptySubsequences: false).first,
            !size.isEmpty, size.count <= 16, size.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
            let count = Int(String(decoding: size, as: UTF8.self), radix: 16), count <= limits.maximumBodyBytes - body.count else {
            throw ProxyClientFailure.protocolFailure
          }
          pending.removeSubrange(..<end.upperBound)
          if count == 0 { readingTrailers = true; continue }
          chunkRemaining = count
        }
        guard let count = chunkRemaining else { return }
        guard pending.count >= count + 2 else { return }
        let chunkEnd = pending.index(pending.startIndex, offsetBy: count)
        let delimiterEnd = pending.index(chunkEnd, offsetBy: 2)
        guard pending[chunkEnd..<delimiterEnd] == Data("\r\n".utf8) else { throw ProxyClientFailure.protocolFailure }
        body.append(pending.prefix(count)); pending.removeFirst(count + 2); chunkRemaining = nil
      }
    } else if let remaining {
      let count = min(remaining, pending.count)
      body.append(pending.prefix(count)); pending.removeFirst(count); self.remaining = remaining - count
      if self.remaining == 0 { complete() }
    } else {
      guard pending.count <= limits.maximumBodyBytes - body.count else { throw ProxyClientFailure.resourceExhausted }
      body.append(pending); pending.removeAll(keepingCapacity: true)
    }
  }
  private func decodeFields(_ bytes: Data) throws -> [HTTPProxyField] {
    guard bytes.count <= configuration.limits.maximumMetadataBytes else { throw ProxyClientFailure.resourceExhausted }
    if bytes.isEmpty { return [] }
    var fields: [HTTPProxyField] = []
    let lines = bytes.split(separator: 10, omittingEmptySubsequences: false)
    for (index, original) in lines.enumerated() {
      let line = index == lines.count - 1 ? original : original.dropLast()
      guard index == lines.count - 1 || original.last == 13, let separator = line.firstIndex(of: 58), fields.count < 128,
        let name = String(data: Data(line[..<separator]), encoding: .ascii) else { throw ProxyClientFailure.protocolFailure }
      let value = Data(line[line.index(after: separator)...].drop(while: { $0 == 32 || $0 == 9 }).reversed().drop(while: { $0 == 32 || $0 == 9 }).reversed())
      fields.append(try HTTPProxyField(name: name, value: value))
    }
    return fields
  }
  func eof() {
    gate.withLock {
      guard !completed else { return }
      if status != nil, !chunked, remaining == nil { complete() }
      else { fail(ProxyClientFailure.protocolFailure) }
    }
  }
  private func complete() {
    guard !completed, let status else { return }
    guard pending.isEmpty else { fail(ProxyClientFailure.protocolFailure); return }
    completed = true
    timer?.cancel(); timer = nil
    ready.succeed(HTTPProxyResponse(status: status, headers: headers, body: body, trailers: trailers))
    channel?.close(promise: nil)
  }
  func fail(_ error: any Error) {
    gate.withLock {
      guard !completed else { return }; completed = true
      timer?.cancel(); timer = nil; ready.fail(error); channel?.close(promise: nil)
    }
  }
  func close() { fail(ProxyClientFailure.closed) }
  func waitClosed() async { if let close = gate.withLock({ closeFuture }) { try? await close.get() } }
  deinit { close() }
}

private final class V4NativeHTTPProxyHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = ByteBuffer
  let owner: V4NativeHTTPProxyConnection
  init(owner: V4NativeHTTPProxyConnection) { self.owner = owner }
  func channelActive(context: ChannelHandlerContext) {
    do { try owner.connected(context) } catch { owner.fail(error) }
    context.fireChannelActive()
  }
  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    do { try owner.input(Data(unwrapInboundIn(data).readableBytesView)) } catch { owner.fail(error) }
  }
  func channelInactive(context: ChannelHandlerContext) { owner.eof(); context.fireChannelInactive() }
  func errorCaught(context: ChannelHandlerContext, error: any Error) { owner.fail(error) }
}
#endif
