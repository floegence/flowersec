import Foundation

/// A configured upstream belongs to the application, while Flowersec owns the
/// authenticated Stream, current proxy framing, bounds and physical cleanup.
/// Upstream implementations preserve ordered octet fields and trailers.
public protocol ProxyUpstream: Sendable {
  func send(_ request: HTTPProxyRequest) async throws -> HTTPProxyResponse
  func openWebSocket(path: String, headers: [HTTPProxyField]) async throws -> any ProxyUpstreamSocket
}
public protocol ProxyUpstreamSocket: Sendable {
  var selectedProtocol: Data? { get }
  func send(_ message: ProxyWebSocketMessage) async throws
  func receive() async throws -> ProxyWebSocketMessage
  /// Returns only after outstanding physical callbacks have returned.
  func close() async
}

/// One server captures its original Session and configured upstream. Serve
/// accepted proxy streams from the application's existing stream dispatcher;
/// unrelated stream kinds retain their application handler.
public actor ProxyServer {
  private let session: any V4ServiceSession
  private let upstream: any ProxyUpstream
  private let limits: ProxyClientLimits
  private let maximumConcurrentStreams: Int
  private var operations: [UUID: Task<Void, any Error>] = [:]
  private var streams: [UUID: V4ProxyStreamAdapter] = [:]
  private var closed = false
  public init(session: any Session, upstream: any ProxyUpstream,
    limits: ProxyClientLimits, maximumConcurrentStreams: Int = 64) throws {
    guard let original = session as? any V4ServiceSession, (1...128).contains(maximumConcurrentStreams) else {
      throw ProxyClientFailure.configurationCapacity
    }
    try original.checkServiceSession()
    self.session = original; self.upstream = upstream; self.limits = limits
    self.maximumConcurrentStreams = maximumConcurrentStreams
  }
  public init(session: any Session, upstream: any ProxyUpstream, maximumConcurrentStreams: Int = 64) throws {
    try self.init(session: session, upstream: upstream, limits: ProxyClientLimits(),
      maximumConcurrentStreams: maximumConcurrentStreams)
  }
  public static func handles(kind: String) -> Bool {
    kind == "flowersec-proxy/http1" || kind == "flowersec-proxy/ws"
  }
  public func serve(_ incoming: IncomingStream) async throws {
    guard !closed, Self.handles(kind: incoming.kind), operations.count < maximumConcurrentStreams else {
      try? await incoming.stream.reset(); throw ProxyClientFailure.resourceExhausted
    }
    let storage: V4CryptoReservation
    let tail: V4ResourceReference
    let original: any V4ProxySessionStream
    do {
      try session.checkServiceSession(); try Task.checkCancellation()
      guard let captured = incoming.stream as? any V4ProxySessionStream,
        incoming.kind == captured.kind else { throw ProxyClientFailure.protocolFailure }
      original = captured
      try original.checkProxySession(session)
      storage = try session.serviceEnvironment.proxyOperationStorage(limits: limits, server: true)
      tail = try storage.executionTail()
    } catch { try? await incoming.stream.reset(); throw error }
    let stream = V4ProxyStreamAdapter(incoming.stream)
    let id = UUID()
    let operation = Task { [session, upstream, limits] in
      defer { tail.release(); withExtendedLifetime(storage) {} }
      do {
        try storage.check(); try session.checkServiceSession()
        try await withThrowingTaskGroup(of: Void.self) { group in
          group.addTask {
            if incoming.kind == "flowersec-proxy/http1" {
              try await V4ProxyServerWire.http(stream: stream, upstream: upstream, session: session, storage: storage, limits: limits)
            } else {
              try await V4ProxyServerWire.webSocket(stream: stream, upstream: upstream, session: session, storage: storage, limits: limits)
            }
          }
          group.addTask {
            // A request FIN leaves the response direction usable. Only the
            // original Stream's terminal failure cancels its upstream work.
            throw try await original.waitProxyTermination()
          }
          defer { group.cancelAll() }
          _ = try await group.next()
          group.cancelAll()
          // Join the observer and every upstream callback before the original
          // operation relinquishes its charged storage and concurrency slot.
          while await group.nextResult() != nil {}
        }
      } catch { try? await stream.reset(); throw error }
    }
    streams[id] = stream; operations[id] = operation
    defer { streams.removeValue(forKey: id); operations.removeValue(forKey: id) }
    try await withTaskCancellationHandler {
      try await operation.value
    } onCancel: { operation.cancel() }
  }
  public func close() async throws {
    closed = true
    let active = Array(operations.values); let sockets = Array(streams.values)
    for operation in active { operation.cancel() }
    for socket in sockets { try? await socket.reset() }
    for operation in active { _ = try? await operation.value }
    operations.removeAll(); streams.removeAll()
  }
  public func cleanupStatus() -> CleanupStatus {
    CleanupStatus(complete: closed && operations.isEmpty, cleanupIncomplete: closed && !operations.isEmpty,
      pendingCallbacks: UInt64(operations.count))
  }
}

private enum V4ProxyServerWire {
  static func check(_ session: any V4ServiceSession, storage: V4CryptoReservation) throws {
    try Task.checkCancellation(); try storage.check(); try session.checkServiceSession()
  }
  static func http(stream: V4ProxyStreamAdapter, upstream: any ProxyUpstream, session: any V4ServiceSession,
    storage: V4CryptoReservation, limits: ProxyClientLimits) async throws {
    let metadata = try await V4ProxyWire.readMetadata(schema: "ProxyHTTPRequest", stream: stream, limits: limits)
    let id = try metadata.b("request_id")
    guard let method = String(data: try metadata.b("method"), encoding: .ascii),
      let path = String(data: try metadata.b("path"), encoding: .utf8),
      V4ProxyWire.token(Data(method.utf8)), V4ProxyWire.path(path) else { throw ProxyClientFailure.protocolFailure }
    let headers = try metadata.optional("headers").map { try V4ProxyWire.decodeFields($0) } ?? []
    let expected = try V4ProxyWire.inspect(headers)
    let externalOrigin = try metadata.optional("external_origin").map {
      guard let origin = String(data: try $0.bytes(), encoding: .ascii) else { throw ProxyClientFailure.protocolFailure }
      return origin
    }
    let timeout = try metadata.optional("timeout_ms").map { try UInt32($0.uint()) }
    var body = Data(); let trailers: [HTTPProxyField]
    while true {
      try check(session, storage: storage)
      let prefix = try await stream.readExact(4)
      let count = Int(prefix.readUInt32BE(at: 0))
      if count == 0 {
        let end = try await V4ProxyWire.readMetadata(schema: "ProxyBodyEnd", stream: stream, limits: limits)
        trailers = try V4ProxyWire.decodeFields(end.field("trailers")); try V4ProxyWire.trailers(trailers)
        break
      }
      guard count <= limits.maximumChunkBytes, count <= limits.maximumBodyBytes - body.count else { throw ProxyClientFailure.protocolFailure }
      body.append(try await stream.readExact(count))
    }
    guard expected == nil || expected == UInt64(body.count) else { throw ProxyClientFailure.protocolFailure }
    try check(session, storage: storage)
    let response: HTTPProxyResponse
    do {
      response = try await upstream.send(HTTPProxyRequest(method: method, path: path, headers: headers,
        body: body, trailers: trailers, externalOrigin: externalOrigin, timeoutMilliseconds: timeout))
    } catch {
      try check(session, storage: storage)
      try await failure(id: id, schema: "ProxyHTTPResponse", errorField: 5, error: error, stream: stream, limits: limits)
      try await V4ProxyWire.writeEnd([], stream: stream, limits: limits)
      try await stream.finish()
      return
    }
    try check(session, storage: storage)
    guard (200...599).contains(response.status), response.body.count <= limits.maximumBodyBytes else { throw ProxyClientFailure.protocolFailure }
    try V4ProxyWire.boundFields(response.headers, maximum: limits.maximumMetadataBytes)
    try V4ProxyWire.boundFields(response.trailers, maximum: limits.maximumMetadataBytes)
    let responseLength = try V4ProxyWire.inspect(response.headers); try V4ProxyWire.trailers(response.trailers)
    let bodyless = method == "HEAD" || response.status == 204 || response.status == 304
    guard bodyless ? response.body.isEmpty : responseLength == nil || responseLength == UInt64(response.body.count) else {
      throw ProxyClientFailure.protocolFailure
    }
    let reply = V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(id)), (2, Data([0xf5])),
      (3, V4NamespaceValue.head(0, UInt64(response.status))), (4, try V4ProxyWire.fields(response.headers))])
    try V4ProxyWire.validate(reply, schema: "ProxyHTTPResponse", limits: limits)
    try await V4ProxyWire.writeMetadata(reply, stream: stream, limits: limits)
    var offset = 0
    while offset < response.body.count {
      try check(session, storage: storage)
      let end = min(response.body.count, offset + limits.maximumChunkBytes)
      try await V4ProxyWire.writeChunk(Data(response.body[offset..<end]), stream: stream); offset = end
    }
    try check(session, storage: storage)
    try await V4ProxyWire.writeEnd(response.trailers, stream: stream, limits: limits)
    try await stream.finish()
  }
  static func webSocket(stream: V4ProxyStreamAdapter, upstream: any ProxyUpstream, session: any V4ServiceSession,
    storage: V4CryptoReservation, limits: ProxyClientLimits) async throws {
    let metadata = try await V4ProxyWire.readMetadata(schema: "ProxyWebSocketOpen", stream: stream, limits: limits)
    let id = try metadata.b("conn_id")
    guard let path = String(data: try metadata.b("path"), encoding: .utf8), V4ProxyWire.path(path) else { throw ProxyClientFailure.protocolFailure }
    let headers = try metadata.optional("headers").map { try V4ProxyWire.decodeFields($0) } ?? []
    _ = try V4ProxyWire.inspect(headers); try check(session, storage: storage)
    let socket: any ProxyUpstreamSocket
    do { socket = try await upstream.openWebSocket(path: path, headers: headers) }
    catch {
      try check(session, storage: storage)
      try await failure(id: id, schema: "ProxyWebSocketResponse", errorField: 4, error: error, stream: stream, limits: limits)
      try await stream.finish()
      return
    }
    do {
      try check(session, storage: storage)
      var reply: [(UInt64, Data)] = [(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(id)), (2, Data([0xf5]))]
      if let selected = socket.selectedProtocol, !selected.isEmpty {
        guard V4ProxyWire.token(selected), headers.contains(where: { field in
          guard field.name.lowercased() == "sec-websocket-protocol", let value = String(data: field.value, encoding: .ascii) else { return false }
          return value.split(separator: ",").contains { Data($0.trimmingCharacters(in: .whitespaces).utf8) == selected }
        }) else { throw ProxyClientFailure.protocolFailure }
        reply.append((3, V4Crypto.bytes(selected)))
      }
      let metadata = V4Crypto.map(reply); try V4ProxyWire.validate(metadata, schema: "ProxyWebSocketResponse", limits: limits)
      try await V4ProxyWire.writeMetadata(metadata, stream: stream, limits: limits)
      try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
          while true {
            try check(session, storage: storage)
            let prefix = try await stream.readExact(5)
            let opcode = prefix[0]; let count = Int(prefix.readUInt32BE(at: 1))
            guard count <= limits.maximumWebSocketFrameBytes, opcode < 8 || count <= 125 else { throw ProxyClientFailure.protocolFailure }
            let bytes = try await stream.readExact(count); try V4ProxyWire.webSocket(opcode, bytes: bytes, limits: limits)
            try await socket.send(try message(opcode, bytes: bytes))
            if opcode == 8 { return }
          }
        }
        group.addTask {
          while true {
            let incoming = try await socket.receive(); try check(session, storage: storage)
            let (opcode, bytes) = frame(incoming); try V4ProxyWire.webSocket(opcode, bytes: bytes, limits: limits)
            var wire = Data([opcode]); wire.appendUInt32BE(UInt32(bytes.count)); wire.append(bytes)
            try await stream.write(wire)
            if opcode == 8 { return }
          }
        }
        do {
          // Either relay returns normally only after forwarding a Close frame.
          // Its original task slot now bounds the opposite Close and send drain.
          _ = try await group.next()
          let deadline = ContinuousClock.now.advanced(by:
            .milliseconds(Int64(FlowersecSDKDefaults.Proxy.defaultTimeoutMilliseconds)))
          group.addTask {
            try await ContinuousClock().sleep(until: deadline)
            throw ProxyUpstreamFailure(.timeout, message: "WebSocket close exchange timed out")
          }
          _ = try await group.next()
          group.addTask {
            try check(session, storage: storage)
            // Write accepted the queued bytes locally. Finish keeps their
            // original owner until the peer authenticates the final send drain.
            try await stream.finish()
          }
          _ = try await group.next()
          try check(session, storage: storage)
          group.cancelAll()
          while await group.nextResult() != nil {}
        } catch {
          group.cancelAll()
          try? await stream.reset()
          await socket.close()
          // A failure or deadline withdraws both relays, but their actual
          // callbacks still own this operation's storage until they return.
          while await group.nextResult() != nil {}
          throw error
        }
      }
      await socket.close()
    } catch { await socket.close(); throw error }
  }
  static func failure(id: Data, schema: String, errorField: UInt64, error: any Error,
    stream: V4ProxyStreamAdapter, limits: ProxyClientLimits) async throws {
    let code: String
    if let failure = error as? ProxyUpstreamFailure {
      switch failure.kind {
      case .timeout: code = "timeout"
      case .dial: code = "upstream_dial_failed"
      case .rejected: code = "upstream_rejected"
      case .request: code = "upstream_request_failed"
      }
    } else { code = (error as? ProxyClientFailure)?.rawValue ?? (error is CancellationError ? "canceled" : "upstream_request_failed") }
    let detail = V4Crypto.map([(0, V4Crypto.bytes(Data(code.utf8))),
      (1, V4Crypto.bytes(Data("The configured upstream could not complete the operation".utf8)))])
    let reply = V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(id)),
      (2, Data([0xf4])), (errorField, detail)])
    try V4ProxyWire.validate(reply, schema: schema, limits: limits)
    try await V4ProxyWire.writeMetadata(reply, stream: stream, limits: limits)
  }
  static func frame(_ message: ProxyWebSocketMessage) -> (UInt8, Data) {
    switch message {
    case .text(let bytes): return (1, bytes)
    case .binary(let bytes): return (2, bytes)
    case .close(let bytes): return (8, bytes)
    case .ping(let bytes): return (9, bytes)
    case .pong(let bytes): return (10, bytes)
    }
  }
  static func message(_ opcode: UInt8, bytes: Data) throws -> ProxyWebSocketMessage {
    switch opcode {
    case 1: return .text(bytes)
    case 2: return .binary(bytes)
    case 8: return .close(bytes)
    case 9: return .ping(bytes)
    case 10: return .pong(bytes)
    default: throw ProxyClientFailure.protocolFailure
    }
  }
}
