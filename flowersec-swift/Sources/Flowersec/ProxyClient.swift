import Foundation

public struct HTTPProxyField: Sendable, Equatable {
  public let name: String
  public let value: Data
  public init(name: String, value: Data) throws {
    guard name.utf8.count <= 1_048_576, value.count <= 1_048_576,
      V4ProxyWire.token(Data(name.utf8)), V4ProxyWire.fieldValue(value) else { throw ProxyClientFailure.protocolFailure }
    self.name = name; self.value = value
  }
  public init(name: String, value: String) throws { try self.init(name: name, value: Data(value.utf8)) }
}

public struct ProxyClientLimits: Sendable, Equatable {
  public let maximumMetadataBytes: Int
  public let maximumChunkBytes: Int
  public let maximumBodyBytes: Int
  public let maximumWebSocketFrameBytes: Int
  public init(maximumMetadataBytes: Int = 1 << 20, maximumChunkBytes: Int = 256 << 10,
    maximumBodyBytes: Int = 64 << 20, maximumWebSocketFrameBytes: Int = 1 << 20) throws {
    guard (256...1_048_576).contains(maximumMetadataBytes), (1...1_048_576).contains(maximumChunkBytes),
      (1...67_108_864).contains(maximumBodyBytes), (1...1_048_576).contains(maximumWebSocketFrameBytes) else {
      throw ProxyClientFailure.configurationCapacity
    }
    self.maximumMetadataBytes = maximumMetadataBytes; self.maximumChunkBytes = maximumChunkBytes
    self.maximumBodyBytes = maximumBodyBytes; self.maximumWebSocketFrameBytes = maximumWebSocketFrameBytes
  }
}

public struct HTTPProxyRequest: Sendable {
  public let method: String
  public let path: String
  public let headers: [HTTPProxyField]
  public let body: Data
  public let trailers: [HTTPProxyField]
  public let externalOrigin: String?
  public let timeoutMilliseconds: UInt32?
  public init(method: String, path: String, headers: [HTTPProxyField] = [], body: Data = Data(),
    trailers: [HTTPProxyField] = [], externalOrigin: String? = nil, timeoutMilliseconds: UInt32? = nil) {
    self.method = method; self.path = path; self.headers = headers; self.body = body; self.trailers = trailers
    self.externalOrigin = externalOrigin; self.timeoutMilliseconds = timeoutMilliseconds
  }
}

public struct HTTPProxyResponse: Sendable {
  public let status: Int
  public let headers: [HTTPProxyField]
  public let body: Data
  public let trailers: [HTTPProxyField]
  public init(status: Int, headers: [HTTPProxyField] = [], body: Data = Data(), trailers: [HTTPProxyField] = []) {
    self.status = status; self.headers = headers; self.body = body; self.trailers = trailers
  }
}

public enum HTTPProxyBodyPart: Sendable { case bytes(Data), end(trailers: [HTTPProxyField]) }
public enum ProxyClientFailure: String, Error, Sendable {
  case configurationCapacity = "configuration_capacity", protocolFailure = "protocol_failure"
  case resourceExhausted = "resource_exhausted", remoteFailure = "remote_failure", closed
}

/// A proxy client captures one established Session. Requests and WebSockets keep
/// that original routing when a Controller publishes another Session.
public final class ProxyClient: Sendable {
  private let session: any V4ServiceSession
  private let limits: ProxyClientLimits
  public init(session: any Session, limits: ProxyClientLimits) throws {
    guard let original = session as? any V4ServiceSession else { throw ProxyClientFailure.configurationCapacity }
    try original.checkServiceSession(); self.session = original; self.limits = limits
  }
  public convenience init(session: any Session) throws { try self.init(session: session, limits: ProxyClientLimits()) }

  public func open(_ request: HTTPProxyRequest) async throws -> HTTPProxyExchange {
    try session.checkServiceSession(); try Task.checkCancellation()
    guard request.method.utf8.count <= limits.maximumMetadataBytes, request.path.utf8.count <= limits.maximumMetadataBytes,
      (request.externalOrigin?.utf8.count ?? 0) <= limits.maximumMetadataBytes,
      V4ProxyWire.token(Data(request.method.utf8)), V4ProxyWire.path(request.path),
      request.body.count <= limits.maximumBodyBytes,
      request.timeoutMilliseconds == nil || request.timeoutMilliseconds! <= FlowersecSDKDefaults.Proxy.maximumTimeoutMilliseconds else { throw ProxyClientFailure.protocolFailure }
    try V4ProxyWire.boundFields(request.headers, maximum: limits.maximumMetadataBytes)
    try V4ProxyWire.boundFields(request.trailers, maximum: limits.maximumMetadataBytes)
    let length = try V4ProxyWire.inspect(request.headers)
    guard length == nil || length == UInt64(request.body.count) else { throw ProxyClientFailure.protocolFailure }
    try V4ProxyWire.trailers(request.trailers)
    let storage = try session.serviceEnvironment.proxyOperationStorage(limits: limits)
    let tail = try storage.executionTail(); defer { tail.release() }
    let id = try V4Crypto.random(16)
    var fields: [(UInt64, Data)] = [(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(id)),
      (2, V4Crypto.bytes(Data(request.method.utf8))), (3, V4Crypto.bytes(Data(request.path.utf8))),
      (4, try V4ProxyWire.fields(request.headers))]
    if let origin = request.externalOrigin { fields.append((5, V4Crypto.bytes(Data(origin.utf8)))) }
    if let timeout = request.timeoutMilliseconds { fields.append((6, V4NamespaceValue.head(0, UInt64(timeout)))) }
    let metadata = V4Crypto.map(fields)
    try V4ProxyWire.validate(metadata, schema: "ProxyHTTPRequest", limits: limits)
    let raw = try await session.openStream(kind: "flowersec-proxy/http1")
    let stream = V4ProxyStreamAdapter(raw)
    do {
      try storage.check(); try session.checkServiceSession()
      try await V4ProxyWire.writeMetadata(metadata, stream: stream, limits: limits)
      var offset = 0
      while offset < request.body.count {
        let end = min(request.body.count, offset + limits.maximumChunkBytes)
        try await V4ProxyWire.writeChunk(Data(request.body[offset..<end]), stream: stream)
        offset = end
      }
      try await V4ProxyWire.writeEnd(request.trailers, stream: stream, limits: limits)
      try await stream.closeWrite()
      let reply = try await V4ProxyWire.readMetadata(schema: "ProxyHTTPResponse", stream: stream, limits: limits)
      guard try reply.b("request_id") == id, try reply.field("ok").equals(true),
        let status = try reply.optional("status") else { throw ProxyClientFailure.remoteFailure }
      let headers = try reply.optional("headers").map { try V4ProxyWire.decodeFields($0) } ?? []
      let expected = try V4ProxyWire.inspect(headers)
      let code = Int(try status.uint())
      let bodyless = request.method == "HEAD" || code == 204 || code == 304
      try storage.check(); try session.checkServiceSession(); try Task.checkCancellation()
      return HTTPProxyExchange(status: code, headers: headers, stream: stream, storage: storage,
        session: session, limits: limits, expected: bodyless ? nil : expected, bodyless: bodyless)
    } catch { try? await stream.reset(); throw error }
  }

  public func send(_ request: HTTPProxyRequest) async throws -> HTTPProxyResponse {
    let exchange = try await open(request)
    do {
      var body = Data()
      while true {
        switch try await exchange.readBodyPart() {
        case .bytes(let bytes): body.append(bytes)
        case .end(let trailers):
          try await exchange.close()
          return HTTPProxyResponse(status: exchange.status, headers: exchange.headers, body: body, trailers: trailers)
        }
      }
    } catch { try? await exchange.close(); throw error }
  }

  public func openWebSocket(path: String, headers: [HTTPProxyField] = []) async throws -> ProxyWebSocket {
    try session.checkServiceSession(); try Task.checkCancellation()
    guard path.utf8.count <= limits.maximumMetadataBytes, V4ProxyWire.path(path) else { throw ProxyClientFailure.protocolFailure }
    try V4ProxyWire.boundFields(headers, maximum: limits.maximumMetadataBytes)
    _ = try V4ProxyWire.inspect(headers)
    let storage = try session.serviceEnvironment.proxyOperationStorage(limits: limits)
    let tail = try storage.executionTail(); defer { tail.release() }
    let id = try V4Crypto.random(16)
    let metadata = V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, V4Crypto.bytes(id)),
      (2, V4Crypto.bytes(Data(path.utf8))), (3, try V4ProxyWire.fields(headers))])
    try V4ProxyWire.validate(metadata, schema: "ProxyWebSocketOpen", limits: limits)
    let raw = try await session.openStream(kind: "flowersec-proxy/ws")
    let stream = V4ProxyStreamAdapter(raw)
    do {
      try await V4ProxyWire.writeMetadata(metadata, stream: stream, limits: limits)
      let reply = try await V4ProxyWire.readMetadata(schema: "ProxyWebSocketResponse", stream: stream, limits: limits)
      guard try reply.b("conn_id") == id, try reply.field("ok").equals(true) else { throw ProxyClientFailure.remoteFailure }
      let selected = try reply.optional("protocol")?.bytes()
      if let selected, !selected.isEmpty {
        guard V4ProxyWire.token(selected), headers.contains(where: { field in
          guard field.name.lowercased() == "sec-websocket-protocol", let value = String(data: field.value, encoding: .ascii) else { return false }
          return value.split(separator: ",").contains { Data($0.trimmingCharacters(in: .whitespaces).utf8) == selected }
        }) else { throw ProxyClientFailure.protocolFailure }
      }
      try storage.check(); try session.checkServiceSession(); try Task.checkCancellation()
      return ProxyWebSocket(selectedProtocol: selected, stream: stream, storage: storage, session: session, limits: limits)
    } catch { try? await stream.reset(); throw error }
  }
}

public actor HTTPProxyExchange {
  public nonisolated let status: Int
  public nonisolated let headers: [HTTPProxyField]
  private let stream: V4ProxyStreamAdapter
  private var storage: V4CryptoReservation?
  private let session: any V4ServiceSession
  private let limits: ProxyClientLimits
  private let expected: UInt64?
  private let bodyless: Bool
  private var total = 0
  private var reading = false
  private var ended = false
  init(status: Int, headers: [HTTPProxyField], stream: V4ProxyStreamAdapter, storage: V4CryptoReservation,
    session: any V4ServiceSession, limits: ProxyClientLimits, expected: UInt64?, bodyless: Bool) {
    self.status = status; self.headers = headers; self.stream = stream; self.storage = storage
    self.session = session; self.limits = limits; self.expected = expected; self.bodyless = bodyless
  }
  public func readBodyPart() async throws -> HTTPProxyBodyPart {
    guard !reading, !ended, let original = storage else { throw ProxyClientFailure.closed }
    let tail = try original.executionTail()
    reading = true; defer { reading = false; tail.release(); withExtendedLifetime(original) {} }
    do {
      try original.check(); try session.checkServiceSession()
      let prefix = try await stream.readExact(4)
      let count = Int(prefix.readUInt32BE(at: 0))
      if count == 0 {
        let terminal = try await V4ProxyWire.readMetadata(schema: "ProxyBodyEnd", stream: stream, limits: limits)
        let trailers = try V4ProxyWire.decodeFields(terminal.field("trailers"))
        try V4ProxyWire.trailers(trailers)
        guard expected == nil || expected == UInt64(total) else { throw ProxyClientFailure.protocolFailure }
        // Drain the original response FIN before reporting success. Closing a
        // completed exchange must not reset the server's pending finish proof.
        try await stream.readEnd()
        try original.check(); try session.checkServiceSession(); try Task.checkCancellation()
        ended = true
        return .end(trailers: trailers)
      }
      guard !bodyless, count <= limits.maximumChunkBytes, count <= limits.maximumBodyBytes - total else { throw ProxyClientFailure.protocolFailure }
      let bytes = try await stream.readExact(count)
      try original.check(); try session.checkServiceSession(); try Task.checkCancellation(); total += count
      return .bytes(bytes)
    } catch { ended = true; try? await stream.reset(); storage = nil; throw error }
  }
  public func close() async throws {
    let original = storage
    let tail = try original?.executionTail()
    defer { tail?.release(); withExtendedLifetime(original) {} }
    storage = nil
    if ended { try await stream.finish() } else { ended = true; try await stream.reset() }
  }
}

public enum ProxyWebSocketMessage: Sendable {
  case text(Data), binary(Data), close(Data), ping(Data), pong(Data)
}
public actor ProxyWebSocket {
  public nonisolated let selectedProtocol: Data?
  private let stream: V4ProxyStreamAdapter
  private var storage: V4CryptoReservation?
  private let session: any V4ServiceSession
  private let limits: ProxyClientLimits
  private var reading = false
  private var writing = false
  init(selectedProtocol: Data?, stream: V4ProxyStreamAdapter, storage: V4CryptoReservation,
    session: any V4ServiceSession, limits: ProxyClientLimits) {
    self.selectedProtocol = selectedProtocol; self.stream = stream; self.storage = storage; self.session = session; self.limits = limits
  }
  public func send(_ message: ProxyWebSocketMessage) async throws {
    guard !writing, let original = storage else { throw ProxyClientFailure.closed }
    let tail = try original.executionTail()
    writing = true; defer { writing = false; tail.release(); withExtendedLifetime(original) {} }
    let operation: UInt8; let bytes: Data
    switch message {
    case .text(let value): operation = 1; bytes = value
    case .binary(let value): operation = 2; bytes = value
    case .close(let value): operation = 8; bytes = value
    case .ping(let value): operation = 9; bytes = value
    case .pong(let value): operation = 10; bytes = value
    }
    do {
      try original.check(); try session.checkServiceSession(); try V4ProxyWire.webSocket(operation, bytes: bytes, limits: limits)
      var frame = Data([operation]); frame.appendUInt32BE(UInt32(bytes.count)); frame.append(bytes)
      try await stream.write(frame)
    } catch { storage = nil; try? await stream.reset(); throw error }
  }
  public func receive() async throws -> ProxyWebSocketMessage {
    guard !reading, let original = storage else { throw ProxyClientFailure.closed }
    let tail = try original.executionTail()
    reading = true; defer { reading = false; tail.release(); withExtendedLifetime(original) {} }
    do {
      try original.check(); try session.checkServiceSession()
      let prefix = try await stream.readExact(5); let operation = prefix[0]
      let count = Int(prefix.readUInt32BE(at: 1))
      guard count <= limits.maximumWebSocketFrameBytes, operation < 8 || count <= 125 else { throw ProxyClientFailure.protocolFailure }
      let bytes = try await stream.readExact(count)
      try original.check(); try session.checkServiceSession(); try V4ProxyWire.webSocket(operation, bytes: bytes, limits: limits)
      switch operation {
      case 1: return .text(bytes)
      case 2: return .binary(bytes)
      case 8: return .close(bytes)
      case 9: return .ping(bytes)
      case 10: return .pong(bytes)
      default: throw ProxyClientFailure.protocolFailure
      }
    } catch { storage = nil; try? await stream.reset(); throw error }
  }
  public func close() async throws {
    let original = storage
    let tail = try original?.executionTail()
    storage = nil
    defer { tail?.release(); withExtendedLifetime(original) {} }
    try await stream.close()
  }
}

// Exact application reads and complete writes adapt the current partial-progress
// ByteStream API. Each adapter owns one original Stream and never reacquires it.
protocol ProxyByteStream: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ count: Int) async throws -> Data
  func close() async throws
  func reset() async throws
}
protocol V4ProxySessionStream: ByteStream {
  func checkProxySession(_ session: any V4ServiceSession) throws
  func waitProxyTermination() async throws -> SessionError
}

actor V4ProxyStreamAdapter: ProxyByteStream {
  private let original: any ByteStream
  private var reading = false
  private var writing = false
  init(_ original: any ByteStream) { self.original = original }
  func write(_ data: Data) async throws {
    guard !writing else { throw ProxyClientFailure.resourceExhausted }
    writing = true; defer { writing = false }
    var offset = 0
    while offset < data.count {
      try Task.checkCancellation()
      let count = try await original.write(Data(data[offset...]))
      guard count > 0, count <= data.count - offset else { throw ProxyClientFailure.protocolFailure }
      offset += count
    }
  }
  func readExact(_ count: Int) async throws -> Data {
    guard !reading, count >= 0, count <= 1_048_576 else { throw ProxyClientFailure.resourceExhausted }
    reading = true; defer { reading = false }
    var data = Data(); data.reserveCapacity(count)
    while data.count < count {
      try Task.checkCancellation()
      guard let bytes = try await original.read(maxBytes: count - data.count), !bytes.isEmpty,
        bytes.count <= count - data.count else { throw ProxyClientFailure.protocolFailure }
      data.append(bytes)
    }
    return data
  }
  func readEnd() async throws {
    guard !reading else { throw ProxyClientFailure.resourceExhausted }
    reading = true; defer { reading = false }
    try Task.checkCancellation()
    guard try await original.read(maxBytes: 1) == nil else { throw ProxyClientFailure.protocolFailure }
  }
  func closeWrite() async throws { try await original.closeWrite() }
  func finish() async throws { try await original.finish() }
  func close() async throws { try await original.close() }
  func reset() async throws { try await original.reset() }
}


enum V4ProxyWire {
  static func token(_ bytes: Data) -> Bool {
    !bytes.isEmpty && bytes.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
      || [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126].contains($0) }
  }
  static func fieldValue(_ bytes: Data) -> Bool { bytes.allSatisfy { $0 == 9 || $0 >= 32 && $0 != 127 } }
  static func path(_ value: String) -> Bool {
    guard value.hasPrefix("/"), !value.hasPrefix("//"), value.utf8.allSatisfy({ $0 > 32 && $0 < 127 && $0 != 35 }),
      let components = URLComponents(string: "http://flowersec.invalid\(value)"),
      components.host == "flowersec.invalid", components.fragment == nil else { return false }
    let encoded = components.percentEncodedPath + (components.percentEncodedQuery.map { "?" + $0 } ?? "")
    return encoded == value
  }
  static func boundFields(_ fields: [HTTPProxyField], maximum: Int) throws {
    guard fields.count <= 128 else { throw ProxyClientFailure.protocolFailure }
    var remaining = maximum
    for field in fields {
      guard field.name.utf8.count <= remaining else { throw ProxyClientFailure.protocolFailure }
      remaining -= field.name.utf8.count
      guard field.value.count <= remaining else { throw ProxyClientFailure.protocolFailure }
      remaining -= field.value.count
    }
  }
  static func fields(_ fields: [HTTPProxyField]) throws -> Data {
    guard fields.count <= 128 else { throw ProxyClientFailure.protocolFailure }
    return fields.reduce(into: V4NamespaceValue.head(4, UInt64(fields.count))) { result, field in
      result.append(V4Crypto.map([(0, V4Crypto.bytes(Data(field.name.utf8))), (1, V4Crypto.bytes(field.value))]))
    }
  }
  static func decodeFields(_ value: V4NamespaceValue) throws -> [HTTPProxyField] {
    try value.children.map { item in
      let name = try item.b("name")
      guard let text = String(data: name, encoding: .ascii) else { throw ProxyClientFailure.protocolFailure }
      return try HTTPProxyField(name: text, value: item.b("value"))
    }
  }
  static func inspect(_ fields: [HTTPProxyField]) throws -> UInt64? {
    guard fields.count <= 128 else { throw ProxyClientFailure.protocolFailure }
    var length: UInt64?
    var transfer = false
    var singletons: [String: Data] = [:]
    for field in fields {
      guard token(Data(field.name.utf8)), fieldValue(field.value) else { throw ProxyClientFailure.protocolFailure }
      let name = field.name.lowercased()
      if name == "transfer-encoding" { transfer = true }
      if name == "content-length" {
        guard let text = String(data: field.value, encoding: .ascii) else { throw ProxyClientFailure.protocolFailure }
        for part in text.split(separator: ",", omittingEmptySubsequences: false) {
          let token = part.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
          guard !token.isEmpty, token.utf8.allSatisfy({ (48...57).contains($0) }), let count = UInt64(token),
            count <= UInt64(Int64.max), length == nil || length == count else { throw ProxyClientFailure.protocolFailure }
          length = count
        }
      }
      if name == "connection" {
        guard let text = String(data: field.value, encoding: .ascii) else { throw ProxyClientFailure.protocolFailure }
        for item in text.split(separator: ",", omittingEmptySubsequences: false) {
          guard token(Data(item.trimmingCharacters(in: CharacterSet(charactersIn: " \t")).utf8)) else { throw ProxyClientFailure.protocolFailure }
        }
      }
      if ["host", "origin", "authorization", "proxy-authorization", "content-type", "content-range", "etag", "last-modified", "location"].contains(name) {
        let value = Data(field.value.drop(while: { $0 == 9 || $0 == 32 }).reversed().drop(while: { $0 == 9 || $0 == 32 }).reversed())
        guard singletons[name] == nil || singletons[name] == value else { throw ProxyClientFailure.protocolFailure }
        singletons[name] = value
      }
    }
    guard !transfer else { throw ProxyClientFailure.protocolFailure }
    return length
  }
  static func trailers(_ fields: [HTTPProxyField]) throws {
    _ = try inspect(fields)
    let forbidden: Set<String> = ["authorization", "connection", "host", "keep-alive", "proxy-authorization",
      "proxy-authenticate", "proxy-connection", "te", "trailer", "set-cookie", "transfer-encoding", "upgrade",
      "content-length", "content-encoding", "content-range", "content-type", "cookie", "origin", "location", "www-authenticate"]
    guard fields.allSatisfy({ !forbidden.contains($0.name.lowercased()) }) else { throw ProxyClientFailure.protocolFailure }
  }
  static func validate(_ bytes: Data, schema: String, limits: ProxyClientLimits) throws {
    _ = try document(bytes, schema: schema, limits: limits)
  }
  static func document(_ bytes: Data, schema: String, limits: ProxyClientLimits) throws -> V4NamespaceDocument {
    try V4NamespaceDocument(bytes, schema: schema, bytes: limits.maximumMetadataBytes,
      nodes: 4096, registry: V4NamespaceRegistry(), limits: ["max_proxy_fields": 128])
  }
  static func writeMetadata(_ bytes: Data, stream: V4ProxyStreamAdapter, limits: ProxyClientLimits) async throws {
    guard !bytes.isEmpty, bytes.count <= limits.maximumMetadataBytes else { throw ProxyClientFailure.protocolFailure }
    var frame = Data(); frame.appendUInt32BE(UInt32(bytes.count)); frame.append(bytes)
    try await stream.write(frame)
  }
  static func readMetadata(schema: String, stream: V4ProxyStreamAdapter, limits: ProxyClientLimits) async throws -> V4NamespaceValue {
    let prefix = try await stream.readExact(4); let count = Int(prefix.readUInt32BE(at: 0))
    guard (1...limits.maximumMetadataBytes).contains(count) else { throw ProxyClientFailure.protocolFailure }
    return try document(await stream.readExact(count), schema: schema, limits: limits).root
  }
  static func writeChunk(_ bytes: Data, stream: V4ProxyStreamAdapter) async throws {
    var frame = Data(); frame.appendUInt32BE(UInt32(bytes.count)); frame.append(bytes)
    try await stream.write(frame)
  }
  static func writeEnd(_ trailers: [HTTPProxyField], stream: V4ProxyStreamAdapter, limits: ProxyClientLimits) async throws {
    let terminal = V4Crypto.map([(0, V4NamespaceValue.head(0, 2)), (1, try fields(trailers))])
    try validate(terminal, schema: "ProxyBodyEnd", limits: limits)
    try await stream.write(Data(repeating: 0, count: 4))
    try await writeMetadata(terminal, stream: stream, limits: limits)
  }
  static func webSocket(_ operation: UInt8, bytes: Data, limits: ProxyClientLimits) throws {
    guard [UInt8(1), 2, 8, 9, 10].contains(operation), bytes.count <= limits.maximumWebSocketFrameBytes,
      operation < 8 || bytes.count <= 125 else { throw ProxyClientFailure.protocolFailure }
    if operation == 1 { guard String(data: bytes, encoding: .utf8) != nil else { throw ProxyClientFailure.protocolFailure } }
    if operation == 8 {
      guard bytes.count != 1 else { throw ProxyClientFailure.protocolFailure }
      if bytes.count >= 2 {
        let code = bytes.readUInt16BE(at: 0)
        guard ((1000...1014).contains(code) && ![1004, 1005, 1006].contains(code)) || (3000...4999).contains(code),
          String(data: Data(bytes.dropFirst(2)), encoding: .utf8) != nil else { throw ProxyClientFailure.protocolFailure }
      }
    }
  }
}
