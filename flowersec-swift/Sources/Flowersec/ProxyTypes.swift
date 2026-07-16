import Foundation

public enum ProxyProtocol {
  public static let version = 1
  public static let http1Kind = "flowersec-proxy/http1"
  public static let webSocketKind = "flowersec-proxy/ws"
}

public struct ProxyHeader: Codable, Equatable, Sendable {
  public var name: String
  public var value: String

  public init(name: String, value: String) {
    self.name = name
    self.value = value
  }
}

public struct ProxyRemoteError: Codable, Equatable, Sendable {
  public var code: String
  public var message: String

  public init(code: String, message: String) {
    self.code = code
    self.message = message
  }
}

public struct ProxyHTTPRequestMeta: Codable, Equatable, Sendable {
  public var version: Int
  public var requestID: String
  public var method: String
  public var path: String
  public var headers: [ProxyHeader]
  public var externalOrigin: String?
  public var timeoutMilliseconds: Int64?

  public init(
    version: Int = ProxyProtocol.version,
    requestID: String,
    method: String,
    path: String,
    headers: [ProxyHeader],
    externalOrigin: String? = nil,
    timeoutMilliseconds: Int64? = nil
  ) {
    self.version = version
    self.requestID = requestID
    self.method = method
    self.path = path
    self.headers = headers
    self.externalOrigin = externalOrigin
    self.timeoutMilliseconds = timeoutMilliseconds
  }

  private enum CodingKeys: String, CodingKey {
    case version = "v"
    case requestID = "request_id"
    case method
    case path
    case headers
    case externalOrigin = "external_origin"
    case timeoutMilliseconds = "timeout_ms"
  }
}

public struct ProxyHTTPResponseMeta: Codable, Equatable, Sendable {
  public var version: Int
  public var requestID: String
  public var ok: Bool
  public var status: Int?
  public var headers: [ProxyHeader]
  public var error: ProxyRemoteError?

  public init(
    version: Int = ProxyProtocol.version,
    requestID: String,
    ok: Bool,
    status: Int? = nil,
    headers: [ProxyHeader] = [],
    error: ProxyRemoteError? = nil
  ) {
    self.version = version
    self.requestID = requestID
    self.ok = ok
    self.status = status
    self.headers = headers
    self.error = error
  }

  private enum CodingKeys: String, CodingKey {
    case version = "v"
    case requestID = "request_id"
    case ok
    case status
    case headers
    case error
  }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    version = try container.decode(Int.self, forKey: .version)
    requestID = try container.decode(String.self, forKey: .requestID)
    ok = try container.decode(Bool.self, forKey: .ok)
    status = try container.decodeIfPresent(Int.self, forKey: .status)
    headers = try container.decodeIfPresent([ProxyHeader].self, forKey: .headers) ?? []
    error = try container.decodeIfPresent(ProxyRemoteError.self, forKey: .error)
  }
}

public struct ProxyWebSocketOpenMeta: Codable, Equatable, Sendable {
  public var version: Int
  public var connectionID: String
  public var path: String
  public var headers: [ProxyHeader]

  public init(
    version: Int = ProxyProtocol.version,
    connectionID: String,
    path: String,
    headers: [ProxyHeader]
  ) {
    self.version = version
    self.connectionID = connectionID
    self.path = path
    self.headers = headers
  }

  private enum CodingKeys: String, CodingKey {
    case version = "v"
    case connectionID = "conn_id"
    case path
    case headers
  }
}

public struct ProxyWebSocketOpenResponse: Codable, Equatable, Sendable {
  public var version: Int
  public var connectionID: String
  public var ok: Bool
  public var selectedProtocol: String?
  public var error: ProxyRemoteError?

  public init(
    version: Int = ProxyProtocol.version,
    connectionID: String,
    ok: Bool,
    selectedProtocol: String? = nil,
    error: ProxyRemoteError? = nil
  ) {
    self.version = version
    self.connectionID = connectionID
    self.ok = ok
    self.selectedProtocol = selectedProtocol
    self.error = error
  }

  private enum CodingKeys: String, CodingKey {
    case version = "v"
    case connectionID = "conn_id"
    case ok
    case selectedProtocol = "protocol"
    case error
  }
}

public struct ProxyHTTPRequest: Equatable, Sendable {
  public var method: String
  public var path: String
  public var headers: [ProxyHeader]
  public var externalOrigin: String?
  public var timeout: Duration?
  public var body: Data

  public init(
    method: String,
    path: String,
    headers: [ProxyHeader] = [],
    externalOrigin: String? = nil,
    timeout: Duration? = nil,
    body: Data = Data()
  ) {
    self.method = method
    self.path = path
    self.headers = headers
    self.externalOrigin = externalOrigin
    self.timeout = timeout
    self.body = body
  }

  public static func get(_ path: String, headers: [ProxyHeader] = []) -> ProxyHTTPRequest {
    ProxyHTTPRequest(method: "GET", path: path, headers: headers)
  }
}

public struct ProxyHTTPResponse: Equatable, Sendable {
  public var status: Int
  public var headers: [ProxyHeader]
  public var body: Data

  public init(status: Int, headers: [ProxyHeader], body: Data) {
    self.status = status
    self.headers = headers
    self.body = body
  }
}

public enum ProxyWebSocketOperation: UInt8, Codable, Equatable, Sendable {
  case text = 1
  case binary = 2
  case close = 8
  case ping = 9
  case pong = 10
}

public struct ProxyWebSocketFrame: Equatable, Sendable {
  public var operation: ProxyWebSocketOperation
  public var payload: Data

  public init(operation: ProxyWebSocketOperation, payload: Data = Data()) {
    self.operation = operation
    self.payload = payload
  }

  public static func close(code: UInt16? = nil, reason: String = "") throws
    -> ProxyWebSocketFrame
  {
    guard reason.utf8.count <= 123 else { throw ProxyError.invalidMetadata("close reason is too long") }
    var payload = Data()
    if let code {
      payload.appendUInt16BE(code)
      payload.append(Data(reason.utf8))
    } else if !reason.isEmpty {
      throw ProxyError.invalidMetadata("close reason requires a close code")
    }
    return ProxyWebSocketFrame(operation: .close, payload: payload)
  }
}

public struct ProxyContractOptions: Equatable, Sendable {
  public var maxJSONFrameBytes: Int
  public var maxChunkBytes: Int
  public var maxBodyBytes: Int
  public var maxWebSocketFrameBytes: Int
  public var defaultHTTPRequestTimeout: Duration?
  public var extraRequestHeaders: [String]
  public var extraResponseHeaders: [String]
  public var blockedResponseHeaders: [String]
  public var extraWebSocketHeaders: [String]
  public var forbiddenCookieNames: [String]
  public var forbiddenCookieNamePrefixes: [String]

  public init(
    maxJSONFrameBytes: Int = FlowersecSDKDefaults.Proxy.maxJSONFrameBytes,
    maxChunkBytes: Int = FlowersecSDKDefaults.Proxy.maxChunkBytes,
    maxBodyBytes: Int = FlowersecSDKDefaults.Proxy.maxBodyBytes,
    maxWebSocketFrameBytes: Int = FlowersecSDKDefaults.Proxy.maxWSFrameBytes,
    defaultHTTPRequestTimeout: Duration? = nil,
    extraRequestHeaders: [String] = [],
    extraResponseHeaders: [String] = [],
    blockedResponseHeaders: [String] = [],
    extraWebSocketHeaders: [String] = [],
    forbiddenCookieNames: [String] = [],
    forbiddenCookieNamePrefixes: [String] = []
  ) {
    self.maxJSONFrameBytes = maxJSONFrameBytes
    self.maxChunkBytes = maxChunkBytes
    self.maxBodyBytes = maxBodyBytes
    self.maxWebSocketFrameBytes = maxWebSocketFrameBytes
    self.defaultHTTPRequestTimeout = defaultHTTPRequestTimeout
    self.extraRequestHeaders = extraRequestHeaders
    self.extraResponseHeaders = extraResponseHeaders
    self.blockedResponseHeaders = blockedResponseHeaders
    self.extraWebSocketHeaders = extraWebSocketHeaders
    self.forbiddenCookieNames = forbiddenCookieNames
    self.forbiddenCookieNamePrefixes = forbiddenCookieNamePrefixes
  }
}

public struct ProxyServerOptions: Equatable, Sendable {
  public var upstream: URL
  public var upstreamOrigin: String
  public var allowedUpstreamHosts: [String]
  public var contract: ProxyContractOptions
  public var defaultTimeout: Duration?
  public var maxTimeout: Duration?
  public var maxConcurrentStreams: Int

  public init(
    upstream: URL,
    upstreamOrigin: String,
    allowedUpstreamHosts: [String] = [],
    contract: ProxyContractOptions = ProxyContractOptions(),
    defaultTimeout: Duration? = .milliseconds(
      FlowersecSDKDefaults.Proxy.defaultTimeoutMilliseconds
    ),
    maxTimeout: Duration? = .milliseconds(FlowersecSDKDefaults.Proxy.maxTimeoutMilliseconds),
    maxConcurrentStreams: Int = 64
  ) {
    self.upstream = upstream
    self.upstreamOrigin = upstreamOrigin
    self.allowedUpstreamHosts = allowedUpstreamHosts
    self.contract = contract
    self.defaultTimeout = defaultTimeout
    self.maxTimeout = maxTimeout
    self.maxConcurrentStreams = maxConcurrentStreams
  }
}

public enum ProxyError: LocalizedError, Equatable, Sendable {
  case invalidConfiguration(String)
  case invalidPath
  case invalidMetadata(String)
  case frameTooLarge
  case bodyTooLarge
  case invalidWebSocketOperation(UInt8)
  case remote(code: String, message: String)
  case stream(String)
  case upstream(String)
  case canceled

  public var errorDescription: String? {
    switch self {
    case .invalidConfiguration(let message): return "Invalid proxy configuration: \(message)"
    case .invalidPath: return "The proxy path is invalid."
    case .invalidMetadata(let message): return "Invalid proxy metadata: \(message)"
    case .frameTooLarge: return "The proxy frame exceeds the configured limit."
    case .bodyTooLarge: return "The proxy body exceeds the configured limit."
    case .invalidWebSocketOperation(let operation): return "Invalid WebSocket operation \(operation)."
    case .remote(let code, let message): return "The proxy peer returned \(code): \(message)"
    case .stream(let message): return "The proxy stream failed: \(message)"
    case .upstream(let message): return "The proxy upstream failed: \(message)"
    case .canceled: return "The proxy operation was canceled."
    }
  }
}

enum ProxyUpstreamFailureKind: Sendable {
  case timeout
  case dial
  case rejected
  case request
}

struct ProxyUpstreamFailure: LocalizedError, Sendable {
  let kind: ProxyUpstreamFailureKind
  let message: String

  init(_ kind: ProxyUpstreamFailureKind, _ error: any Error) {
    self.kind = kind
    self.message = error.localizedDescription
  }

  init(_ kind: ProxyUpstreamFailureKind, message: String) {
    self.kind = kind
    self.message = message
  }

  var errorDescription: String? { message }
}

public protocol ProxyStreamRoute: Sendable {
  func openStream(kind: String) async throws -> any FlowersecByteStream
}

extension FlowersecClient: ProxyStreamRoute {}
extension EndpointSession: ProxyStreamRoute {}

public struct ProxyHeaderPolicy: Sendable {
  private enum Direction { case request, response, webSocket }

  private static let requestHeaders: Set<String> = [
    "accept", "accept-language", "cache-control", "content-type", "if-match",
    "if-modified-since", "if-none-match", "if-unmodified-since", "origin", "pragma",
    "range", "x-requested-with",
  ]
  private static let responseHeaders: Set<String> = [
    "cache-control", "content-disposition", "content-encoding", "content-language",
    "content-security-policy", "content-security-policy-report-only",
    "content-type", "cross-origin-embedder-policy", "cross-origin-opener-policy",
    "cross-origin-resource-policy", "etag", "expires", "last-modified", "location",
    "permissions-policy", "pragma", "referrer-policy", "set-cookie", "vary",
    "www-authenticate", "x-content-type-options", "x-frame-options",
  ]
  private static let webSocketHeaders: Set<String> = ["sec-websocket-protocol"]
  private static let hopByHopHeaders: Set<String> = [
    "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te",
    "trailer", "content-length",
  ]

  private let requestHeaders: Set<String>
  private let responseHeaders: Set<String>
  private let blockedResponseHeaders: Set<String>
  private let webSocketHeaders: Set<String>
  private let forbiddenCookieNames: Set<String>
  private let forbiddenCookieNamePrefixes: [String]

  public init(options: ProxyContractOptions = ProxyContractOptions()) throws {
    requestHeaders = Self.requestHeaders.union(try proxyHeaderNameSet(options.extraRequestHeaders))
    responseHeaders = Self.responseHeaders.union(try proxyHeaderNameSet(options.extraResponseHeaders))
    blockedResponseHeaders = try proxyHeaderNameSet(options.blockedResponseHeaders)
    webSocketHeaders = Self.webSocketHeaders.union(
      try proxyHeaderNameSet(options.extraWebSocketHeaders)
    )
    forbiddenCookieNames = try proxyNonemptyNameSet(options.forbiddenCookieNames)
    forbiddenCookieNamePrefixes = try proxyNonemptyNames(options.forbiddenCookieNamePrefixes)
  }

  public func filterRequest(_ headers: [ProxyHeader]) -> [ProxyHeader] {
    filter(headers, direction: .request)
  }

  public func filterResponse(_ headers: [ProxyHeader]) -> [ProxyHeader] {
    filter(headers, direction: .response)
  }

  public func filterWebSocket(_ headers: [ProxyHeader]) -> [ProxyHeader] {
    filter(headers, direction: .webSocket)
  }

  private func filter(_ headers: [ProxyHeader], direction: Direction) -> [ProxyHeader] {
    headers.compactMap { header in
      let name = header.name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
      guard proxyValidHeaderName(name), proxySafeHeaderValue(header.value),
        !Self.hopByHopHeaders.contains(name)
      else { return nil }
      let allowed: Bool
      switch direction {
      case .request:
        allowed = name == "cookie"
          || (name != "host" && name != "authorization" && requestHeaders.contains(name))
      case .response:
        allowed = responseHeaders.contains(name) && !blockedResponseHeaders.contains(name)
      case .webSocket:
        allowed = name == "cookie" || webSocketHeaders.contains(name)
      }
      guard allowed else { return nil }
      let value = name == "cookie" ? filteredCookie(header.value) : header.value
      return value.isEmpty ? nil : ProxyHeader(name: name, value: value)
    }
  }

  private func filteredCookie(_ value: String) -> String {
    value.split(separator: ";").compactMap { part in
      let value = part.trimmingCharacters(in: .whitespacesAndNewlines)
      guard let separator = value.firstIndex(of: "=") else { return nil }
      let name = value[..<separator].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
      guard !name.isEmpty, !forbiddenCookieNames.contains(name),
        !forbiddenCookieNamePrefixes.contains(where: name.hasPrefix)
      else { return nil }
      return value
    }.joined(separator: "; ")
  }
}

public struct ProxyCookieJar: Sendable {
  private struct Cookie: Sendable {
    var name: String
    var value: String
    var path: String
  }

  private var cookies: [String: Cookie] = [:]

  public init() {}

  public mutating func capture(requestPath: String, headers: [ProxyHeader]) {
    let defaultPath = proxyDefaultCookiePath(requestPath)
    for header in headers where header.name.caseInsensitiveCompare("set-cookie") == .orderedSame {
      let parts = header.value.split(separator: ";", omittingEmptySubsequences: false)
      guard let first = parts.first,
        let separator = first.firstIndex(of: "=")
      else { continue }
      let name = first[..<separator].trimmingCharacters(in: .whitespacesAndNewlines)
      let value = first[first.index(after: separator)...].trimmingCharacters(in: .whitespacesAndNewlines)
      guard !name.isEmpty else { continue }
      var path = defaultPath
      var delete = value.isEmpty
      for rawAttribute in parts.dropFirst() {
        let attribute = rawAttribute.trimmingCharacters(in: .whitespacesAndNewlines)
        let components = attribute.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        let attributeName = components[0].lowercased()
        let attributeValue = components.count == 2 ? String(components[1]) : ""
        if attributeName == "path", attributeValue.hasPrefix("/") { path = attributeValue }
        if attributeName == "max-age", Int64(attributeValue).map({ $0 <= 0 }) == true { delete = true }
      }
      let key = "\(name)\u{0}\(path)"
      if delete { cookies.removeValue(forKey: key) }
      else { cookies[key] = Cookie(name: name, value: value, path: path) }
    }
  }

  public func requestHeader(for path: String) -> ProxyHeader? {
    let values = cookies.values
      .filter { proxyCookiePathMatches(cookiePath: $0.path, requestPath: path) }
      .sorted { $0.path.count > $1.path.count }
    guard !values.isEmpty else { return nil }
    return ProxyHeader(
      name: "cookie",
      value: values.map { "\($0.name)=\($0.value)" }.joined(separator: "; ")
    )
  }
}

enum ProxyFraming {
  static func writeJSON<Value: Encodable>(
    _ value: Value,
    to stream: any FlowersecByteStream,
    maxBytes: Int
  ) async throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(value)
    guard data.count <= maxBytes, data.count <= Int(UInt32.max) else {
      throw ProxyError.frameTooLarge
    }
    var frame = Data()
    frame.appendUInt32BE(UInt32(data.count))
    frame.append(data)
    try await stream.write(frame)
  }

  static func readJSON<Value: Decodable>(
    _ type: Value.Type,
    from stream: any FlowersecByteStream,
    maxBytes: Int
  ) async throws -> Value {
    let header = try await stream.readExact(4)
    guard header.count == 4 else { throw ProxyError.stream("truncated JSON frame header") }
    let length = Int(header.readUInt32BE(at: 0))
    guard length <= maxBytes else { throw ProxyError.frameTooLarge }
    let payload = try await stream.readExact(length)
    guard payload.count == length else { throw ProxyError.stream("truncated JSON frame") }
    do { return try JSONDecoder().decode(type, from: payload) }
    catch { throw ProxyError.invalidMetadata(error.localizedDescription) }
  }

  static func writeBody(
    _ body: Data,
    to stream: any FlowersecByteStream,
    options: ProxyContractOptions
  ) async throws {
    guard body.count <= options.maxBodyBytes else { throw ProxyError.bodyTooLarge }
    var offset = 0
    while offset < body.count {
      let count = min(options.maxChunkBytes, body.count - offset)
      var frame = Data()
      frame.appendUInt32BE(UInt32(count))
      frame.append(body.subdata(in: offset..<(offset + count)))
      try await stream.write(frame)
      offset += count
    }
    try await stream.write(Data(repeating: 0, count: 4))
  }

  static func readBody(
    from stream: any FlowersecByteStream,
    options: ProxyContractOptions
  ) async throws -> Data {
    var body = Data()
    while true {
      let header = try await stream.readExact(4)
      guard header.count == 4 else { throw ProxyError.stream("truncated body chunk header") }
      let length = Int(header.readUInt32BE(at: 0))
      if length == 0 { return body }
      guard length <= options.maxChunkBytes else { throw ProxyError.frameTooLarge }
      guard body.count <= options.maxBodyBytes - length else { throw ProxyError.bodyTooLarge }
      let chunk = try await stream.readExact(length)
      guard chunk.count == length else { throw ProxyError.stream("truncated body chunk") }
      body.append(chunk)
    }
  }

  static func writeWebSocketFrame(
    _ frame: ProxyWebSocketFrame,
    to stream: any FlowersecByteStream,
    maxBytes: Int
  ) async throws {
    guard frame.payload.count <= maxBytes, frame.payload.count <= Int(UInt32.max) else {
      throw ProxyError.frameTooLarge
    }
    var data = Data([frame.operation.rawValue])
    data.appendUInt32BE(UInt32(frame.payload.count))
    data.append(frame.payload)
    try await stream.write(data)
  }

  static func readWebSocketFrame(
    from stream: any FlowersecByteStream,
    maxBytes: Int
  ) async throws -> ProxyWebSocketFrame {
    let header = try await stream.readExact(5)
    guard header.count == 5 else { throw ProxyError.stream("truncated WebSocket frame header") }
    guard let operation = ProxyWebSocketOperation(rawValue: header[0]) else {
      throw ProxyError.invalidWebSocketOperation(header[0])
    }
    let length = Int(header.readUInt32BE(at: 1))
    guard length <= maxBytes else { throw ProxyError.frameTooLarge }
    let payload = try await stream.readExact(length)
    guard payload.count == length else { throw ProxyError.stream("truncated WebSocket frame") }
    return ProxyWebSocketFrame(operation: operation, payload: payload)
  }
}

func proxyValidateContract(_ options: ProxyContractOptions) throws {
  guard options.maxJSONFrameBytes > 0, options.maxChunkBytes > 0,
    options.maxBodyBytes > 0, options.maxWebSocketFrameBytes > 0,
    options.maxChunkBytes <= Int(UInt32.max)
  else { throw ProxyError.invalidConfiguration("proxy limits must be positive") }
  if let timeout = options.defaultHTTPRequestTimeout, timeout < .zero {
    throw ProxyError.invalidConfiguration("default HTTP timeout must be non-negative")
  }
  _ = try ProxyHeaderPolicy(options: options)
}

func proxyValidatePath(_ path: String) throws {
  guard path == path.trimmingCharacters(in: .whitespacesAndNewlines),
    path.hasPrefix("/"), !path.hasPrefix("//"), !path.contains("://"),
    !path.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.contains),
    !path.contains("#"), URL(string: "http://flowersec.invalid\(path)") != nil
  else { throw ProxyError.invalidPath }
}

func proxyNormalizedOrigin(_ rawValue: String) throws -> String {
  guard var components = URLComponents(string: rawValue.trimmingCharacters(in: .whitespacesAndNewlines)),
    let scheme = components.scheme?.lowercased(), scheme == "http" || scheme == "https",
    components.host != nil, components.user == nil, components.password == nil,
    components.query == nil, components.fragment == nil,
    components.path.isEmpty || components.path == "/"
  else { throw ProxyError.invalidConfiguration("origin must be an http(s) origin") }
  components.scheme = scheme
  components.path = ""
  guard let normalized = components.url?.absoluteString else {
    throw ProxyError.invalidConfiguration("origin is invalid")
  }
  return normalized.hasSuffix("/") ? String(normalized.dropLast()) : normalized
}

func proxyDurationMilliseconds(_ duration: Duration) throws -> Int64 {
  guard duration >= .zero else { throw ProxyError.invalidMetadata("timeout must be non-negative") }
  let components = duration.components
  let milliseconds = Double(components.seconds) * 1_000
    + Double(components.attoseconds) / 1_000_000_000_000_000
  guard milliseconds <= Double(Int64.max) else {
    throw ProxyError.invalidMetadata("timeout is too large")
  }
  return Int64(milliseconds.rounded(.up))
}

private func proxyHeaderNameSet(_ names: [String]) throws -> Set<String> {
  Set(try names.map { name in
    let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard proxyValidHeaderName(normalized) else {
      throw ProxyError.invalidConfiguration("invalid header name")
    }
    return normalized
  })
}

private func proxyNonemptyNameSet(_ names: [String]) throws -> Set<String> {
  Set(try proxyNonemptyNames(names))
}

private func proxyNonemptyNames(_ names: [String]) throws -> [String] {
  try names.map { name in
    let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !normalized.isEmpty else {
      throw ProxyError.invalidConfiguration("policy names must not be empty")
    }
    return normalized
  }
}

private func proxyValidHeaderName(_ name: String) -> Bool {
  guard !name.isEmpty else { return false }
  let punctuation = Set("!#$%&'*+-.^_`|~".utf8)
  return name.utf8.allSatisfy { byte in
    (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39)
      || punctuation.contains(byte)
  }
}

private func proxySafeHeaderValue(_ value: String) -> Bool {
  !value.contains("\r") && !value.contains("\n")
}

private func proxyDefaultCookiePath(_ requestPath: String) -> String {
  let path = requestPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
  guard path.hasPrefix("/"), path != "/", let slash = path.dropLast().lastIndex(of: "/") else {
    return "/"
  }
  let result = String(path[...slash])
  return result.isEmpty ? "/" : result
}

private func proxyCookiePathMatches(cookiePath: String, requestPath: String) -> Bool {
  let path = requestPath.split(separator: "?", maxSplits: 1).first.map(String.init) ?? "/"
  if path == cookiePath { return true }
  guard path.hasPrefix(cookiePath) else { return false }
  return cookiePath.hasSuffix("/") || path.dropFirst(cookiePath.count).first == "/"
}
