import Foundation

internal struct ProxyHeader: Codable, Equatable, Sendable {
  internal var name: String
  internal var value: String

  internal init(name: String, value: String) {
    self.name = name
    self.value = value
  }
}

internal enum ProxyWebSocketOperation: UInt8, Codable, Equatable, Sendable {
  case text = 1
  case binary = 2
  case close = 8
  case ping = 9
  case pong = 10
}

internal struct ProxyWebSocketFrame: Equatable, Sendable {
  internal var operation: ProxyWebSocketOperation
  internal var payload: Data

  internal init(operation: ProxyWebSocketOperation, payload: Data = Data()) {
    self.operation = operation
    self.payload = payload
  }

  internal static func close(code: UInt16? = nil, reason: String = "") throws
    -> ProxyWebSocketFrame
  {
    guard reason.utf8.count <= 123 else {
      throw ProxyError.invalidMetadata("close reason is too long")
    }
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

internal struct ProxyForwardingOptions: Equatable, Sendable {
  var extraRequestHeaders: [String]
  var extraResponseHeaders: [String]
  var blockedResponseHeaders: [String]
  var extraWebSocketHeaders: [String]
  var forbiddenCookieNames: [String]
  var forbiddenCookieNamePrefixes: [String]
  init(extraRequestHeaders: [String] = [], extraResponseHeaders: [String] = [],
    blockedResponseHeaders: [String] = [], extraWebSocketHeaders: [String] = [],
    forbiddenCookieNames: [String] = [], forbiddenCookieNamePrefixes: [String] = []) {
    self.extraRequestHeaders = extraRequestHeaders; self.extraResponseHeaders = extraResponseHeaders
    self.blockedResponseHeaders = blockedResponseHeaders; self.extraWebSocketHeaders = extraWebSocketHeaders
    self.forbiddenCookieNames = forbiddenCookieNames; self.forbiddenCookieNamePrefixes = forbiddenCookieNamePrefixes
  }
}

internal enum ProxyError: LocalizedError, Equatable, Sendable {
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

  internal var errorDescription: String? {
    switch self {
    case .invalidConfiguration(let message): return "Invalid proxy configuration: \(message)"
    case .invalidPath: return "The proxy path is invalid."
    case .invalidMetadata(let message): return "Invalid proxy metadata: \(message)"
    case .frameTooLarge: return "The proxy frame exceeds the configured limit."
    case .bodyTooLarge: return "The proxy body exceeds the configured limit."
    case .invalidWebSocketOperation(let operation):
      return "Invalid WebSocket operation \(operation)."
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
  let tlsLocated: Bool

  init(_ kind: ProxyUpstreamFailureKind, _ error: any Error, tlsLocated: Bool = false) {
    self.kind = kind
    self.message = error.localizedDescription
    self.tlsLocated = tlsLocated
  }

  init(_ kind: ProxyUpstreamFailureKind, message: String) {
    self.kind = kind
    self.message = message
    self.tlsLocated = false
  }

  var errorDescription: String? { message }
}

internal struct ProxyHeaderPolicy: Sendable {
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

  internal init(options: ProxyForwardingOptions = ProxyForwardingOptions()) throws {
    requestHeaders = Self.requestHeaders.union(try proxyHeaderNameSet(options.extraRequestHeaders))
    responseHeaders = Self.responseHeaders.union(
      try proxyHeaderNameSet(options.extraResponseHeaders))
    blockedResponseHeaders = try proxyHeaderNameSet(options.blockedResponseHeaders)
    webSocketHeaders = Self.webSocketHeaders.union(
      try proxyHeaderNameSet(options.extraWebSocketHeaders)
    )
    forbiddenCookieNames = try proxyNonemptyNameSet(options.forbiddenCookieNames)
    forbiddenCookieNamePrefixes = try proxyNonemptyNames(options.forbiddenCookieNamePrefixes)
  }

  internal func filterRequest(_ headers: [ProxyHeader]) -> [ProxyHeader] {
    filter(headers, direction: .request)
  }

  internal func filterResponse(_ headers: [ProxyHeader]) -> [ProxyHeader] {
    filter(headers, direction: .response)
  }

  internal func filterWebSocket(_ headers: [ProxyHeader]) -> [ProxyHeader] {
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
        allowed =
          name == "cookie"
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

internal struct ProxyCookieJar: Sendable {
  private struct Cookie: Sendable {
    var name: String
    var value: String
    var path: String
  }

  private var cookies: [String: Cookie] = [:]

  internal init() {}

  internal mutating func capture(requestPath: String, headers: [ProxyHeader]) {
    let defaultPath = proxyDefaultCookiePath(requestPath)
    for header in headers where header.name.caseInsensitiveCompare("set-cookie") == .orderedSame {
      let parts = header.value.split(separator: ";", omittingEmptySubsequences: false)
      guard let first = parts.first,
        let separator = first.firstIndex(of: "=")
      else { continue }
      let name = first[..<separator].trimmingCharacters(in: .whitespacesAndNewlines)
      let value = first[first.index(after: separator)...].trimmingCharacters(
        in: .whitespacesAndNewlines)
      guard !name.isEmpty else { continue }
      var path = defaultPath
      var delete = value.isEmpty
      for rawAttribute in parts.dropFirst() {
        let attribute = rawAttribute.trimmingCharacters(in: .whitespacesAndNewlines)
        let components = attribute.split(
          separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        let attributeName = components[0].lowercased()
        let attributeValue = components.count == 2 ? String(components[1]) : ""
        if attributeName == "path", attributeValue.hasPrefix("/") { path = attributeValue }
        if attributeName == "max-age", Int64(attributeValue).map({ $0 <= 0 }) == true {
          delete = true
        }
      }
      let key = "\(name)\u{0}\(path)"
      if delete {
        cookies.removeValue(forKey: key)
      } else {
        cookies[key] = Cookie(name: name, value: value, path: path)
      }
    }
  }

  internal mutating func captureBounded(requestPath: String, headers: [ProxyHeader]) throws {
    var next = self
    next.capture(requestPath: requestPath, headers: headers)
    let bytes = next.cookies.reduce(0) { total, pair in
      total + pair.key.utf8.count + pair.value.name.utf8.count + pair.value.value.utf8.count + pair.value.path.utf8.count + 128
    }
    guard next.cookies.count <= 128, bytes <= 65_536 else { throw ProxyClientFailure.resourceExhausted }
    self = next
  }

  internal func requestHeader(for path: String) -> ProxyHeader? {
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

func proxyValidatePath(_ path: String) throws {
  guard path == path.trimmingCharacters(in: .whitespacesAndNewlines),
    path.hasPrefix("/"), !path.hasPrefix("//"), !path.contains("://"),
    !path.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.contains),
    !path.contains("#"), URL(string: "http://flowersec.invalid\(path)") != nil
  else { throw ProxyError.invalidPath }
}

func proxyNormalizedOrigin(_ rawValue: String) throws -> String {
  guard
    var components = URLComponents(
      string: rawValue.trimmingCharacters(in: .whitespacesAndNewlines)),
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
  let milliseconds =
    Double(components.seconds) * 1_000
    + Double(components.attoseconds) / 1_000_000_000_000_000
  guard milliseconds <= Double(Int64.max) else {
    throw ProxyError.invalidMetadata("timeout is too large")
  }
  return Int64(milliseconds.rounded(.up))
}

private func proxyHeaderNameSet(_ names: [String]) throws -> Set<String> {
  Set(
    try names.map { name in
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
