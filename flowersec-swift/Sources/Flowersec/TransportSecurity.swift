import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

public enum TransportRuntime: String, Codable, Equatable, Sendable {
  case swift
}

public struct TransportSecurityPolicyInput: Equatable, Sendable {
  public var path: FlowersecPath
  public var scheme: String
  public var host: String
  public var runtime: TransportRuntime

  public init(path: FlowersecPath, scheme: String, host: String, runtime: TransportRuntime) {
    self.path = path
    self.scheme = scheme
    self.host = host
    self.runtime = runtime
  }
}

public enum PlaintextRiskAcceptance: String, Equatable, Sendable {
  case acceptPreE2ECredentialExposure = "accept_pre_e2ee_credential_exposure"
}

public struct NetworkPlaintextPolicyOptions: Equatable, Sendable {
  public var allowedHosts: [String]
  public var riskAcceptance: PlaintextRiskAcceptance

  public init(allowedHosts: [String], riskAcceptance: PlaintextRiskAcceptance) {
    self.allowedHosts = allowedHosts
    self.riskAcceptance = riskAcceptance
  }
}

public enum TransportSecurityPolicy: Sendable {
  case requireTLS
  case allowPlaintextForLoopback
  @available(
    *, deprecated,
    message: "Use requireTLS, allowPlaintextForLoopback, or networkPlaintext(options:)."
  )
  case allowPlaintext
  case custom(@Sendable (TransportSecurityPolicyInput) async throws -> Bool)

  public static func networkPlaintext(options: NetworkPlaintextPolicyOptions) throws -> Self {
    guard options.riskAcceptance == .acceptPreE2ECredentialExposure else {
      throw NetworkPlaintextPolicyError.invalidRiskAcceptance
    }
    guard !options.allowedHosts.isEmpty else {
      throw NetworkPlaintextPolicyError.missingAllowedHosts
    }
    let hosts = try Set(options.allowedHosts.map(canonicalNetworkPlaintextHost))
    return .custom { input in
      input.scheme == "wss" || (input.scheme == "ws" && hosts.contains(input.host))
    }
  }
}

private enum NetworkPlaintextPolicyError: Error {
  case invalidRiskAcceptance
  case missingAllowedHosts
  case invalidAllowedHost(String)
}

private func stringFromNullTerminatedBuffer(_ buffer: [CChar]) -> String {
  String(
    decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
    as: UTF8.self
  )
}

private func canonicalNetworkPlaintextHost(_ rawHost: String) throws -> String {
  let host = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
  guard !host.isEmpty,
    host == host.lowercased(),
    host.rangeOfCharacter(from: CharacterSet(charactersIn: "@/?#%[]")) == nil
  else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
  }

  if host.contains(":") {
    var address = in6_addr()
    guard inet_pton(AF_INET6, host, &address) == 1 else {
      throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
    }
    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    let rendered = buffer.withUnsafeMutableBufferPointer { output in
      withUnsafePointer(to: &address) { pointer in
        inet_ntop(AF_INET6, UnsafeRawPointer(pointer), output.baseAddress, socklen_t(output.count))
      }
    }
    guard rendered != nil else {
      throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
    }
    let canonical = stringFromNullTerminatedBuffer(buffer)
    guard canonical == host else {
      throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
    }
    let words = try expandIPv6Words(canonical)
    let unspecified = words.allSatisfy { $0 == 0 }
    let loopback = words.dropLast().allSatisfy { $0 == 0 } && words.last == 1
    let mappedIPv4 = words.prefix(5).allSatisfy { $0 == 0 } && words[5] == 0xffff
    let multicast = words[0] & 0xff00 == 0xff00
    let linkLocal = words[0] & 0xffc0 == 0xfe80
    guard !unspecified, !loopback, !mappedIPv4, !multicast, !linkLocal else {
      throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
    }
    return canonical
  }

  var address = in_addr()
  guard inet_pton(AF_INET, host, &address) == 1 else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
  }
  var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
  let rendered = buffer.withUnsafeMutableBufferPointer { output in
    withUnsafePointer(to: &address) { pointer in
      inet_ntop(AF_INET, UnsafeRawPointer(pointer), output.baseAddress, socklen_t(output.count))
    }
  }
  guard rendered != nil else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
  }
  let canonical = stringFromNullTerminatedBuffer(buffer)
  guard canonical == host else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
  }
  let octets = host.split(separator: ".").compactMap { Int($0) }
  guard octets.count == 4,
    octets[0] != 127,
    !(octets[0] == 169 && octets[1] == 254),
    octets[0] < 224,
    !octets.allSatisfy({ $0 == 0 })
  else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(rawHost)
  }
  return canonical
}

private func expandIPv6Words(_ host: String) throws -> [UInt16] {
  let halves = host.components(separatedBy: "::")
  guard halves.count <= 2 else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(host)
  }
  let left = halves[0].isEmpty ? [] : halves[0].split(separator: ":").map(String.init)
  let right =
    halves.count == 1 || halves[1].isEmpty ? [] : halves[1].split(separator: ":").map(String.init)
  let missing = 8 - left.count - right.count
  guard (halves.count == 1 && missing == 0) || (halves.count == 2 && missing > 0) else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(host)
  }
  let parts = left + Array(repeating: "0", count: missing) + right
  let words = parts.compactMap { UInt16($0, radix: 16) }
  guard words.count == 8 else {
    throw NetworkPlaintextPolicyError.invalidAllowedHost(host)
  }
  return words
}

public struct TransportSecurityDiagnostic: Equatable, Sendable {
  public var code: String
  public var path: FlowersecPath
  public var scheme: String
  public var host: String
  public var runtime: TransportRuntime

  public init(
    code: String,
    path: FlowersecPath,
    scheme: String,
    host: String,
    runtime: TransportRuntime
  ) {
    self.code = code
    self.path = path
    self.scheme = scheme
    self.host = host
    self.runtime = runtime
  }
}

enum FlowersecTransportSecurity {
  static func enforce(url: URL, path: FlowersecPath, options: ConnectOptions) async throws {
    let target: (scheme: String, host: String)
    do {
      target = try parse(url)
    } catch {
      throw denied(path: path)
    }
    let input = TransportSecurityPolicyInput(
      path: path,
      scheme: target.scheme,
      host: target.host,
      runtime: .swift
    )

    let allowed: Bool
    do {
      switch options.transportSecurityPolicy {
      case .requireTLS:
        allowed = target.scheme == "wss"
      case .allowPlaintextForLoopback:
        allowed = target.scheme == "wss" || isLiteralLoopbackHost(target.host)
      case .allowPlaintext:
        allowed = true
      case .custom(let evaluate):
        try Task.checkCancellation()
        allowed = try await evaluate(input)
        try Task.checkCancellation()
      }
    } catch is CancellationError {
      throw CancellationError()
    } catch {
      if Task.isCancelled { throw CancellationError() }
      throw denied(path: path)
    }
    if !allowed {
      throw denied(path: path)
    }
    if target.scheme == "ws" {
      options.onDiagnosticEvent?(
        DiagnosticEvent(
          path: path,
          stage: .transport,
          codeDomain: .event,
          code: "plaintext_transport",
          result: .skip,
          resource: "websocket_transport"
        )
      )
      options.onTransportSecurityDiagnostic?(
        TransportSecurityDiagnostic(
          code: "plaintext_transport",
          path: path,
          scheme: target.scheme,
          host: target.host,
          runtime: .swift
        )
      )
    }
  }

  private static func denied(path: FlowersecPath) -> FlowersecError {
    FlowersecError(
      path: path,
      stage: .validate,
      code: .transportPolicyDenied,
      message: "Transport security policy denied the WebSocket URL."
    )
  }

  private static func parse(_ url: URL) throws -> (scheme: String, host: String) {
    let raw = url.absoluteString.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let separator = raw.range(of: "://") else { throw ParseError.invalid }
    let scheme = raw[..<separator.lowerBound].lowercased()
    guard scheme == "ws" || scheme == "wss" else { throw ParseError.invalid }
    let suffix = raw[separator.upperBound...]
    let authority = String(suffix.prefix { $0 != "/" && $0 != "?" && $0 != "#" })
    guard !authority.isEmpty, !authority.contains("@") else { throw ParseError.invalid }

    let host: String
    if authority.hasPrefix("[") {
      guard let end = authority.firstIndex(of: "]"), end > authority.startIndex else {
        throw ParseError.invalid
      }
      host = String(authority[authority.index(after: authority.startIndex)..<end]).lowercased()
      let remainder = authority[authority.index(after: end)...]
      if !remainder.isEmpty {
        guard remainder.first == ":", remainder.dropFirst().allSatisfy(\.isNumber) else {
          throw ParseError.invalid
        }
      }
    } else {
      let pieces = authority.split(separator: ":", omittingEmptySubsequences: false)
      guard pieces.count <= 2 else { throw ParseError.invalid }
      if pieces.count == 2 {
        guard !pieces[1].isEmpty, pieces[1].allSatisfy(\.isNumber) else {
          throw ParseError.invalid
        }
      }
      host = String(pieces[0]).lowercased()
    }
    guard !host.isEmpty else { throw ParseError.invalid }
    return (scheme, host)
  }

  private static func isLiteralLoopbackHost(_ host: String) -> Bool {
    if host == "localhost" || host == "::1" { return true }
    let pieces = host.split(separator: ".", omittingEmptySubsequences: false)
    guard pieces.count == 4 else { return false }
    var octets: [Int] = []
    for piece in pieces {
      let value = String(piece)
      guard !value.isEmpty,
        value == "0" || !value.hasPrefix("0"),
        value.allSatisfy(\.isNumber),
        let octet = Int(value),
        octet <= 255
      else { return false }
      octets.append(octet)
    }
    return octets.first == 127
  }

  private enum ParseError: Error {
    case invalid
  }
}
