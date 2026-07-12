import Foundation

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

public enum TransportSecurityPolicy: Sendable {
  case requireTLS
  case allowPlaintextForLoopback
  case allowPlaintext
  case custom(@Sendable (TransportSecurityPolicyInput) async throws -> Bool)
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

    guard let policy = options.transportSecurityPolicy else {
      if target.scheme == "ws" {
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
      return
    }

    let allowed: Bool
    do {
      switch policy {
      case .requireTLS:
        allowed = target.scheme == "wss"
      case .allowPlaintextForLoopback:
        allowed = target.scheme == "wss" || isLiteralLoopbackHost(target.host)
      case .allowPlaintext:
        allowed = true
      case .custom(let evaluate):
        allowed = try await evaluate(input)
      }
    } catch {
      throw denied(path: path)
    }
    if !allowed {
      throw denied(path: path)
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
