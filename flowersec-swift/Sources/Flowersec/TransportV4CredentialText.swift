import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

// Wire addresses are already canonical. This predicate never rewrites signed
// input; the existing frozen IDNA implementation is used only as an equality
// check for DNS labels, independently of any transport implementation.
enum V4CredentialText {
  static func validate(_ text: String, format: String, registry: V4NamespaceRegistry) throws {
    switch format {
    case "host", "loopback_host":
      let loopback = try host(text)
      guard format != "loopback_host" || loopback else { throw V4NamespaceFailure.schema }
    case "origin": _ = try origin(text, registry: registry)
    default: throw V4NamespaceFailure.schema
    }
  }

  static func addressBytes(_ text: String) -> Data? {
    var ipv4 = in_addr()
    if text.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
      return withUnsafeBytes(of: &ipv4) { Data($0) }
    }
    var ipv6 = in6_addr()
    guard text.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return nil }
    return withUnsafeBytes(of: &ipv6) { Data($0) }
  }

  static func isLoopbackAddress(_ text: String) -> Bool {
    var ipv4 = in_addr()
    if text.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
      return withUnsafeBytes(of: &ipv4) { $0.first == 127 }
    }
    var ipv6 = in6_addr()
    guard text.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else { return false }
    return withUnsafeBytes(of: &ipv6) { bytes in
      bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
    }
  }

  private static func host(_ text: String) throws -> Bool {
    guard !text.isEmpty, text.utf8.count <= 253, text.utf8.allSatisfy({ (33...126).contains($0) }),
      text == text.lowercased(), !text.contains("%"), !text.contains("["), !text.contains("]")
    else { throw V4NamespaceFailure.schema }
    if text.contains(":") {
      guard !text.contains(".") else { throw V4NamespaceFailure.schema }
      var address = in6_addr()
      guard text.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
        throw V4NamespaceFailure.schema
      }
      let bytes = withUnsafeBytes(of: &address) { Array($0) }
      let words = stride(from: 0, to: 16, by: 2).map {
        UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1])
      }
      var bestStart = -1
      var bestLength = 1
      var index = 0
      while index < 8 {
        if words[index] != 0 {
          index += 1
          continue
        }
        let start = index
        while index < 8 && words[index] == 0 { index += 1 }
        if index - start > bestLength {
          bestStart = start
          bestLength = index - start
        }
      }
      let strings = words.map { String($0, radix: 16) }
      let canonical =
        bestStart < 0
        ? strings.joined(separator: ":")
        : strings[..<bestStart].joined(separator: ":") + "::"
          + strings[(bestStart + bestLength)...].joined(separator: ":")
      guard canonical == text else { throw V4NamespaceFailure.schema }
      return bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes.last == 1
    }
    if text.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) {
      let parts = text.split(separator: ".", omittingEmptySubsequences: false)
      guard parts.count == 4 else { throw V4NamespaceFailure.schema }
      let numbers = try parts.map { part -> UInt8 in
        guard let number = UInt8(part), String(number) == part else {
          throw V4NamespaceFailure.schema
        }
        return number
      }
      return numbers[0] == 127
    }
    guard let last = text.split(separator: ".").last,
      !last.utf8.allSatisfy({ (48...57).contains($0) }),
      !(last.hasPrefix("0x") && last.dropFirst(2).allSatisfy({ $0.isHexDigit })),
      try IDNAHost.lookupASCII(text) == text
    else { throw V4NamespaceFailure.schema }
    return false
  }

  static func origin(_ text: String, registry: V4NamespaceRegistry) throws
    -> (scheme: String, host: String, port: UInt64)
  {
    guard text.utf8.count <= 320, text.utf8.allSatisfy({ (33...126).contains($0) }),
      let separator = text.range(of: "://")
    else { throw V4NamespaceFailure.schema }
    let scheme = String(text[..<separator.lowerBound])
    guard let schemas = registry.fieldRegistries["origin_schemes"] as? [String: [String: Any]],
      let defaultPort = V4NamespaceRegistry.number(schemas[scheme]?["default_port"])
    else { throw V4NamespaceFailure.schema }
    let authority = text[separator.upperBound...]
    let name: String
    let portText: Substring?
    if authority.first == "[" {
      guard let end = authority.firstIndex(of: "]") else { throw V4NamespaceFailure.schema }
      name = String(authority[authority.index(after: authority.startIndex)..<end])
      guard name.contains(":") else { throw V4NamespaceFailure.schema }
      let rest = authority[authority.index(after: end)...]
      guard rest.isEmpty || rest.first == ":" else { throw V4NamespaceFailure.schema }
      portText = rest.isEmpty ? nil : rest.dropFirst()
    } else if let colon = authority.firstIndex(of: ":") {
      name = String(authority[..<colon])
      portText = authority[authority.index(after: colon)...]
    } else {
      name = String(authority)
      portText = nil
    }
    _ = try host(name)
    let port: UInt64
    if let portText {
      guard let number = UInt16(portText), number > 0, String(number) == portText,
        UInt64(number) != defaultPort
      else { throw V4NamespaceFailure.schema }
      port = UInt64(number)
    } else {
      port = defaultPort
    }
    return (scheme, name, port)
  }
}
