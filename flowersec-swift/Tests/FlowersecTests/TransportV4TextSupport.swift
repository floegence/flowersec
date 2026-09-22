import Foundation

// Signed text syntax only; real DNS/TLS/Origin admission remains separate.
struct V4TextReference: Sendable {
  let shape: V4ShapeReference
  let idna: V4IDNA

  init() throws { shape = try V4ShapeReference(); idna = try V4IDNA(syntax: shape.syntax) }

  func issuerHost(_ input: String) throws -> String {
    guard !input.isEmpty else { throw V4CBORFailure("host_text") }
    let forbidden: Set<UInt32> = [32, 91, 93, 37, 92, 47, 63, 35, 64, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]
    guard !input.unicodeScalars.contains(where: { (9...13).contains($0.value) || (0x2000...0x200a).contains($0.value) || forbidden.contains($0.value) }) else { throw V4CBORFailure("host_syntax") }
    if input.utf8.contains(58) {
      guard let words = v4IPv6(input) else { throw V4CBORFailure("host_ipv6") }
      return v4IPv6Hex(words)
    }
    if input.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) {
      guard let octets = v4IPv4(input) else { throw V4CBORFailure("host_ipv4") }
      return octets.map(String.init).joined(separator: ".")
    }
    let dns = try idna.issuerDNS(input), last = dns.split(separator: ".").last!
    if last.utf8.allSatisfy({ (48...57).contains($0) }) || last.hasPrefix("0x") && last.dropFirst(2).utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
      throw V4CBORFailure("host_numeric_final_label")
    }
    return dns
  }

  func wireHost(_ input: String) throws {
    guard !input.isEmpty, input.utf8.allSatisfy({ $0 < 128 }) else { throw V4CBORFailure("host_wire_ascii") }
    guard try Data(issuerHost(input).utf8) == Data(input.utf8) else { throw V4CBORFailure("host_noncanonical") }
  }

  private func defaultPort(_ scheme: String) throws -> UInt64 {
    guard let entry = try shape.fieldRegistry("origin_schemes").object?[scheme] else { throw V4CBORFailure("origin_scheme_unregistered") }
    return try v4RuleInteger(entry["default_port"])
  }

  func wireOrigin(_ input: String) throws {
    guard !input.isEmpty, input.utf8.allSatisfy({ (0x21...0x7e).contains($0) }) else { throw V4CBORFailure("origin_ascii") }
    let parts = input.components(separatedBy: "://")
    guard parts.count == 2, let first = parts[0].utf8.first, (97...122).contains(first),
          parts[0].utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || [43, 46, 45].contains($0) }) else { throw V4CBORFailure("origin_syntax") }
    let defaultValue = try defaultPort(parts[0]), authority = parts[1]
    let host: String, port: String?
    if authority.hasPrefix("[") {
      let pair = authority.components(separatedBy: "]")
      guard pair.count == 2 else { throw V4CBORFailure("origin_syntax") }
      host = String(pair[0].dropFirst())
      guard host.utf8.contains(58), host.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) || $0 == 58 }) else { throw V4CBORFailure("origin_syntax") }
      if pair[1].isEmpty { port = nil }
      else {
        guard pair[1].hasPrefix(":") else { throw V4CBORFailure("origin_syntax") }; port = String(pair[1].dropFirst())
      }
    } else {
      let pair = authority.components(separatedBy: ":")
      guard pair.count <= 2 else { throw V4CBORFailure("origin_syntax") }
      host = pair[0]; port = pair.count == 2 ? pair[1] : nil
    }
    try wireHost(host)
    if let port {
      guard !port.isEmpty, port.utf8.allSatisfy({ (48...57).contains($0) }), !(port.count > 1 && port.hasPrefix("0")),
            let value = UInt16(port) else { throw V4CBORFailure("origin_port") }
      guard UInt64(value) != defaultValue else { throw V4CBORFailure("origin_default_port") }
    }
  }

  private func format(_ name: String, _ input: String) throws {
    switch name {
    case "host": try wireHost(input)
    case "origin": try wireOrigin(input)
    case "loopback_host":
      try wireHost(input)
      guard input == "::1" || v4IPv4(input)?.first == 127 else { throw V4CBORFailure("host_loopback") }
    default: throw V4CBORFailure("text_format_unresolved")
    }
  }

  private func fieldFormats(_ original: V4JSON, _ value: V4CBORValue, context: V4CBORContext) throws {
    let field = try shape.selectedField(original, context: context)
    if let name = field["text_format"].text {
      guard case .text(let text) = value else { throw V4CBORFailure("field_type") }
      return try format(name, text)
    }
    switch field["type"].text {
    case "array":
      guard case .array(let items) = value else { throw V4CBORFailure("field_type") }
      for item in items { try fieldFormats(field["items"], item, context: context) }
    case "text_map":
      guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
      for pair in pairs {
        try fieldFormats(field["keys"], pair.key, context: context)
        guard case .text(let text) = pair.key else { throw V4CBORFailure("field_type") }
        let child: V4JSON
        if let entries = field["entries"].object {
          guard let entry = entries[text] else { throw V4CBORFailure("unknown_field") }; child = entry
        } else {
          guard let entry = field.object?["values"] else { throw V4CBORFailure("registry_unresolved") }; child = entry
        }
        try fieldFormats(child, pair.value, context: context)
      }
    default: break
    }
    // The shared walker visits map and embedded children under their own scope.
  }

  private func checkMap(_ name: String, _ value: V4CBORValue, _ context: V4CBORContext) throws {
    guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
    let descriptor = try shape.descriptor(name)
    for pair in pairs {
      guard case .uint(let id) = pair.key else { throw V4CBORFailure("field_id_type") }
      guard let field = descriptor["fields"].object?[String(id)] else { throw V4CBORFailure("unknown_field") }
      try fieldFormats(field, pair.value, context: context)
    }
    guard let rules = shape.registry["text_rules"].object?[name] else { return }
    guard let rules = rules.array else { throw V4CBORFailure("rule_unresolved") }
    let keys: Set<String> = ["op", "field", "format", "host", "port", "origin", "scheme", "when"]
    for rule in rules {
      guard let object = rule.object, Set(object.keys).isSubset(of: keys) else { throw V4CBORFailure("rule_unresolved") }
      guard try shape.ruleApplies(name, value, when: object["when"], context: context) else { continue }
      func get(_ key: String) throws -> V4CBORValue {
        guard let path = rule[key].text, let result = try shape.rulePath(name, value, path, context: context) else { throw V4CBORFailure("unknown_rule_field") }; return result
      }
      switch rule["op"].text {
      case "text_format":
        guard case .text(let text) = try get("field"), let kind = rule["format"].text else { throw V4CBORFailure("field_type") }
        try format(kind, text)
      case "origin_endpoint":
        guard case .text(let host) = try get("host"), case .uint(let port) = try get("port"),
              case .text(let origin) = try get("origin"), let scheme = rule["scheme"].text else { throw V4CBORFailure("field_type") }
        var expected = scheme + "://" + (host.utf8.contains(58) ? "[\(host)]" : host)
        if port != (try defaultPort(scheme)) { expected += ":\(port)" }
        guard Data(expected.utf8) == Data(origin.utf8) else { throw V4CBORFailure("origin_endpoint") }
      default: throw V4CBORFailure("rule_unresolved")
      }
    }
  }

  func wireMap(_ input: Data, schema: String = "", context: V4CBORContext = .init(), cap: UInt64) throws -> V4CBORValue {
    let value = try shape.relations(input, schema: schema, context: context, cap: cap)
    if !schema.isEmpty { try shape.walkRules(schema, value, context: context, check: checkMap) }
    return value
  }
}

func v4IPv4(_ text: String) -> [UInt8]? {
  let parts = text.components(separatedBy: ".")
  guard parts.count == 4 else { return nil }
  var octets: [UInt8] = []
  for part in parts {
    guard !part.isEmpty, part.utf8.allSatisfy({ (48...57).contains($0) }), !(part.count > 1 && part.hasPrefix("0")), let octet = UInt8(part) else { return nil }
    octets.append(octet)
  }
  return octets
}

func v4IPv6(_ text: String) -> [UInt16]? {
  let halves = text.components(separatedBy: "::")
  guard halves.count <= 2 else { return nil }
  func words(_ text: String, allowIPv4: Bool) -> [UInt16]? {
    if text.isEmpty { return [] }
    let fields = text.components(separatedBy: ":")
    var result: [UInt16] = []
    for (index, field) in fields.enumerated() {
      if field.utf8.contains(46) {
        guard allowIPv4, index == fields.count - 1, let octets = v4IPv4(field) else { return nil }
        result.append(UInt16(octets[0]) << 8 | UInt16(octets[1])); result.append(UInt16(octets[2]) << 8 | UInt16(octets[3]))
      } else {
        guard !field.isEmpty, field.utf8.count <= 4,
              field.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }),
              let n = UInt16(field, radix: 16) else { return nil }
        result.append(n)
      }
    }
    return result
  }
  guard let left = words(halves[0], allowIPv4: halves.count == 1) else { return nil }
  if halves.count == 1 { return left.count == 8 ? left : nil }
  guard let right = words(halves[1], allowIPv4: true), left.count + right.count < 8 else { return nil }
  return left + Array(repeating: 0, count: 8 - left.count - right.count) + right
}

func v4IPv6Hex(_ words: [UInt16]) -> String {
  precondition(words.count == 8)
  var best: Int?, length = 1, index = 0
  while index < words.count {
    if words[index] != 0 { index += 1; continue }
    var end = index + 1
    while end < words.count && words[end] == 0 { end += 1 }
    if end - index > length { best = index; length = end - index }
    index = end
  }
  let text = words.map { String($0, radix: 16) }
  if let start = best { return text[..<start].joined(separator: ":") + "::" + text[(start + length)...].joined(separator: ":") }
  return text.joined(separator: ":")
}
