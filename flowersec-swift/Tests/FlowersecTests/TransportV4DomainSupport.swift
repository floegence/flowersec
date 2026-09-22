import Crypto
import Foundation
@testable import Flowersec

// Test-only generated inputs. No key custody, trust or live exporter capability.
enum V4DomainArgument: Equatable, Sendable {
  case uint(UInt64), bytes(Data), text(String), overflow, invalid
}
struct V4DomainOutput: Equatable, Sendable {
  var label: Data, input: Data
  var output: Data?, salt: Data?, ikm: Data?
  var outputLength: UInt64?
}
enum V4Domains {
  static let registry = try! JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.domainRegistryJSON.utf8)).array!
}

private func domainUInt(_ value: V4DomainArgument) throws -> UInt64 {
  if case .overflow = value { throw V4CBORFailure("domain_integer_range") }
  guard case .uint(let n) = value else { throw V4CBORFailure("domain_integer_type") }; return n
}
func v4DomainUnsigned(_ value: V4DomainArgument, width: Int) throws -> Data {
  guard [1, 4, 8].contains(width) else { throw V4CBORFailure("registry_unresolved") }
  let n = try domainUInt(value)
  guard width == 8 || n < UInt64(1) << (width * 8) else { throw V4CBORFailure("domain_integer_range") }
  var big = n.bigEndian
  return withUnsafeBytes(of: &big) { Data($0.suffix(width)) }
}
private func domainLP(_ data: Data) throws -> Data {
  try v4DomainUnsigned(.uint(UInt64(data.count)), width: 4) + data
}
private func domainMatch(_ actual: V4CBORValue, _ expected: V4DomainArgument) -> Bool {
  switch (actual, expected) {
  case (.uint(let a), .uint(let b)): return a == b
  case (.bytes(let a), .bytes(let b)): return a == b
  case (.text(let a), .text(let b)): return Data(a.utf8) == Data(b.utf8)
  default: return false
  }
}
private func domainText(_ value: V4JSON) throws -> String {
  guard let text = value.text else { throw V4CBORFailure("registry_unresolved") }; return text
}
private func domainList(_ value: V4JSON) throws -> [V4JSON] {
  guard let list = value.array else { throw V4CBORFailure("registry_unresolved") }; return list
}

extension V4TextReference {
  private func domainMap(_ part: V4JSON, input: Data, args: [String: V4DomainArgument], context: V4CBORContext, cap: UInt64) throws -> Data {
    let name: String
    if let exact = part["schema_ref"].text { name = exact }
    else {
      let selector = try domainUInt(args[domainText(part["selector"])] ?? .invalid)
      guard let selected = part["schema_cases"][String(selector)].text else { throw V4CBORFailure("domain_variant") }; name = selected
    }
    let value = try wireMap(input, schema: name, context: context, cap: cap)
    guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
    for (field, arg) in part["bindings"].object ?? [:] {
      guard try domainMatch(shape.requiredValue(name, value, field), args[domainText(arg)] ?? .invalid) else { throw V4CBORFailure("domain_binding") }
    }
    for (arg, fields) in part["one_of_bindings"].object ?? [:] {
      var found = false
      for field in try domainList(fields) { found = try domainMatch(shape.requiredValue(name, value, domainText(field)), args[arg] ?? .invalid) || found }
      guard found else { throw V4CBORFailure("domain_binding") }
    }
    let projection = try domainText(part["projection"])
    if projection == "full" { return try domainLP(input) }
    let descriptor = try shape.descriptor(name), excluded: [UInt64]
    switch projection {
    case "without_signature": excluded = [try v4RuleInteger(descriptor["signature_field"])]
    case "without_mac": excluded = [try v4RuleInteger(descriptor["mac_field"])]
    case "without_open_digest": excluded = [try shape.namedField(name, "open_digest").0]
    case "without_fields", "without_fields_raw": excluded = try domainList(part["fields"]).map { try shape.namedField(name, domainText($0)).0 }
    default: throw V4CBORFailure("domain_projection")
    }
    guard Set(excluded).count == excluded.count, excluded.allSatisfy({ value.field($0) != nil }) else { throw V4CBORFailure("domain_projection") }
    // Retain surviving field IDs and received order, without zero placeholders.
    let projected = V4CBORValue.map(pairs.filter { if case .uint(let id) = $0.key { return !excluded.contains(id) }; return true }).encoded()
    return try projection == "without_fields_raw" ? projected : domainLP(projected)
  }

  private func domainPart(_ part: V4JSON, args: [String: V4DomainArgument], context: V4CBORContext, cap: UInt64) throws -> Data {
    let encoding = try domainText(part["encoding"])
    if encoding == "hex" { return try v4RuleHex(domainText(part["hex"])) }
    let value: V4DomainArgument
    if let key = part["const_ref"].text { value = try .text(domainText(shape.fieldRegistry(key))) }
    else if let constant = part.object?["const"] { value = try .uint(v4RuleInteger(constant)) }
    else { value = try args[domainText(part["name"])] ?? .invalid }
    if let width = ["u8": 1, "u32": 4, "u64": 8][encoding] {
      let output = try v4DomainUnsigned(value, width: width), n = try domainUInt(value)
      if let values = part["enum"].array, !(try values.map(v4RuleInteger)).contains(n) { throw V4CBORFailure("domain_enum") }
      if let min = part.object?["min"], n < (try v4RuleInteger(min)) { throw V4CBORFailure("domain_integer_range") }
      if let max = part.object?["max"], n > (try v4RuleInteger(max)) { throw V4CBORFailure("domain_integer_range") }
      if let divisor = part.object?["multiple_of"] {
        let divisor = try v4RuleInteger(divisor); guard divisor > 0 else { throw V4CBORFailure("registry_unresolved") }
        guard n.isMultiple(of: divisor) else { throw V4CBORFailure("domain_integer_multiple") }
      }
      return output
    }
    if encoding == "lp-ascii" {
      guard case .text(let text) = value, !text.isEmpty, text.utf8.allSatisfy({ $0 < 128 }) else { throw V4CBORFailure("domain_ascii") }
      if let key = part["text_enum_ref"].text, try shape.fieldRegistry(key).object?[text] == nil { throw V4CBORFailure("domain_enum") }
      return try domainLP(Data(text.utf8))
    }
    guard case .bytes(let raw) = value else { throw V4CBORFailure("domain_bytes_type") }
    if encoding == "lp-map" { return try domainMap(part, input: raw, args: args, context: context, cap: cap) }
    guard ["raw", "lp-bytes"].contains(encoding) else { throw V4CBORFailure("registry_unresolved") }
    if let exact = part.object?["length"] {
      guard UInt64(raw.count) == (try v4RuleInteger(exact)) else { throw V4CBORFailure("domain_bytes_length") }
    } else { guard UInt64(raw.count) <= (try v4RuleInteger(part["max_length"])) else { throw V4CBORFailure("domain_bytes_length") } }
    if part["nonzero"].bool == true, raw.allSatisfy({ $0 == 0 }) { throw V4CBORFailure("domain_zero_secret") }
    return try encoding == "raw" ? raw.withUnsafeBytes { Data($0) } : domainLP(raw)
  }

  func evaluateDomain(_ name: String, args: [String: V4DomainArgument], context caller: V4CBORContext = .init(), cap: UInt64) throws -> V4DomainOutput {
    guard cap > 0 else { throw V4CBORFailure("limit_unresolved") }
    guard let domain = V4Domains.registry.first(where: { $0["name"].text == name }) else { throw V4CBORFailure("domain_unknown") }
    let spec = domain["input_schema"], parts = try domainList(spec["parts"])
    let all = parts + ["key", "salt", "ikm"].compactMap { spec.object?[$0] }
    let names = all.compactMap { $0["name"].text }
    guard args.count == names.count, names.allSatisfy({ args[$0] != nil }) else { throw V4CBORFailure("domain_arguments") }
    var context = caller
    if let value = args["profile"] {
      if let supplied = caller.selectors["crypto_profile_id"], !domainMatch(.text(supplied), value) { throw V4CBORFailure("domain_context") }
      guard case .text(let profile) = value else { throw V4CBORFailure("domain_ascii") }; context.selectors["crypto_profile_id"] = profile
    }
    let label = try v4RuleHex(domainText(domain["label_bytes"]))
    var content = Data()
    for part in parts { content += try domainPart(part, args: args, context: context, cap: cap) }
    for rule in spec["relations"].array ?? [] {
      let left = try domainUInt(args[domainText(rule["left"])] ?? .invalid), right = try domainUInt(args[domainText(rule["right"])] ?? .invalid)
      let valid: Bool
      switch rule["op"].text {
      case "successor": let next = left.addingReportingOverflow(1); valid = !next.overflow && next.partialValue == right
      case "allowed_pairs": valid = try domainList(rule["pairs"]).contains { pair in
        let pair = try domainList(pair); guard pair.count == 2 else { throw V4CBORFailure("registry_unresolved") }
        return try v4RuleInteger(pair[0]) == left && v4RuleInteger(pair[1]) == right
      }
      default: throw V4CBORFailure("registry_unresolved")
      }
      guard valid else { throw V4CBORFailure("domain_relation") }
    }
    let operation = try domainText(domain["operation"])
    var result = V4DomainOutput(label: label, input: ["tls-exporter", "sha256-raw"].contains(operation) ? content : label + content)
    if ["sha256", "sha256-raw", "hmac-sha256", "hkdf-expand", "hkdf-extract"].contains(operation), domain["output_length"].uint != 32 { throw V4CBORFailure("registry_unresolved") }
    switch operation {
    case "sha256", "sha256-raw": result.output = Data(SHA256.hash(data: result.input))
    case "hmac-sha256", "hkdf-expand":
      let key = try domainPart(spec["key"], args: args, context: context, cap: cap)
      // Single Expand block, no prior T and no extra Extract.
      let message = operation == "hkdf-expand" ? result.input + Data([1]) : result.input
      result.output = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    case "hkdf-extract":
      guard label.isEmpty, parts.isEmpty else { throw V4CBORFailure("registry_unresolved") }
      let salt = try domainPart(spec["salt"], args: args, context: context, cap: cap), ikm = try domainPart(spec["ikm"], args: args, context: context, cap: cap)
      result.salt = salt; result.ikm = ikm; result.output = Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: salt)))
    case "tls-exporter": result.outputLength = try v4RuleInteger(domain["output_length"])
    case "ed25519", "aead-aad", "noise-prologue": break
    default: throw V4CBORFailure("registry_unresolved")
    }
    return result
  }
}
