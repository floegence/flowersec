import Crypto
import Foundation
@testable import Flowersec

// Stateless map relations over generated rules, not signature/trust verification.
extension V4ShapeReference {
  private static let domains = try! JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.domainRegistryJSON.utf8))

  func relations(_ input: Data, schema: String = "", context: V4CBORContext = .init(), cap: UInt64) throws -> V4CBORValue {
    let value = try decode(input, schema: schema, context: context, cap: cap)
    if !schema.isEmpty {
      try walkRules(schema, value, context: context) { name, value, context in
        try checkVariants(name, value, context)
        guard let rules = registry["relation_rules"].object?[name] else { return }
        guard let rules = rules.array else { throw V4CBORFailure("rule_unresolved") }
        for rule in rules {
          try validateRelation(rule)
          if try ruleApplies(name, value, when: rule.object?["when"], context: context) {
            try checkRelation(name, value, rule, context: context)
          }
        }
      }
    }
    return value
  }

  private func validateRelation(_ rule: V4JSON) throws {
    let keys: Set<String> = ["op", "field", "left", "right", "profile", "algorithm", "registry", "source", "domain", "when", "fields", "pairs", "rows", "max", "item_field_id", "item_fields", "item_field", "value", "feature", "present", "code_field", "target_scope_field", "stream_id_field", "retry_after_field", "selectors"]
    guard let object = rule.object, Set(object.keys).isSubset(of: keys) else { throw V4CBORFailure("rule_unresolved") }
    for selector in rule["selectors"].array ?? [] {
      guard let selector = selector.object, Set(selector.keys).isSubset(of: ["field", "context"]) else { throw V4CBORFailure("rule_unresolved") }
    }
  }

  private func checkRelation(_ name: String, _ value: V4CBORValue, _ rule: V4JSON, context: V4CBORContext) throws {
    func text(_ key: String) throws -> String {
      guard let text = rule[key].text else { throw V4CBORFailure("rule_unresolved") }; return text
    }
    func get(_ path: String) throws -> V4CBORValue? { try rulePath(name, value, path, context: context) }
    func field(_ key: String) throws -> V4CBORValue? { try get(text(key)) }
    let op = try text("op")
    switch op {
    case "is_null":
      guard case .some(.null) = try field("field") else { throw V4CBORFailure("field_null") }
    case "at_least_one":
      guard let fields = rule["fields"].array else { throw V4CBORFailure("rule_unresolved") }
      var found = false
      for path in fields { if try get(path.text!) != nil { found = true } }
      guard found else { throw V4CBORFailure("field_presence") }
    case "equal", "equal_if_present", "not_equal":
      let a = try field("left"), b = try field("right")
      if op == "equal_if_present", a == nil || b == nil { return }
      let same = a?.encoded() == b?.encoded()
      if op == "not_equal" {
        guard !same else { throw V4CBORFailure("field_distinctness") }
      } else if !same { throw V4CBORFailure("field_equality") }
    case "less_than", "less_or_equal", "max_difference", "bit_subset":
      let a = try unsigned(field("left")), b = try unsigned(field("right"))
      switch op {
      case "less_than" where a >= b, "less_or_equal" where a > b: throw V4CBORFailure("field_order")
      case "max_difference":
        let limit = try v4RuleInteger(rule["max"])
        guard a <= b, b - a <= limit else { throw V4CBORFailure("field_duration") }
      case "bit_subset" where a & ~b != 0: throw V4CBORFailure("feature_subset")
      default: break
      }
    case "allowed_pairs", "allowed_tuples":
      let fields = op == "allowed_pairs" ? [try text("left"), try text("right")] : (rule["fields"].array ?? []).compactMap(\.text)
      guard let rows = rule[op == "allowed_pairs" ? "pairs" : "rows"].array else { throw V4CBORFailure("rule_unresolved") }
      var found = false
      for row in rows {
        guard let entries = row.array, entries.count == fields.count else { throw V4CBORFailure("rule_unresolved") }
        var matches = true
        for (path, n) in zip(fields, entries) { if try !v4RawEqual(get(path), n) { matches = false } }
        if matches { found = true }
      }
      guard found else { throw V4CBORFailure(op == "allowed_pairs" ? "field_pair" : "field_tuple") }
    case "feature_bit":
      let bit = try v4RuleInteger(fieldRegistry("feature_registry")[text("feature")]["bit"])
      guard bit < 64, let present = rule["present"].bool else { throw V4CBORFailure("registry_unresolved") }
      guard try (unsigned(field("field")) & (UInt64(1) << bit) != 0) == present else { throw V4CBORFailure("feature_policy") }
    case "profile_algorithm":
      guard case .text(let profile) = try field("profile") else { throw V4CBORFailure("field_type") }
      guard try unsigned(field("algorithm")) == v4RuleInteger(fieldRegistry("crypto_profiles")[profile]["dh_algorithm"]) else { throw V4CBORFailure("profile_algorithm") }
    case "error_scope":
      let code = try field("code_field")
      guard let label = try fieldRegistry("error_codes").object?.first(where: { v4RawEqual(code, $0.value) })?.key else { throw V4CBORFailure("enum_value") }
      let policy = try fieldRegistry("error_code_metadata")[label], target = try field("target_scope_field"), stream = try field("stream_id_field")
      guard case .uint(let n) = target else { throw V4CBORFailure("error_scope") }
      switch policy["scope"].text {
      case "session": guard n == 0, stream == nil else { throw V4CBORFailure("error_scope") }
      case "stream": guard n > 0, stream?.encoded() == V4CBORValue.uint(n).encoded() else { throw V4CBORFailure("error_scope") }
      default: throw V4CBORFailure("registry_unresolved")
      }
      guard let retryable = policy["retryable"].bool else { throw V4CBORFailure("registry_unresolved") }
      if !retryable, try field("retry_after_field") != nil { throw V4CBORFailure("retry_after_forbidden") }
    case "registry_tuple":
      var tuple = try fieldRegistry(text("registry"))
      guard let selectors = rule["selectors"].array, let fields = rule["fields"].array else { throw V4CBORFailure("rule_unresolved") }
      for selector in selectors {
        let key: String
        if let contextName = selector["context"].text {
          guard let selected = context.selectors[contextName] else { throw V4CBORFailure("context_unresolved") }; key = selected
        } else {
          guard let path = selector["field"].text else { throw V4CBORFailure("rule_unresolved") }
          let actual = try get(path)
          guard let field = try descriptor(name)["fields"].object?.values.first(where: { $0["name"].text == path }),
                let label = field["enum"].object?.first(where: { v4RawEqual(actual, $0.value) })?.key else { throw V4CBORFailure("context_unresolved") }
          key = label
        }
        guard let selected = tuple.object?[key] else { throw V4CBORFailure("context_unresolved") }; tuple = selected
      }
      for path in fields {
        guard let path = path.text, let expected = tuple.object?[path] else { throw V4CBORFailure("registry_unresolved") }
        guard try v4RawEqual(get(path), expected) else { throw V4CBORFailure("carrier_tuple") }
      }
    case "map_digest":
      try mapDigest(text("domain"), source: field("source"), target: field("field"))
    case "unique_by", "increasing_tuple", "ordinal_indices", "increasing", "increasing_bytes", "increasing_cbor", "increasing_scopes", "exclusive_item":
      try arrayRelation(name, value, rule, context: context)
    default: throw V4CBORFailure("rule_unresolved")
    }
  }

  private func unsigned(_ value: V4CBORValue?) throws -> UInt64 {
    guard case .uint(let n) = value else { throw V4CBORFailure("integer_type") }; return n
  }

  private func compare(_ a: V4CBORValue, _ b: V4CBORValue) throws -> Int {
    switch (a, b) {
    case (.uint(let a), .uint(let b)): return a == b ? 0 : a < b ? -1 : 1
    case (.bytes(let a), .bytes(let b)): return a == b ? 0 : a.lexicographicallyPrecedes(b) ? -1 : 1
    default: throw V4CBORFailure("field_type")
    }
  }

  private func mapDigest(_ name: String, source: V4CBORValue?, target: V4CBORValue?) throws {
    guard case .bytes(let expected) = target else { throw V4CBORFailure("field_type") }
    let raw: Data
    switch source {
    case .bytes(let bytes): raw = bytes
    case .map: raw = source!.encoded()
    default: throw V4CBORFailure("field_type")
    }
    guard let domain = Self.domains.array?.first(where: { $0["name"].text == name }) else { throw V4CBORFailure("registry_unresolved") }
    guard let parts = domain["input_schema"]["parts"].array, domain["operation"].text == "sha256",
          domain["output_length"].uint == 32, parts.count == 1, parts[0]["encoding"].text == "lp-map",
          parts[0]["projection"].text == "full" else { throw V4CBORFailure("domain_projection") }
    guard let label = domain["label_bytes"].text else { throw V4CBORFailure("registry_unresolved") }
    guard let length = UInt32(exactly: raw.count) else { throw V4CBORFailure("map_size") }
    var big = length.bigEndian
    let input = try v4RuleHex(label) + withUnsafeBytes(of: &big) { Data($0) } + raw
    // Complete embedded bytes retain the original signature in the digest.
    guard Data(SHA256.hash(data: input)) == expected else { throw V4CBORFailure("map_digest_mismatch") }
  }

  private func arrayRelation(_ name: String, _ value: V4CBORValue, _ rule: V4JSON, context: V4CBORContext) throws {
    guard let op = rule["op"].text, let path = rule["field"].text else { throw V4CBORFailure("rule_unresolved") }
    func get(_ path: String) throws -> V4CBORValue? { try rulePath(name, value, path, context: context) }
    let array = try get(path)
    if array == nil, ["increasing_bytes", "increasing_cbor"].contains(op) { return }
    guard case .array(let items) = array else { throw V4CBORFailure("field_type") }
    let scopeMax = op == "increasing_scopes" ? try v4RuleInteger(fieldRegistry("resource_caps")["scope_id"]["max"]) : 0
    var previous: [V4CBORValue] = [], previousBytes = Data(), seen = Set<Data>()
    for (index, item) in items.enumerated() {
      let current: V4CBORValue
      if let id = rule["item_field_id"].uint {
        guard let member = item.field(id) else { throw V4CBORFailure("unknown_rule_field") }; current = member
      } else { current = item }
      let base = "\(path).\(index)."
      switch op {
      case "unique_by", "increasing_tuple":
        guard let fields = rule["item_fields"].array else { throw V4CBORFailure("rule_unresolved") }
        let tuple = try fields.map { field -> V4CBORValue in
          guard let field = field.text, let member = try get(base + field) else { throw V4CBORFailure("unknown_rule_field") }; return member
        }
        if op == "unique_by" {
          guard seen.insert(V4CBORValue.array(tuple).encoded()).inserted else { throw V4CBORFailure("item_identity") }
        } else if index > 0 {
          var order = 0
          for (a, b) in zip(previous, tuple) { order = try compare(a, b); if order != 0 { break } }
          guard order < 0 else { throw V4CBORFailure("item_order") }
        }
        previous = tuple
      case "ordinal_indices":
        guard case .uint(let n) = current, n == UInt64(index) else { throw V4CBORFailure("item_index") }
      case "increasing", "increasing_scopes":
        guard case .uint(let n) = current else { throw V4CBORFailure("integer_type") }
        let unordered = try index > 0 && compare(previous[0], current) >= 0
        if op == "increasing_scopes" {
          guard n > 0, n <= scopeMax, !unordered else { throw V4CBORFailure("scope_order") }
        } else if unordered { throw V4CBORFailure("item_order") }
        previous = [current]
      case "increasing_bytes", "increasing_cbor":
        let currentBytes: Data
        if op == "increasing_cbor" { currentBytes = current.encoded() }
        else { guard case .bytes(let raw) = current else { throw V4CBORFailure("field_type") }; currentBytes = raw }
        // Array ordering is bytewise; map-key length-first ordering is different.
        if index > 0, !previousBytes.lexicographicallyPrecedes(currentBytes) { throw V4CBORFailure("item_order") }
        previousBytes = currentBytes
      case "exclusive_item":
        guard let field = rule["item_field"].text else { throw V4CBORFailure("rule_unresolved") }
        if try v4RawEqual(get(base + field), rule["value"]), items.count != 1 { throw V4CBORFailure("item_exclusive") }
      default: throw V4CBORFailure("rule_unresolved")
      }
    }
  }
}
