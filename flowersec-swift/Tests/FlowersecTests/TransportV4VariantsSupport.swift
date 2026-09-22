import Foundation

// Stateless closed variants. This creates no live reservations or authority.
extension V4ShapeReference {
  func variants(_ input: Data, schema: String = "", context: V4CBORContext = .init(), cap: UInt64) throws -> V4CBORValue {
    let value = try decode(input, schema: schema, context: context, cap: cap)
    if !schema.isEmpty { try walkRules(schema, value, context: context, check: checkVariants) }
    return value
  }

  func ruleApplies(_ name: String, _ value: V4CBORValue, when: V4JSON?, context: V4CBORContext) throws -> Bool {
    guard let when else { return true }
    if let selector = when["context"].text {
      guard let text = context.selectors[selector] else { throw V4CBORFailure("context_unresolved") }
      return when["value"].text == text
    }
    guard let field = when["field"].text else { throw V4CBORFailure("rule_unresolved") }
    return try v4RawEqual(rulePath(name, value, field, context: context), when["value"])
  }

  private func validateBranch(_ branch: V4JSON) throws {
    let keys: Set<String> = ["absent", "required", "constants", "enum_values", "equal", "less_or_equal", "nonzero", "zero_bytes", "byte_lengths", "byte_prefixes", "registered"]
    guard let object = branch.object, Set(object.keys).isSubset(of: keys) else { throw V4CBORFailure("rule_unresolved") }
    for key in ["absent", "required", "nonzero", "zero_bytes"] {
      if let values = object[key] {
        guard let values = values.array, values.allSatisfy({ $0.text != nil }) else { throw V4CBORFailure("rule_unresolved") }
      }
    }
    for key in ["equal", "less_or_equal"] {
      if let values = object[key] {
        guard let values = values.array, values.allSatisfy({ $0.array?.count == 2 && $0.array!.allSatisfy({ $0.text != nil }) }) else { throw V4CBORFailure("rule_unresolved") }
      }
    }
    for key in ["constants", "enum_values", "byte_lengths", "byte_prefixes", "registered"] {
      if let values = object[key], values.object == nil { throw V4CBORFailure("rule_unresolved") }
    }
    for values in branch["enum_values"].object?.values ?? Dictionary<String, V4JSON>().values {
      guard let values = values.array, values.allSatisfy({ if case .uint = $0 { return true }; return false }) else { throw V4CBORFailure("rule_unresolved") }
    }
    for length in branch["byte_lengths"].object?.values ?? Dictionary<String, V4JSON>().values {
      guard case .uint = length else { throw V4CBORFailure("rule_unresolved") }
    }
    for key in ["byte_prefixes", "registered"] {
      for item in branch[key].object?.values ?? Dictionary<String, V4JSON>().values {
        guard item.text != nil else { throw V4CBORFailure("rule_unresolved") }
      }
    }
  }

  func checkVariants(_ name: String, _ value: V4CBORValue, _ context: V4CBORContext) throws {
    guard let rules = registry["variant_rules"].object?[name] else { return }
    guard let rules = rules.array else { throw V4CBORFailure("rule_unresolved") }
    let metadata: Set<String> = ["op", "when", "field", "min", "max", "discriminator", "value", "context", "cases"]
    for rule in rules {
      guard let object = rule.object else { throw V4CBORFailure("rule_unresolved") }
      let branch = V4JSON.object(object.filter { !metadata.contains($0.key) })
      try validateBranch(branch)
      // Validate all branch instructions even when this input selects another case.
      for item in rule["cases"].object?.values ?? Dictionary<String, V4JSON>().values { try validateBranch(item) }
      guard try ruleApplies(name, value, when: object["when"], context: context) else { continue }
      switch rule["op"].text {
      case "range":
        guard let path = rule["field"].text,
              case .uint(let n) = try rulePath(name, value, path, context: context) else { throw V4CBORFailure("field_range") }
        guard n >= (try v4RuleInteger(rule["min"])), n <= (try v4RuleInteger(rule["max"])) else { throw V4CBORFailure("field_range") }
      case "variant":
        guard let path = rule["discriminator"].text else { throw V4CBORFailure("rule_unresolved") }
        if try v4RawEqual(rulePath(name, value, path, context: context), rule["value"]) { try checkBranch(name, value, branch, context: context) }
      case "context_variant":
        guard let selector = rule["context"].text, let selected = context.selectors[selector],
              let branch = rule["cases"].object?[selected] else { throw V4CBORFailure("context_unresolved") }
        try checkBranch(name, value, branch, context: context)
      default: throw V4CBORFailure("rule_unresolved")
      }
    }
  }

  private func checkBranch(_ name: String, _ value: V4CBORValue, _ branch: V4JSON, context: V4CBORContext) throws {
    func get(_ path: String) throws -> V4CBORValue? { try rulePath(name, value, path, context: context) }
    for path in branch["absent"].array ?? [] { if try get(path.text!) != nil { throw V4CBORFailure("variant_absent") } }
    for path in branch["required"].array ?? [] { if try get(path.text!) == nil { throw V4CBORFailure("variant_required") } }
    for (path, constant) in branch["constants"].object ?? [:] {
      guard try v4RawEqual(get(path), constant) else { throw V4CBORFailure("variant_constant") }
    }
    for (path, allowed) in branch["enum_values"].object ?? [:] {
      guard case .uint(let n) = try get(path), allowed.array!.contains(where: { $0.uint == n }) else { throw V4CBORFailure("enum_value") }
    }
    for pair in branch["equal"].array ?? [] {
      let paths = pair.array!
      guard try get(paths[0].text!)?.encoded() == get(paths[1].text!)?.encoded() else { throw V4CBORFailure("field_equality") }
    }
    for pair in branch["less_or_equal"].array ?? [] {
      let paths = pair.array!
      guard case .uint(let a) = try get(paths[0].text!), case .uint(let b) = try get(paths[1].text!), a <= b else { throw V4CBORFailure("field_order") }
    }
    for path in branch["nonzero"].array ?? [] {
      switch try get(path.text!) {
      case .uint(let n) where n > 0: break
      case .bytes(let raw) where raw.contains(where: { $0 != 0 }): break
      default: throw V4CBORFailure("variant_nonzero")
      }
    }
    for path in branch["zero_bytes"].array ?? [] {
      guard case .bytes(let raw) = try get(path.text!), raw.allSatisfy({ $0 == 0 }) else { throw V4CBORFailure("variant_zero_bytes") }
    }
    for (path, length) in branch["byte_lengths"].object ?? [:] {
      guard case .bytes(let raw) = try get(path), UInt64(raw.count) == length.uint! else { throw V4CBORFailure("field_length") }
    }
    for (path, prefix) in branch["byte_prefixes"].object ?? [:] {
      let prefix = try v4RuleHex(prefix.text!)
      guard case .bytes(let raw) = try get(path), raw.starts(with: prefix) else { throw V4CBORFailure("field_prefix") }
    }
    for (path, registryName) in branch["registered"].object ?? [:] {
      guard case .uint(let n) = try get(path) else { throw V4CBORFailure("enum_value") }
      guard let entries = try fieldRegistry(registryName.text!).object else { throw V4CBORFailure("registry_unresolved") }
      let allowed = try entries.values.map { try v4RuleInteger($0.object?["code"] ?? $0) }
      guard allowed.contains(n) else { throw V4CBORFailure("enum_value") }
    }
  }
}
