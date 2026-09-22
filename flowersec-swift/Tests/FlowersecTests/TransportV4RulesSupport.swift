import Foundation

// Generated rule traversal over shape-checked input; no authenticated authority.
extension V4ShapeReference {
  func selectedField(_ field: V4JSON, context: V4CBORContext) throws -> V4JSON {
    if field["type"].text == "context_variant" {
      guard let key = field["context"].text, let selected = context.selectors[key],
            let descriptor = field["cases"].object?[selected] else { throw V4CBORFailure("context_unresolved") }
      return descriptor
    }
    return field
  }

  func rulePath(_ name: String, _ value: V4CBORValue, _ path: String, context: V4CBORContext) throws -> V4CBORValue? {
    try pathField(.object(["type": .text("map"), "schema_ref": .text(name)]), value,
                  path.split(separator: ".", omittingEmptySubsequences: false)[...], context: context)
  }

  private func pathField(_ original: V4JSON, _ value: V4CBORValue, _ path: ArraySlice<Substring>, context: V4CBORContext) throws -> V4CBORValue? {
    guard let part = path.first else { return value }
    let field = try selectedField(original, context: context), rest = path.dropFirst()
    if ["array", "array<uint64>"].contains(field["type"].text ?? "") {
      guard let index = UInt64(part), case .array(let items) = value else { throw V4CBORFailure("unknown_rule_field") }
      guard index < UInt64(items.count) else { return nil }
      let child = field["type"].text == "array<uint64>" ? V4JSON.object(["type": .text("uint64")]) : field["items"]
      return try pathField(child, items[Int(index)], rest, context: context)
    }
    let name: String, mapValue: V4CBORValue
    if let embedded = field["encoded_schema_ref"].text {
      guard case .bytes(let raw) = value else { throw V4CBORFailure("unknown_rule_field") }
      name = embedded; mapValue = try decode(raw, schema: name, context: context, cap: UInt64(raw.count) + 1)
    } else {
      guard let schema = field["schema_ref"].text else { throw V4CBORFailure("unknown_rule_field") }
      name = schema; mapValue = value
    }
    let descriptor = try descriptor(name), context = try mapContext(descriptor, mapValue, original: context)
    guard let (key, child) = descriptor["fields"].object?.first(where: { $0.value["name"].text == String(part) }),
          let id = UInt64(key) else { throw V4CBORFailure("unknown_rule_field") }
    guard let childValue = mapValue.field(id) else { return nil }
    return try pathField(child, childValue, rest, context: context)
  }

  func walkRules(_ name: String, _ value: V4CBORValue, context: V4CBORContext,
                 check: (String, V4CBORValue, V4CBORContext) throws -> Void) throws {
    let descriptor = try descriptor(name), context = try mapContext(descriptor, value, original: context)
    guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
    for pair in pairs {
      guard case .uint(let id) = pair.key else { throw V4CBORFailure("field_id_type") }
      guard let field = descriptor["fields"].object?[String(id)] else { throw V4CBORFailure("unknown_field") }
      try walkField(field, pair.value, context: context, check: check)
    }
    try check(name, value, context)
  }

  private func walkField(_ original: V4JSON, _ value: V4CBORValue, context: V4CBORContext,
                         check: (String, V4CBORValue, V4CBORContext) throws -> Void) throws {
    let field = try selectedField(original, context: context)
    switch field["type"].text {
    case "map":
      guard let name = field["schema_ref"].text else { throw V4CBORFailure("registry_unresolved") }
      try walkRules(name, value, context: context, check: check)
    case "array":
      guard case .array(let items) = value else { throw V4CBORFailure("field_type") }
      for item in items { try walkField(field["items"], item, context: context, check: check) }
    case "text_map":
      guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
      for pair in pairs {
        guard case .text(let key) = pair.key else { throw V4CBORFailure("field_type") }
        let child: V4JSON
        if let entries = field["entries"].object {
          guard let entry = entries[key] else { throw V4CBORFailure("unknown_field") }; child = entry
        } else {
          guard let entry = field.object?["values"] else { throw V4CBORFailure("registry_unresolved") }; child = entry
        }
        try walkField(child, pair.value, context: context, check: check)
      }
    case "bytes":
      if let name = field["encoded_schema_ref"].text {
        guard case .bytes(let raw) = value else { throw V4CBORFailure("field_type") }
        if !(field["allow_empty"].bool == true && raw.isEmpty) {
          let nested = try decode(raw, schema: name, context: context, cap: UInt64(raw.count) + 1)
          try walkRules(name, nested, context: context, check: check)
        }
      }
    default: break
    }
  }
}

func v4RawEqual(_ value: V4CBORValue?, _ expected: V4JSON) -> Bool {
  switch value {
  case .uint(let n): if case .uint(let expected) = expected { return n == expected }; return false
  case .bool(let b): return expected.bool == b
  case .text(let s): return expected.text.map { Data($0.utf8) == Data(s.utf8) } ?? false
  default: return false
  }
}

func v4RuleInteger(_ value: V4JSON) throws -> UInt64 {
  guard let n = value.uint else { throw V4CBORFailure("rule_unresolved") }; return n
}

func v4RuleHex(_ text: String) throws -> Data {
  let bytes = Array(text.utf8)
  guard bytes.count.isMultiple(of: 2) else { throw V4CBORFailure("registry_unresolved") }
  return try Data(stride(from: 0, to: bytes.count, by: 2).map {
    guard let n = UInt8(String(decoding: bytes[$0...$0 + 1], as: UTF8.self), radix: 16) else { throw V4CBORFailure("registry_unresolved") }
    return n
  })
}
