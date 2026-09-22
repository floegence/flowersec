import Foundation

// Test-only generated field validation; variants, relations and authority are separate.
struct V4CBORContext: Equatable, Sendable {
  var limits: [String: UInt64] = [:]
  var selectors: [String: String] = [:]
}

extension V4CBORValue {
  func field(_ id: UInt64) -> V4CBORValue? {
    guard case .map(let pairs) = self else { return nil }
    return pairs.first { if case .uint(let key) = $0.key { return key == id }; return false }?.value
  }
}

struct V4ShapeReference: Sendable {
  let syntax: V4CBORReference
  let patterns: [String: NSRegularExpression]
  var registry: V4JSON { syntax.registry }

  init() throws {
    syntax = try V4CBORReference()
    patterns = try syntax.registry["field_registries"]["text_patterns"].object!.mapValues {
      try NSRegularExpression(pattern: $0.text!)
    }
  }

  func decode(_ input: Data, schema: String = "", context: V4CBORContext = .init(), cap: UInt64) throws -> V4CBORValue {
    let value = try syntax.decode(input, schema: schema, limits: context.limits, cap: cap).0.get()
    if !schema.isEmpty { try checkMap(schema, value, context: context) }
    return value
  }

  func descriptor(_ name: String) throws -> V4JSON {
    guard let map = registry["frame_maps"].object?[name] else { throw V4CBORFailure("unknown_schema") }
    return map
  }

  func fieldRegistry(_ name: String) throws -> V4JSON {
    guard let field = registry["field_registries"].object?[name] else { throw V4CBORFailure("registry_unresolved") }
    return field
  }

  func mapContext(_ map: V4JSON, _ value: V4CBORValue, original: V4CBORContext) throws -> V4CBORContext {
    var context = original
    for (selector, name) in map["context_fields"].object ?? [:] {
      guard let (key, field) = map["fields"].object?.first(where: { $0.value["name"].text == name.text }),
            let id = UInt64(key) else { throw V4CBORFailure("registry_unresolved") }
      guard let actual = value.field(id) else { throw V4CBORFailure("missing_field") }
      guard case .uint(let n) = actual else { throw V4CBORFailure("integer_type") }
      guard let label = field["enum"].object?.first(where: { $0.value.uint == n })?.key else { throw V4CBORFailure("context_unresolved") }
      // A containing discriminator affects only its descendants, never caller/siblings.
      context.selectors[selector] = label
    }
    return context
  }

  func checkMap(_ name: String, _ value: V4CBORValue, context: V4CBORContext) throws {
    let map = try descriptor(name)
    guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
    let context = try mapContext(map, value, original: context)
    for pair in pairs {
      guard case .uint(let id) = pair.key else { throw V4CBORFailure("field_id_type") }
      guard let field = map["fields"].object?[String(id)] else { throw V4CBORFailure("unknown_field") }
      try checkField(field, pair.value, context: context)
    }
    guard let required = map["required"].array else { throw V4CBORFailure("registry_unresolved") }
    for id in required {
      guard value.field(try integer(id)) != nil else { throw V4CBORFailure("missing_field") }
    }
    let count = UInt64(value.encoded().count)
    if let bound = map.object?["max_encoded_bytes"], count > (try integer(bound)) { throw V4CBORFailure("map_size") }
    if let exact = map.object?["encoded_bytes"], count != (try integer(exact)) { throw V4CBORFailure("map_size") }
    if let key = map["max_encoded_bytes_ref"].text {
      guard let bound = context.limits[key], bound > 0 else { throw V4CBORFailure("limit_unresolved") }
      guard count <= bound else { throw V4CBORFailure("map_size") }
    }
  }

  private func integer(_ value: V4JSON) throws -> UInt64 {
    guard let n = value.uint else { throw V4CBORFailure("registry_unresolved") }; return n
  }

  private func bounded(_ n: UInt64, _ field: V4JSON, min: String, max: String, exact: String? = nil, error: String) throws {
    if let bound = field.object?[min], n < (try integer(bound)) { throw V4CBORFailure(error) }
    if let bound = field.object?[max], n > (try integer(bound)) { throw V4CBORFailure(error) }
    if let key = exact, let bound = field.object?[key], n != (try integer(bound)) { throw V4CBORFailure(error) }
  }

  func checkField(_ field: V4JSON, _ value: V4CBORValue, context: V4CBORContext) throws {
    guard let kind = field["type"].text else { throw V4CBORFailure("schema_type_unresolved") }
    if kind == "context_variant" {
      guard let key = field["context"].text, let selected = context.selectors[key],
            let descriptor = field["cases"].object?[selected] else { throw V4CBORFailure("context_unresolved") }
      return try checkField(descriptor, value, context: context)
    }
    if kind == "uint64", field["nullable"].bool == true, case .null = value { return }
    switch kind {
    case "uint8", "uint16", "uint32", "uint64":
      guard case .uint(let n) = value else { throw V4CBORFailure("integer_type") }
      let width = Int(kind.dropFirst(4))!
      if width < 64, n >= UInt64(1) << width { throw V4CBORFailure("integer_range") }
      try bounded(n, field, min: "min", max: "max", error: "field_range")
      if let bits = field.object?["bitmask"], n & ~(try integer(bits)) != 0 { throw V4CBORFailure("unknown_bits") }
      if let exact = field.object?["const"], n != (try integer(exact)) { throw V4CBORFailure("constant_mismatch") }
      if let entries = field["enum"].object, !entries.values.contains(where: { $0.uint == n }) { throw V4CBORFailure("enum_value") }
      if let name = field["enum_ref"].text {
        guard let entries = try fieldRegistry(name).object else { throw V4CBORFailure("registry_unresolved") }
        let values = try entries.values.map { try integer($0.object?["code"] ?? $0) }
        guard values.contains(n) else { throw V4CBORFailure("enum_value") }
      }
    case "bytes", "text":
      let raw: Data
      switch (kind, value) {
      case ("bytes", .bytes(let bytes)): raw = bytes
      case ("text", .text(let text)): raw = Data(text.utf8)
      default: throw V4CBORFailure("field_type")
      }
      let n = UInt64(raw.count)
      try bounded(n, field, min: "min_bytes", max: "max_bytes", exact: "length", error: "field_length")
      if field["nonzero"].bool == true, raw.allSatisfy({ $0 == 0 }) { throw V4CBORFailure("field_nonzero") }
      if field["profile_public_key"].bool == true {
        guard let name = context.selectors["crypto_profile_id"],
              let profile = try fieldRegistry("crypto_profiles").object?[name] else { throw V4CBORFailure("context_unresolved") }
        guard n == (try integer(profile["dh_public_bytes"])) else { throw V4CBORFailure("field_length") }
        if profile["dh_algorithm"].uint == 1, raw.first != 4 { throw V4CBORFailure("field_prefix") }
      }
      if let exact = field.object?["const"] {
        guard let text = exact.text else { throw V4CBORFailure("registry_unresolved") }
        guard raw == Data(text.utf8) else { throw V4CBORFailure("constant_mismatch") }
      }
      if let name = field["const_ref"].text {
        guard let text = try fieldRegistry(name).text else { throw V4CBORFailure("registry_unresolved") }
        guard raw == Data(text.utf8) else { throw V4CBORFailure("constant_mismatch") }
      }
      if let name = field["pattern_ref"].text {
        guard let pattern = patterns[name] else { throw V4CBORFailure("pattern_unresolved") }
        guard let text = String(validating: raw, as: UTF8.self) else { throw V4CBORFailure("text_pattern") }
        let whole = NSRange(text.startIndex..<text.endIndex, in: text)
        guard pattern.firstMatch(in: text, range: whole)?.range == whole else { throw V4CBORFailure("text_pattern") }
      }
      if let name = field["text_enum_ref"].text {
        guard let text = String(validating: raw, as: UTF8.self),
              try fieldRegistry(name).object?[text] != nil else { throw V4CBORFailure("enum_value") }
      }
      if let prefix = field["forbidden_prefix"].text, raw.starts(with: prefix.utf8) { throw V4CBORFailure("reserved_namespace") }
      if let name = field["encoded_schema_ref"].text, !(field["allow_empty"].bool == true && raw.isEmpty) {
        _ = try decode(raw, schema: name, context: context, cap: n + 1)
      }
      if let name = field["max_ref"].text {
        guard let max = context.limits[name] else { throw V4CBORFailure("limit_unresolved") }
        guard n <= max else { throw V4CBORFailure("field_length") }
      }
    case "bool":
      guard case .bool(let actual) = value else { throw V4CBORFailure("field_type") }
      if let exact = field.object?["const"], exact.bool != actual { throw V4CBORFailure("field_equality") }
    case "map":
      guard let name = field["schema_ref"].text else { throw V4CBORFailure("registry_unresolved") }
      try checkMap(name, value, context: context)
    case "text_map":
      guard case .map(let pairs) = value else { throw V4CBORFailure("map_type") }
      guard field["min_items"].uint != nil, field["max_items"].uint != nil else { throw V4CBORFailure("schema_type_unresolved") }
      try bounded(UInt64(pairs.count), field, min: "min_items", max: "max_items", error: "map_length")
      for pair in pairs {
        try checkField(field["keys"], pair.key, context: context)
        guard case .text(let text) = pair.key else { throw V4CBORFailure("field_type") }
        let child: V4JSON
        if let entries = field["entries"].object {
          guard let entry = entries[text] else { throw V4CBORFailure("unknown_field") }; child = entry
        } else {
          guard let entry = field.object?["values"] else { throw V4CBORFailure("schema_type_unresolved") }; child = entry
        }
        try checkField(child, pair.value, context: context)
      }
      for key in field["entries"].object?.keys ?? Dictionary<String, V4JSON>().keys {
        guard pairs.contains(where: { if case .text(let text) = $0.key { return Data(text.utf8) == Data(key.utf8) }; return false }) else { throw V4CBORFailure("missing_field") }
      }
    case "array", "array<uint64>":
      guard case .array(let items) = value else { throw V4CBORFailure("field_type") }
      var max = try integer(field.object?["max_items"] ?? registry["encoding"]["ordinary_array_items"])
      if let name = field["max_items_ref"].text {
        guard let bound = context.limits[name], bound <= UInt32.max else { throw V4CBORFailure("limit_unresolved") }; max = bound
      }
      guard let min = field["min_items"].uint else { throw V4CBORFailure("schema_type_unresolved") }
      guard UInt64(items.count) >= min, UInt64(items.count) <= max else { throw V4CBORFailure("array_length") }
      for item in items {
        if kind == "array<uint64>" {
          guard case .uint = item else { throw V4CBORFailure("integer_type") }
        } else { try checkField(field["items"], item, context: context) }
      }
    default: throw V4CBORFailure("schema_type_unresolved")
    }
  }
}
