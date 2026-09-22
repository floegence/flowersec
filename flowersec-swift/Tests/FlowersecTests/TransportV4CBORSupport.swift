import Crypto
import Foundation
@testable import Flowersec

// Independent test-only syntax reference. No field semantics or live authority.
struct V4CBORFailure: Error, Equatable { let code: String; init(_ code: String) { self.code = code } }

indirect enum V4JSON: Decodable, Sendable {
  case uint(UInt64), text(String), bool(Bool), array([V4JSON]), object([String: V4JSON]), null

  init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer()
    if value.decodeNil() { self = .null }
    else if let v = try? value.decode(Bool.self) { self = .bool(v) }
    else if let v = try? value.decode(UInt64.self) { self = .uint(v) }
    else if let v = try? value.decode(String.self) { self = .text(v) }
    else if let v = try? value.decode([V4JSON].self) { self = .array(v) }
    else { self = .object(try value.decode([String: V4JSON].self)) }
  }

  subscript(_ key: String) -> V4JSON { object?[key] ?? .null }
  var object: [String: V4JSON]? { if case .object(let value) = self { return value }; return nil }
  var array: [V4JSON]? { if case .array(let value) = self { return value }; return nil }
  var text: String? { if case .text(let value) = self { return value }; return nil }
  var uint: UInt64? {
    if case .uint(let value) = self { return value }
    if case .text(let value) = self { return UInt64(value) }
    return nil
  }
  var bool: Bool? { if case .bool(let value) = self { return value }; return nil }
}

func v4Hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

// UAX #15 over hash-pinned Unicode 15.1 data, never host normalization tables.
struct V4NFC: Sendable {
  let classes: [UInt32: UInt8]
  let decompositions: [UInt32: [UInt32]]
  let compositions: [UInt64: UInt32]
  let ranges: [(UInt32, UInt32)]
  let conformanceSHA256: String

  init(path: String, hash: String) throws {
    guard path == "testdata/unicode15_1/normalization_generated.json" else { throw V4CBORFailure("unicode_path") }
    let data = try Data(contentsOf: packageRoot().appendingPathComponent(path))
    guard v4Hash(data) == hash else { throw V4CBORFailure("unicode_hash") }
    let table = try JSONDecoder().decode(V4JSON.self, from: data)
    guard table["unicode_version"].text == "15.1.0" else { throw V4CBORFailure("unicode_version") }
    classes = Dictionary(uniqueKeysWithValues: table["ccc"].array!.map { row in
      let row = row.array!; return (UInt32(row[0].uint!), UInt8(row[1].uint!))
    })
    decompositions = Dictionary(uniqueKeysWithValues: table["decompositions"].array!.map { row in
      let row = row.array!; return (UInt32(row[0].uint!), row[1].array!.map { UInt32($0.uint!) })
    })
    compositions = Dictionary(uniqueKeysWithValues: table["compositions"].array!.map { row in
      let row = row.array!; return ((row[0].uint! << 32) | row[1].uint!, UInt32(row[2].uint!))
    })
    ranges = table["assigned"].array!.map { row in
      let row = row.array!; return (UInt32(row[0].uint!), UInt32(row[1].uint!))
    }
    conformanceSHA256 = table["sources"]["NormalizationTest.txt"]["sha256"].text!
  }

  func assigned(_ cp: UInt32) -> Bool {
    var lo = 0, hi = ranges.count
    while lo < hi { let mid = lo + (hi - lo) / 2; if ranges[mid].1 < cp { lo = mid + 1 } else { hi = mid } }
    return lo < ranges.count && ranges[lo].0 <= cp
  }

  private func ccc(_ cp: UInt32) -> UInt8 { classes[cp] ?? 0 }

  private func decompose(_ cp: UInt32, into output: inout [UInt32]) {
    if (0xac00..<0xac00 + 11172).contains(cp) {
      let index = cp - 0xac00
      output.append(contentsOf: [0x1100 + index / 588, 0x1161 + index % 588 / 28])
      if index % 28 != 0 { output.append(0x11a7 + index % 28) }
    } else if let parts = decompositions[cp] {
      for part in parts { decompose(part, into: &output) }
    } else { output.append(cp) }
  }

  private func compose(_ a: UInt32, _ b: UInt32) -> UInt32? {
    if (0x1100..<0x1100 + 19).contains(a), (0x1161..<0x1161 + 21).contains(b) {
      return 0xac00 + ((a - 0x1100) * 21 + b - 0x1161) * 28
    }
    if (0xac00..<0xac00 + 11172).contains(a), (a - 0xac00) % 28 == 0, (0x11a8..<0x11a7 + 28).contains(b) {
      return a + b - 0x11a7
    }
    return compositions[(UInt64(a) << 32) | UInt64(b)]
  }

  func normalize(_ text: String) -> String {
    var scalars: [UInt32] = []
    for scalar in text.unicodeScalars { decompose(scalar.value, into: &scalars) }
    var start = 0
    while start < scalars.count {
      if ccc(scalars[start]) == 0 { start += 1; continue }
      var end = start + 1
      while end < scalars.count && ccc(scalars[end]) != 0 { end += 1 }
      // Explicit original-index tie break preserves equal-class blocking.
      let sorted = scalars[start..<end].enumerated().sorted {
        let a = ccc($0.element), b = ccc($1.element)
        return a < b || a == b && $0.offset < $1.offset
      }.map(\.element)
      scalars.replaceSubrange(start..<end, with: sorted)
      start = end
    }
    var output: [UInt32] = [], starter: Int?, previous: UInt8 = 0
    for cp in scalars {
      let current = ccc(cp)
      if let index = starter, previous == 0 || previous < current, let combined = compose(output[index], cp) {
        output[index] = combined
        continue
      }
      if current == 0 { starter = output.count }
      output.append(cp)
      previous = current
    }
    return String(String.UnicodeScalarView(output.map { UnicodeScalar($0)! }))
  }
}

indirect enum V4CBORValue: Sendable {
  struct Pair: Sendable { let key: V4CBORValue; var value: V4CBORValue }
  case uint(UInt64), bytes(Data), text(String), array([V4CBORValue]), map([Pair]), bool(Bool), null

  static func head(_ major: UInt8, _ n: UInt64) -> Data {
    if n < 24 { return Data([major << 5 | UInt8(n)]) }
    let (ai, width): (UInt8, Int) = n <= 255 ? (24, 1) : n <= 65535 ? (25, 2) : n <= 0xffffffff ? (26, 4) : (27, 8)
    var big = n.bigEndian
    return Data([major << 5 | ai]) + withUnsafeBytes(of: &big) { Data($0.suffix(width)) }
  }

  func encoded() -> Data {
    switch self {
    case .uint(let n): return Self.head(0, n)
    case .bytes(let bytes): return Self.head(2, UInt64(bytes.count)) + bytes
    case .text(let text): let bytes = Data(text.utf8); return Self.head(3, UInt64(bytes.count)) + bytes
    case .bool(let value): return Data([value ? 0xf5 : 0xf4])
    case .null: return Data([0xf6])
    case .array(let values): return values.reduce(into: Self.head(4, UInt64(values.count))) { $0.append($1.encoded()) }
    case .map(let pairs): return pairs.reduce(into: Self.head(5, UInt64(pairs.count))) { $0.append($1.key.encoded()); $0.append($1.value.encoded()) }
    }
  }
}

struct V4CBORReference: Sendable {
  let registry: V4JSON
  let nfc: V4NFC

  init() throws {
    registry = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.cborRegistryJSON.utf8))
    let source = registry["unicode"]["nfc_data"]
    nfc = try V4NFC(path: source["path"].text!, hash: source["sha256"].text!)
  }

  func decode(_ input: Data, schema: String = "", limits: [String: UInt64] = [:], cap: UInt64) -> (Result<V4CBORValue, V4CBORFailure>, Int) {
    var nodes = 0
    do { return (.success(try document(input, schema: schema, limits: limits, cap: cap, nodes: &nodes)), nodes) }
    catch let failure as V4CBORFailure { return (.failure(failure), nodes) }
    catch { return (.failure(V4CBORFailure("reference_error")), nodes) }
  }

  fileprivate func documentField(length: UInt64, schema: String, limits: [String: UInt64], cap: UInt64) throws -> V4JSON {
    guard cap > 0 else { throw V4CBORFailure("limit_unresolved") }
    var cap = cap, field = V4JSON.null
    if !schema.isEmpty {
      guard let map = registry["frame_maps"].object?[schema] else { throw V4CBORFailure("unknown_schema") }
      if let bound = map["max_encoded_bytes"].uint { cap = min(cap, bound) }
      if let name = map["max_encoded_bytes_ref"].text {
        guard let bound = limits[name], bound > 0 else { throw V4CBORFailure("limit_unresolved") }
        cap = min(cap, bound)
      }
      field = .object(["type": .text("map"), "schema_ref": .text(schema)])
    }
    // No parsed nodes or input copy before the explicit caller/schema cap.
    guard length <= cap else { throw V4CBORFailure("map_size") }
    return field
  }

  fileprivate func document(_ input: Data, schema: String, limits: [String: UInt64], cap: UInt64, nodes: inout Int) throws -> V4CBORValue {
    let field = try documentField(length: UInt64(input.count), schema: schema, limits: limits, cap: cap)
    var reader = V4CBORReader(reference: self, input: input, limits: limits)
    let value = try reader.item(depth: 0, field: field, nodes: &nodes)
    guard reader.offset == input.count else { throw V4CBORFailure("trailing_bytes") }
    return value
  }
}

private struct V4CBORReader {
  let reference: V4CBORReference
  let input: Data
  let limits: [String: UInt64]
  var offset = 0

  mutating func take(_ n: UInt64) throws -> Data {
    guard n <= UInt64(input.count - offset) else { throw V4CBORFailure("truncated") }
    let start = input.startIndex + offset
    offset += Int(n)
    return input.subdata(in: start..<input.startIndex + offset)
  }

  mutating func item(depth: UInt64, field: V4JSON, nodes: inout Int) throws -> V4CBORValue {
    let policy = reference.registry["encoding"]
    guard depth <= policy["max_depth"].uint! else { throw V4CBORFailure("depth_limit") }
    let byte = try take(1)[0], major = byte >> 5, ai = byte & 31
    guard ai != 31 else { throw V4CBORFailure("indefinite_length") }
    if major == 7 {
      let value: V4CBORValue
      switch ai {
      case 20: value = .bool(false)
      case 21: value = .bool(true)
      case 22 where field["type"].text == "uint64" && field["nullable"].bool == true: value = .null
      default: throw V4CBORFailure("unsupported_type")
      }
      nodes += 1
      return value
    }
    guard [0, 2, 3, 4, 5].contains(major) else { throw V4CBORFailure("unsupported_type") }
    guard ai <= 27 else { throw V4CBORFailure("invalid_header") }
    let n: UInt64
    if ai < 24 { n = UInt64(ai) }
    else {
      n = try take(UInt64(1) << (ai - 24)).reduce(0) { $0 << 8 | UInt64($1) }
      guard n >= [24, 256, 65536, 4294967296][Int(ai - 24)] else { throw V4CBORFailure("non_shortest_integer") }
    }
    switch major {
    case 0: nodes += 1; return .uint(n)
    case 2, 3:
      if major == 2, let schema = field["encoded_schema_ref"].text, !(field["allow_empty"].bool == true && n == 0) {
        // Resolve the embedded document's own cap from its declared length
        // before take() copies any of its payload. No untrusted n + 1 overflow.
        _ = try reference.documentField(length: n, schema: schema, limits: limits, cap: max(n, 1))
      }
      let raw = try take(n)
      let value: V4CBORValue
      if major == 3 {
        // Standard-library validation preserves a leading U+FEFF; Foundation's
        // encoding initializer may consume those signed bytes as a BOM.
        guard let text = String(validating: raw, as: UTF8.self) else { throw V4CBORFailure("invalid_utf8") }
        guard text.unicodeScalars.allSatisfy({ reference.nfc.assigned($0.value) }) else { throw V4CBORFailure("unassigned_code_point") }
        // Swift String equality is canonically equivalent, not byte equality.
        guard Data(reference.nfc.normalize(text).utf8) == raw else { throw V4CBORFailure("non_canonical_text") }
        value = .text(text)
      } else {
        if let schema = field["encoded_schema_ref"].text, !(field["allow_empty"].bool == true && raw.isEmpty) {
          _ = try reference.document(raw, schema: schema, limits: limits, cap: UInt64(raw.count) + 1, nodes: &nodes)
        }
        value = .bytes(raw)
      }
      nodes += 1
      return value
    case 4:
      var cap = policy["ordinary_array_items"].uint!
      if let name = field["max_items_ref"].text {
        guard let bound = limits[name], bound <= UInt32.max else { throw V4CBORFailure("limit_unresolved") }
        cap = bound
      }
      guard n <= cap else { throw V4CBORFailure("array_limit") }
      guard n <= UInt64(input.count - offset) else { throw V4CBORFailure("truncated") }
      nodes += 1
      var items: [V4CBORValue] = []; items.reserveCapacity(Int(n))
      for _ in 0..<n { items.append(try item(depth: depth + 1, field: field["items"], nodes: &nodes)) }
      return .array(items)
    case 5:
      guard n <= policy["max_map_entries"].uint! else { throw V4CBORFailure("map_limit") }
      guard n <= UInt64((input.count - offset) / 2) else { throw V4CBORFailure("truncated") }
      nodes += 1
      var pairs: [V4CBORValue.Pair] = [], seen = Set<Data>(), previous: Data?
      pairs.reserveCapacity(Int(n))
      let textMap = field["type"].text == "text_map"
      for _ in 0..<n {
        let start = offset, key = try item(depth: depth + 1, field: .null, nodes: &nodes)
        let child: V4JSON
        switch key {
        case .uint(let id) where !textMap && id <= policy["max_field_id"].uint!:
          child = reference.registry["frame_maps"][field["schema_ref"].text ?? ""]["fields"][String(id)]
        case .text(let text) where textMap:
          child = field["entries"].object?[text] ?? field["values"]
        default: throw V4CBORFailure("field_id_type")
        }
        let bytes = input.subdata(in: input.startIndex + start..<input.startIndex + offset)
        guard seen.insert(bytes).inserted else { throw V4CBORFailure("duplicate_key") }
        if let previous, previous.count > bytes.count || previous.count == bytes.count && !previous.lexicographicallyPrecedes(bytes) {
          throw V4CBORFailure("map_order")
        }
        previous = bytes
        pairs.append(.init(key: key, value: try item(depth: depth + 1, field: child, nodes: &nodes)))
      }
      return .map(pairs)
    default: throw V4CBORFailure("unsupported_type")
    }
  }
}
