import Foundation

// Independent test-only Unicode 15.1 UTS46/IDNA2008; no host mapping tables.
struct V4IDNA: Sendable {
  struct Property: Sendable { let first: UInt32; let last: UInt32; let kind: String; let mapped: [UInt32] }
  let nfc: V4NFC
  let tables: [String: [Property]]
  let conformanceSHA256: String

  init(syntax: V4CBORReference) throws {
    let unicode = syntax.registry["unicode"], source = unicode["idna_data"]
    guard source["path"].text == "testdata/unicode15_1/idna_generated.json" else { throw V4CBORFailure("idna_path") }
    let raw = try Data(contentsOf: packageRoot().appendingPathComponent(source["path"].text!))
    guard v4Hash(raw) == source["sha256"].text else { throw V4CBORFailure("idna_hash") }
    let data = try JSONDecoder().decode(V4JSON.self, from: raw)
    guard data["unicode_version"].text == "15.1.0", data["uts46_revision"].uint == 31,
          data["nfc_data_sha256"].text == unicode["nfc_data"]["sha256"].text else { throw V4CBORFailure("idna_version") }
    nfc = syntax.nfc
    var tables: [String: [Property]] = [:]
    for name in ["mapping", "classes", "categories", "bidi", "ccc", "joining", "scripts"] {
      let rows = data[name].array!.map { row -> Property in
        let row = row.array!; precondition((3...4).contains(row.count))
        return Property(first: UInt32(row[0].uint!), last: UInt32(row[1].uint!),
                        kind: row[2].text ?? String(row[2].uint!), mapped: row.count == 4 ? row[3].array!.map { UInt32($0.uint!) } : [])
      }
      for (index, row) in rows.enumerated() {
        precondition(row.first <= row.last && (index == 0 || rows[index - 1].last < row.first))
      }
      tables[name] = rows
    }
    self.tables = tables
    conformanceSHA256 = data["sources"]["IdnaTestV2.txt"]["sha256"].text!
  }

  private func lookup(_ table: String, _ cp: UInt32) -> Property? {
    let rows = tables[table]!
    var low = 0, high = rows.count
    while low < high { let mid = low + (high - low) / 2; if rows[mid].last < cp { low = mid + 1 } else { high = mid } }
    return low < rows.count && rows[low].first <= cp ? rows[low] : nil
  }
  private func prop(_ table: String, _ cp: UInt32) -> String { lookup(table, cp)?.kind ?? "" }

  private func contextJ(_ label: [UInt32], _ index: Int) -> Bool {
    if index > 0, prop("ccc", label[index - 1]) == "9" { return true }
    if label[index] == 0x200d { return false }
    let left = label[..<index].reversed().first { prop("joining", $0) != "T" }
    let right = label[(index + 1)...].first { prop("joining", $0) != "T" }
    return left.map { ["L", "D"].contains(prop("joining", $0)) } == true && right.map { ["R", "D"].contains(prop("joining", $0)) } == true
  }

  private func contextO(_ label: [UInt32], _ index: Int) -> Bool {
    switch label[index] {
    case 0xb7: return index > 0 && index + 1 < label.count && label[index - 1] == 0x6c && label[index + 1] == 0x6c
    case 0x375: return index + 1 < label.count && prop("scripts", label[index + 1]) == "Greek"
    case 0x5f3, 0x5f4: return index > 0 && prop("scripts", label[index - 1]) == "Hebrew"
    case 0x30fb: return label.contains { ["Hiragana", "Katakana", "Han"].contains(prop("scripts", $0)) }
    case 0x660...0x669: return !label.contains { (0x6f0...0x6f9).contains($0) }
    case 0x6f0...0x6f9: return !label.contains { (0x660...0x669).contains($0) }
    default: return false
    }
  }

  private func bidi(_ label: [UInt32]) throws {
    guard let cp = label.first else { throw V4CBORFailure("idna_empty_label") }
    let first = prop("bidi", cp), rtl = ["R", "AL"].contains(first)
    guard rtl || first == "L" else { throw V4CBORFailure("idna_bidi_start") }
    var last = "", arabic = false, european = false
    for cp in label {
      let direction = prop("bidi", cp)
      let common = ["EN", "ES", "CS", "ET", "ON", "BN", "NSM"].contains(direction)
      guard common || (rtl ? ["R", "AL", "AN"].contains(direction) : direction == "L") else { throw V4CBORFailure("idna_bidi_character") }
      if direction != "NSM" { last = direction }
      arabic = arabic || direction == "AN"; european = european || direction == "EN"
    }
    guard (rtl ? ["R", "AL", "EN", "AN"] : ["L", "EN"]).contains(last) else { throw V4CBORFailure("idna_bidi_end") }
    guard !(rtl && arabic && european) else { throw V4CBORFailure("idna_bidi_digits") }
  }

  private func validUTSLabel(_ label: [UInt32]) throws {
    guard !label.isEmpty else { throw V4CBORFailure("idna_empty_label") }
    let text = v4ScalarText(label)
    guard Data(nfc.normalize(text).utf8) == Data(text.utf8) else { throw V4CBORFailure("idna_nfc") }
    guard label.first != 45, label.last != 45, !(label.count >= 4 && label[2] == 45 && label[3] == 45) else { throw V4CBORFailure("idna_hyphen") }
    guard !prop("categories", label[0]).hasPrefix("M") else { throw V4CBORFailure("idna_initial_mark") }
    for (index, cp) in label.enumerated() {
      guard ["valid", "deviation"].contains(prop("mapping", cp)) else { throw V4CBORFailure("idna_validity") }
      if [0x200c, 0x200d].contains(cp), !contextJ(label, index) { throw V4CBORFailure("idna_contextj") }
    }
  }

  func process(_ input: String) throws -> (ascii: String, labels: [[UInt32]], trailing: Bool) {
    var mapped: [UInt32] = []
    for scalar in input.unicodeScalars {
      if let row = lookup("mapping", scalar.value) {
        switch row.kind {
        case "mapped": mapped.append(contentsOf: row.mapped)
        case "ignored": break
        case "valid", "deviation", "disallowed", "disallowed_STD3_valid", "disallowed_STD3_mapped": mapped.append(scalar.value)
        default: throw V4CBORFailure("idna_mapping")
        }
      } else { mapped.append(scalar.value) }
    }
    // UTS46 r31 checks validity after NFC composition. Split scalar dots,
    // never Swift grapheme clusters that could include adjacent combining marks.
    let normalized = nfc.normalize(v4ScalarText(mapped)).unicodeScalars.map(\.value)
    var names = normalized.split(separator: 46, omittingEmptySubsequences: false).map(Array.init)
    let trailing = names.last?.isEmpty == true
    if trailing { names.removeLast() }
    guard !names.isEmpty else { throw V4CBORFailure("idna_empty_domain") }
    var labels: [[UInt32]] = [], bidiDomain = false
    for name in names {
      let label: [UInt32]
      if name.starts(with: [120, 110, 45, 45]) {
        let text = v4ScalarText(name), payload = v4ScalarText(Array(name.dropFirst(4)))
        guard text.utf8.count <= 63 else { throw V4CBORFailure("idna_label_length") }
        label = try v4PunyDecode(payload)
        guard label.contains(where: { $0 >= 128 }) else { throw V4CBORFailure("idna_fake_alabel") }
        guard try Data(v4PunyEncode(label).utf8) == Data(payload.utf8) else { throw V4CBORFailure("idna_alabel_roundtrip") }
      } else { label = name }
      try validUTSLabel(label)
      bidiDomain = bidiDomain || label.contains { ["R", "AL", "AN"].contains(prop("bidi", $0)) }
      labels.append(label)
    }
    var ascii: [String] = []
    for label in labels {
      if bidiDomain { try bidi(label) }
      let text = try label.contains(where: { $0 >= 128 }) ? "xn--" + v4PunyEncode(label) : v4ScalarText(label)
      guard !text.isEmpty, text.utf8.count <= 63 else { throw V4CBORFailure("idna_label_length") }
      ascii.append(text)
    }
    var result = ascii.joined(separator: ".")
    guard result.utf8.count <= 253 else { throw V4CBORFailure("idna_domain_length") }
    if trailing { result += "." }
    return (result, labels, trailing)
  }

  func issuerDNS(_ input: String) throws -> String {
    guard input.unicodeScalars.allSatisfy({ nfc.assigned($0.value) }) else { throw V4CBORFailure("idna_unassigned") }
    let result = try process(input)
    guard !result.trailing else { throw V4CBORFailure("idna_trailing_dot") }
    for label in result.labels {
      for (index, cp) in label.enumerated() {
        guard nfc.assigned(cp) else { throw V4CBORFailure("idna_unassigned") }
        let allowed: Bool
        switch prop("classes", cp) {
        case "PVALID": allowed = true
        case "CONTEXTJ": allowed = contextJ(label, index)
        case "CONTEXTO": allowed = contextO(label, index)
        default: allowed = false
        }
        guard allowed else { throw V4CBORFailure("idna2008_validity") }
      }
    }
    return result.ascii
  }

  func wireDNS(_ input: String) throws {
    guard !input.isEmpty, input.utf8.allSatisfy({ $0 < 128 }) else { throw V4CBORFailure("idna_wire_ascii") }
    guard try Data(issuerDNS(input).utf8) == Data(input.utf8) else { throw V4CBORFailure("idna_wire_noncanonical") }
  }
}

func v4ScalarText(_ scalars: [UInt32]) -> String { String(String.UnicodeScalarView(scalars.map { UnicodeScalar($0)! })) }

private let v4PunyMax: UInt64 = 0x7fffffff
private func v4PunyThreshold(_ k: UInt64, _ bias: UInt64) -> UInt64 { min(26, max(1, k > bias ? k - bias : 0)) }
private func v4PunyAdapt(_ original: UInt64, _ count: UInt64, _ first: Bool) -> UInt64 {
  var delta = original / (first ? 700 : 2), k: UInt64 = 0
  delta += delta / count
  while delta > 455 { delta /= 35; k += 36 }
  return k + 36 * delta / (delta + 38)
}
private func v4PunyDigit(_ n: UInt64) -> UInt8 { UInt8(n < 26 ? n + 97 : n - 26 + 48) }

func v4PunyEncode(_ input: [UInt32]) throws -> String {
  guard input.allSatisfy({ UnicodeScalar($0) != nil }) else { throw V4CBORFailure("punycode_scalar") }
  var out = input.filter { $0 < 128 }.map(UInt8.init)
  let basic = UInt64(out.count)
  var handled = basic, n: UInt64 = 128, delta: UInt64 = 0, bias: UInt64 = 72
  if basic > 0 { out.append(45) }
  while handled < UInt64(input.count) {
    guard let next = input.map(UInt64.init).filter({ $0 >= n }).min() else { throw V4CBORFailure("punycode_scalar") }
    guard next - n <= (v4PunyMax - delta) / (handled + 1) else { throw V4CBORFailure("punycode_overflow") }
    delta += (next - n) * (handled + 1); n = next
    for scalar in input {
      let cp = UInt64(scalar)
      if cp < n { guard delta < v4PunyMax else { throw V4CBORFailure("punycode_overflow") }; delta += 1 }
      if cp != n { continue }
      var q = delta, k: UInt64 = 36
      while true {
        let t = v4PunyThreshold(k, bias)
        if q < t { break }
        out.append(v4PunyDigit(t + (q - t) % (36 - t))); q = (q - t) / (36 - t); k += 36
      }
      out.append(v4PunyDigit(q)); bias = v4PunyAdapt(delta, handled + 1, handled == basic); delta = 0; handled += 1
    }
    guard delta < v4PunyMax else { throw V4CBORFailure("punycode_overflow") }; delta += 1; n += 1
  }
  return String(decoding: out, as: UTF8.self)
}

func v4PunyDecode(_ input: String) throws -> [UInt32] {
  let bytes = Array(input.utf8)
  guard bytes.allSatisfy({ $0 < 128 }) else { throw V4CBORFailure("punycode_ascii") }
  var out: [UInt32] = [], index = 0
  if let dash = bytes.lastIndex(of: 45), dash > 0 { out = bytes[..<dash].map(UInt32.init); index = dash + 1 }
  var n: UInt64 = 128, i: UInt64 = 0, bias: UInt64 = 72
  while index < bytes.count {
    let old = i
    var weight: UInt64 = 1, k: UInt64 = 36
    while true {
      guard index < bytes.count else { throw V4CBORFailure("punycode_truncated") }
      let byte = bytes[index]; index += 1
      let digit: UInt64
      switch byte {
      case 97...122: digit = UInt64(byte - 97)
      case 65...90: digit = UInt64(byte - 65)
      case 48...57: digit = UInt64(byte - 48 + 26)
      default: throw V4CBORFailure("punycode_digit")
      }
      guard digit <= (v4PunyMax - i) / weight else { throw V4CBORFailure("punycode_overflow") }
      i += digit * weight
      let t = v4PunyThreshold(k, bias)
      if digit < t { break }
      guard weight <= v4PunyMax / (36 - t) else { throw V4CBORFailure("punycode_overflow") }
      weight *= 36 - t; k += 36
    }
    let count = UInt64(out.count) + 1
    bias = v4PunyAdapt(i - old, count, old == 0)
    guard i / count <= v4PunyMax - n else { throw V4CBORFailure("punycode_overflow") }
    n += i / count; i %= count
    guard let scalar = UInt32(exactly: n), UnicodeScalar(scalar) != nil else { throw V4CBORFailure("punycode_scalar") }
    out.insert(scalar, at: Int(i)); i += 1
  }
  return out
}
