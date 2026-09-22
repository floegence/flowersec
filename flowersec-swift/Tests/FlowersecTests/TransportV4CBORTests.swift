import Foundation
import XCTest
@testable import Flowersec

final class TransportV4CBORTests: XCTestCase {
  private static let reference = try! V4CBORReference()
  private static let corpus: [V4JSON] = {
    let data = try! Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json"))
    let corpus = try! JSONDecoder().decode(V4JSON.self, from: data)
    precondition(corpus["schema_sha256"].text == TransportV4Registry.schemaSHA256)
    return corpus["vectors"].array!
  }()

  private func hex(_ text: String) -> Data {
    let bytes = Array(text.utf8)
    precondition(bytes.count.isMultiple(of: 2))
    return Data(stride(from: 0, to: bytes.count, by: 2).map {
      UInt8(String(decoding: bytes[$0...$0 + 1], as: UTF8.self), radix: 16)!
    })
  }

  private func limits(_ vector: V4JSON) -> [String: UInt64] {
    (vector["limits"].object ?? [:]).compactMapValues { if case .uint(let n) = $0 { return n }; return nil }
  }

  private func error(_ result: Result<V4CBORValue, V4CBORFailure>) -> String? {
    if case .failure(let error) = result { return error.code }; return nil
  }

  // v4.swift_cbor.corpus
  func testSharedSyntaxCorpus() throws {
    let syntaxErrors: Set<String> = ["non_canonical_text", "unassigned_code_point", "invalid_utf8", "unsupported_type", "array_limit", "duplicate_key", "non_shortest_integer", "map_order", "truncated", "trailing_bytes", "field_id_type", "indefinite_length", "depth_limit", "invalid_header", "map_limit"]
    var positive = 0, negative = 0
    for vector in Self.corpus {
      if let expected = vector["expected_error"].text, !syntaxErrors.contains(expected) { continue }
      let input = hex(vector["hex"].text!), original = input, id = vector["id"].text!
      let (result, nodes) = Self.reference.decode(input, schema: vector["schema"].text ?? "", limits: limits(vector), cap: UInt64(input.count) + 1)
      XCTAssertLessThanOrEqual(nodes, input.count, id)
      XCTAssertEqual(input, original, id)
      if let expected = vector["expected_error"].text {
        negative += 1
        XCTAssertNotNil(error(result), id)
        if vector["kind"].text == "cbor_syntax" { XCTAssertEqual(error(result), expected, id) }
      } else {
        positive += 1
        guard case .success(let value) = result else { XCTFail("\(id): \(error(result) ?? "unknown")"); continue }
        XCTAssertEqual(value.encoded(), input, id)
        if let decimal = vector["decimal"].text {
          guard case .uint(let n) = value else { XCTFail(id); continue }
          XCTAssertEqual(n, UInt64(decimal), id)
        }
      }
    }
    XCTAssertEqual(positive, 337)
    XCTAssertGreaterThan(negative, 0)
    print("Swift syntax: \(positive) positive / \(negative) syntax-negative cases")
  }

  // v4.swift_cbor.limits
  func testAllocationAndCapacityBoundaries() throws {
    let r = Self.reference
    for text in ["5bffffffffffffffff", "7bffffffffffffffff", "9bffffffffffffffff", "bbffffffffffffffff", "99040b", "b880"] {
      let (result, nodes) = r.decode(hex(text), cap: 64)
      XCTAssertNotNil(error(result), text)
      XCTAssertEqual(nodes, 0, text)
    }
    for (input, name, cap, expected) in [
      (Data([0xff, 0xff]), "", UInt64(1), "map_size"),
      (Data(), "", UInt64(0), "limit_unresolved"),
      (Data([0]), "RevocationState", UInt64(1), "limit_unresolved"),
      (Data([0]), "Unregistered", UInt64(1), "unknown_schema"),
    ] {
      let (result, nodes) = r.decode(input, schema: name, cap: cap)
      XCTAssertEqual(error(result), expected); XCTAssertEqual(nodes, 0)
    }
    for (major, bound) in [(UInt8(5), r.registry["encoding"]["max_map_entries"].uint!), (UInt8(4), r.registry["encoding"]["ordinary_array_items"].uint!)] {
      var input = V4CBORValue.head(major, bound)
      for n in 0..<bound { if major == 5 { input.append(V4CBORValue.head(0, n)) }; input.append(0) }
      XCTAssertEqual(try r.decode(input, cap: UInt64(input.count)).0.get().encoded(), input)
      XCTAssertNotNil(error(r.decode(V4CBORValue.head(major, bound + 1), cap: 64).0))
    }
    let sliced = Data([0xff, 0x01, 0xff])[1..<2]
    XCTAssertEqual(try r.decode(sliced, cap: 1).0.get().encoded(), Data([1]))
  }

  // v4.swift_cbor.context
  func testScopedNullTextKeysAndCapacityArrays() throws {
    let r = Self.reference
    XCTAssertEqual(error(r.decode(Data([0xf6]), cap: 1).0), "unsupported_type")
    let vector = Self.corpus.first { $0["id"].text == "revoked_issuer_minimum" }!
    let schema = vector["schema"].text!, input = hex(vector["hex"].text!)
    var limits: [String: UInt64] = ["max_state_encoded_bytes": 1 << 20, "max_revoked_issuer_authorizations": 1036]
    guard case .map(var pairs) = try r.decode(input, schema: schema, limits: limits, cap: 1 << 20).0.get() else { return XCTFail("not map") }
    let fields = r.registry["frame_maps"][schema]["fields"].object!
    let id = UInt64(fields.first { $0.value["max_items_ref"].text == "max_revoked_issuer_authorizations" }!.key)!
    let index = pairs.firstIndex { if case .uint(let key) = $0.key { return key == id }; return false }!
    guard case .array(let items) = pairs[index].value else { return XCTFail("not array") }
    // Repeated entries isolate syntax capacity; semantic uniqueness is separate.
    pairs[index].value = .array(Array(repeating: items[0], count: 1036))
    let large = V4CBORValue.map(pairs).encoded()
    XCTAssertEqual(try r.decode(large, schema: schema, limits: limits, cap: UInt64(large.count)).0.get().encoded(), large)
    limits["max_revoked_issuer_authorizations"] = 1035
    XCTAssertEqual(error(r.decode(large, schema: schema, limits: limits, cap: UInt64(large.count)).0), "array_limit")
    limits["max_revoked_issuer_authorizations"] = 1 << 32
    XCTAssertEqual(error(r.decode(large, schema: schema, limits: limits, cap: UInt64(large.count)).0), "limit_unresolved")
    limits["max_revoked_issuer_authorizations"] = 1036
    limits["max_state_encoded_bytes"] = UInt64(large.count) - 1
    let (failure, nodes) = r.decode(large, schema: schema, limits: limits, cap: UInt64(large.count))
    XCTAssertEqual(error(failure), "map_size"); XCTAssertEqual(nodes, 0)
    let textMap = V4CBORValue.map([.init(key: .text("a"), value: .text("b"))]).encoded()
    XCTAssertEqual(error(r.decode(textMap, cap: 64).0), "field_id_type")
  }

  // v4.swift_cbor.embedded_cap
  func testEmbeddedDocumentCapPrecedesPayloadExtraction() throws {
    let r = Self.reference, schema = "TopUpRequest"
    let field = r.registry["frame_maps"][schema]["fields"].object!.first { $0.value["encoded_schema_ref"].text == "OwnerFenceProof" }!
    let bound = r.registry["frame_maps"]["OwnerFenceProof"]["max_encoded_bytes"].uint!
    let prefix = V4CBORValue.head(5, 1) + V4CBORValue.head(0, UInt64(field.key)!)
    // With no payload present, truncated would show extraction ran first.
    // An excessive declared length must fail the inner cap before take().
    for n in [bound + 1, UInt64.max] {
      let headerOnly = prefix + V4CBORValue.head(2, n)
      XCTAssertEqual(error(r.decode(headerOnly, schema: schema, cap: 65536).0), "map_size")
    }
    XCTAssertEqual(error(r.decode(prefix + V4CBORValue.head(2, bound), schema: schema, cap: 65536).0), "truncated")
    let overfull = prefix + V4CBORValue.head(2, bound + 1) + Data(repeating: 0, count: Int(bound + 1))
    XCTAssertEqual(error(r.decode(overfull, schema: schema, cap: 65536).0), "map_size")
  }

  // v4.swift_cbor.unicode
  func testPinnedUnicodeConformanceAndPartOneComplement() throws {
    let nfc = Self.reference.nfc
    let raw = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/unicode15_1/NormalizationTest.txt"))
    XCTAssertEqual(v4Hash(raw), nfc.conformanceSHA256)
    var partOne = false, covered = Set<UInt32>(), count = 0
    for rawLine in String(data: raw, encoding: .utf8)!.split(separator: "\n") {
      let line = rawLine.split(separator: "#", omittingEmptySubsequences: false)[0].trimmingCharacters(in: .whitespaces)
      if line.hasPrefix("@") { partOne = line.hasPrefix("@Part1"); continue }
      if line.isEmpty { continue }
      let columns = line.split(separator: ";", omittingEmptySubsequences: false).prefix(5).map { column in
        String(String.UnicodeScalarView(column.split(separator: " ").map { UnicodeScalar(UInt32($0, radix: 16)!)! }))
      }
      XCTAssertEqual(columns.count, 5)
      if partOne { covered.formUnion(columns[0].unicodeScalars.map(\.value)) }
      for (index, input) in columns.enumerated() {
        XCTAssertEqual(Data(nfc.normalize(input).utf8), Data(columns[index < 3 ? 1 : 3].utf8), "case \(count) column \(index)")
      }
      count += 1
    }
    XCTAssertEqual(count, 19074)
    for cp in UInt32(0)...0x10ffff {
      if let scalar = UnicodeScalar(cp), !covered.contains(cp) {
        let input = String(scalar)
        if Data(nfc.normalize(input).utf8) != Data(input.utf8) { XCTFail("Part1 complement U+\(String(cp, radix: 16))"); return }
      }
    }
    XCTAssertFalse(nfc.assigned(0x1cc00)); XCTAssertFalse(nfc.assigned(0x378))
    let long = "A" + String(repeating: "\u{315}\u{300}", count: 10000)
    let normalized = nfc.normalize(long)
    XCTAssertEqual(Data(nfc.normalize(normalized).utf8), Data(normalized.utf8))
    // Swift's default equality hides this distinction; wire acceptance must not.
    XCTAssertEqual("e\u{301}", "\u{e9}")
    XCTAssertEqual(error(Self.reference.decode(V4CBORValue.text("e\u{301}").encoded(), cap: 64).0), "non_canonical_text")
  }

  // v4.swift_cbor.properties
  func testDeterministicArbitraryAndMutatedInputs() throws {
    var state: UInt64 = 0x41cb041cb041cb04
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      let count = Int(next() % 8192)
      let input = Data((0..<count).map { _ in UInt8(truncatingIfNeeded: next()) })
      let (result, nodes) = Self.reference.decode(input, cap: 4096)
      XCTAssertLessThanOrEqual(nodes, input.count)
      if input.count > 4096 { XCTAssertEqual(error(result), "map_size"); XCTAssertEqual(nodes, 0) }
      if case .success(let value) = result { XCTAssertEqual(value.encoded(), input) }
      let vector = Self.corpus[Int(next() % UInt64(Self.corpus.count))]
      var changed = hex(vector["hex"].text!)
      if !changed.isEmpty { let at = Int(next() % UInt64(changed.count)); changed[at] ^= UInt8(truncatingIfNeeded: next()) }
      let (decoded, used) = Self.reference.decode(changed, schema: vector["schema"].text ?? "", limits: limits(vector), cap: UInt64(changed.count) + 1)
      XCTAssertLessThanOrEqual(used, changed.count)
      if case .success(let value) = decoded { XCTAssertEqual(value.encoded(), changed) }
    }
  }
}
