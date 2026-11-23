import Foundation
import XCTest
@testable import Flowersec

final class TransportV4TextTests: XCTestCase {
  private static let reference = try! V4TextReference()
  private static let corpus: [V4JSON] = {
    let raw = try! Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json"))
    let corpus = try! JSONDecoder().decode(V4JSON.self, from: raw)
    precondition(corpus["schema_sha256"].text == TransportV4Registry.schemaSHA256)
    return corpus["vectors"].array!
  }()

  private func context(_ vector: V4JSON) -> V4CBORContext {
    var context = V4CBORContext()
    for (key, value) in vector["limits"].object ?? [:] {
      if case .uint(let n) = value { context.limits[key] = n }
      if case .text(let text) = value { context.selectors[key] = text }
    }
    return context
  }

  // v4.swift_text.corpus
  func testSharedIssuerAndWireTextCorpus() throws {
    let r = Self.reference, raw = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/text.json"))
    let corpus = try JSONDecoder().decode(V4JSON.self, from: raw)
    XCTAssertEqual(corpus["schema_sha256"].text, TransportV4Registry.schemaSHA256)
    let vectors = corpus["vectors"].array!
    for vector in vectors {
      let input = vector["input"].text!, id = vector["id"].text!
      do {
        let output: String
        switch vector["operation"].text {
        case "issuer_dns": output = try r.idna.issuerDNS(input)
        case "wire_dns": try r.idna.wireDNS(input); output = input
        case "issuer_host": output = try r.issuerHost(input)
        case "wire_host": try r.wireHost(input); output = input
        case "wire_origin": try r.wireOrigin(input); output = input
        default: XCTFail("unknown text operation"); continue
        }
        XCTAssertNil(vector["expected_error"].text, "accepted \(id)")
        XCTAssertEqual(Data(output.utf8), Data((vector["output"].text ?? "").utf8), id)
        XCTAssertEqual(Data(output.utf8), try v4RuleHex(vector["utf8_hex"].text ?? ""), id)
      } catch { XCTAssertNotNil(vector["expected_error"].text, "\(id): \(error)") }
    }
    XCTAssertEqual(vectors.count, 100)
  }

  // v4.swift_text.wire_maps
  func testSharedWireMapCorpusExceptExternalComposition() throws {
    var positive = 0, negative = 0, separate = 0
    for vector in Self.corpus {
      if ["pool_set_membership", "open_digest_mismatch"].contains(vector["expected_error"].text ?? "") { separate += 1; continue }
      let raw = try v4RuleHex(vector["hex"].text!), ctx = context(vector), before = ctx, id = vector["id"].text!
      do {
        let value = try Self.reference.wireMap(raw, schema: vector["schema"].text ?? "", context: ctx, cap: UInt64(raw.count) + 1)
        XCTAssertNil(vector["expected_error"].text, "accepted \(id)")
        XCTAssertEqual(value.encoded(), raw, id)
      } catch { XCTAssertNotNil(vector["expected_error"].text, "\(id): \(error)") }
      XCTAssertEqual(ctx, before)
      if vector["expected_error"].text == nil { positive += 1 } else { negative += 1 }
    }
    XCTAssertEqual(positive, 337); XCTAssertEqual(negative, 826); XCTAssertEqual(separate, 2)
    print("Swift text maps: \(positive) positive / \(negative) negative / \(separate) external composition cases")
  }

  // v4.swift_text.address_boundaries
  func testCanonicalAddressesAndRegisteredOriginPorts() throws {
    let r = Self.reference
    for (input, canonical) in [("2001:0DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1"), ("0:0:0:0:0:0:0:0", "::"), ("::FFFF:192.0.2.1", "::ffff:c000:201"), ("0:0:0:0:0:0:0:1", "::1")] {
      XCTAssertEqual(try r.issuerHost(input), canonical)
      XCTAssertEqual(v4IPv6(input), v4IPv6(canonical))
      XCTAssertNoThrow(try r.wireHost(canonical)); XCTAssertThrowsError(try r.wireHost(input))
    }
    for host in ["127.1", "127.00.0.1", "2130706433", "0x7f000001", "example.0x", "example.123", "::ffff:127.0.0.1%lo", "example.com.", "example.com/path", "example.com\u{a0}", "1::2::3", ":::1", "1:::2", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "192.0.2.1::", "+1::", "::ffff:192.00.2.1"] {
      XCTAssertThrowsError(try r.issuerHost(host), host)
    }
    XCTAssertNoThrow(try r.wireHost("example.0xg"))
    for origin in ["https://example.com", "https://[::ffff:c000:201]", "http://127.0.0.1:3000"] { XCTAssertNoThrow(try r.wireOrigin(origin), origin) }
    for origin in ["https://example.com:443", "http://127.0.0.1:80", "https://example.com:0443", "https://example.com:65536", "https://user@example.com", "https://example.com/", "https://example.com?x", "https://example.com#x", "https://EXAMPLE.COM", "https://[::ffff:192.0.2.1]", "https://example.com\n", "unregistered://example.com", "https://example.com:", "https://[example.com]", "https://[::1]]", "https://[::1]:+1"] {
      XCTAssertThrowsError(try r.wireOrigin(origin), origin)
    }
    XCTAssertEqual(v4IPv6Hex([1, 0, 0, 2, 0, 0, 3, 4]), "1::2:0:0:3:4")
    XCTAssertEqual(v4IPv6Hex([1, 0, 2, 3, 4, 5, 6, 7]), "1:0:2:3:4:5:6:7")
    XCTAssertEqual(v4IPv6("::ffff:c000:201"), [0, 0, 0, 0, 0, 65535, 49152, 513])
  }

  // v4.swift_text.properties
  func testAddressIssuerAndMutatedMapProperties() throws {
    let r = Self.reference
    var state: UInt64 = 0x41e7141e7141e714
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      let words = (0..<8).map { _ -> UInt16 in let n = next(); return n % 3 == 0 ? 0 : UInt16(truncatingIfNeeded: n) }
      let full = words.map { String(format: "%04X", $0) }.joined(separator: ":")
      let canonical = try r.issuerHost(full)
      XCTAssertEqual(v4IPv6(canonical), words)
      XCTAssertNoThrow(try r.wireHost(canonical)); XCTAssertNoThrow(try r.wireOrigin("https://[\(canonical)]"))
      let points = (0..<Int(next() % 128)).compactMap { _ -> UInt32? in
        let cp = UInt32(next() % 0x110000); return UnicodeScalar(cp) == nil ? nil : cp
      }
      if let host = try? r.issuerHost(v4ScalarText(points)) {
        XCTAssertNoThrow(try r.wireHost(host))
        XCTAssertNoThrow(try r.wireOrigin("https://" + (host.contains(":") ? "[\(host)]" : host)))
      }
      let vector = Self.corpus[Int(next() % UInt64(Self.corpus.count))]
      var raw = try v4RuleHex(vector["hex"].text!)
      if !raw.isEmpty { let at = Int(next() % UInt64(raw.count)); raw[at] ^= UInt8(truncatingIfNeeded: next()) }
      let ctx = context(vector), before = ctx
      if let value = try? r.wireMap(raw, schema: vector["schema"].text ?? "", context: ctx, cap: UInt64(raw.count) + 1) { XCTAssertEqual(value.encoded(), raw) }
      XCTAssertEqual(ctx, before)
    }
  }
}
