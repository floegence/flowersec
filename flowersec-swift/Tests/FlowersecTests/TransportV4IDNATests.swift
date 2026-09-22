import Foundation
import XCTest
@testable import Flowersec

final class TransportV4IDNATests: XCTestCase {
  private static let reference = try! V4IDNA(syntax: V4CBORReference())

  private func unescape(_ input: String) throws -> String {
    let scalars = input.unicodeScalars.map(\.value)
    var points: [UInt32] = [], index = 0
    while index < scalars.count {
      if scalars[index] == 92, index + 1 < scalars.count, [117, 120].contains(scalars[index + 1]) {
        let start: Int, end: Int
        if scalars[index + 1] == 117 { start = index + 2; end = start + 4; index = end }
        else {
          guard index + 2 < scalars.count, scalars[index + 2] == 123,
                let close = scalars[(index + 3)...].firstIndex(of: 125) else { throw V4CBORFailure("invalid_scalar") }
          start = index + 3; end = close; index = close + 1
        }
        guard end <= scalars.count, let cp = UInt32(v4ScalarText(Array(scalars[start..<end])), radix: 16) else { throw V4CBORFailure("invalid_scalar") }
        points.append(cp)
      } else { points.append(scalars[index]); index += 1 }
    }
    var output: [UInt32] = []; index = 0
    while index < points.count {
      var cp = points[index]
      if (0xd800...0xdbff).contains(cp), index + 1 < points.count, (0xdc00...0xdfff).contains(points[index + 1]) {
        cp = 0x10000 + ((cp - 0xd800) << 10) + points[index + 1] - 0xdc00; index += 1
      }
      guard UnicodeScalar(cp) != nil else { throw V4CBORFailure("invalid_scalar") }
      output.append(cp); index += 1
    }
    return v4ScalarText(output)
  }

  // v4.swift_idna.conformance
  func testOfficialNontransitionalToASCIIConformance() throws {
    let raw = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/unicode15_1/IdnaTestV2.txt"))
    XCTAssertEqual(v4Hash(raw), Self.reference.conformanceSHA256)
    var count = 0
    let trim = CharacterSet(charactersIn: " \t\r")
    for (lineNumber, line) in String(validating: raw, as: UTF8.self)!.components(separatedBy: "\n").enumerated() {
      let line = line.components(separatedBy: "#")[0].trimmingCharacters(in: trim)
      if line.isEmpty { continue }
      let cols = line.components(separatedBy: ";").map { $0.trimmingCharacters(in: trim) }
      XCTAssertGreaterThanOrEqual(cols.count, 5)
      let expected = !cols[3].isEmpty ? cols[3] : !cols[1].isEmpty ? cols[1] : cols[0]
      let status = !cols[4].isEmpty ? cols[4] : !cols[2].isEmpty ? cols[2] : "[]"
      do {
        // Swift strings cannot represent isolated surrogates. Reject at the
        // fixture scalar boundary without inserting replacement characters.
        let actual = try Self.reference.process(unescape(cols[0])).ascii
        XCTAssertEqual(status, "[]", "line \(lineNumber + 1) accepted \(actual)")
        if status == "[]" { XCTAssertEqual(Data(actual.utf8), Data(try unescape(expected).utf8), "line \(lineNumber + 1)") }
      } catch { XCTAssertNotEqual(status, "[]", "line \(lineNumber + 1): \(error)") }
      count += 1
    }
    XCTAssertEqual(count, 6265)
  }

  // v4.swift_idna.context
  func testIDNA2008ContextsAndExactWireIdentity() throws {
    let r = Self.reference
    // Multilingual samples are limited to script, joiner and Bidi behavior.
    for input in ["\u{375}\u{3b1}.example", "\u{5d0}\u{5f3}.example", "\u{5d0}\u{5f4}.example", "\u{30ab}\u{30fb}\u{30ca}.example", "\u{30fb}\u{4e00}.example", "\u{627}\u{660}\u{661}.example", "\u{627}\u{6f0}\u{6f1}.example", "\u{915}\u{94d}\u{200d}\u{937}.example", "\u{915}\u{94d}\u{200c}\u{937}.example", "a1.\u{645}\u{62b}\u{627}\u{644}"] {
      let ascii = try r.issuerDNS(input)
      XCTAssertNoThrow(try r.wireDNS(ascii), input)
    }
    for input in ["\u{375}a.example", "\u{5f3}\u{5d0}.example", "\u{5f4}\u{5d0}.example", "a\u{30fb}b.example", "\u{627}\u{660}\u{6f0}.example", "\u{915}\u{200d}\u{937}.example", "\u{628}\u{200c}\u{301}a.example", "a\u{200c}\u{628}.example", "1.\u{645}\u{62b}\u{627}\u{644}", "\u{1f600}.example", "xn--e28h.example", "xn--abc-.example", "xn--a!", "a_b.example", "\u{1cc00}.example"] {
      XCTAssertThrowsError(try r.issuerDNS(input), input)
    }
    XCTAssertEqual(try r.process("\u{1f600}.example").ascii, "xn--e28h.example")
    for input in ["EXAMPLE.COM", "\u{fc}.example", "example.com.", "xn--BCHER-kva.example"] { XCTAssertThrowsError(try r.wireDNS(input), input) }
    XCTAssertEqual(try r.issuerDNS("EXAMPLE.COM"), "example.com")
    XCTAssertThrowsError(try unescape("\\uD800")); XCTAssertThrowsError(try unescape("\\x{110000}"))
    XCTAssertEqual(try unescape("\\uD83D\\uDE00"), "\u{1f600}")
  }

  // v4.swift_idna.shared_dns
  func testSharedDNSCorpus() throws {
    let data = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/text.json"))
    let corpus = try JSONDecoder().decode(V4JSON.self, from: data)
    XCTAssertEqual(corpus["schema_sha256"].text, TransportV4Registry.schemaSHA256)
    var positive = 0, negative = 0
    for vector in corpus["vectors"].array! {
      guard let operation = vector["operation"].text, ["issuer_dns", "wire_dns"].contains(operation) else { continue }
      let input = vector["input"].text!, id = vector["id"].text!
      do {
        let output: String
        if operation == "issuer_dns" { output = try Self.reference.issuerDNS(input) }
        else { try Self.reference.wireDNS(input); output = input }
        XCTAssertNil(vector["expected_error"].text, "accepted \(id)")
        XCTAssertEqual(Data(output.utf8), Data((vector["output"].text ?? "").utf8), id)
        XCTAssertEqual(Data(output.utf8), try v4RuleHex(vector["utf8_hex"].text ?? ""), id)
      } catch { XCTAssertNotNil(vector["expected_error"].text, "\(id): \(error)") }
      if vector["expected_error"].text == nil { positive += 1 } else { negative += 1 }
    }
    XCTAssertGreaterThan(positive, 0); XCTAssertGreaterThan(negative, 0)
  }

  // v4.swift_idna.properties
  func testBootstringAndIssuerWireProperties() throws {
    var state: UInt64 = 0x41d0a41d0a41d0a4
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    func point() -> UInt32 {
      while true { let cp = UInt32(next() % 0x110000); if UnicodeScalar(cp) != nil { return cp } }
    }
    for _ in 0..<4096 {
      let points = (0..<Int(next() % 64)).map { _ in point() }
      XCTAssertEqual(try v4PunyDecode(v4PunyEncode(points)), points)
      let input = v4ScalarText((0..<Int(next() % 128)).map { _ in point() })
      if let ascii = try? Self.reference.issuerDNS(input) {
        XCTAssertNoThrow(try Self.reference.wireDNS(ascii))
        XCTAssertEqual(try Self.reference.issuerDNS(ascii), ascii)
      }
    }
  }
}
