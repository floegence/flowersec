import Foundation
import Testing

@testable import Flowersec

struct IDNAHostTests {
  @Test func lookupASCIIUsesFrozenUnicode151UTS46() throws {
    let fixture = try loadFixture()
    #expect(fixture.unicodeVersion == IDNAHost.unicodeVersion)
    for vector in fixture.positive {
      #expect(
        try IDNAHost.lookupASCII(vector.input) == vector.ascii, Comment(rawValue: vector.id))
    }
  }

  @Test func lookupASCIIRejectsInvalidAndPost151Hosts() throws {
    for vector in try loadFixture().negative {
      #expect(throws: IDNAHostError.invalidHost) {
        try IDNAHost.lookupASCII(vector.input)
      }
    }
  }

  @Test func unicode151DeltaFallbackMatchesFrozenVectors() throws {
    // RFC 3492 multilingual labels exercise the package-owned bootstring codec.
    for (unicode, ascii) in [
      ("bücher", "bcher-kva"), ("mañana", "maana-pta"),
      ("例え", "r8jz45g"), ("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"),
      ("abc", "abc-"), ("", ""), ("\u{10ffff}", "dn32g"),
    ] {
      #expect(try IDNAHost.punycodeEncode(unicode) == ascii)
      #expect(try IDNAHost.punycodeDecode(ascii) == unicode)
    }
    for invalid in ["!", "é", "9999999999999999999999999", "a-!", "a-0"] {
      #expect(throws: IDNAHostError.invalidHost) {
        try IDNAHost.punycodeDecode(invalid)
      }
    }
    for codePoint in UInt32(0x2EBF0)...UInt32(0x2EE5D) {
      let label = "a" + String(UnicodeScalar(codePoint)!) + "中"
      let ascii = "xn--" + (try IDNAHost.punycodeEncode(label)) + ".example"
      #expect(try IDNAHost.punycodeDecode(String(ascii.dropFirst(4).dropLast(8))) == label)
      #expect(try IDNAHost.lookupUnicode151DeltaASCII(label + ".example") == ascii)
      #expect(try IDNAHost.lookupUnicode151DeltaASCII(ascii) == ascii)
    }

    for vector in try loadFixture().positive where vector.id.hasPrefix("unicode-15-1-extension-i") {
      #expect(
        try IDNAHost.lookupUnicode151DeltaASCII(vector.input) == vector.ascii,
        Comment(rawValue: vector.id))
    }
  }

  private func loadFixture() throws -> IDNAVectorFixture {
    let url = packageRoot().appendingPathComponent("testdata/idna/idna_vectors.json")
    return try JSONDecoder().decode(IDNAVectorFixture.self, from: Data(contentsOf: url))
  }
}

private struct IDNAVectorFixture: Decodable {
  let unicodeVersion: String
  let positive: [IDNAPositiveVector]
  let negative: [IDNANegativeVector]

  private enum CodingKeys: String, CodingKey {
    case unicodeVersion = "unicode_version"
    case positive
    case negative
  }
}

private struct IDNAPositiveVector: Decodable {
  let id: String
  let input: String
  let ascii: String
}

private struct IDNANegativeVector: Decodable {
  let id: String
  let input: String
}
