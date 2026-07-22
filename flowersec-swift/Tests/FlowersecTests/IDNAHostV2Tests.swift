import Foundation
import Testing

@testable import Flowersec

struct IDNAHostV2Tests {
  @Test func lookupASCIIUsesFrozenUnicode151UTS46() throws {
    let fixture = try loadFixture()
    #expect(fixture.unicodeVersion == IDNAHostV2.unicodeVersion)
    for vector in fixture.positive {
      #expect(
        try IDNAHostV2.lookupASCII(vector.input) == vector.ascii, Comment(rawValue: vector.id))
    }
  }

  @Test func lookupASCIIRejectsInvalidAndPost151Hosts() throws {
    for vector in try loadFixture().negative {
      #expect(throws: IDNAHostErrorV2.invalidHost) {
        try IDNAHostV2.lookupASCII(vector.input)
      }
    }
  }

  private func loadFixture() throws -> IDNAVectorFixture {
    let url = packageRoot().appendingPathComponent("testdata/transport_v2/idna_vectors.json")
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
