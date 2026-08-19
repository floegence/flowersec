import Foundation
import Testing

@testable import Flowersec

struct IDNAHostV3Tests {
  @Test func lookupASCIIUsesFrozenUnicode151UTS46() throws {
    let fixture = try loadFixture()
    #expect(fixture.unicodeVersion == IDNAHostV3.unicodeVersion)
    for vector in fixture.positive {
      #expect(
        try IDNAHostV3.lookupASCII(vector.input) == vector.ascii, Comment(rawValue: vector.id))
    }
  }

  @Test func lookupASCIIRejectsInvalidAndPost151Hosts() throws {
    for vector in try loadFixture().negative {
      #expect(throws: IDNAHostErrorV3.invalidHost) {
        try IDNAHostV3.lookupASCII(vector.input)
      }
    }
  }

  @Test func unicode151DeltaFallbackMatchesFrozenVectors() throws {
    for vector in try loadFixture().positive where vector.id.hasPrefix("unicode-15-1-extension-i") {
      #expect(
        try IDNAHostV3.lookupUnicode151DeltaASCII(vector.input) == vector.ascii,
        Comment(rawValue: vector.id))
    }
  }

  @Test func artifactURLNormalizerConsumesEverySharedVector() throws {
    let vectors = try loadFixture().urlNormalization
    #expect(!vectors.positive.isEmpty)
    #expect(!vectors.negative.isEmpty)
    for vector in vectors.positive {
      #expect(
        try ArtifactCodecV3.normalizeURL(
          vector.input, carrier: vector.carrier, kind: vector.pathKind) == vector.normalized,
        Comment(rawValue: vector.id))
    }
    for vector in vectors.negative {
      #expect(vector.errorCode == "invalid_artifact", Comment(rawValue: vector.id))
      #expect(throws: ArtifactErrorV3.invalidArtifact, Comment(rawValue: vector.id)) {
        try ArtifactCodecV3.normalizeURL(
          vector.input, carrier: vector.carrier, kind: vector.pathKind)
      }
    }
  }

  private func loadFixture() throws -> IDNAVectorFixture {
    let url = packageRoot().appendingPathComponent("testdata/transport_v3/idna_vectors.json")
    return try JSONDecoder().decode(IDNAVectorFixture.self, from: Data(contentsOf: url))
  }
}

private struct IDNAVectorFixture: Decodable {
  let unicodeVersion: String
  let positive: [IDNAPositiveVector]
  let negative: [IDNANegativeVector]
  let urlNormalization: URLNormalizationVectors

  private enum CodingKeys: String, CodingKey {
    case unicodeVersion = "unicode_version"
    case positive
    case negative
    case urlNormalization = "url_normalization"
  }
}

private struct URLNormalizationVectors: Decodable {
  let positive: [URLNormalizationPositiveVector]
  let negative: [URLNormalizationNegativeVector]
}

private struct URLNormalizationPositiveVector: Decodable {
  let id: String
  let carrier: String
  let pathKind: String
  let input: String
  let normalized: String

  private enum CodingKeys: String, CodingKey {
    case id
    case carrier
    case pathKind = "path_kind"
    case input
    case normalized
  }
}

private struct URLNormalizationNegativeVector: Decodable {
  let id: String
  let carrier: String
  let pathKind: String
  let input: String
  let errorCode: String

  private enum CodingKeys: String, CodingKey {
    case id
    case carrier
    case pathKind = "path_kind"
    case input
    case errorCode = "error_code"
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
