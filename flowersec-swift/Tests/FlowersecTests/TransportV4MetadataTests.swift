import Foundation
import XCTest

@testable import Flowersec

final class TransportMetadataTests: XCTestCase {
  func testPublicMetadataConsumesSharedValidAndInvalidCorpus() throws {
    let cases = try cryptoCorpus("corpus")["vectors"].array!.filter {
      $0["schema"].text == "StreamMetadata"
    }
    XCTAssertEqual(cases.count, 28)
    for item in cases {
      let bytes = cryptoHex(item["hex"].text!)
      if item["kind"].text == "cbor_fields" {
        let metadata = try StreamMetadata(encoded: bytes)
        XCTAssertEqual(try metadata.encoded(), bytes, item["id"].text!)
        let rebuilt = try StreamMetadata(
          namespace: metadata.namespace!,
          version: metadata.version!, values: metadata.byteValues!)
        XCTAssertEqual(rebuilt, metadata, item["id"].text!)
      } else {
        XCTAssertThrowsError(try StreamMetadata(encoded: bytes), item["id"].text!) {
          XCTAssertEqual($0 as? StreamMetadataError, .invalidValue)
        }
      }
    }
  }

  func testEmptySentinelAndOrdinaryEmptyMapRemainDistinctFromJSON() throws {
    XCTAssertEqual(try StreamMetadata(encoded: Data()), .empty)
    XCTAssertEqual(try StreamMetadata.empty.encoded(), Data())
    XCTAssertNil(StreamMetadata.empty.namespace)
    let metadata = try StreamMetadata(namespace: "acme/chat", version: 0, values: [:])
    XCTAssertNotEqual(metadata, .empty)
    XCTAssertEqual(try metadata.encoded(), cryptoHex("a3006961636d652f63686174010002a0"))
    XCTAssertEqual(metadata.byteValues, [:])
    let json = try StreamMetadata(["key": .string("value")])
    XCTAssertEqual(json.namespace, "application/json")
    XCTAssertEqual(json.version, 1)
    XCTAssertEqual(json.byteValues?["key"], Data("\"value\"".utf8))
  }

  func testJSONConvenienceUsesV4BytesWithoutChangingApplicationNumbersOrText() throws {
    let values: [String: JSONValue] = [
      "integer": .integer(.max), "fraction": .number(0.125),
      "text": .string("e\u{301}"), "array": .array([.null, .bool(true)]),
    ]
    let metadata = try StreamMetadata(values)
    let decoded = try StreamMetadata(encoded: metadata.encoded())
    XCTAssertEqual(try decoded.jsonValues(), values)
    XCTAssertEqual(metadata, decoded)
    XCTAssertThrowsError(try StreamMetadata(["number": .number(.infinity)]))
    XCTAssertThrowsError(try StreamMetadata(["large": .string(String(repeating: "x", count: 1025))]))
    let opaque = try StreamMetadata(namespace: "example/binary", version: 1, values: ["key": Data([255])])
    XCTAssertThrowsError(try opaque.jsonValues())
    XCTAssertEqual(opaque.byteValues?["key"], Data([255]))
  }

  func testPublicConstructorEnforcesBoundsAndPinnedUnicode() throws {
    for namespace in ["flowersec/chat", "Acme/chat", "acme", "acme/", "acme/a/b"] {
      XCTAssertThrowsError(try StreamMetadata(namespace: namespace, version: 0, values: [:]))
    }
    for key in ["", String(repeating: "a", count: 65), "e\u{301}", "\u{0378}"] {
      XCTAssertThrowsError(
        try StreamMetadata(namespace: "acme/chat", version: 0, values: [key: Data()]))
    }
    let all = Dictionary(uniqueKeysWithValues: (0..<64).map { ("k\($0)", Data()) })
    XCTAssertEqual(
      try StreamMetadata(namespace: "acme/chat", version: .max, values: all).byteValues, all)
    var tooMany = all
    tooMany["more"] = Data()
    XCTAssertThrowsError(try StreamMetadata(namespace: "acme/chat", version: 0, values: tooMany))
    XCTAssertThrowsError(
      try StreamMetadata(
        namespace: "acme/chat", version: 0,
        values: ["key": Data(repeating: 0, count: 1025)]))
    let tooLarge = Dictionary(
      uniqueKeysWithValues: (0..<4).map { ("k\($0)", Data(repeating: 0, count: 1024)) })
    XCTAssertThrowsError(try StreamMetadata(namespace: "acme/chat", version: 0, values: tooLarge))
    // Controls are not globally forbidden in the v4 metadata key grammar.
    let unicode = try StreamMetadata(
      namespace: "acme/chat", version: 1,
      values: ["é": Data([1]), "\u{0000}": Data()])
    XCTAssertEqual(try StreamMetadata(encoded: unicode.encoded()), unicode)
  }

  func testEncodedBytesAndProjectionHaveIndependentValueOwnership() throws {
    let metadata = try StreamMetadata(
      namespace: "acme/chat", version: 1, values: ["key": Data([1, 2])])
    var input = try metadata.encoded()
    let original = input
    let decoded = try StreamMetadata(encoded: input)
    input[input.count - 1] = 99
    var projection = decoded.byteValues!
    projection["key"]![0] = 99
    var output = try decoded.encoded()
    output[output.count - 1] = 88
    XCTAssertEqual(try decoded.encoded(), original)
    XCTAssertEqual(decoded.byteValues?["key"], Data([1, 2]))
  }

  func testRawMetadataContractProjectsTypedValuesAndRetainsWireBytes() throws {
    let metadata = try StreamMetadata(["message": .string("hello"), "count": .integer(2)])
    let original = try metadata.encoded()
    let contract = try RawStreamMetadataContract(
      contractID: "code.raw.v1", namespace: "application/json", version: 1,
      fields: [
        RawStreamMetadataField(name: "message", type: .string, required: true),
        RawStreamMetadataField(name: "count", type: .number),
      ])
    let projected = try metadata.applyingRawMetadataContract(contract)
    XCTAssertEqual(try projected.descriptorValues()["message"], .string("hello"))
    XCTAssertEqual(try projected.descriptorValues()["count"], .integer(2))
    XCTAssertEqual(try projected.encoded(), original)
  }

  func testRawMetadataContractRejectsUnknownTypeAndDecodedOverflow() throws {
    let metadata = try StreamMetadata(["message": .bool(true)])
    let contract = try RawStreamMetadataContract(
      contractID: "code.raw.v1", namespace: "application/json", version: 1,
      fields: [RawStreamMetadataField(name: "message", type: .string)])
    XCTAssertThrowsError(try metadata.applyingRawMetadataContract(contract))
    XCTAssertThrowsError(try RawStreamMetadataContract(
      contractID: "bad id", namespace: "application/json", version: 1,
      fields: []))
  }
}
