import Foundation
import XCTest

@testable import Flowersec

final class TransportV4MetadataTests: XCTestCase {
  func testPublicMetadataConsumesSharedValidAndInvalidCorpus() throws {
    let cases = try cryptoCorpus("corpus")["vectors"].array!.filter {
      $0["schema"].text == "StreamMetadata"
    }
    XCTAssertEqual(cases.count, 28)
    for item in cases {
      let bytes = cryptoHex(item["hex"].text!)
      if item["kind"].text == "cbor_fields" {
        let metadata = try StreamMetadata(encodedV4: bytes)
        XCTAssertEqual(try metadata.encodedV4(), bytes, item["id"].text!)
        let rebuilt = try StreamMetadata(
          namespace: metadata.v4Namespace!,
          version: metadata.v4Version!, values: metadata.v4Values!)
        XCTAssertEqual(rebuilt, metadata, item["id"].text!)
      } else {
        XCTAssertThrowsError(try StreamMetadata(encodedV4: bytes), item["id"].text!) {
          XCTAssertEqual($0 as? StreamMetadataError, .invalidValue)
        }
      }
    }
  }

  func testEmptySentinelAndOrdinaryEmptyMapRemainDistinctFromJSON() throws {
    XCTAssertEqual(try StreamMetadata(encodedV4: Data()), .empty)
    XCTAssertEqual(try StreamMetadata.empty.encodedV4(), Data())
    XCTAssertNil(StreamMetadata.empty.v4Namespace)
    let metadata = try StreamMetadata(namespace: "acme/chat", version: 0, values: [:])
    XCTAssertNotEqual(metadata, .empty)
    XCTAssertEqual(try metadata.encodedV4(), cryptoHex("a3006961636d652f63686174010002a0"))
    XCTAssertEqual(metadata.v4Values, [:])
    XCTAssertThrowsError(try TransportV3MetadataCodec.encode(metadata))
    let json = try StreamMetadata(["key": .string("value")])
    XCTAssertEqual(json.v4Namespace, "application/json")
    XCTAssertEqual(json.v4Version, 1)
    XCTAssertEqual(json.v4Values?["key"], Data("\"value\"".utf8))
    XCTAssertEqual(try TransportV3MetadataCodec.encode(.empty), Data("{}".utf8))
  }

  func testJSONConvenienceUsesV4BytesWithoutChangingApplicationNumbersOrText() throws {
    let values: [String: JSONValue] = [
      "integer": .integer(.max), "fraction": .number(0.125),
      "text": .string("e\u{301}"), "array": .array([.null, .bool(true)]),
    ]
    let metadata = try StreamMetadata(values)
    let decoded = try StreamMetadata(encodedV4: metadata.encodedV4())
    XCTAssertEqual(try decoded.jsonValues(), values)
    XCTAssertEqual(metadata, decoded)
    XCTAssertThrowsError(try StreamMetadata(["number": .number(.infinity)]))
    XCTAssertThrowsError(try StreamMetadata(["large": .string(String(repeating: "x", count: 1025))]))
    let opaque = try StreamMetadata(namespace: "example/binary", version: 1, values: ["key": Data([255])])
    XCTAssertThrowsError(try opaque.jsonValues())
    XCTAssertEqual(opaque.v4Values?["key"], Data([255]))
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
      try StreamMetadata(namespace: "acme/chat", version: .max, values: all).v4Values, all)
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
    XCTAssertEqual(try StreamMetadata(encodedV4: unicode.encodedV4()), unicode)
  }

  func testEncodedBytesAndProjectionHaveIndependentValueOwnership() throws {
    let metadata = try StreamMetadata(
      namespace: "acme/chat", version: 1, values: ["key": Data([1, 2])])
    var input = try metadata.encodedV4()
    let original = input
    let decoded = try StreamMetadata(encodedV4: input)
    input[input.count - 1] = 99
    var projection = decoded.v4Values!
    projection["key"]![0] = 99
    var output = try decoded.encodedV4()
    output[output.count - 1] = 88
    XCTAssertEqual(try decoded.encodedV4(), original)
    XCTAssertEqual(decoded.v4Values?["key"], Data([1, 2]))
  }

  func testRawMetadataContractProjectsTypedValuesAndRetainsWireBytes() throws {
    let metadata = try StreamMetadata(["message": .string("hello"), "count": .integer(2)])
    let original = try metadata.encodedV4()
    let contract = try RawStreamMetadataContract(
      contractID: "code.raw.v1", namespace: "application/json", version: 1,
      fields: [
        RawStreamMetadataField(name: "message", type: .string, required: true),
        RawStreamMetadataField(name: "count", type: .number),
      ])
    let projected = try metadata.applyingRawMetadataContract(contract)
    XCTAssertEqual(try projected.descriptorValues()["message"], .string("hello"))
    XCTAssertEqual(try projected.descriptorValues()["count"], .integer(2))
    XCTAssertEqual(try projected.encodedV4(), original)
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
