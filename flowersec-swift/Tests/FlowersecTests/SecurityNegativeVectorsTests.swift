import Foundation
import XCTest

@testable import Flowersec

final class SecurityNegativeVectorsTests: XCTestCase {
  private struct Fixture: Decodable {
    let version: Int
    let profile: String
    let vectors: [Vector]
  }

  private struct Vector: Decodable {
    let id: String
    let kind: String
    let value: String
  }

  func testSharedSecurityNegativeVectorsRejectMalformedInputs() throws {
    let url = packageRoot().appendingPathComponent("testdata/transport_v2/security_negative_vectors.json")
    let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    XCTAssertEqual(fixture.version, 1)
    XCTAssertEqual(fixture.profile, "flowersec/2")
    for vector in fixture.vectors {
      let value = vector.kind == "artifact_json"
        ? Data(vector.value.utf8)
        : try data(fromHex: vector.value)
      XCTAssertThrowsError(try parse(vector.kind, value), vector.id)
    }
  }

  private func parse(_ kind: String, _ value: Data) throws {
    switch kind {
    case "artifact_json": _ = try parseArtifact(value)
    case "fsa2_hex": _ = try AdmissionCodecV2.decodeFSA2(value)
    case "fsr2_hex": _ = try RecordHeaderV2(encoded: value)
    case "open_hex": _ = try OpenPayloadV2.decode(value)
    default: throw NSError(domain: "SecurityNegativeVectors", code: 1)
    }
  }

  private func data(fromHex value: String) throws -> Data {
    guard value.count.isMultiple(of: 2) else {
      throw NSError(domain: "SecurityNegativeVectors", code: 2)
    }
    var bytes = [UInt8]()
    bytes.reserveCapacity(value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        throw NSError(domain: "SecurityNegativeVectors", code: 3)
      }
      bytes.append(byte)
      index = next
    }
    return Data(bytes)
  }
}
