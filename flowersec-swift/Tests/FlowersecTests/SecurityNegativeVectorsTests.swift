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

  func testBoundedSharedFrameMutationsFailClosed() throws {
    let validFSA2 = try data(fromHex: "46534132020200086361706163697479")
    let validFSR2 = try RecordHeaderV2(epoch: 0, sequence: 0, ciphertextLength: 16).encoded()
    let validOpen = try OpenPayloadV2(
      logicalStreamID: 1,
      fss2Hash: Data(repeating: 0, count: 32),
      kind: "rpc",
      metadata: Data("{}".utf8)
    ).encoded()

    for (name, frame, parser) in [
      ("fsa2", validFSA2, { try AdmissionCodecV2.decodeFSA2($0) }),
      ("fsr2", validFSR2, { try RecordHeaderV2(encoded: $0) }),
      ("open", validOpen, { try OpenPayloadV2.decode($0) }),
    ] as [(String, Data, (Data) throws -> Any)] {
      XCTAssertNoThrow(try parser(frame), "\(name)/valid")
      for (mutation, value) in boundedMutations(frame) {
        XCTAssertThrowsError(try parser(value), "\(name)/\(mutation)")
      }
    }

    let document = try XCTUnwrap(
      JSONSerialization.jsonObject(
        with: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v2/artifact_vectors.json"))
      ) as? [String: Any]
    )
    let positives = try XCTUnwrap(document["positive"] as? [[String: Any]])
    let artifactJSON = try XCTUnwrap(positives.first?["artifact_json"] as? String)
    XCTAssertNoThrow(try parseArtifactV2(Data(artifactJSON.utf8)))
    for (mutation, value) in boundedTextMutations(artifactJSON) {
      XCTAssertThrowsError(try parseArtifactV2(Data(value.utf8)), "artifact/\(mutation)")
    }

    let validEnvelope = Data("{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1}".utf8)
    XCTAssertNoThrow(try RPCEnvelope(data: validEnvelope))
    for (name, value) in [
      ("unsafe-integer", "{\"payload\":{},\"request_id\":9007199254740992,\"response_to\":0,\"type_id\":1}"),
      ("fractional-id", "{\"payload\":{},\"request_id\":1.5,\"response_to\":0,\"type_id\":1}"),
      ("boolean-type-id", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":true}"),
      ("negative-type-id", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":-1}"),
      ("fractional-type-id", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1.5}"),
      ("oversized-type-id", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":4294967296}"),
      ("boolean-error-code", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1,\"error\":{\"code\":true}}"),
      ("negative-error-code", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1,\"error\":{\"code\":-1}}"),
      ("fractional-error-code", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1,\"error\":{\"code\":1.5}}"),
      ("oversized-error-code", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1,\"error\":{\"code\":4294967296}}"),
      ("invalid-error-message", "{\"payload\":{},\"request_id\":1,\"response_to\":0,\"type_id\":1,\"error\":{\"code\":1,\"message\":2}}"),
    ] {
      XCTAssertThrowsError(try RPCEnvelope(data: Data(value.utf8)), name)
    }
  }

  private func parse(_ kind: String, _ value: Data) throws {
    switch kind {
    case "artifact_json": _ = try parseArtifactV2(value)
    case "fsa2_hex": _ = try AdmissionCodecV2.decodeFSA2(value)
    case "fsr2_hex": _ = try RecordHeaderV2(encoded: value)
    case "open_hex": _ = try OpenPayloadV2.decode(value)
    default: throw NSError(domain: "SecurityNegativeVectors", code: 1)
    }
  }

  private func boundedMutations(_ frame: Data) -> [(String, Data)] {
    let points = Array(Set([0, 1, 4, 8, frame.count / 2, frame.count - 1]))
      .filter { $0 >= 0 && $0 < frame.count }
    var mutations = points.map { ("truncate-\($0)", Data(frame.prefix($0))) }
    var trailing = frame
    trailing.append(0)
    mutations.append(("trailing-byte", trailing))
    return mutations
  }

  private func boundedTextMutations(_ value: String) -> [(String, String)] {
    let points = Array(Set([0, 1, value.count / 2, value.count - 1]))
      .filter { $0 >= 0 && $0 < value.count }
    return points.map { ("truncate-\($0)", String(value.prefix($0))) }
      + [
        ("trailing-json", "\(value){}"),
        ("duplicate-version", value.replacingOccurrences(of: "\"v\":2", with: "\"v\":2,\"v\":2")),
      ]
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
