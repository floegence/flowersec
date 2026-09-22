import Foundation
import XCTest
@testable import Flowersec

final class TransportV4ProfileDHTests: XCTestCase {
  private struct Vector: Decodable {
    let id: String
    let profile: String
    let private_hex: String
    let public_hex: String?
    let shared_hex: String?
    let accept: Bool
  }

  private func hex(_ value: String?) throws -> Data {
    let bytes = Array((value ?? "").utf8)
    guard bytes.count.isMultiple(of: 2) else { throw CocoaError(.coderReadCorrupt) }
    return try Data(stride(from: 0, to: bytes.count, by: 2).map { index in
      guard let byte = UInt8(String(decoding: bytes[index...index + 1], as: UTF8.self), radix: 16)
      else { throw CocoaError(.coderReadCorrupt) }
      return byte
    })
  }

  func testSharedDHAndKeyMaterialCorpus() throws {
    struct Corpus: Decodable {
      let schema_sha256: String
      let policy_revision: Int
      let vectors: [Vector]
      let keys: [Vector]
    }
    struct Policy: Decodable { let revision: Int }
    let input = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/profile_dh.json"))
    let corpus = try JSONDecoder().decode(Corpus.self, from: input)
    let policy = try JSONDecoder().decode(Policy.self, from: Data(TransportV4Registry.dhPolicyJSON.utf8))
    XCTAssertEqual(corpus.schema_sha256, TransportV4Registry.schemaSHA256)
    XCTAssertEqual(corpus.policy_revision, policy.revision)
    XCTAssertFalse(corpus.vectors.isEmpty)
    XCTAssertFalse(corpus.keys.isEmpty)
    for (keyOnly, vectors) in [(false, corpus.vectors), (true, corpus.keys)] {
      for v in vectors {
        let privateKey = try hex(v.private_hex), publicKey = try hex(v.public_hex)
        let result = Result {
          if keyOnly { return try ProfileDHV4Reference.publicKey(profile: v.profile, privateKey: privateKey) }
          return try ProfileDHV4Reference.derive(profile: v.profile, privateKey: privateKey, publicKey: publicKey)
        }
        if v.accept {
          XCTAssertEqual(try result.get(), try hex(keyOnly ? v.public_hex : v.shared_hex), v.id)
        } else {
          switch result {
          case .success: XCTFail("invalid DH material escaped: \(v.id)")
          case .failure(let error): XCTAssertEqual(error as? ProfileDHV4Reference.Failure, .invalidDH, v.id)
          }
        }
        XCTAssertEqual(privateKey, try hex(v.private_hex))
        XCTAssertEqual(publicKey, try hex(v.public_hex))
      }
    }
    XCTAssertThrowsError(try ProfileDHV4Reference.derive(profile: "unregistered", privateKey: Data(count: 32), publicKey: Data(count: 32))) {
      XCTAssertEqual(($0 as? ProfileDHV4Reference.Failure)?.code, TransportV4Registry.dhFailure)
    }
  }
}
