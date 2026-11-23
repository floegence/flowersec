import Crypto
import Clibsodium
import Foundation
import XCTest
@testable import Flowersec

final class TransportV4StrictSignatureTests: XCTestCase {
  private struct Vector: Decodable {
    let id: String
    let message_hex: String
    let public_key_hex: String
    let signature_hex: String
    let accept: Bool
  }

  private func hex(_ value: String) throws -> Data {
    let bytes = Array(value.utf8)
    guard bytes.count.isMultiple(of: 2) else { throw CocoaError(.coderReadCorrupt) }
    var result = Data()
    for index in stride(from: 0, to: bytes.count, by: 2) {
      guard let byte = UInt8(String(decoding: bytes[index...index + 1], as: UTF8.self), radix: 16)
      else { throw CocoaError(.coderReadCorrupt) }
      result.append(byte)
    }
    return result
  }

  func testSharedStrictAcceptanceAndSignerOutputGate() throws {
    XCTAssertEqual(String(cString: sodium_version_string()), "1.0.22")
    struct Corpus: Decodable {
      let schema_sha256: String
      let policy_revision: Int
      let vectors: [Vector]
    }
    struct Policy: Decodable { let revision: Int }
    let input = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/strict_signatures.json"))
    let corpus = try JSONDecoder().decode(Corpus.self, from: input)
    let policy = try JSONDecoder().decode(Policy.self, from: Data(TransportV4Registry.strictEd25519PolicyJSON.utf8))
    XCTAssertEqual(corpus.schema_sha256, TransportV4Registry.schemaSHA256)
    XCTAssertEqual(corpus.policy_revision, policy.revision)
    XCTAssertFalse(corpus.vectors.isEmpty)
    for vector in corpus.vectors {
      let message = try hex(vector.message_hex), key = try hex(vector.public_key_hex)
      let signature = try hex(vector.signature_hex)
      XCTAssertEqual(StrictEd25519V4Reference.verify(signature: signature, message: message, publicKey: key), vector.accept, vector.id)
      var calls = 0
      let result = Result {
        try StrictEd25519V4Reference.signOnce(message: message) {
          calls += 1
          return (key, signature)
        }
      }
      XCTAssertEqual(calls, 1, vector.id)
      if vector.accept {
        XCTAssertEqual(try result.get(), signature, vector.id)
      } else {
        switch result {
        case .success: XCTFail("invalid signer output escaped: \(vector.id)")
        case .failure(let error):
          XCTAssertEqual(error as? StrictEd25519V4Reference.Failure, .signatureGenerationFailed, vector.id)
        }
      }
      XCTAssertEqual(message, try hex(vector.message_hex))
      XCTAssertEqual(key, try hex(vector.public_key_hex))
      XCTAssertEqual(signature, try hex(vector.signature_hex))
    }
  }

  func testFreshSignerOutputAndStableFailures() throws {
    struct Corpus: Decodable {
      let signing_seed_hex: String
      let vectors: [Vector]
    }
    let input = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/signatures.json"))
    let corpus = try JSONDecoder().decode(Corpus.self, from: input)
    let seed = try hex(corpus.signing_seed_hex)
    for vector in corpus.vectors where vector.accept {
      let message = try hex(vector.message_hex), key = try hex(vector.public_key_hex)
      let signature = try StrictEd25519V4Reference.sign(message: message, seed: seed)
      // CryptoKit may randomize signing; independent libsodium checks the fresh
      // output rather than requiring deterministic equality with the fixture.
      XCTAssertTrue(StrictEd25519V4Reference.verify(signature: signature, message: message, publicKey: key), vector.id)
    }
    for count in [0, 31, 33, 64] {
      XCTAssertThrowsError(try StrictEd25519V4Reference.sign(message: Data(), seed: Data(count: count))) {
        XCTAssertEqual($0 as? StrictEd25519V4Reference.Failure, .signatureGenerationFailed)
      }
    }
    var calls = 0
    XCTAssertThrowsError(try StrictEd25519V4Reference.signOnce(message: Data()) {
      calls += 1
      throw CocoaError(.fileReadUnknown)
    }) {
      XCTAssertEqual($0 as? StrictEd25519V4Reference.Failure, .signatureGenerationFailed)
      XCTAssertEqual(($0 as? StrictEd25519V4Reference.Failure)?.code, TransportV4Registry.strictEd25519SigningFailure)
    }
    XCTAssertEqual(calls, 1)
  }
}
