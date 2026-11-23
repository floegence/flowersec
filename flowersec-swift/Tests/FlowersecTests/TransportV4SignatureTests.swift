import Crypto
import Foundation
import XCTest
@testable import Flowersec

// Public-fixture primitive interoperability, not runtime credential validation.
final class TransportV4SignatureTests: XCTestCase {
  private struct Corpus: Decodable {
    let schema_sha256: String
    let signing_seed_hex: String
    let vectors: [Vector]
  }

  private struct Vector: Decodable {
    let id: String
    let domain: String?
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

  func testV4SignatureVectors() throws {
    let input = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/signatures.json"))
    let corpus = try JSONDecoder().decode(Corpus.self, from: input)
    XCTAssertEqual(corpus.schema_sha256, TransportV4Registry.schemaSHA256)
    let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: hex(corpus.signing_seed_hex))
    var covered = Set<String>()
    var knownAnswer = false
    for vector in corpus.vectors {
      let message = try hex(vector.message_hex), signature = try hex(vector.signature_hex)
      let keyBytes = try hex(vector.public_key_hex)
      let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: keyBytes)
      let valid = publicKey?.isValidSignature(signature, for: message) ?? false
      XCTAssertEqual(valid, vector.accept, vector.id)
      if vector.accept {
        XCTAssertEqual(signingKey.publicKey.rawRepresentation, keyBytes, vector.id)
        // CryptoKit documents randomized Ed25519 signing. The shared input and
        // received signature remain exact; freshly signed bytes need not match.
        let generated = try signingKey.signature(for: message)
        XCTAssertEqual(generated.count, 64, vector.id)
        XCTAssertTrue(signingKey.publicKey.isValidSignature(generated, for: message), vector.id)
        if let domain = vector.domain { covered.insert(domain) } else { knownAnswer = true }
      }
    }
    let domains = try JSONSerialization.jsonObject(with: Data(TransportV4Registry.domainRegistryJSON.utf8)) as? [[String: Any]]
    for domain in try XCTUnwrap(domains) where domain["operation"] as? String == "ed25519" {
      XCTAssertTrue(covered.contains(try XCTUnwrap(domain["name"] as? String)))
    }
    XCTAssertTrue(knownAnswer, "missing external known-answer vector")
  }
}
