import Crypto
import Foundation
import XCTest
@testable import Flowersec

// Fixed public fixtures. No live READY, epoch/scope, replay or key-use authority.
final class TransportV4RecordTests: XCTestCase {
  private struct Field: Decodable {
    let name: String
    let type: String
    let `const`: UInt64?
    let max: UInt64?
  }
  private struct Domain: Decodable {
    struct Input: Decodable {
      struct Part: Decodable {
        let name: String?
        let encoding: String
        let length: Int?
        let `enum`: [UInt64]?
      }
      let parts: [Part]
    }
    let name: String
    let label_bytes: String
    let input_schema: Input
  }
  private struct Registry: Decodable {
    struct Envelope: Decodable { let layout: [Field] }
    struct Profile: Decodable { let record_aead: String; let tag_bytes: Int }
    let envelope: Envelope
    let header: [Field]
    let nonce: [Field]
    let profiles: [String: Profile]
  }
  private struct Vector: Decodable {
    let id, profile, algorithm: String
    let epoch, direction, frame_type: UInt64
    let sequence_scope, sequence: String
    let epoch_root_hex, handshake_hash_hex, key_info_hex, key_hex, nonce_hex: String
    let envelope_header_hex, record_header_hex, aad_hex, plaintext_hex, ciphertext_hex, wire_hex: String
  }
  private struct Negative: Decodable { let id, source, field, value_hex, expected_error: String }
  private struct Corpus: Decodable { let schema_sha256: String; let vectors: [Vector]; let negatives: [Negative] }
  private enum Invalid: Error { case fixture }

  private func hex(_ value: String) throws -> Data {
    let text = Array(value.utf8)
    guard text.count.isMultiple(of: 2) else { throw Invalid.fixture }
    return try Data(stride(from: 0, to: text.count, by: 2).map { i in
      guard let byte = UInt8(String(decoding: text[i...i + 1], as: UTF8.self), radix: 16) else { throw Invalid.fixture }
      return byte
    })
  }

  private func layout(_ fields: [Field], _ values: [String: UInt64]) throws -> Data {
    var out = Data()
    for field in fields {
      guard let width = ["uint8": 1, "uint16_be": 2, "uint32_be": 4, "uint64_be": 8][field.type],
        let value = field.const ?? values[field.name],
        width == 8 || value < UInt64(1) << (width * 8), field.max.map({ value <= $0 }) ?? true
      else { throw Invalid.fixture }
      var bigEndian = value.bigEndian
      out.append(withUnsafeBytes(of: &bigEndian) { Data($0).suffix(width) })
    }
    return out
  }

  private func domain(_ domains: [Domain], _ name: String, _ bytes: [String: Data], _ integers: [String: UInt64]) throws -> Data {
    guard let spec = domains.first(where: { $0.name == name }) else { throw Invalid.fixture }
    var out = try hex(spec.label_bytes)
    for part in spec.input_schema.parts {
      guard let name = part.name else { throw Invalid.fixture }
      if ["raw", "lp-bytes", "lp-ascii"].contains(part.encoding) {
        guard let value = bytes[name], part.length.map({ value.count == $0 }) ?? true else { throw Invalid.fixture }
        if part.encoding == "lp-ascii", !value.allSatisfy({ $0 < 128 }) { throw Invalid.fixture }
        if part.encoding != "raw" {
          out.append(try layout([Field(name: "length", type: "uint32_be", const: nil, max: nil)], ["length": UInt64(value.count)]))
        }
        out.append(value)
      } else {
        guard let type = ["u8": "uint8", "u32": "uint32_be", "u64": "uint64_be"][part.encoding],
          let value = integers[name], part.enum.map({ $0.contains(value) }) ?? true else { throw Invalid.fixture }
        out.append(try layout([Field(name: name, type: type, const: nil, max: nil)], integers))
      }
    }
    return out
  }

  private func seal(_ algorithm: String, _ key: Data, _ nonce: Data, _ aad: Data, _ plaintext: Data) throws -> Data {
    guard key.count == 32 else { throw Invalid.fixture }
    switch algorithm {
    case "chacha20-poly1305":
      let box = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: key), nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad)
      return box.ciphertext + box.tag
    case "aes-256-gcm":
      let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
      return box.ciphertext + box.tag
    default: throw Invalid.fixture
    }
  }

  private func open(_ algorithm: String, _ key: Data, _ nonce: Data, _ aad: Data, _ ciphertext: Data) throws -> Data {
    guard key.count == 32, ciphertext.count >= 16 else { throw Invalid.fixture }
    switch algorithm {
    case "chacha20-poly1305":
      let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
      return try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
    case "aes-256-gcm":
      let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
      return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    default: throw Invalid.fixture
    }
  }

  func testSharedRecordEncodingAndAuthentication() throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let corpus = try JSONDecoder().decode(Corpus.self, from: Data(contentsOf: root.appendingPathComponent("testdata/transport_v4/records.json")))
    let registry = try JSONDecoder().decode(Registry.self, from: Data(TransportV4Registry.recordRegistryJSON.utf8))
    let domains = try JSONDecoder().decode([Domain].self, from: Data(TransportV4Registry.domainRegistryJSON.utf8))
    XCTAssertEqual(corpus.schema_sha256, TransportV4Registry.schemaSHA256)
    XCTAssertFalse(corpus.vectors.isEmpty); XCTAssertFalse(corpus.negatives.isEmpty)
    for v in corpus.vectors {
      let profile = try XCTUnwrap(registry.profiles[v.profile])
      XCTAssertEqual(profile.record_aead, v.algorithm)
      let values: [String: UInt64] = ["epoch": v.epoch, "direction": v.direction,
        "sequence_scope": try XCTUnwrap(UInt64(v.sequence_scope)), "sequence": try XCTUnwrap(UInt64(v.sequence))]
      let header = try layout(registry.header, values), nonce = try layout(registry.nonce, values), plaintext = try hex(v.plaintext_hex)
      let envelope = try layout(registry.envelope.layout, ["payload_length": UInt64(header.count + plaintext.count + profile.tag_bytes), "frame_type": v.frame_type])
      let info = try domain(domains, "record_key", ["profile": Data(v.profile.utf8), "handshake_hash": hex(v.handshake_hash_hex)], values)
      let derived = try HKDF<SHA256>.expand(pseudoRandomKey: hex(v.epoch_root_hex), info: info, outputByteCount: 32)
      let key = derived.withUnsafeBytes { Data($0) }
      let aad = try domain(domains, "record_aad", ["profile": Data(v.profile.utf8), "envelope_header": envelope, "record_header": header], values)
      let ciphertext = try seal(profile.record_aead, key, nonce, aad, plaintext)
      for (actual, expected) in [(header, v.record_header_hex), (nonce, v.nonce_hex), (envelope, v.envelope_header_hex),
        (info, v.key_info_hex), (key, v.key_hex), (aad, v.aad_hex), (ciphertext, v.ciphertext_hex), (envelope + header + ciphertext, v.wire_hex)] {
        XCTAssertEqual(actual, try hex(expected), v.id)
      }
      XCTAssertEqual(try open(profile.record_aead, key, nonce, aad, ciphertext), plaintext, v.id)
    }
    let byID = Dictionary(uniqueKeysWithValues: corpus.vectors.map { ($0.id, $0) })
    for n in corpus.negatives {
      XCTAssertEqual(n.expected_error, "record_authentication_failed")
      let v = try XCTUnwrap(byID[n.source])
      var material = ["key": try hex(v.key_hex), "nonce": try hex(v.nonce_hex), "aad": try hex(v.aad_hex), "ciphertext": try hex(v.ciphertext_hex)]
      XCTAssertNotNil(material[n.field])
      material[n.field] = try hex(n.value_hex)
      XCTAssertThrowsError(try open(v.algorithm, material["key"]!, material["nonce"]!, material["aad"]!, material["ciphertext"]!), n.id)
    }
  }
}
