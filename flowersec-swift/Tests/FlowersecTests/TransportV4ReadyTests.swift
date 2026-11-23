import Crypto
import Foundation
import XCTest
@testable import Flowersec

// Public fixture composition only, not authenticated credentials or dual-READY
// Session publication, lifecycle, resource or authorization ownership.
final class TransportV4ReadyTests: XCTestCase {
  private struct Field: Decodable {
    let name, type: String
    let length: Int?
    let bitmask: UInt64?
    let `enum`: [String: UInt64]?
    let `const`: UInt64?
  }
  private struct Definition: Decodable { let fields: [String: Field] }
  private struct Domain: Decodable {
    struct Input: Decodable {
      struct Part: Decodable { let name: String?; let encoding: String; let length: Int?; let `enum`: [UInt64]? }
      let parts: [Part]
    }
    let name, label_bytes: String
    let input_schema: Input
  }
  private struct Record: Decodable {
    struct Envelope: Decodable { let layout: [Field] }
    let envelope: Envelope
    let profiles: [String: Profile]
    struct Profile: Decodable {}
  }
  private enum Invalid: Error { case fixture }
  private lazy var maps = try! JSONDecoder().decode([String: Definition].self, from: Data(TransportV4Registry.readyRegistryJSON.utf8))
  private lazy var domains = try! JSONDecoder().decode([Domain].self, from: Data(TransportV4Registry.domainRegistryJSON.utf8))
  private lazy var record = try! JSONDecoder().decode(Record.self, from: Data(TransportV4Registry.recordRegistryJSON.utf8))

  private func hex(_ text: String) throws -> Data {
    let chars = Array(text.utf8)
    guard chars.count.isMultiple(of: 2) else { throw Invalid.fixture }
    return try Data(stride(from: 0, to: chars.count, by: 2).map { i in
      guard let b = UInt8(String(decoding: chars[i...i + 1], as: UTF8.self), radix: 16) else { throw Invalid.fixture }; return b
    })
  }
  private func text(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
  private func bytes(_ context: [String: Any], _ key: String) throws -> Data {
    guard let value = context[key] as? String else { throw Invalid.fixture }; return try hex(value)
  }
  private func unsigned(_ value: UInt64, _ width: Int) throws -> Data {
    guard (1...8).contains(width), width == 8 || value < UInt64(1) << (width * 8) else { throw Invalid.fixture }
    var n = value.bigEndian
    return withUnsafeBytes(of: &n) { Data($0).suffix(width) }
  }
  private func head(_ major: UInt8, _ value: UInt64) throws -> Data {
    if value < 24 { return Data([major << 5 | UInt8(value)]) }
    for (width, ai): (Int, UInt8) in [(1,24),(2,25),(4,26),(8,27)] {
      if width == 8 || value < UInt64(1) << (width * 8) { return Data([major << 5 | ai]) + (try unsigned(value, width)) }
    }
    throw Invalid.fixture
  }
  private func fields(_ name: String) throws -> [(UInt64, Field)] {
    guard let definition = maps[name] else { throw Invalid.fixture }
    return try definition.fields.map { key, field in
      guard let id = UInt64(key) else { throw Invalid.fixture }; return (id,field)
    }.sorted { $0.0 < $1.0 }
  }
  private func encode(_ name: String, _ context: [String: Any]) throws -> Data {
    let entries = try fields(name); var out = try head(5, UInt64(entries.count))
    for (id, field) in entries {
      out.append(try head(0,id))
      switch field.type {
      case "bytes":
        let value = try bytes(context, field.name + "_hex")
        guard value.count == field.length else { throw Invalid.fixture }
        out.append(try head(2,UInt64(value.count))); out.append(value)
      case "text":
        guard let value = context[field.name] as? String, record.profiles[value] != nil else { throw Invalid.fixture }
        let raw = Data(value.utf8); out.append(try head(3,UInt64(raw.count))); out.append(raw)
      case "uint8", "uint64":
        guard let value = context[field.name] as? UInt64,
          field.type != "uint8" || value <= 255,
          field.enum.map({ $0.values.contains(value) }) ?? true,
          field.bitmask.map({ value & ~$0 == 0 }) ?? true else { throw Invalid.fixture }
        out.append(try head(0,value))
      default: throw Invalid.fixture
      }
    }
    return out
  }
  private func decode(_ wire: Data) throws -> [String: Any] {
    var cursor = 0; var out: [String: Any] = [:]
    func take(_ expected: Data) throws {
      guard cursor + expected.count <= wire.count,
        wire.subdata(in: cursor..<cursor + expected.count) == expected else { throw Invalid.fixture }
      cursor += expected.count
    }
    let entries = try fields("READY"); try take(head(5,UInt64(entries.count)))
    for (id, field) in entries {
      guard field.type == "bytes", let length = field.length else { throw Invalid.fixture }
      try take(head(0,id)); try take(head(2,UInt64(length)))
      guard cursor + length <= wire.count else { throw Invalid.fixture }
      out[field.name + "_hex"] = text(wire.subdata(in: cursor..<cursor + length)); cursor += length
    }
    guard cursor == wire.count else { throw Invalid.fixture }; return out
  }
  private func domain(_ name: String, _ values: [String: Data], _ role: UInt64) throws -> Data {
    guard let spec = domains.first(where: { $0.name == name }) else { throw Invalid.fixture }
    var out = try hex(spec.label_bytes)
    for part in spec.input_schema.parts {
      if part.encoding == "u8" {
        guard part.enum.map({ $0.contains(role) }) ?? true else { throw Invalid.fixture }; out.append(try unsigned(role,1))
      } else {
        guard ["lp-map", "lp-ascii", "lp-bytes"].contains(part.encoding), let name = part.name,
          let value = values[name], part.length.map({ value.count == $0 }) ?? true else { throw Invalid.fixture }
        out.append(try unsigned(UInt64(value.count),4)); out.append(value)
      }
    }
    return out
  }
  private func material(_ context: [String: Any], _ proof: Data) throws -> [String: Data] {
    guard let role = context["role"] as? UInt64, let profile = context["crypto_profile_id"] as? String else { throw Invalid.fixture }
    let proofInput = try encode("ReadyProofInput",context)
    let message = try domain("ready_identity",["proof":proofInput],role)
    let info = try domain("ready_key",["profile":Data(profile.utf8),"handshake_hash":bytes(context,"handshake_hash_hex"),"context_digest":bytes(context,"transport_context_digest_hex")],role)
    let root = try bytes(context,"epoch_root_hex"); guard root.count == 32 else { throw Invalid.fixture }
    let key = HKDF<SHA256>.expand(pseudoRandomKey:root,info:info,outputByteCount:32)
    var values = context; values["identity_proof_hex"] = text(proof)
    let macInput = try encode("ReadyMACInput",values), macMessage = try domain("ready_mac",["mac_input":macInput],role)
    let mac = Data(HMAC<SHA256>.authenticationCode(for:macMessage,using:key))
    return ["proof_input_hex":proofInput,"signature_message_hex":message,"key_info_hex":info,
      "key_hex":key.withUnsafeBytes { Data($0) },"mac_input_hex":macInput,"mac_message_hex":macMessage,"confirmation_mac_hex":mac]
  }
  private func verify(_ context: [String: Any], _ wire: Data) -> Bool {
    do {
      let received = try decode(wire), proof = try bytes(received,"identity_proof_hex"), m = try material(context,proof)
      return try HMAC<SHA256>.isValidAuthenticationCode(bytes(received,"confirmation_mac_hex"), authenticating:m["mac_message_hex"]!,using:SymmetricKey(data:m["key_hex"]!))
        && StrictEd25519V4Reference.verify(signature:proof,message:m["signature_message_hex"]!,publicKey:bytes(context,"public_key_hex"))
    } catch { return false }
  }

  func testSharedReadyCompositionAndRejection() throws {
    let root = URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let corpus = try XCTUnwrap(JSONSerialization.jsonObject(with:Data(contentsOf:root.appendingPathComponent("testdata/transport_v4/ready.json"))) as? [String: Any])
    XCTAssertEqual(corpus["schema_sha256"] as? String,TransportV4Registry.schemaSHA256)
    let vectors = try XCTUnwrap(corpus["vectors"] as? [[String: Any]])
    let negatives = try XCTUnwrap(corpus["negatives"] as? [[String: Any]])
    XCTAssertEqual(vectors.count,8); XCTAssertFalse(negatives.isEmpty)
    var contexts: [String: [String: Any]] = [:]
    for v in vectors {
      let id = try XCTUnwrap(v["id"] as? String), context = try XCTUnwrap(v["context"] as? [String: Any]); contexts[id] = context
      let proof = try bytes(v,"identity_proof_hex"), m = try material(context,proof)
      for (name,value) in m { XCTAssertEqual(value,try bytes(v,name),id+name) }
      let ready = try encode("READY",["identity_proof_hex":text(proof),"confirmation_mac_hex":text(m["confirmation_mac_hex"]!)])
      var envelope = Data(); let values: [String: UInt64] = ["payload_length":UInt64(ready.count),"frame_type":UInt64(TransportV4Registry.frameReady)]
      for field in record.envelope.layout {
        let width = try XCTUnwrap(["uint8":1,"uint16_be":2,"uint32_be":4][field.type])
        envelope.append(try unsigned(XCTUnwrap(field.const ?? values[field.name]),width))
      }
      XCTAssertEqual(ready,try bytes(v,"ready_hex")); XCTAssertEqual(envelope,try bytes(v,"envelope_header_hex"))
      XCTAssertEqual(envelope+ready,try bytes(v,"wire_hex")); XCTAssertTrue(verify(context,ready),id)
      // CryptoKit may randomize signatures; authenticate its exact fresh output
      // and bind that output into a newly computed MAC instead of byte comparing.
      let signed = try StrictEd25519V4Reference.sign(message:m["signature_message_hex"]!,seed:bytes(v,"signing_seed_hex"))
      let own = try material(context,signed)
      XCTAssertTrue(verify(context,try encode("READY",["identity_proof_hex":text(signed),"confirmation_mac_hex":text(own["confirmation_mac_hex"]!)])),id)
    }
    for n in negatives {
      let id = try XCTUnwrap(n["id"] as? String), source = try XCTUnwrap(n["source"] as? String)
      var context = try XCTUnwrap(contexts[source]); let patch = try XCTUnwrap(n["context_patch"] as? [String: Any])
      for (key,value) in patch { context[key] = value }
      XCTAssertEqual(n["expected_error"] as? String,"ready_rejected")
      XCTAssertFalse(verify(context,try bytes(n,"ready_hex")),id)
    }
  }
}
