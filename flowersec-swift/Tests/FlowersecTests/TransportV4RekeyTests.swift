import Crypto
import Foundation
import XCTest
@testable import Flowersec

// Public fixed transactions only. Expected-byte matching is not a receiver
// codec, barrier proof, epoch installation, clock or single-publisher gate.
final class TransportV4RekeyTests: XCTestCase {
  private typealias Object = [String: Any]
  private enum Invalid: Error { case fixture }
  private func object(_ value: Any?) throws -> Object { guard let v = value as? Object else { throw Invalid.fixture }; return v }
  private func list(_ value: Any?) throws -> [Object] { guard let v = value as? [Object] else { throw Invalid.fixture }; return v }
  private func text(_ value: Any?) throws -> String { guard let v = value as? String else { throw Invalid.fixture }; return v }
  private func number(_ value: Any?) throws -> UInt64 {
    if let v = value as? String, let n = UInt64(v) { return n }
    guard let v = value as? NSNumber, v.doubleValue >= 0, v.doubleValue == Double(v.uint64Value) else { throw Invalid.fixture }
    return v.uint64Value
  }
  private func hex(_ value: Any?) throws -> Data {
    if let b = value as? Data { return b }
    let s = Array(try text(value).utf8)
    guard s.count.isMultiple(of: 2) else { throw Invalid.fixture }
    return try Data(stride(from: 0, to: s.count, by: 2).map { i in
      guard let b = UInt8(String(decoding: s[i...i+1], as: UTF8.self), radix: 16) else { throw Invalid.fixture }; return b
    })
  }
  private func uint(_ n: UInt64, _ width: Int) throws -> Data {
    guard width == 8 || n < UInt64(1) << (width * 8) else { throw Invalid.fixture }
    var be = n.bigEndian; return withUnsafeBytes(of: &be) { Data($0).suffix(width) }
  }
  private func head(_ major: UInt8, _ n: UInt64) throws -> Data {
    if n < 24 { return Data([major << 5 | UInt8(n)]) }
    for (width, ai) in [(1, UInt8(24)), (2, 25), (4, 26), (8, 27)] {
      if width == 8 || n < UInt64(1) << (width * 8) { return try Data([major << 5 | ai]) + uint(n,width) }
    }
    throw Invalid.fixture
  }
  private func expand(_ key: Data, _ info: Data) -> Data {
    HKDF<SHA256>.expand(pseudoRandomKey: key, info: info, outputByteCount: 32).withUnsafeBytes { Data($0) }
  }
  private func mac(_ key: Data, _ message: Data) -> Data { Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))) }
  private func encode(_ registry: Object, _ profiles: Object, _ name: String, _ profile: String, _ values: Object, _ unsigned: Bool = false) throws -> Data {
    let def = try object(registry[name]), fields = try object(def["fields"])
    let ids = fields.keys.compactMap(UInt64.init).sorted().filter { !unsigned || $0 != (try? number(def["mac_field"])) }
    var out = try head(5,UInt64(ids.count))
    for id in ids {
      let f = try object(fields[String(id)]), name = try text(f["name"]), kind = try text(f["type"])
      out += try head(0,id)
      if kind.hasPrefix("uint") {
        let n = try number(values[name]), bits = try XCTUnwrap(Int(kind.dropFirst(4)))
        guard bits == 64 || n < UInt64(1) << bits else { throw Invalid.fixture }
        if let constant = f["const"], n != (try number(constant)) { throw Invalid.fixture }
        out += try head(0,n)
      } else if kind == "bytes" {
        let b = try hex(values[name]), p = try object(profiles[profile])
        let length = try number((f["profile_public_key"] as? Bool == true) ? p["dh_public_bytes"] : f["length"])
        guard b.count == length else { throw Invalid.fixture }; out += try head(2,length); out += b
      } else if kind == "array" {
        let items = try list(values[name]), item = try object(f["items"]), nested = try text(item["schema_ref"])
        out += try head(4,UInt64(items.count))
        for v in items { out += try encode(registry,profiles,nested,profile,v) }
      } else { throw Invalid.fixture }
    }
    return out
  }
  private func domain(_ domains: [Object], _ name: String, _ c: Object, _ phase: UInt64 = 0, _ role: UInt64 = 0, _ extra: [String: Data] = [:], _ integers: [String: UInt64] = [:]) throws -> Data {
    let spec = try XCTUnwrap(domains.first { $0["name"] as? String == name }), input = try object(spec["input_schema"])
    var values = try ["profile": Data(text(c["profile"]).utf8), "handshake_hash": hex(c["handshake_hash_hex"]), "context_digest": hex(c["context_digest_hex"]), "rekey_id": hex(c["rekey_id_hex"])]
    values.merge(extra) { _, new in new }
    var nums = try ["epoch": number(c["epoch"]), "next_epoch": number(c["next_epoch"]), "phase": phase, "role": role]
    nums.merge(integers) { _, new in new }
    var out = try hex(spec["label_bytes"])
    for part in try list(input["parts"]) {
      let field = try text(part["name"]), encoding = try text(part["encoding"])
      if encoding == "raw" || encoding.hasPrefix("lp-") {
        let b = try XCTUnwrap(values[field]); if let length = part["length"], b.count != (try number(length)) { throw Invalid.fixture }
        if encoding != "raw" { out += try uint(UInt64(b.count),4) }; out += b
      } else {
        let width = try XCTUnwrap(["u8":1,"u32":4,"u64":8][encoding]); out += try uint(XCTUnwrap(nums[field]),width)
      }
    }
    return out
  }
  private func message(_ reg: Object, _ profiles: Object, _ domains: [Object], _ c: Object, _ p: Object, _ base: Data, _ values: Object) throws -> (Data, [String: Data]) {
    let epoch = try number(c["epoch"]), next = try number(c["next_epoch"])
    guard epoch < UInt32.max, next == epoch+1, base.count == 32 else { throw Invalid.fixture }
    let name = try text(p["schema"]), def = try object(reg[name]), role = try number(def["sender_role"]), phase = try number(p["phase"])
    var v = values; v["phase"] = phase; v["next_epoch"] = next; v["rekey_id"] = try hex(c["rekey_id_hex"])
    let unsigned = try encode(reg,profiles,name,text(c["profile"]),v,true)
    let info = try domain(domains,"rekey_confirm_key",c,phase,role), key = expand(base,info)
    let input = try domain(domains,"rekey_confirm_mac",c,phase,role,["message":unsigned]), confirmation = mac(key,input)
    v["confirmation_mac"] = confirmation
    return try (encode(reg,profiles,name,text(c["profile"]),v),["unsigned_hex":unsigned,"key_info_hex":info,"key_hex":key,"mac_message_hex":input,"confirmation_mac_hex":confirmation])
  }
  private func layout(_ fields: [Object], _ values: [String: UInt64]) throws -> Data {
    var out = Data()
    for f in fields {
      let name = try text(f["name"]), kind = try text(f["type"]), width = try XCTUnwrap(["uint8":1,"uint16_be":2,"uint32_be":4,"uint64_be":8][kind])
      let n = try number(f["const"] ?? values[name]); out += try uint(n,width)
    }
    return out
  }

  func testSharedRekeyCompositionAndFixedTransactionRejection() throws {
    let raw = try Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/rekey.json"))
    let corpus = try object(JSONSerialization.jsonObject(with: raw))
    let reg = try object(JSONSerialization.jsonObject(with: Data(TransportV4Registry.rekeyRegistryJSON.utf8)))
    let records = try object(JSONSerialization.jsonObject(with: Data(TransportV4Registry.recordRegistryJSON.utf8))), profiles = try object(records["profiles"])
    let domains = try list(JSONSerialization.jsonObject(with: Data(TransportV4Registry.domainRegistryJSON.utf8)))
    XCTAssertEqual(try text(corpus["schema_sha256"]),TransportV4Registry.schemaSHA256)
    let rounds = try list(corpus["rounds"]); XCTAssertEqual(rounds.count,4)
    var previous: [String:Data] = [:], phases: [String:(Object,Object,Object)] = [:]
    for r in rounds {
      let c = try object(r["context"]), input = try object(r["input"]), profile = try text(c["profile"]), spec = try object(profiles[profile])
      if try number(c["epoch"]) > 0 { XCTAssertEqual(try hex(r["old_root_hex"]),previous[profile]) }
      let cp = try ProfileDHV4Reference.publicKey(profile: profile,privateKey: hex(input["client_private_hex"]))
      let sp = try ProfileDHV4Reference.publicKey(profile: profile,privateKey: hex(input["server_private_hex"]))
      let dh = try ProfileDHV4Reference.derive(profile: profile,privateKey: hex(input["client_private_hex"]),publicKey: sp)
      XCTAssertEqual(dh,try ProfileDHV4Reference.derive(profile: profile,privateKey: hex(input["server_private_hex"]),publicKey: cp)); XCTAssertEqual(dh,try hex(r["dh_hex"]))
      let secret = try expand(hex(r["old_root_hex"]),domain(domains,"rekey_secret",c)); XCTAssertEqual(secret,try hex(r["secret_hex"]))
      var values: [Object] = [["client_ephemeral":cp,"client_barrier":try list(input["client_barrier"])],["server_ephemeral":sp,"server_barrier":try list(input["server_barrier"])],[:],[:]]
      var initial = Data(), reply = Data(), root = Data(), transcript = Data()
      for (i,p) in try list(r["phases"]).enumerated() {
        if i == 1 { values[i]["init_digest"] = try Data(SHA256.hash(data: domain(domains,"rekey_init_digest",c,0,0,["init":initial]))); XCTAssertEqual(try hex(values[i]["init_digest"]),try hex(r["init_digest_hex"])) }
        if i == 2 {
          transcript = try Data(SHA256.hash(data: domain(domains,"rekey_transcript",c,0,0,["init":initial,"reply":reply]))); XCTAssertEqual(transcript,try hex(r["transcript_hex"]))
          let prk = mac(secret,dh); XCTAssertEqual(prk,try hex(r["prk_hex"]))
          root = try expand(prk,domain(domains,"rekey_root",c,0,0,["transcript_digest":transcript])); XCTAssertEqual(root,try hex(r["new_root_hex"]))
        }
        let role = try number(p["role"]), oldSequence = try number(input[role == 0 ? "client_old_sequence":"server_old_sequence"])
        if i >= 2 { values[i]["transcript_digest"] = transcript; values[i]["old_maintenance_next_sequence"] = oldSequence+1 }
        let base = i < 2 ? secret:root, (wire,material) = try message(reg,profiles,domains,c,p,base,values[i])
        XCTAssertEqual(base,try hex(p["base_hex"])); XCTAssertEqual(wire,try hex(p["message_hex"]))
        for (k,v) in material { XCTAssertEqual(v,try hex(p[k]),k) }
        if i == 0 { initial = wire }; if i == 1 { reply = wire }
        phases[try text(p["id"])] = (c,p,values[i])
        let record = try object(p["record"]), epoch = try number(c[i < 2 ? "epoch":"next_epoch"]), sequence = i < 2 ? oldSequence:0
        XCTAssertEqual(try number(record["epoch"]),epoch); XCTAssertEqual(try number(record["sequence"]),sequence)
        XCTAssertEqual(try number(record["direction"]),try number(object(reg[text(p["schema"])])["sender_role"]))
        let nums = ["epoch":epoch,"sequence":sequence,"direction":role,"sequence_scope":UInt64(0)]
        let header = try layout(list(records["header"]),nums), nonce = try layout(list(records["nonce"]),nums)
        let envelope = try layout(list(object(records["envelope"])["layout"]),["payload_length":UInt64(header.count+wire.count)+number(spec["tag_bytes"]),"frame_type":UInt64(TransportV4Registry.frameRekey)])
        let key = try expand(i < 2 ? hex(r["old_root_hex"]):root,domain(domains,"record_key",c,0,0,[:],nums))
        let aad = try domain(domains,"record_aad",c,0,0,["envelope_header":envelope,"record_header":header],nums), sealed: Data, opened: Data
        if try text(spec["record_aead"]) == "chacha20-poly1305" {
          let box = try ChaChaPoly.seal(wire,using: SymmetricKey(data:key),nonce: ChaChaPoly.Nonce(data:nonce),authenticating:aad)
          sealed = box.ciphertext+box.tag; opened = try ChaChaPoly.open(box,using:SymmetricKey(data:key),authenticating:aad)
        } else {
          let box = try AES.GCM.seal(wire,using:SymmetricKey(data:key),nonce:AES.GCM.Nonce(data:nonce),authenticating:aad)
          sealed = box.ciphertext+box.tag; opened = try AES.GCM.open(box,using:SymmetricKey(data:key),authenticating:aad)
        }
        XCTAssertEqual(envelope+header+sealed,try hex(record["wire_hex"])); XCTAssertEqual(opened,wire)
      }
      previous[profile] = try hex(r["new_root_hex"])
    }
    let negatives = try list(corpus["negatives"]); XCTAssertFalse(negatives.isEmpty)
    for n in negatives {
      let (original,p,v) = try XCTUnwrap(phases[text(n["source"])])
      var c = original, values = v
      c.merge(try object(n["context_patch"])) { _,new in new }; values.merge(try object(n["expected"])) { _,new in new }
      let received = try hex(n["message_hex"]), base = try hex(n["base_hex"])
      let expected = try? message(reg,profiles,domains,c,p,base,values).0
      let id = try text(n["id"])
      XCTAssertNotEqual(expected,received,id)
    }
  }
}
