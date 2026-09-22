import Foundation
import XCTest
@testable import Flowersec

// Independent test-only charges, not input eligibility, counters or reservation.
private struct V4CryptoUsageReference {
  let spec: V4JSON
  let profiles: V4JSON
  init() throws {
    spec = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.cryptoUsageRegistryJSON.utf8))
    profiles = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.recordRegistryJSON.utf8))["profiles"]
  }
  func charge(_ profile: String, _ input: V4JSON) throws -> [String: String] {
    guard spec["profiles"].object?[profile] != nil else { throw V4CBORFailure("crypto_usage_profile") }
    guard let object = input.object else { throw V4CBORFailure("crypto_usage_input") }
    let fields = spec["charge_fields"].array!.map { $0.text! }
    guard object.count == fields.count, object.keys.allSatisfy({fields.contains($0)}) else { throw V4CBORFailure("crypto_usage_fields") }
    guard let operation = input["operation"].text, spec["operations"].array!.contains(where: {$0.text == operation}) else { throw V4CBORFailure("crypto_usage_operation") }
    let maximum = UInt64(spec["quantity_max"].text!)!
    func integer(_ value: V4JSON) throws -> UInt64 {
      guard let text = value.text, !text.isEmpty, text.utf8.count <= spec["quantity_max"].text!.utf8.count,
            text == "0" || text.first != "0", text.utf8.allSatisfy({(48...57).contains($0)}), let n = UInt64(text), n <= maximum else { throw V4CBORFailure("crypto_usage_integer") }
      return n
    }
    let aad = try integer(input["aad_bytes"]), bytes = try integer(input["input_bytes"]), tag = profiles[profile]["tag_bytes"].uint!
    let payload: UInt64, ciphertext: UInt64
    if operation == "seal" {
      let (n, overflow) = bytes.addingReportingOverflow(tag)
      guard !overflow, n <= maximum else { throw V4CBORFailure("crypto_usage_overflow") }
      payload = bytes; ciphertext = n
    } else {
      guard bytes >= tag else { throw V4CBORFailure("crypto_usage_ciphertext") }; payload = bytes - tag; ciphertext = bytes
    }
    let block = spec["authentication_block_bytes"].uint!
    func blocks(_ n: UInt64) -> UInt64 { n / block + (n % block == 0 ? 0 : 1) }
    let (sum, overflow) = blocks(aad).addingReportingOverflow(blocks(payload))
    let (total, overflow2) = sum.addingReportingOverflow(spec["length_blocks"].uint!)
    guard !overflow, !overflow2, total <= maximum else { throw V4CBORFailure("crypto_usage_overflow") }
    return ["calls":"1","authentication_blocks":String(total),"ciphertext_bytes":String(ciphertext)]
  }
}
final class TransportV4CryptoUsageTests: XCTestCase {
  func testSharedCorpus() throws {
    let reference = try V4CryptoUsageReference()
    let corpus = try JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/crypto_usage.json")))
    let vectors = corpus["vectors"].array!; XCTAssertEqual(vectors.count,28)
    for v in vectors {
      if let error = v["expected_error"].text {
        XCTAssertThrowsError(try reference.charge(v["profile"].text!,v["input"]),v["id"].text!) { actual in XCTAssertEqual((actual as? V4CBORFailure)?.code,error) }
      } else { XCTAssertEqual(try reference.charge(v["profile"].text!,v["input"]),v["expected"].object!.mapValues {$0.text!},v["id"].text!) }
    }
  }
  func testBlockBoundariesAndInputs() throws {
    let reference = try V4CryptoUsageReference()
    for profile in reference.spec["profiles"].object!.keys {
      for aad in 0...33 { for payload in 0...33 {
        let seal = try reference.charge(profile,.object(["operation":.text("seal"),"aad_bytes":.text(String(aad)),"input_bytes":.text(String(payload))]))
        let open = try reference.charge(profile,.object(["operation":.text("open"),"aad_bytes":.text(String(aad)),"input_bytes":.text(String(payload+16))]))
        XCTAssertEqual(seal,open); XCTAssertEqual(seal["authentication_blocks"],String((aad+15)/16+(payload+15)/16+1))
      } }
      for bad: V4JSON in [.uint(1),.bool(true),.null,.text(""),.text("01"),.text("-1"),.text("+1"),.text("1.0"),.text("1\n"),.text("١"),.text("18446744073709551616")] {
        XCTAssertThrowsError(try reference.charge(profile,.object(["operation":.text("seal"),"aad_bytes":bad,"input_bytes":.text("0")]))) { error in XCTAssertEqual((error as? V4CBORFailure)?.code,"crypto_usage_integer") }
      }
    }
  }
}
