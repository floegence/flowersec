import Foundation
import XCTest
@testable import Flowersec

// Independent test arithmetic, with no live INIT/ACK owner or service reserve.
private struct V4RekeyCreditReference {
  let spec: V4JSON
  let usage: V4JSON
  let time: V4TimeReference
  init() throws {
    spec = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.rekeyCreditRegistryJSON.utf8))
    usage = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.cryptoUsageRegistryJSON.utf8))
    time = try V4TimeReference()
  }
  func compute(_ profile: String, _ operation: String, _ input: V4JSON) throws -> [String: String?] {
    guard let profile = usage["profiles"].object?[profile] else { throw V4CBORFailure("rekey_credit_profile") }
    guard let fields = spec["operations"][operation].array?.map({ $0.text! }) else { throw V4CBORFailure("rekey_credit_operation") }
    guard let object = input.object else { throw V4CBORFailure("rekey_credit_input") }
    guard object.count == fields.count, object.keys.allSatisfy({fields.contains($0)}) else { throw V4CBORFailure("rekey_credit_fields") }
    var values: [String: UInt128] = [:]
    for field in fields {
      guard let text = object[field]?.text, !text.isEmpty, text.utf8.count <= spec["quantity_max"].text!.utf8.count,
            text == "0" || text.first != "0", text.utf8.allSatisfy({(48...57).contains($0)}),
            let n = UInt64(text) else { throw V4CBORFailure("rekey_credit_integer") }
      values[field] = UInt128(n)
    }
    func v(_ key: String) -> UInt128 { values[key]! }
    func requireCapacity(_ condition: Bool) throws { guard condition else { throw V4CBORFailure("configuration_capacity") } }
    let wide = UInt128(spec["intermediate_max"].text!)!
    func product(_ a: UInt128, _ b: UInt128) throws -> UInt128 {
      let (n, overflow) = a.multipliedReportingOverflow(by: b)
      try requireCapacity(!overflow && n <= wide); return n
    }
    func ceiling(_ a: UInt128, _ b: UInt128) -> UInt128 { a / b + (a % b == 0 ? 0 : 1) }
    for field in spec["envelope_fields"].object!.values {
      let key = field["name"].text!
      if let n = values[key] {
        let bits = UInt128(field["type"].text!.dropFirst(4))!
        try requireCapacity(n >= UInt128(field["min"].uint!) && n < (UInt128(1) << bits))
      }
    }
    let b = v("burst_rounds"), r = v("refill_period_ms"), capacity = try product(b, r)
    let epochs = UInt128(profile["max_epochs"].text!)!
    try requireCapacity(b < epochs)
    if operation == "service" {
      let n = v("rate_numerator"), d = v("rate_denominator"), q = v("quantization_ms")
      try requireCapacity(d > 0 && n < d && v("issued_at_ms") < v("session_not_after_ms"))
      let dm = d - n, dp = d + n, duration = v("session_not_after_ms") - v("issued_at_ms")
      let maxError = (r - 1) / b
      try requireCapacity(maxError >= 1)
      try requireCapacity(q <= product(maxError - 1, dm) / product(2, d))
      let e = try ceiling(product(product(2, q), d), dm) + 1
      let charge = try product(b, e)
      try requireCapacity(charge < r)
      let period = r - charge
      let denominator = try product(period, dm), initial = try product(capacity, dm), rate = try product(b, dp)
      let limit = try product(epochs, denominator)
      try requireCapacity(initial < limit)
      try requireCapacity(duration <= (limit - 1 - initial) / rate)
      let (numerator, overflow) = try initial.addingReportingOverflow(product(rate, duration))
      try requireCapacity(!overflow && numerator <= wide)
      let rounds = numerator / denominator
      try requireCapacity(rounds > 0 && rounds < epochs)
      return ["service_ms":String(duration),"error_allowance_ms":String(e),"denominator_ms":String(period),
              "capacity_credit":String(capacity),"max_rounds":String(rounds),"required_epochs":String(rounds+1)]
    }
    var available = capacity
    if operation != "initial_credit" {
      let base = v("base_credit"); try requireCapacity(base <= capacity)
      let timeFields = Dictionary(uniqueKeysWithValues: ["delta_ms","rate_numerator","rate_denominator","quantization_ms"].map { ($0, V4JSON.text(String(v($0)))) })
      let elapsed = try time.compute("elapsed", .object(timeFields))
      let u = UInt128(elapsed[spec["elapsed_bound"][operation].text!]!)!
      if u < r {
        let refill = try product(b, u)
        if refill < capacity - base { available = base + refill }
      }
    }
    return ["capacity_credit":String(capacity),"available_credit":String(available),
            "post_charge_credit":available >= r ? String(available-r) : nil]
  }
}

final class TransportV4RekeyCreditTests: XCTestCase {
  func testSharedCorpus() throws {
    let reference = try V4RekeyCreditReference()
    let corpus = try JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/rekey_credit.json")))
    let vectors = corpus["vectors"].array!; XCTAssertEqual(vectors.count,48)
    for v in vectors {
      if let error = v["expected_error"].text {
        XCTAssertThrowsError(try reference.compute(v["profile"].text!,v["operation"].text!,v["input"]),v["id"].text!) { actual in
          XCTAssertEqual((actual as? V4CBORFailure)?.code,error)
        }
      } else {
        XCTAssertEqual(try reference.compute(v["profile"].text!,v["operation"].text!,v["input"]),v["expected"].object!.mapValues {$0.text},v["id"].text!)
      }
    }
  }
  func testFloorBoundariesPartialCreditAndInputs() throws {
    let reference = try V4RekeyCreditReference(), profile = TransportV4Registry.dhProfileX25519
    for duration in 1...120 {
      let input = V4JSON.object(["burst_rounds":.text("2"),"refill_period_ms":.text("30"),"request_start_budget_ms":.text("5"),
                                "issued_at_ms":.text("0"),"session_not_after_ms":.text(String(duration)),
                                "rate_numerator":.text("1"),"rate_denominator":.text("2"),"quantization_ms":.text("2")])
      let result = try reference.compute(profile,"service",input), n = Int(result["max_rounds"]!! )!
      XCTAssertLessThanOrEqual(n*12,60+6*duration); XCTAssertGreaterThan((n+1)*12,60+6*duration)
    }
    for bad: V4JSON in [.uint(1),.bool(true),.null,.text(""),.text("01"),.text("-1"),.text("+1"),.text("1.0"),.text("1\n"),.text("١"),.text("18446744073709551616")] {
      XCTAssertThrowsError(try reference.compute(profile,"initial_credit",.object(["burst_rounds":bad,"refill_period_ms":.text("30")]))) { error in
        XCTAssertEqual((error as? V4CBORFailure)?.code,"rekey_credit_integer")
      }
    }
    var input: [String: V4JSON] = ["burst_rounds":.text("2"),"refill_period_ms":.text("30"),"base_credit":.text("10"),"delta_ms":.text("9"),
                                 "rate_numerator":.text("0"),"rate_denominator":.text("1"),"quantization_ms":.text("0")]
    for _ in 0..<50 {
      let peek = try reference.compute(profile,"client_credit",.object(input))
      XCTAssertEqual(peek["available_credit"]!!,"28"); XCTAssertNotNil(peek["post_charge_credit"] as Any?); XCTAssertNil(peek["post_charge_credit"]!)
    }
    input["delta_ms"] = .text("10")
    XCTAssertEqual(try reference.compute(profile,"client_credit",.object(input))["post_charge_credit"]!!,"0")
  }
}
