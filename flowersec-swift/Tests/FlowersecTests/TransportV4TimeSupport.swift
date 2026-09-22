import Foundation
@testable import Flowersec

// Independent test-only arithmetic. No Clock, source authentication, owner,
// timer or gate. Quantization bounds observed minus ideal monotonic increments.
struct V4TimeReference {
  private let spec: V4JSON
  private let maximum: UInt128
  private let wideMaximum: UInt128
  init() throws {
    spec = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.timeArithmeticRegistryJSON.utf8))
    maximum = UInt128(spec["quantity_max"].text!)!
    wideMaximum = UInt128(spec["intermediate_max"].text!)!
  }
  func compute(_ operation: String, _ input: V4JSON) throws -> [String: String] {
    guard let fields = spec["operations"][operation].array?.map({ $0.text! }) else { throw V4CBORFailure("time_operation") }
    guard let object = input.object else { throw V4CBORFailure("time_input_object") }
    guard object.count == fields.count, object.keys.allSatisfy({ fields.contains($0) }) else { throw V4CBORFailure("time_input_fields") }
    var values: [String: UInt128] = [:]
    for key in fields {
      guard let text = object[key]?.text, !text.isEmpty, text.utf8.count <= spec["quantity_max"].text!.utf8.count,
            text == "0" || text.first != "0", text.utf8.allSatisfy({ (48...57).contains($0) }),
            let value = UInt64(text), UInt128(value) <= maximum else { throw V4CBORFailure("time_integer") }
      values[key] = UInt128(value)
    }
    func v(_ key: String) -> UInt128 { values[key]! }
    func checked(_ value: UInt128) throws -> UInt128 {
      guard value <= maximum else { throw V4CBORFailure("time_overflow") }; return value
    }
    func product(_ a: UInt128, _ b: UInt128) throws -> UInt128 {
      let (value, overflow) = a.multipliedReportingOverflow(by: b)
      guard !overflow, value <= wideMaximum else { throw V4CBORFailure("time_overflow") }; return value
    }
    func ceiling(_ a: UInt128, _ b: UInt128) -> UInt128 { a / b + (a % b == 0 ? 0 : 1) }
    let n = v("rate_numerator"), d = v("rate_denominator"), q = v("quantization_ms")
    guard d > 0, n < d else { throw V4CBORFailure("time_rate") }
    func elapsed() throws -> (UInt128, UInt128) {
      let delta = v("delta_ms")
      let lower = try product(delta > q ? delta - q : 0, d) / (d + n)
      let upper = try checked(ceiling(product(checked(delta + q), d), d - n))
      return (lower, upper)
    }
    func interval(_ lower: UInt128, _ upper: UInt128) throws -> [String: String] {
      _ = try checked(lower); _ = try checked(upper)
      guard lower <= upper else { throw V4CBORFailure("time_interval") }
      guard v("max_width_ms") > 0, upper - lower <= v("max_width_ms") else { throw V4CBORFailure("time_width") }
      return ["lower_ms": String(lower), "upper_ms": String(upper)]
    }
    switch operation {
    case "elapsed":
      let (lower, upper) = try elapsed()
      return ["elapsed_lower_ms": String(lower), "elapsed_upper_ms": String(upper)]
    case "network_anchor":
      let (_, upper) = try elapsed()
      guard v("max_round_trip_ms") > 0, upper <= v("max_round_trip_ms") else { throw V4CBORFailure("time_round_trip") }
      guard v("sample_ms") >= v("source_error_ms") else { throw V4CBORFailure("time_overflow") }
      return try interval(v("sample_ms") - v("source_error_ms"), v("sample_ms") + v("source_error_ms") + upper)
    case "advance_anchor":
      guard v("lower_ms") <= v("upper_ms") else { throw V4CBORFailure("time_interval") }
      let (lower, upper) = try elapsed()
      guard v("max_age_ms") > 0, upper <= v("max_age_ms") else { throw V4CBORFailure("time_anchor_age") }
      return try interval(v("lower_ms") + lower, v("upper_ms") + upper)
    case "deadline_delta":
      guard v("upper_ms") < v("deadline_ms") else { throw V4CBORFailure("time_expired") }
      let budget = try product(v("deadline_ms") - v("upper_ms"), d - n) / d
      guard budget >= q else { throw V4CBORFailure("time_deadline_unrepresentable") }
      return ["delta_ms": String(try checked(budget - q))]
    case "prove_delta":
      guard v("bound_ms") > v("lower_ms") else { return ["delta_ms": "0"] }
      let rounded = try ceiling(product(v("bound_ms") - v("lower_ms"), d + n), d)
      let (result, overflow) = rounded.addingReportingOverflow(q)
      guard !overflow else { throw V4CBORFailure("time_overflow") }
      return ["delta_ms": String(try checked(result))]
    default: throw V4CBORFailure("time_operation")
    }
  }
}
