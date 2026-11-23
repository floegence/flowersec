import Foundation
import XCTest

final class TransportV4TimeTests: XCTestCase {
  func testSharedCorpus() throws {
    let corpus = try JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/time_arithmetic.json")))
    let vectors = corpus["vectors"].array!, reference = try V4TimeReference()
    XCTAssertEqual(vectors.count, 37)
    for vector in vectors {
      let id = vector["id"].text!
      if let error = vector["expected_error"].text {
        XCTAssertThrowsError(try reference.compute(vector["operation"].text!, vector["input"]), id) { actual in
          XCTAssertEqual((actual as? V4CBORFailure)?.code, error, id)
        }
      } else {
        XCTAssertEqual(try reference.compute(vector["operation"].text!, vector["input"]), vector["expected"].object!.mapValues { $0.text! }, id)
      }
    }
  }
  func testRoundingAndInverseExtrema() throws {
    let reference = try V4TimeReference()
    for d in 1...8 { for n in 0..<d { for gap in 1...20 { for q in 0...2 {
      func run(_ operation: String, _ fields: [String: Int], _ output: String) throws -> Int {
        let all = fields.merging(["rate_numerator":n,"rate_denominator":d,"quantization_ms":q]) { _, b in b }
        let result = try reference.compute(operation, .object(all.mapValues { .text(String($0)) }))
        return Int(result[output]!)!
      }
      func elapsed(_ delta: Int, _ output: String) throws -> Int { try run("elapsed", ["delta_ms":delta], output) }
      let lo = try elapsed(gap,"elapsed_lower_ms"), hi = try elapsed(gap,"elapsed_upper_ms")
      XCTAssertLessThanOrEqual(lo * (d+n), max(0,gap-q)*d)
      XCTAssertGreaterThanOrEqual(hi * (d-n), (gap+q)*d)
      if q <= gap*(d-n)/d {
        let delta = try run("deadline_delta", ["upper_ms":0,"deadline_ms":gap], "delta_ms")
        XCTAssertLessThanOrEqual(try elapsed(delta,"elapsed_upper_ms"),gap)
        XCTAssertGreaterThan(try elapsed(delta+1,"elapsed_upper_ms"),gap)
      } else {
        XCTAssertThrowsError(try run("deadline_delta", ["upper_ms":0,"deadline_ms":gap], "delta_ms")) { error in
          XCTAssertEqual((error as? V4CBORFailure)?.code,"time_deadline_unrepresentable")
        }
      }
      let delta = try run("prove_delta", ["lower_ms":0,"bound_ms":gap], "delta_ms")
      XCTAssertGreaterThanOrEqual(try elapsed(delta,"elapsed_lower_ms"),gap)
      XCTAssertLessThan(try elapsed(delta-1,"elapsed_lower_ms"),gap)
    } } } }
  }
  func testStrictInputs() throws {
    let reference = try V4TimeReference()
    let input: [String: V4JSON] = ["rate_numerator":.text("0"),"rate_denominator":.text("1"),"quantization_ms":.text("0"),"delta_ms":.text("1")]
    for bad: V4JSON in [.uint(1),.bool(true),.null,.text(""),.text("01"),.text("-1"),.text("+1"),.text("1.0"),.text("1\n"),.text("١"),.text("18446744073709551616")] {
      var fields = input; fields["delta_ms"] = bad
      XCTAssertThrowsError(try reference.compute("elapsed", .object(fields))) { error in
        XCTAssertEqual((error as? V4CBORFailure)?.code, "time_integer")
      }
    }
    var extra = input; extra["extra"] = .text("1")
    XCTAssertThrowsError(try reference.compute("elapsed", .object(extra)))
    XCTAssertThrowsError(try reference.compute("elapsed", .null))
    XCTAssertThrowsError(try reference.compute("unknown", .object(input)))
  }
}
