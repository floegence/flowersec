import Foundation
import XCTest

final class TransportV4ResourceTests: XCTestCase {
  func testPartialCostCorpus() throws {
    let corpus = try JSONSerialization.jsonObject(with: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/resource_costs.json"))) as! [String: Any]
    let vectors = corpus["vectors"] as! [[String: Any]], reference = try V4ResourceCostReference()
    XCTAssertEqual(vectors.count, 18)
    for vector in vectors {
      let input = vector["input"]!, id = vector["id"] as! String
      if let error = vector["expected_error"] as? String {
        XCTAssertThrowsError(try reference.costs(input), id) { actual in XCTAssertEqual((actual as? V4CBORFailure)?.code, error, id) }
      } else {
        let expected = vector["expected"] as! [String: Any]
        XCTAssertTrue(NSDictionary(dictionary: try reference.costs(input)).isEqual(to: expected), id)
      }
    }
    for bad: Any in [true, "1", 0.5, -1, UInt64(4294967296), NSNull()] {
      XCTAssertThrowsError(try reference.costs(["max_frame_bytes": 131072, "small_auth_slots": bad, "application_profile": "transport"])) { error in
        XCTAssertEqual((error as? V4CBORFailure)?.code, "resource_auth_slots")
      }
    }
  }
  private static let corpus = try! JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/resources.json")))
  private func basic() -> V4JSON { Self.corpus["vectors"].array!.first { $0["id"].text == "resources_empty_features" }!["input"] }
  private func replace(_ value: V4JSON, _ path: [String], _ next: V4JSON) -> V4JSON {
    guard let key = path.first else { return next }
    if var array = value.array { let index = Int(key)!; array[index] = replace(array[index], Array(path.dropFirst()), next); return .array(array) }
    var object = value.object!; object[key] = replace(object[key] ?? .null, Array(path.dropFirst()), next); return .object(object)
  }
  private func rejects(_ input: V4JSON, _ code: String, file: StaticString = #filePath, line: UInt = #line) throws {
    let reference = try V4ResourceReference()
    XCTAssertThrowsError(try reference.minimum(input), file: file, line: line) { error in
      XCTAssertEqual((error as? V4CBORFailure)?.code, code, file: file, line: line)
    }
  }

  func testSharedCorpus() throws {
    let reference = try V4ResourceReference(), vectors = Self.corpus["vectors"].array!
    XCTAssertEqual(vectors.count, 19)
    for vector in vectors {
      if let code = vector["expected_error"].text { try rejects(vector["input"], code) }
      else {
        let expected = vector["expected_ready_min"].object!.mapValues { $0.object!.mapValues { $0.text! } }
        XCTAssertEqual(try reference.minimum(vector["input"]), expected, vector["id"].text!)
      }
    }
  }

  func testCheckedArithmeticAndTypes() throws {
    for dimension in ["bytes", "work", "items"] {
      for bad: V4JSON in [.uint(1), .text("01"), .text("-1"), .text("18446744073709551616"), .null] {
        try rejects(replace(basic(), ["base", "transport_core", "0", "vector", dimension], bad), "resource_quantity")
      }
      var input = replace(basic(), ["base", "transport_core", "0", "vector", dimension], .text("18446744073709551615"))
      var second = replace(basic()["base"]["transport_core"].array![0], ["owner_instance_id"], .text("other"))
      second = replace(second, ["vector", dimension], .text("1"))
      input = replace(input, ["base", "actual_shared_refs"], .array([second]))
      try rejects(input, "resource_sum_overflow")
    }
    try rejects(replace(basic(), ["reference_limit"], .text("64")), "resource_reference_limit")
  }

  func testOriginalIdentityBytesAndChargeBinding() throws {
    let reference = try V4ResourceReference()
    for key in reference.keys {
      let second = replace(basic()["base"]["transport_core"].array![0], [key], .text("other"))
      let input = replace(basic(), ["base", "actual_shared_refs"], .array([second]))
      XCTAssertEqual(try reference.minimum(input)["sdk_owned"]?["bytes"], "200")
    }
    for key in reference.bindings {
      let second = replace(basic()["base"]["transport_core"].array![0], [key], .text("other"))
      try rejects(replace(basic(), ["base", "actual_shared_refs"], .array([second])), "resource_owner_conflict")
    }
    var input = replace(basic(), ["base", "transport_core", "0", "environment_id"], .text("é"))
    let second = replace(basic()["base"]["transport_core"].array![0], ["environment_id"], .text("e\u{301}"))
    input = replace(input, ["base", "actual_shared_refs"], .array([second]))
    XCTAssertEqual(try reference.minimum(input)["sdk_owned"]?["bytes"], "200")
  }
}
