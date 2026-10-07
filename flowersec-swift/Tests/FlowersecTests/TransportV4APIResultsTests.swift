import Foundation
import XCTest
@testable import Flowersec

final class TransportAPIResultsTests: XCTestCase {
  func testTopUpErrorsPreserveSchemaScopeAndAuthorizedWriteActions() throws {
    let data = try Data(contentsOf: packageRoot().appendingPathComponent("stability/transport_v4_schema.json"))
    let schema = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let metadata = try XCTUnwrap(schema["top_up_error_metadata"] as? [String: [String: Any]])
    XCTAssertEqual(metadata.count, 17)
    for (name, entry) in metadata {
      let code = try XCTUnwrap(V4TopUpErrorCode(rawValue: name))
      let scope = try XCTUnwrap(entry["scope"] as? String)
      let actions = try XCTUnwrap(entry["write_actions"] as? [String])
      for action in [V4TopUpWriteAction.none, .terminal] {
        let result = topUpErrorProjection(code, action)
        XCTAssertEqual(result != nil, actions.contains(action.rawValue), "\(name)/\(action.rawValue)")
        if let result {
          XCTAssertEqual(result.code.rawValue, name)
          XCTAssertEqual(result.scope.rawValue, scope)
          XCTAssertEqual(result.writeAction, action)
        }
      }
    }
  }

  func testUncertainStateAndPermissionErrorsCannotBecomeTerminalFacts() {
    for code in [V4TopUpErrorCode.sourceStateUnknown, .operationConflict, .permissionDenied] {
      XCTAssertNil(topUpErrorProjection(code, .terminal))
    }
  }
}
