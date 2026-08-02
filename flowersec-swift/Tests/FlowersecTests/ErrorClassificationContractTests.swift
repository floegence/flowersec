import Foundation
import Testing
@testable import Flowersec

struct ErrorClassificationContractTests {
  @Test func classificationsMatchSharedContract() throws {
    let document = try loadContract()
    let decisions = try #require(document["decisions"] as? [String: [String: Any]])
    try verifyCases(document["connect"], language: "swift", decisions: decisions) { code in
      classifyConnectError(try #require(ConnectError(rawValue: code)))
    }
    try verifyCases(document["session"], language: "swift", decisions: decisions) { code in
      classifySessionError(try #require(SessionError(rawValue: code)))
    }
  }

  private func verifyCases(
    _ rawCases: Any?,
    language: String,
    decisions: [String: [String: Any]],
    classify: (String) throws -> ErrorRetryClassification
  ) throws {
    let cases = try #require(rawCases as? [[String: Any]])
    for item in cases {
      let decisionName = try #require(item["decision"] as? String)
      let expected = try #require(decisions[decisionName])
      let codes = try #require(item["codes"] as? [String: [String]])
      for code in try #require(codes[language]) {
        let actual = try classify(code)
        #expect(actual.action.rawValue == expected["action"] as? String)
        #expect(actual.callerCanceled == expected["caller_canceled"] as? Bool)
        #expect(actual.sessionClosed == expected["session_closed"] as? Bool)
      }
    }
  }

  private func loadContract() throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
    let data = try Data(contentsOf: root.appending(path: "stability/public_error_classification.json"))
    return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }
}
