import Foundation
import Testing
@testable import Flowersec

struct ErrorClassificationContractTests {
  @Test func classificationsMatchSharedContract() throws {
    let document = try loadContract()
    let decisions = try #require(document["decisions"] as? [String: [String: Any]])
    try verifyCases(document["connect"], language: "swift", decisions: decisions) { code in
      classifyConnectErrorV2(try #require(ConnectErrorV2(rawValue: code)))
    }
    try verifyCases(document["session"], language: "swift", decisions: decisions) { code in
      classifySessionErrorV2(try #require(SessionErrorV2(rawValue: code)))
    }
  }

  private func verifyCases(
    _ rawCases: Any?,
    language: String,
    decisions: [String: [String: Any]],
    classify: (String) throws -> FlowersecErrorRetryClassificationV2
  ) throws {
    let cases = try #require(rawCases as? [[String: Any]])
    for item in cases {
      let decisionName = try #require(item["decision"] as? String)
      let expected = try #require(decisions[decisionName])
      let codes = try #require(item["codes"] as? [String: [String]])
      for code in try #require(codes[language]) {
        let actual = try classify(code)
        #expect(actual.action.rawValue == expected["action"] as? String)
        #expect(actual.retryable == expected["retryable"] as? Bool)
        #expect(actual.refreshArtifact == expected["refresh_artifact"] as? Bool)
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
