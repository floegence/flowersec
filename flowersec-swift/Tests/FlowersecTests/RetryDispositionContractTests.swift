import Foundation
import Testing

@testable import Flowersec

struct RetryDispositionContractTests {
  @Test func dispositionsMatchSharedRecoveryContract() throws {
    let document = try loadContract()
    try verifyCases(document["connect"], language: "swift") { code in
      try #require(ConnectErrorV2(rawValue: code)).retryDispositionV2
    }
    try verifyCases(document["session"], language: "swift") { code in
      try #require(SessionError(rawValue: code)).retryDispositionV2
    }
  }

  @Test func retryAfterPreservesTheAbsoluteNotBeforeDeadline() {
    let deadline: UInt64 = 2_000_000_000_000
    let failure = ArtifactSourceFailure(disposition: .retryAfter(deadline))
    #expect(failure.disposition == .retryAfter(deadline))
  }

  private func verifyCases(
    _ rawCases: Any?,
    language: String,
    disposition: (String) throws -> RetryDispositionV2
  ) throws {
    let cases = try #require(rawCases as? [[String: Any]])
    for item in cases {
      let expected = try #require(item["decision"] as? String)
      let codes = try #require(item["codes"] as? [String: [String]])
      for code in try #require(codes[language]) {
        switch try disposition(code) {
        case .terminal:
          #expect(expected == "terminal")
        case .retryable:
          #expect(expected == "retryable")
        case .retryAfter:
          #expect(expected == "retry_after")
        }
      }
    }
  }

  private func loadContract() throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
    let data = try Data(
      contentsOf: root.appending(path: "stability/connection_controller_recovery.json"))
    return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }
}
