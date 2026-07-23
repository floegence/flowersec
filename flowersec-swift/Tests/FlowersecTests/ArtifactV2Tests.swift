import Foundation
import XCTest

@testable import Flowersec

final class ArtifactV2Tests: XCTestCase {
  func testSharedArtifactVectorsAcceptValidAndRejectInvalidArtifactJSON() throws {
    let vectors = try loadVectors()
    for item in vectors.positive {
      XCTAssertNoThrow(try parseArtifactV2(Data(item.artifactJSON.utf8)), item.id)
    }
    for item in vectors.negative where item.kind == "artifact_json" {
      XCTAssertThrowsError(try parseArtifactV2(Data(item.value.utf8)), item.id)
    }
  }

  func testOpaqueArtifactDescriptionAndMirrorDoNotRevealCredentials() throws {
    let raw = try XCTUnwrap(loadVectors().positive.first?.artifactJSON)
    let artifact = try parseArtifactV2(Data(raw.utf8))
    let rendered = String(describing: artifact) + String(reflecting: artifact)

    XCTAssertEqual(String(describing: artifact), "Flowersec.ArtifactV2(<redacted>)")
    XCTAssertFalse(rendered.contains("routing-token"))
    XCTAssertFalse(rendered.contains("e2ee_psk_b64u"))
    XCTAssertFalse(rendered.contains("channel-1"))
  }

  func testArtifactLeaseExposesExplicitDurableSpendBoundary() async throws {
    let raw = try XCTUnwrap(loadVectors().positive.first?.artifactJSON)
    let artifact = try parseArtifactV2(Data(raw.utf8))
    let recorder = SpendRecorderV2()
    let lease = ArtifactLeaseV2(artifact: artifact) {
      await recorder.recordDurableSpend()
    }

    let before = await recorder.didSpend
    XCTAssertFalse(before)
    try await lease.commitSpend()
    let after = await recorder.didSpend
    XCTAssertTrue(after)
    do {
      try await lease.commitSpend()
      XCTFail("Expected a committed lease to reject reuse")
    } catch {
      XCTAssertEqual(error as? ArtifactLeaseErrorV2, .alreadyCommitted)
    }
  }

  func testArtifactLeaseAllowsRetryAfterDurableCommitFailure() async throws {
    let raw = try XCTUnwrap(loadVectors().positive.first?.artifactJSON)
    let artifact = try parseArtifactV2(Data(raw.utf8))
    let recorder = RetryingSpendRecorderV2()
    let lease = ArtifactLeaseV2(artifact: artifact) {
      try await recorder.commit()
    }

    do {
      try await lease.commitSpend()
      XCTFail("Expected the first durable commit to fail")
    } catch {
      XCTAssertEqual(error as? SpendTestErrorV2, .durabilityFailure)
    }
    try await lease.commitSpend()
    let attempts = await recorder.attemptCount()
    XCTAssertEqual(attempts, 2)
    do {
      try await lease.commitSpend()
      XCTFail("Expected a successfully committed lease to reject reuse")
    } catch {
      XCTAssertEqual(error as? ArtifactLeaseErrorV2, .alreadyCommitted)
    }
  }

  func testRejectsNestedUnknownAndEscapedDuplicateKeys() throws {
    let raw = try XCTUnwrap(loadVectors().positive.first?.artifactJSON)
    let nestedUnknown = raw.replacingOccurrences(
      of: "\"channel_id\":\"channel-1\"",
      with: "\"channel_id\":\"channel-1\",\"tenant_id\":\"secret\""
    )
    XCTAssertThrowsError(try parseArtifactV2(Data(nestedUnknown.utf8)))

    let escapedDuplicate = raw.replacingOccurrences(
      of: "\"profile\":\"flowersec/2\"",
      with: "\"profile\":\"flowersec/2\",\"pro\\u0066ile\":\"flowersec/2\""
    )
    XCTAssertThrowsError(try parseArtifactV2(Data(escapedDuplicate.utf8)))
  }

  private func loadVectors() throws -> ArtifactVectorsV2 {
    let url = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("testdata/transport_v2/artifact_vectors.json")
    return try JSONDecoder().decode(ArtifactVectorsV2.self, from: Data(contentsOf: url))
  }
}

private actor SpendRecorderV2 {
  private(set) var didSpend = false
  func recordDurableSpend() { didSpend = true }
}

private enum SpendTestErrorV2: Error, Equatable { case durabilityFailure }

private actor RetryingSpendRecorderV2 {
  private var attempts = 0
  func commit() throws {
    attempts += 1
    if attempts == 1 { throw SpendTestErrorV2.durabilityFailure }
  }
  func attemptCount() -> Int { attempts }
}

private struct ArtifactVectorsV2: Decodable {
  let positive: [Positive]
  let negative: [Negative]
  struct Positive: Decodable {
    let id: String
    let artifactJSON: String
    enum CodingKeys: String, CodingKey { case id; case artifactJSON = "artifact_json" }
  }
  struct Negative: Decodable { let id: String; let kind: String; let value: String }
}
