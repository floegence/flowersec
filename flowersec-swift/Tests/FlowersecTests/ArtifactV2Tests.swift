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

  func testSharedCandidateAndFSB2VectorsMatchByteForByte() throws {
    for item in try loadVectors().positive {
      let artifact = try parseArtifactV2(Data(item.artifactJSON.utf8))
      let candidateSet = try AdmissionCodecV2.canonicalizeCandidates(artifact)
      XCTAssertEqual(String(decoding: candidateSet.canonicalJSON, as: UTF8.self), item.candidatesCanonicalJSON, item.id)
      XCTAssertEqual(candidateSet.hash.base64URLForTest, item.candidateSetHashBase64URL, item.id)
      for winner in item.winners {
        XCTAssertEqual(try AdmissionCodecV2.encodeFSB2(artifact: artifact, chosenCandidateID: winner.candidateID).hexV2, winner.fsb2Hex, item.id)
      }
    }
  }

  func testSharedFSA2VectorsStrictlyDecode() throws {
    let vectors = try loadVectors()
    let reasons: Set<String> = ["invalid_token", "capacity"]
    for item in vectors.fsa2 {
      let decoded = try AdmissionCodecV2.decodeFSA2(try Data(hexV2: item.frameHex), reasons: reasons)
      XCTAssertEqual(decoded.status.rawValue, item.status, item.id)
      XCTAssertEqual(decoded.reason, item.reason, item.id)
    }
    for item in vectors.negative where item.kind == "fsa2_hex" {
      XCTAssertThrowsError(try AdmissionCodecV2.decodeFSA2(try Data(hexV2: item.value), reasons: reasons), item.id)
    }
  }

  func testFSA2RejectsEveryMalformedStatusAndReasonBoundary() throws {
    let reasons: Set<String> = ["capacity"]
    let invalidFrames = [
      "465341", // Truncated header.
      "5853413202000000", // Wrong magic.
      "4653413203000000", // Wrong version.
      "4653413209000000", // Unknown status.
      "465341320200000100", // Success with a reason.
      "4653413202010000", // Reject without a reason.
      "465341320201000141", // Non-canonical reason token.
      "4653413202010001ff", // Invalid UTF-8.
      "4653413202020041", // Reason exceeds the bound.
      "4653413202020008636170616369747900", // Trailing byte.
      "465341320202000863617061636974", // Truncated reason.
    ]
    for frame in invalidFrames {
      XCTAssertThrowsError(try AdmissionCodecV2.decodeFSA2(try Data(hexV2: frame), reasons: reasons), frame)
    }
    XCTAssertEqual(
      try AdmissionCodecV2.decodeFSA2(try Data(hexV2: "46534132020200086361706163697479"), reasons: reasons),
      AdmissionResponseV2(status: .retryable, reason: "capacity")
    )
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
  let fsa2: [FSA2]
  let negative: [Negative]
  struct Positive: Decodable {
    let id: String; let artifactJSON: String; let candidatesCanonicalJSON: String
    let candidateSetHashBase64URL: String; let winners: [Winner]
    enum CodingKeys: String, CodingKey {
      case id, winners; case artifactJSON = "artifact_json"
      case candidatesCanonicalJSON = "candidates_canonical_json"
      case candidateSetHashBase64URL = "candidate_set_hash_b64u"
    }
  }
  struct Winner: Decodable {
    let candidateID: String; let fsb2Hex: String
    enum CodingKeys: String, CodingKey { case candidateID = "candidate_id"; case fsb2Hex = "fsb2_hex" }
  }
  struct FSA2: Decodable {
    let id: String; let status: UInt8; let reason: String; let frameHex: String
    enum CodingKeys: String, CodingKey { case id, status, reason; case frameHex = "frame_hex" }
  }
  struct Negative: Decodable { let id: String; let kind: String; let value: String }
}

private extension Data {
  init(hexV2: String) throws {
    guard hexV2.count.isMultiple(of: 2) else { throw ArtifactCodecErrorV2.invalidArtifact }
    self.init()
    var index = hexV2.startIndex
    while index < hexV2.endIndex {
      let next = hexV2.index(index, offsetBy: 2)
      guard let byte = UInt8(hexV2[index..<next], radix: 16) else { throw ArtifactCodecErrorV2.invalidArtifact }
      append(byte); index = next
    }
  }
  var hexV2: String { map { String(format: "%02x", $0) }.joined() }
  var base64URLForTest: String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}
