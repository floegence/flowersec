import Foundation
import XCTest

@testable import Flowersec

final class ConnectArtifactTests: XCTestCase {
  func testCanonicalFixtureManifest() throws {
    for artifactCase in try artifactManifest().cases {
      let inputData = try Data(contentsOf: fixtureURL(artifactCase.input))
      if artifactCase.ok {
        let artifact = try JSONDecoder().decode(ConnectArtifact.self, from: inputData)
        try assertSemanticShape(artifact, id: artifactCase.id)
        if let normalized = artifactCase.normalized {
          let encoded = try JSONEncoder.flowersecArtifactTest.encode(artifact)
          let expectedData = try Data(contentsOf: fixtureURL(normalized))
          XCTAssertEqual(
            try canonicalJSONString(encoded),
            try canonicalJSONString(expectedData),
            artifactCase.id
          )
        }
      } else {
        XCTAssertThrowsError(
          try JSONDecoder().decode(ConnectArtifact.self, from: inputData),
          artifactCase.id
        )
      }
    }
  }

  func testPublicInitializersRejectDuplicateScopesAndTags() throws {
    let payload = try ScopePayload(["max_chunk_bytes": .number(262_144)])
    let scope = try ScopeMetadataEntry(
      scope: "proxy.runtime",
      scopeVersion: 1,
      critical: false,
      payload: payload
    )
    XCTAssertThrowsError(
      try ConnectArtifactMetadata(scoped: [scope, scope], correlation: nil)
    )

    let tag = try CorrelationKV(key: "route", value: "ingress-a")
    XCTAssertThrowsError(
      try CorrelationContext(traceID: nil, sessionID: nil, tags: [tag, tag])
    )
  }

  func testRejectsServerRoleTunnelArtifact() throws {
    let data = Data(
      """
      {
        "v": 1,
        "transport": "tunnel",
        "tunnel_grant": {
          "tunnel_url": "wss://tunnel.example/ws",
          "channel_id": "channel-server",
          "channel_init_expire_at_unix_s": 1700000000,
          "idle_timeout_seconds": 30,
          "role": 2,
          "token": "token-server",
          "e2ee_psk_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "allowed_suites": [1],
          "default_suite": 1
        }
      }
      """.utf8
    )
    XCTAssertThrowsError(try JSONDecoder().decode(ConnectArtifact.self, from: data))
  }

  private func assertSemanticShape(_ artifact: ConnectArtifact, id: String) throws {
    switch id {
    case "tunnel_valid_basic":
      guard case .tunnel(let grant, metadata: let metadata) = artifact else {
        return XCTFail("Expected tunnel artifact")
      }
      XCTAssertEqual(grant.channelID, "channel-001")
      XCTAssertEqual(grant.role, 1)
      XCTAssertEqual(grant.psk.count, 32)
      XCTAssertEqual(grant.allowedSuites, [.x25519HKDFSHA256AES256GCM])
      XCTAssertEqual(metadata.scoped.count, 1)
      XCTAssertEqual(metadata.scoped.first?.scope, "proxy.runtime")
      XCTAssertEqual(
        metadata.scoped.first?.payload.object["max_ws_frame_bytes"],
        .number(1_048_576)
      )
      XCTAssertEqual(metadata.correlation?.traceID, "trace-0001")
      XCTAssertEqual(metadata.correlation?.sessionID, "session-0001")
      XCTAssertEqual(metadata.correlation?.tags, [
        try CorrelationKV(key: "tenant", value: "acme")
      ])

    case "direct_valid_sanitized_correlation":
      guard case .direct(let info, metadata: let metadata) = artifact else {
        return XCTFail("Expected direct artifact")
      }
      XCTAssertEqual(info.channelID, "channel-002")
      XCTAssertNil(metadata.correlation?.traceID)
      XCTAssertNil(metadata.correlation?.sessionID)
      XCTAssertEqual(metadata.correlation?.tags, [
        try CorrelationKV(key: "route", value: "ingress-a")
      ])

    case "direct_valid_missing_correlation_tags":
      guard case .direct(let info, metadata: let metadata) = artifact else {
        return XCTFail("Expected direct artifact")
      }
      XCTAssertEqual(info.channelID, "channel-003")
      XCTAssertEqual(info.psk.count, 32)
      XCTAssertEqual(info.defaultSuite, .p256HKDFSHA256AES256GCM)
      XCTAssertEqual(metadata.correlation?.traceID, "trace-0003")
      XCTAssertEqual(metadata.correlation?.tags, [])

    default:
      break
    }
  }

  private func artifactManifest() throws -> ArtifactManifest {
    let data = try Data(contentsOf: fixtureURL("manifest.json"))
    return try JSONDecoder().decode(ArtifactManifest.self, from: data)
  }

  private func fixtureURL(_ name: String) -> URL {
    packageRoot()
      .appendingPathComponent("testdata/connect_artifact_cases/\(name)")
  }

  private func canonicalJSONString(_ data: Data) throws -> String {
    let object = try JSONSerialization.jsonObject(with: data)
    let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    return String(decoding: canonical, as: UTF8.self)
  }
}

private struct ArtifactManifest: Decodable {
  var cases: [ArtifactCase]
}

private struct ArtifactCase: Decodable {
  var id: String
  var input: String
  var ok: Bool
  var normalized: String?
}

private extension JSONEncoder {
  static var flowersecArtifactTest: JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }
}
