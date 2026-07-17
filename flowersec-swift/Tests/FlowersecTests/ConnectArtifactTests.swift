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

  func testConnectRejectsCriticalScopeBeforeTransportPolicyEvaluation() async throws {
    let policyCalled = expectation(description: "transport policy")
    policyCalled.isInverted = true
    let metadata = try ConnectArtifactMetadata(
      scoped: [
        try ScopeMetadataEntry(
          scope: "proxy.runtime",
          scopeVersion: 2,
          critical: true,
          payload: ScopePayload(["mode": .string("strict")])
        )
      ]
    )
    let artifact = ConnectArtifact.direct(validDirectInfo(), metadata: metadata)
    let options = ConnectOptions(
      transportSecurityPolicy: .custom { _ in
        policyCalled.fulfill()
        return true
      }
    )

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected the critical scope to fail before connecting")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .resolveFailed)
      XCTAssertEqual(error.message, "Missing scope resolver for proxy.runtime@2.")
    }
    await fulfillment(of: [policyCalled], timeout: 0.05)
  }

  func testConnectIgnoresOptionalScopeAndCorrelatesDiagnostic() async throws {
    let emitted = expectation(description: "optional scope diagnostic")
    let correlation = try CorrelationContext(
      traceID: "trace-optional-001",
      sessionID: "session-optional-001"
    )
    let metadata = try ConnectArtifactMetadata(
      scoped: [
        try ScopeMetadataEntry(
          scope: "proxy.runtime",
          scopeVersion: 2,
          critical: false,
          payload: ScopePayload(["mode": .string("hint")])
        )
      ],
      correlation: correlation
    )
    let artifact = ConnectArtifact.direct(validDirectInfo(), metadata: metadata)
    let options = ConnectOptions(onDiagnosticEvent: { event in
      guard event.code == "scope_ignored_missing_resolver" else { return }
      XCTAssertEqual(event.path, .direct)
      XCTAssertEqual(event.stage, .scope)
      XCTAssertEqual(event.result, .skip)
      XCTAssertEqual(event.traceID, "trace-optional-001")
      XCTAssertEqual(event.sessionID, "session-optional-001")
      emitted.fulfill()
    })

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected the plaintext transport policy to stop the test connection")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .transportPolicyDenied)
    }
    await fulfillment(of: [emitted], timeout: 1)
  }

  func testConnectRunsRegisteredScopeResolverBeforeTransportPolicy() async throws {
    let resolved = expectation(description: "scope resolved")
    let policyCalled = expectation(description: "transport policy")
    let entry = try ScopeMetadataEntry(
      scope: "proxy.runtime",
      scopeVersion: 2,
      critical: true,
      payload: ScopePayload(["mode": .string("strict")])
    )
    let artifact = ConnectArtifact.direct(
      validDirectInfo(),
      metadata: try ConnectArtifactMetadata(scoped: [entry])
    )
    let options = ConnectOptions(
      transportSecurityPolicy: .custom { _ in
        policyCalled.fulfill()
        return false
      },
      scopeResolvers: [
        "proxy.runtime": { received in
          XCTAssertEqual(received, entry)
          resolved.fulfill()
        }
      ]
    )

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected the transport policy to reject the test connection")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .transportPolicyDenied)
    }
    await fulfillment(of: [resolved, policyCalled], timeout: 1)
  }

  func testConnectValidatesArtifactBeforeScopeResolution() async throws {
    let resolverCalled = expectation(description: "scope resolver")
    resolverCalled.isInverted = true
    let entry = try ScopeMetadataEntry(
      scope: "proxy.runtime",
      scopeVersion: 2,
      critical: true,
      payload: ScopePayload(["mode": .string("strict")])
    )
    var info = validDirectInfo()
    info.channelID = " "
    let artifact = ConnectArtifact.direct(
      info,
      metadata: try ConnectArtifactMetadata(scoped: [entry])
    )
    let options = ConnectOptions(scopeResolvers: [
      "proxy.runtime": { _ in resolverCalled.fulfill() }
    ])

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected invalid artifact transport contract")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .missingChannelID)
    }
    await fulfillment(of: [resolverCalled], timeout: 0.05)
  }

  func testOptionalScopeResolverFailureFailsFastByDefault() async throws {
    let policyCalled = expectation(description: "transport policy")
    policyCalled.isInverted = true
    let artifact = try artifactWithScope(critical: false)
    let options = ConnectOptions(
      transportSecurityPolicy: .custom { _ in
        policyCalled.fulfill()
        return true
      },
      scopeResolvers: [
        "proxy.runtime": { _ in throw ScopeResolverTestError.rejected }
      ]
    )

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected optional resolver failure to fail closed")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .resolveFailed)
      XCTAssertEqual(error.message, "Scope validation failed for proxy.runtime@2.")
    }
    await fulfillment(of: [policyCalled], timeout: 0.05)
  }

  func testRelaxedOptionalScopeResolverFailureIsIgnoredWithCorrelatedDiagnostic() async throws {
    let emitted = expectation(description: "relaxed scope diagnostic")
    let policyCalled = expectation(description: "transport policy")
    let metadata = try ConnectArtifactMetadata(
      scoped: [scopeEntry(critical: false)],
      correlation: CorrelationContext(
        traceID: "trace-relaxed-001",
        sessionID: "session-relaxed-001"
      )
    )
    let artifact = ConnectArtifact.direct(validDirectInfo(), metadata: metadata)
    let options = ConnectOptions(
      transportSecurityPolicy: .custom { _ in
        policyCalled.fulfill()
        return false
      },
      onDiagnosticEvent: { event in
        guard event.code == "scope_ignored_relaxed_validation" else { return }
        XCTAssertEqual(event.path, .direct)
        XCTAssertEqual(event.stage, .scope)
        XCTAssertEqual(event.result, .skip)
        XCTAssertEqual(event.traceID, "trace-relaxed-001")
        XCTAssertEqual(event.sessionID, "session-relaxed-001")
        emitted.fulfill()
      },
      scopeResolvers: [
        "proxy.runtime": { _ in throw ScopeResolverTestError.rejected }
      ],
      relaxedOptionalScopeValidation: true
    )

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected the transport policy to reject the test connection")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .transportPolicyDenied)
    }
    await fulfillment(of: [emitted, policyCalled], timeout: 1)
  }

  func testRelaxedValidationNeverIgnoresCriticalResolverFailure() async throws {
    let policyCalled = expectation(description: "transport policy")
    policyCalled.isInverted = true
    let artifact = try artifactWithScope(critical: true)
    let options = ConnectOptions(
      transportSecurityPolicy: .custom { _ in
        policyCalled.fulfill()
        return true
      },
      scopeResolvers: [
        "proxy.runtime": { _ in throw ScopeResolverTestError.rejected }
      ],
      relaxedOptionalScopeValidation: true
    )

    do {
      _ = try await Flowersec.connect(artifact, options: options)
      XCTFail("Expected critical resolver failure to fail closed")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .resolveFailed)
    }
    await fulfillment(of: [policyCalled], timeout: 0.05)
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

  private func validDirectInfo() -> DirectConnectInfo {
    DirectConnectInfo(
      wsURL: URL(string: "ws://example.invalid/ws")!,
      channelID: "channel-scope-test",
      psk: Data(repeating: 0x2a, count: 32),
      channelInitExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 60,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
  }

  private func artifactWithScope(critical: Bool) throws -> ConnectArtifact {
    ConnectArtifact.direct(
      validDirectInfo(),
      metadata: try ConnectArtifactMetadata(scoped: [scopeEntry(critical: critical)])
    )
  }

  private func scopeEntry(critical: Bool) throws -> ScopeMetadataEntry {
    try ScopeMetadataEntry(
      scope: "proxy.runtime",
      scopeVersion: 2,
      critical: critical,
      payload: ScopePayload(["mode": .string("test")])
    )
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

private enum ScopeResolverTestError: Error {
  case rejected
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
