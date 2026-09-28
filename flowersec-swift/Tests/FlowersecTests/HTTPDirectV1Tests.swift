import Foundation
import Testing

@testable import Flowersec

@Suite("Explicit public HTTP direct")
struct HTTPDirectV1Tests {
  @Test(arguments: [
    "192.168.31.42:23998", "127.0.0.1:23998", "localhost", "[::1]:443", "[fd12::2]:23998",
  ])
  func parsesBoundNetworkAndLoopbackEnvelopes(authority: String) throws {
    let raw = try envelope(endpoint: "ws://\(authority)/flowersec/v3/direct")
    let artifact = try parseHTTPDirectArtifactV1(raw)
    #expect(artifact.endpoint == "ws://\(authority)/flowersec/v3/direct")
    #expect(throws: ArtifactError.self) { try parseArtifact(raw) }
    #expect(!String(reflecting: artifact).contains(authority))
    #expect(Mirror(reflecting: artifact).children.isEmpty)
  }

  @Test func rejectsWrongProfileDuplicateFieldsAndAlteredBinding() throws {
    let valid = try envelope()
    let text = String(decoding: valid, as: UTF8.self)
    for raw in [
      Data(
        text.replacingOccurrences(
          of: "flowersec-http-direct/1", with: "flowersec-private-loopback/1"
        ).utf8),
      Data(text.replacingOccurrences(of: "\"v\":1", with: "\"v\":1,\"v\":1").utf8),
      Data(text.replacingOccurrences(of: "\"v\":1", with: "\"v\":true").utf8),
      Data(
        text.replacingOccurrences(of: "ws://192.168.31.42:23998", with: "ws://192.168.31.43:23998")
          .utf8),
      Data([32]) + valid,
    ] {
      #expect(throws: ArtifactError.self) { try parseHTTPDirectArtifactV1(raw) }
    }
    let source = try privateVector()
    #expect(throws: ArtifactError.self) { try parseHTTPDirectArtifactV1(source) }
  }

  @Test func rejectsUnsafeOrNoncanonicalEndpointAuthorities() {
    for authority in [
      "0.0.0.0", "255.255.255.255", "224.0.0.1", "169.254.1.2", "example.com",
      "127.0.0.1:80", "127.0.0.1:080", "127.0.0.1:0", "127.0.0.1:65536",
      "[::]", "[fe80::1]", "[ff01::1]", "[::ffff:127.0.0.1]", "LOCALHOST",
    ] {
      #expect(throws: ArtifactError.self) {
        try HTTPDirectEndpointV1("ws://\(authority)/flowersec/v3/direct")
      }
    }
    for endpoint in [
      "wss://127.0.0.1/flowersec/v3/direct", "ws://user@127.0.0.1/flowersec/v3/direct",
      "ws://127.0.0.1/flowersec/v3/direct?token=x", "ws://127.0.0.1/flowersec/v3/direct#x",
      "ws://127.0.0.1/other", "ws://127.0.0.1/%66lowersec/v3/direct",
    ] {
      #expect(throws: ArtifactError.self) { try HTTPDirectEndpointV1(endpoint) }
    }
  }

  @Test func wrongOriginRetiresLeaseWithoutSpendingAndCannotReuseIt() async throws {
    let counter = HTTPDirectLeaseCounter()
    let lease = HTTPDirectArtifactLeaseV1(
      artifact: try parseHTTPDirectArtifactV1(envelope()),
      commitSpend: { await counter.spend() }, retire: { await counter.retire() })
    for _ in 0..<2 {
      await #expect(throws: ConnectError.artifactInvalid) {
        try await connectHTTPDirectV1(
          lease: lease, options: ConnectorOptions(origin: "http://192.168.31.43:23998"))
      }
    }
    #expect(await counter.spent == 0)
    #expect(await counter.retired == 1)
  }

  @Test func ordinaryAppleAdapterKeepsTLSRequired() throws {
    let adapter = AppleWebSocketRuntimeAdapterV3()
    #expect(adapter.httpDirectEndpoint == nil)
    let http = AppleWebSocketRuntimeAdapterV3(
      httpDirectEndpoint: "ws://127.0.0.1/flowersec/v3/direct")
    #expect(throws: SwiftRuntimeErrorV3.self) {
      try http.validate(options: ConnectorOptions(origin: "https://127.0.0.1"))
    }
  }

  private func privateVector() throws -> Data {
    let rootURL = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent()
    let root = try #require(
      JSONSerialization.jsonObject(
        with: Data(
          contentsOf: rootURL.appendingPathComponent(
            "testdata/private_loopback_v1/profile_vectors.json"))) as? [String: Any])
    let positive = try #require(root["positive"] as? [[String: Any]])
    return Data(try #require(positive.first?["artifact_json"] as? String).utf8)
  }

  private func envelope(
    endpoint: String = "ws://192.168.31.42:23998/flowersec/v3/direct"
  ) throws -> Data {
    let source = try #require(JSONSerialization.jsonObject(with: privateVector()) as? [String: Any])
    let encoded = try #require(source["artifact_b64u"] as? String)
    let bytes = try #require(Data(base64URLEncoded: encoded))
    var inner = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    var path = try #require(inner["path"] as? [String: Any])
    var candidates = try #require(path["candidates"] as? [[String: Any]])
    candidates[0]["id"] = "http-direct"
    candidates[0]["url"] = try HTTPDirectEndpointV1(endpoint).tlsBinding
    path["candidates"] = candidates
    inner["path"] = path
    return try FlowersecJCSV3.encode([
      "v": 1, "profile": "flowersec-http-direct/1", "endpoint": endpoint,
      "artifact_b64u": try FlowersecJCSV3.encode(inner).base64URLEncodedString(),
    ])
  }
}

private actor HTTPDirectLeaseCounter {
  var spent = 0
  var retired = 0
  func spend() { spent += 1 }
  func retire() { retired += 1 }
}
