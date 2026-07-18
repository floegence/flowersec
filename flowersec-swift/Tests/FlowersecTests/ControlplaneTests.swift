import Crypto
import Foundation
import XCTest

@testable import Flowersec

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

final class ControlplaneTests: XCTestCase {
  func testArtifactFetchDecodesHTTPEnvelope() async throws {
    let artifact = ConnectArtifact.direct(
      DirectConnectInfo(
        wsURL: URL(string: "wss://direct.example.test/v1/connect")!,
        channelID: "channel-artifact",
        psk: Data(repeating: 3, count: 32),
        channelInitExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 600,
        defaultSuite: .x25519HKDFSHA256AES256GCM
      ),
      metadata: .empty
    )
    let response = try Controlplane.encodeArtifactEnvelope(artifact)
    ArtifactURLProtocol.setHandler { request in
      XCTAssertEqual(request.httpMethod, "POST")
      XCTAssertEqual(request.url?.path, Controlplane.artifactPath)
      XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
      let body = try artifactRequestBody(request)
      let decoded = try JSONDecoder().decode(ControlplaneArtifactRequest.self, from: body)
      XCTAssertEqual(decoded.endpointID, "endpoint-artifact")
      return ArtifactHTTPResponse(status: 200, chunks: [response])
    }
    defer { ArtifactURLProtocol.setHandler(nil) }
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [ArtifactURLProtocol.self]
    let session = URLSession(configuration: configuration)

    let fetched = try await Controlplane.requestConnectArtifact(
      ArtifactRequestOptions(
        baseURL: URL(string: "https://controlplane.example.test")!,
        endpointID: "endpoint-artifact",
        maxResponseBodyBytes: response.count
      ),
      session: session
    )
    XCTAssertEqual(fetched, artifact)
  }

  func testArtifactRequestRejectsPlaintextUnlessLoopbackIsExplicitlyAllowed() async throws {
    let remote = ArtifactRequestOptions(
      baseURL: URL(string: "http://192.0.2.10")!,
      endpointID: "env-remote",
      allowLoopbackHTTP: true
    )
    do {
      _ = try await Controlplane.requestConnectArtifact(remote, session: artifactURLSession())
      XCTFail("Expected transport policy denial")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.status, 0)
      XCTAssertEqual(error.code, "transport_policy_denied")
    }

    let loopback = ArtifactRequestOptions(
      baseURL: URL(string: "http://127.0.0.1")!,
      endpointID: "env-loopback"
    )
    do {
      _ = try await Controlplane.requestConnectArtifact(loopback, session: artifactURLSession())
      XCTFail("Expected explicit loopback opt-in requirement")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.code, "transport_policy_denied")
    }
  }

  func testArtifactRequestAllowsExplicitLoopbackHTTP() async throws {
    let response = try Controlplane.encodeErrorEnvelope(code: "reachable", message: "request reached")
    ArtifactURLProtocol.setHandler { request in
      XCTAssertEqual(request.url?.scheme, "http")
      XCTAssertEqual(request.url?.host, "127.0.0.1")
      return ArtifactHTTPResponse(status: 403, chunks: [response])
    }
    defer { ArtifactURLProtocol.setHandler(nil) }

    do {
      _ = try await Controlplane.requestConnectArtifact(
        ArtifactRequestOptions(
          baseURL: URL(string: "http://127.0.0.1")!,
          endpointID: "env-loopback",
          allowLoopbackHTTP: true
        ),
        session: artifactURLSession()
      )
      XCTFail("Expected the test server response")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.status, 403)
      XCTAssertEqual(error.code, "reachable")
    }
  }

  func testArtifactRequestAllowsAllLiteralLoopbackForms() async throws {
    let response = try Controlplane.encodeErrorEnvelope(code: "reachable", message: "request reached")
    ArtifactURLProtocol.setHandler { _ in
      ArtifactHTTPResponse(status: 403, chunks: [response])
    }
    defer { ArtifactURLProtocol.setHandler(nil) }

    for baseURL in ["http://localhost", "http://127.42.0.9", "http://[::1]"] {
      do {
        _ = try await Controlplane.requestConnectArtifact(
          ArtifactRequestOptions(
            baseURL: URL(string: baseURL)!,
            endpointID: "env-literal-loopback",
            allowLoopbackHTTP: true
          ),
          session: artifactURLSession()
        )
        XCTFail("Expected the test server response for \(baseURL)")
      } catch let error as ControlplaneRequestError {
        XCTAssertEqual(error.status, 403, baseURL)
        XCTAssertEqual(error.code, "reachable", baseURL)
      }
    }
  }

  func testArtifactRequestRejectsCredentialsUnknownSchemesAndMalformedURLs() async throws {
    let invalidBaseURLs = [
      ("userinfo", URL(string: "https://user:secret@controlplane.example.test")!),
      ("unknown scheme", URL(string: "ftp://controlplane.example.test")!),
      ("relative URL", URL(string: "not-an-absolute-controlplane-url")!),
    ]

    for (name, baseURL) in invalidBaseURLs {
      do {
        _ = try await Controlplane.requestConnectArtifact(
          ArtifactRequestOptions(baseURL: baseURL, endpointID: "env-invalid"),
          session: artifactURLSession()
        )
        XCTFail("Expected transport policy denial for \(name)")
      } catch let error as ControlplaneRequestError {
        XCTAssertEqual(error.status, 0, name)
        XCTAssertEqual(error.code, "transport_policy_denied", name)
      }
    }

    for baseURL in ["http://127.1", "http://127.0.00.1", "http://2130706433"] {
      do {
        _ = try await Controlplane.requestConnectArtifact(
          ArtifactRequestOptions(
            baseURL: URL(string: baseURL)!,
            endpointID: "env-noncanonical-loopback",
            allowLoopbackHTTP: true
          ),
          session: artifactURLSession()
        )
        XCTFail("Expected transport policy denial for \(baseURL)")
      } catch let error as ControlplaneRequestError {
        XCTAssertEqual(error.status, 0, baseURL)
        XCTAssertEqual(error.code, "transport_policy_denied", baseURL)
      }
    }
  }

  func testArtifactRequestRejectsRedirectWithoutForwardingBearerToken() async throws {
    let response = try Controlplane.encodeErrorEnvelope(
      code: "redirected",
      message: "redirects are not followed"
    )
    ArtifactURLProtocol.setHandler { request in
      XCTAssertEqual(request.url?.host, "controlplane.example.test")
      XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer secret-ticket")
      return ArtifactHTTPResponse(
        status: 302,
        headers: ["Location": "https://redirect-target.example.test/artifact"],
        chunks: [response]
      )
    }
    defer { ArtifactURLProtocol.setHandler(nil) }

    do {
      _ = try await Controlplane.requestEntryConnectArtifact(
        ArtifactRequestOptions(
          baseURL: URL(string: "https://controlplane.example.test")!,
          endpointID: "env-redirect"
        ),
        entryTicket: "secret-ticket",
        session: artifactURLSession()
      )
      XCTFail("Expected redirect rejection")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.status, 302)
      XCTAssertEqual(error.code, "redirected")
    }
  }

  func testArtifactFetchCancelsResponseDeclaredOverLimit() async throws {
    ArtifactURLProtocol.reset()
    ArtifactURLProtocol.setHandler { _ in
      ArtifactHTTPResponse(
        status: 200,
        headers: ["Content-Length": "64"],
        chunks: [Data(repeating: 1, count: 64)]
      )
    }
    defer { ArtifactURLProtocol.reset() }

    do {
      _ = try await Controlplane.requestConnectArtifact(
        ArtifactRequestOptions(
          baseURL: URL(string: "https://controlplane.example.test")!,
          endpointID: "endpoint-artifact",
          maxResponseBodyBytes: 16
        ),
        session: artifactURLSession()
      )
      XCTFail("Expected an oversized response error")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.code, "response_too_large")
      XCTAssertEqual(error.status, 200)
      XCTAssertTrue(error.responseBody.isEmpty)
    }
    try await waitForArtifactProtocolStop()
  }

  func testArtifactFetchCancelsChunkedResponseOverLimit() async throws {
    ArtifactURLProtocol.reset()
    ArtifactURLProtocol.setHandler { _ in
      ArtifactHTTPResponse(
        status: 503,
        chunks: [
          Data(repeating: 1, count: 6),
          Data(repeating: 2, count: 6),
          Data(repeating: 3, count: 6),
        ],
        controlledChunks: true
      )
    }
    defer { ArtifactURLProtocol.reset() }

    let request = Task {
      try await Controlplane.requestConnectArtifact(
        ArtifactRequestOptions(
          baseURL: URL(string: "https://controlplane.example.test")!,
          endpointID: "endpoint-artifact",
          maxResponseBodyBytes: 10
        ),
        session: artifactURLSession()
      )
    }
    ArtifactURLProtocol.allowNextChunk()
    try await waitForArtifactProtocolChunks(1)
    ArtifactURLProtocol.allowNextChunk()
    do {
      _ = try await request.value
      XCTFail("Expected an oversized response error")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.code, "response_too_large")
      XCTAssertEqual(error.status, 503)
    }
    try await waitForArtifactProtocolStop()
    XCTAssertEqual(ArtifactURLProtocol.deliveredChunkCount, 2)
  }

  func testArtifactFetchRejectsBodyLargerThanReportedContentLength() async throws {
    ArtifactURLProtocol.reset()
    ArtifactURLProtocol.setHandler { _ in
      ArtifactHTTPResponse(
        status: 200,
        headers: ["Content-Length": "1"],
        chunks: [Data(repeating: 1, count: 6), Data(repeating: 2, count: 6)]
      )
    }
    defer { ArtifactURLProtocol.reset() }

    do {
      _ = try await Controlplane.requestConnectArtifact(
        ArtifactRequestOptions(
          baseURL: URL(string: "https://controlplane.example.test")!,
          endpointID: "endpoint-artifact",
          maxResponseBodyBytes: 10
        ),
        session: artifactURLSession()
      )
      XCTFail("Expected an oversized response error")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.code, "response_too_large")
      XCTAssertEqual(error.status, 200)
    }
    try await waitForArtifactProtocolStop()
  }

  func testArtifactFetchPreservesBoundedStructuredError() async throws {
    let body = try Controlplane.encodeErrorEnvelope(code: "denied", message: "not allowed")
    ArtifactURLProtocol.reset()
    ArtifactURLProtocol.setHandler { _ in
      ArtifactHTTPResponse(status: 403, chunks: [body])
    }
    defer { ArtifactURLProtocol.reset() }

    do {
      _ = try await Controlplane.requestConnectArtifact(
        ArtifactRequestOptions(
          baseURL: URL(string: "https://controlplane.example.test")!,
          endpointID: "endpoint-artifact",
          maxResponseBodyBytes: body.count
        ),
        session: artifactURLSession()
      )
      XCTFail("Expected a structured request error")
    } catch let error as ControlplaneRequestError {
      XCTAssertEqual(error.status, 403)
      XCTAssertEqual(error.code, "denied")
      XCTAssertEqual(error.message, "not allowed")
      XCTAssertEqual(error.responseBody, body)
    }
  }

  func testFST2TokenMatchesSharedGoldenVector() async throws {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let data = try Data(
      contentsOf: root.appending(path: "idl/flowersec/testdata/v1/token_vectors.json"))
    let document = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let cases = try XCTUnwrap(document["cases"] as? [[String: Any]])
    let vector = try XCTUnwrap(cases.first)
    let inputs = try XCTUnwrap(vector["inputs"] as? [String: Any])
    let rawPayload = try XCTUnwrap(inputs["payload"])
    let payloadData = try JSONSerialization.data(withJSONObject: rawPayload)
    let payload = try JSONDecoder().decode(FST2TokenPayload.self, from: payloadData)
    let seed = try Data(hex: XCTUnwrap(inputs["ed25519_seed_hex"] as? String))
    let expected = try XCTUnwrap((vector["expected"] as? [String: Any])?["token"] as? String)

    let issuer = try TokenIssuer(kid: payload.kid, seed: seed)
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    XCTAssertEqual(
      privateKey.publicKey.rawRepresentation,
      try Data(hex: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    )
    let publicKeys = await issuer.publicKeys()
    XCTAssertEqual(
      try FST2Token.verify(
        expected,
        keys: publicKeys,
        options: FST2VerifyOptions(
          nowUnixS: payload.issuedAtUnixS,
          audience: payload.audience,
          issuer: payload.issuer
        )
      ),
      payload
    )

    // CryptoKit randomizes Ed25519 signing on Apple platforms. The generated
    // token is therefore validated semantically instead of compared byte-for-byte.
    let token = try FST2Token.sign(privateKey: privateKey, payload: payload)
    XCTAssertEqual(
      try FST2Token.verify(
        token,
        keys: publicKeys,
        options: FST2VerifyOptions(
          nowUnixS: payload.issuedAtUnixS,
          audience: payload.audience,
          issuer: payload.issuer
        )
      ),
      payload
    )
  }

  func testFST2TokenAcceptsOmittedIssuer() throws {
    let seed = Data(repeating: 9, count: 32)
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    let payload = FST2TokenPayload(
      kid: "key-no-issuer",
      audience: "flowersec-tunnel:test",
      channelID: "channel-no-issuer",
      role: 1,
      tokenID: "token-no-issuer",
      initExpiresAtUnixS: 1_700_000_100,
      idleTimeoutSeconds: 60,
      issuedAtUnixS: 1_700_000_000,
      expiresAtUnixS: 1_700_000_060
    )
    let token = try FST2Token.sign(privateKey: privateKey, payload: payload)
    XCTAssertEqual(
      try FST2Token.verify(
        token,
        keys: [payload.kid: privateKey.publicKey.rawRepresentation],
        options: FST2VerifyOptions(
          nowUnixS: payload.issuedAtUnixS,
          audience: payload.audience,
          issuer: ""
        )
      ),
      payload
    )
  }

  func testChannelInitIssuesAndReissuesPairedGrants() async throws {
    let issuer = try TokenIssuer(kid: "key-1", seed: Data(repeating: 7, count: 32))
    let service = ChannelInitService(
      issuer: issuer,
      params: ChannelInitParams(
        tunnelURL: URL(string: "wss://tunnel.example.test/v1/connect")!,
        tunnelAudience: "flowersec-tunnel:test",
        issuerID: "issuer-test",
        allowedSuites: [.x25519HKDFSHA256AES256GCM, .p256HKDFSHA256AES256GCM],
        defaultSuite: .p256HKDFSHA256AES256GCM
      ),
      now: { 1_700_000_000 }
    )
    let grants = try await service.issue(channelID: "channel-1")
    XCTAssertEqual(grants.client.role, 1)
    XCTAssertEqual(grants.server.role, 2)
    XCTAssertEqual(grants.client.psk, grants.server.psk)
    let payload = try FST2Token.verify(
      grants.client.token,
      keys: await issuer.publicKeys(),
      options: FST2VerifyOptions(
        nowUnixS: 1_700_000_000,
        audience: "flowersec-tunnel:test",
        issuer: "issuer-test"
      )
    )
    XCTAssertEqual(payload.channelID, "channel-1")
    let refreshed = try await service.reissue(grants.client)
    XCTAssertNotEqual(refreshed.token, grants.client.token)
    XCTAssertEqual(refreshed.psk, grants.client.psk)
  }

  func testTokenIssuerUsesStrictPrepublishedRotation() async throws {
    let seed1 = Data(repeating: 7, count: 32)
    let seed2 = Data(repeating: 8, count: 32)
    let publicKey2 = try Curve25519.Signing.PrivateKey(rawRepresentation: seed2)
      .publicKey.rawRepresentation
    let issuer = try TokenIssuer(kid: "z-key", seed: seed1)
    let payload = tokenPayload(kid: "ignored")
    let oldToken = try await issuer.sign(payload)

    do {
      try await issuer.rotate(kid: "a-key", seed: seed2)
      XCTFail("Expected rotation to require prepublication")
    } catch let error as FST2TokenError {
      XCTAssertEqual(error, .invalidFormat)
    }
    let currentAfterUnpublishedRotation = await issuer.currentKeyID()
    XCTAssertEqual(currentAfterUnpublishedRotation, "z-key")

    try await issuer.addVerificationKey(kid: " a-key ", publicKey: publicKey2)
    try await issuer.addVerificationKey(kid: "a-key", publicKey: publicKey2)
    do {
      let conflictingKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 9, count: 32)
      ).publicKey.rawRepresentation
      try await issuer.addVerificationKey(kid: "a-key", publicKey: conflictingKey)
      XCTFail("Expected a conflicting verification key rejection")
    } catch let error as FST2TokenError {
      XCTAssertEqual(error, .invalidFormat)
    }
    try await issuer.rotate(kid: "a-key", seed: seed2)
    let newToken = try await issuer.sign(payload)
    let overlappingKeys = await issuer.publicKeys()
    let verifyOptions = FST2VerifyOptions(nowUnixS: 1_700_000_000)
    XCTAssertEqual(Set(overlappingKeys.keys), ["a-key", "z-key"])
    XCTAssertEqual(
      try FST2Token.verify(oldToken, keys: overlappingKeys, options: verifyOptions).kid,
      "z-key"
    )
    XCTAssertEqual(
      try FST2Token.verify(newToken, keys: overlappingKeys, options: verifyOptions).kid,
      "a-key"
    )

    let exported = try await issuer.exportTunnelKeyset()
    let root = try XCTUnwrap(JSONSerialization.jsonObject(with: exported) as? [String: Any])
    let keys = try XCTUnwrap(root["keys"] as? [[String: String]])
    XCTAssertEqual(keys.compactMap { $0["kid"] }, ["a-key", "z-key"])

    try await issuer.retireVerificationKey(kid: "z-key")
    let retiredKeys = await issuer.publicKeys()
    XCTAssertEqual(Set(retiredKeys.keys), ["a-key"])
    do {
      try await issuer.retireVerificationKey(kid: "a-key")
      XCTFail("Expected active key retirement to fail")
    } catch let error as FST2TokenError {
      XCTAssertEqual(error, .invalidFormat)
    }
  }

  func testTokenIssuerMatchesSharedRotationVector() async throws {
    let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let data = try Data(
      contentsOf: root.appendingPathComponent("testdata/issuer_rotation_vectors.json")
    )
    let vector = try JSONDecoder().decode(IssuerRotationVector.self, from: data)
    XCTAssertEqual(vector.version, 1)
    let first = try XCTUnwrap(vector.keys.first)
    let second = try XCTUnwrap(vector.keys.dropFirst().first)
    let firstSeed = try XCTUnwrap(Data(base64URLEncoded: first.seedB64U))
    let secondSeed = try XCTUnwrap(Data(base64URLEncoded: second.seedB64U))
    let secondPublicKey = try XCTUnwrap(Data(base64URLEncoded: second.publicKeyB64U))
    let issuer = try TokenIssuer(kid: first.kid, seed: firstSeed)

    try await assertIssuer(issuer, matches: vector.stages[0])
    try await issuer.addVerificationKey(kid: second.kid, publicKey: secondPublicKey)
    try await assertIssuer(issuer, matches: vector.stages[1])
    try await issuer.rotate(kid: second.kid, seed: secondSeed)
    try await assertIssuer(issuer, matches: vector.stages[2])
    try await issuer.retireVerificationKey(kid: first.kid)
    try await assertIssuer(issuer, matches: vector.stages[3])
  }

  func testTokenIssuerRotationFailurePreservesStateAndSnapshots() async throws {
    let seed1 = Data(repeating: 3, count: 32)
    let seed2 = Data(repeating: 4, count: 32)
    let issuer = try TokenIssuer(kid: "key-1", seed: seed1)
    let publicKey2 = try Curve25519.Signing.PrivateKey(rawRepresentation: seed2)
      .publicKey.rawRepresentation
    try await issuer.addVerificationKey(kid: "key-2", publicKey: publicKey2)

    do {
      try await issuer.rotate(kid: "key-2", seed: Data(repeating: 0, count: 31))
      XCTFail("Expected invalid seed rejection")
    } catch {
      let currentKeyID = await issuer.currentKeyID()
      XCTAssertEqual(currentKeyID, "key-1")
    }
    do {
      try await issuer.rotate(kid: "key-2", seed: Data(repeating: 9, count: 32))
      XCTFail("Expected prepublished key mismatch rejection")
    } catch let error as FST2TokenError {
      XCTAssertEqual(error, .invalidFormat)
    }
    let currentAfterMismatchedRotation = await issuer.currentKeyID()
    XCTAssertEqual(currentAfterMismatchedRotation, "key-1")

    var snapshot = await issuer.publicKeys()
    snapshot["key-1"] = Data(repeating: 0, count: 32)
    let currentKeys = await issuer.publicKeys()
    XCTAssertNotEqual(currentKeys["key-1"], snapshot["key-1"])
  }

  func testControlplaneHTTPCodec() throws {
    let request = try Controlplane.decodeArtifactRequest(
      contentType: "application/json; charset=utf-8",
      body: Data(
        "{\"endpoint_id\":\" endpoint-1 \",\"correlation\":{\"trace_id\":\" trace-1 \"}}".utf8)
    )
    XCTAssertEqual(request.endpointID, "endpoint-1")
    XCTAssertEqual(request.correlation?.traceID, "trace-1")
    XCTAssertEqual(Controlplane.bearerToken("Bearer ticket-1"), "ticket-1")
    let error = try Controlplane.encodeErrorEnvelope(code: "denied", message: "not allowed")
    XCTAssertEqual(
      try JSONSerialization.jsonObject(with: error) as? NSDictionary,
      ["error": ["code": "denied", "message": "not allowed"]] as NSDictionary
    )
  }
}

private func tokenPayload(kid: String) -> FST2TokenPayload {
  FST2TokenPayload(
    kid: kid,
    audience: "flowersec-tunnel:test",
    issuer: "issuer-test",
    channelID: "channel-token",
    role: 1,
    tokenID: UUID().uuidString,
    initExpiresAtUnixS: 1_700_000_100,
    idleTimeoutSeconds: 60,
    issuedAtUnixS: 1_700_000_000,
    expiresAtUnixS: 1_700_000_060
  )
}

private func assertIssuer(
  _ issuer: TokenIssuer,
  matches stage: IssuerRotationVector.Stage
) async throws {
  let activeKeyID = await issuer.currentKeyID()
  let keyIDs = Set(await issuer.publicKeys().keys)
  XCTAssertEqual(activeKeyID, stage.activeKID, stage.name)
  XCTAssertEqual(keyIDs, Set(stage.verificationKIDs), stage.name)
}

private struct IssuerRotationVector: Decodable {
  struct Key: Decodable {
    var kid: String
    var seedB64U: String
    var publicKeyB64U: String

    private enum CodingKeys: String, CodingKey {
      case kid
      case seedB64U = "seed_b64u"
      case publicKeyB64U = "public_key_b64u"
    }
  }

  struct Stage: Decodable {
    var name: String
    var activeKID: String
    var verificationKIDs: [String]

    private enum CodingKeys: String, CodingKey {
      case name
      case activeKID = "active_kid"
      case verificationKIDs = "verification_kids"
    }
  }

  var version: Int
  var keys: [Key]
  var stages: [Stage]
}

private func artifactURLSession() -> URLSession {
  let configuration = URLSessionConfiguration.ephemeral
  configuration.protocolClasses = [ArtifactURLProtocol.self]
  return URLSession(configuration: configuration)
}

private func waitForArtifactProtocolStop() async throws {
  for _ in 0..<100 where ArtifactURLProtocol.stopCount == 0 {
    try await Task.sleep(for: .milliseconds(5))
  }
  XCTAssertGreaterThan(ArtifactURLProtocol.stopCount, 0)
}

private func waitForArtifactProtocolChunks(_ count: Int) async throws {
  for _ in 0..<100 where ArtifactURLProtocol.deliveredChunkCount < count {
    try await Task.sleep(for: .milliseconds(5))
  }
  XCTAssertEqual(ArtifactURLProtocol.deliveredChunkCount, count)
}

private func artifactRequestBody(_ request: URLRequest) throws -> Data {
  if let body = request.httpBody { return body }
  let stream = try XCTUnwrap(request.httpBodyStream)
  stream.open()
  defer { stream.close() }
  var output = Data()
  var buffer = [UInt8](repeating: 0, count: 4096)
  while stream.hasBytesAvailable {
    let count = stream.read(&buffer, maxLength: buffer.count)
    if count < 0 { throw try XCTUnwrap(stream.streamError) }
    if count == 0 { break }
    output.append(contentsOf: buffer.prefix(count))
  }
  return output
}

private final class ArtifactURLProtocol: URLProtocol, @unchecked Sendable {
  private static let handlerStore = ArtifactURLProtocolHandlerStore()

  static var stopCount: Int { handlerStore.stopCount }
  static var deliveredChunkCount: Int { handlerStore.deliveredChunkCount }

  static func allowNextChunk() {
    handlerStore.allowNextChunk()
  }

  static func setHandler(
    _ handler: (@Sendable (URLRequest) throws -> ArtifactHTTPResponse)?
  ) {
    handlerStore.set(handler)
  }

  static func reset() {
    handlerStore.reset()
  }

  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    do {
      let handler = try XCTUnwrap(Self.handlerStore.get())
      let specification = try handler(request)
      var headers = specification.headers
      headers["Content-Type"] = headers["Content-Type"] ?? "application/json"
      let response = HTTPURLResponse(
        url: try XCTUnwrap(request.url),
        statusCode: specification.status,
        httpVersion: "HTTP/1.1",
        headerFields: headers
      )!
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      if specification.controlledChunks {
        DispatchQueue.global().async { [self] in
          deliverControlledChunks(specification.chunks)
        }
      } else {
        for chunk in specification.chunks {
          client?.urlProtocol(self, didLoad: chunk)
          Self.handlerStore.recordDeliveredChunk()
        }
        client?.urlProtocolDidFinishLoading(self)
      }
    } catch {
      client?.urlProtocol(self, didFailWithError: error)
    }
  }

  private func deliverControlledChunks(_ chunks: [Data]) {
    for chunk in chunks {
      guard Self.handlerStore.waitForChunkPermission() else { return }
      client?.urlProtocol(self, didLoad: chunk)
      Self.handlerStore.recordDeliveredChunk()
    }
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {
    Self.handlerStore.recordStop()
  }
}

private struct ArtifactHTTPResponse: Sendable {
  var status: Int
  var headers: [String: String] = [:]
  var chunks: [Data]
  var controlledChunks = false
}

private final class ArtifactURLProtocolHandlerStore: @unchecked Sendable {
  private let condition = NSCondition()
  private var handler: (@Sendable (URLRequest) throws -> ArtifactHTTPResponse)?
  private var stops = 0
  private var deliveredChunks = 0
  private var chunkPermits = 0
  private var stopped = false

  var stopCount: Int {
    condition.lock()
    defer { condition.unlock() }
    return stops
  }

  var deliveredChunkCount: Int {
    condition.lock()
    defer { condition.unlock() }
    return deliveredChunks
  }

  func set(_ handler: (@Sendable (URLRequest) throws -> ArtifactHTTPResponse)?) {
    condition.lock()
    self.handler = handler
    condition.unlock()
  }

  func get() -> (@Sendable (URLRequest) throws -> ArtifactHTTPResponse)? {
    condition.lock()
    defer { condition.unlock() }
    return handler
  }

  func recordStop() {
    condition.lock()
    stops += 1
    stopped = true
    condition.broadcast()
    condition.unlock()
  }

  func allowNextChunk() {
    condition.lock()
    chunkPermits += 1
    condition.signal()
    condition.unlock()
  }

  func waitForChunkPermission() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    while chunkPermits == 0, !stopped {
      condition.wait()
    }
    guard !stopped else { return false }
    chunkPermits -= 1
    return true
  }

  func recordDeliveredChunk() {
    condition.lock()
    deliveredChunks += 1
    condition.unlock()
  }

  func reset() {
    condition.lock()
    handler = nil
    stops = 0
    deliveredChunks = 0
    chunkPermits = 0
    stopped = false
    condition.broadcast()
    condition.unlock()
  }
}

extension Data {
  fileprivate init(hex: String) throws {
    guard hex.count.isMultiple(of: 2) else { throw FST2TokenError.invalidFormat }
    var output = Data()
    output.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let end = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<end], radix: 16) else {
        throw FST2TokenError.invalidFormat
      }
      output.append(byte)
      index = end
    }
    self = output
  }
}
