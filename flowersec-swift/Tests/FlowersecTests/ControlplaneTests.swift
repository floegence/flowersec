import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import Flowersec

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
      return (200, response)
    }
    defer { ArtifactURLProtocol.setHandler(nil) }
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [ArtifactURLProtocol.self]
    let session = URLSession(configuration: configuration)

    let fetched = try await Controlplane.requestConnectArtifact(
      ArtifactRequestOptions(
        baseURL: URL(string: "https://controlplane.example.test")!,
        endpointID: "endpoint-artifact"
      ),
      session: session
    )
    XCTAssertEqual(fetched, artifact)
  }

  func testFST2TokenMatchesSharedGoldenVector() async throws {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let data = try Data(contentsOf: root.appending(path: "idl/flowersec/testdata/v1/token_vectors.json"))
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

  func testControlplaneHTTPCodec() throws {
    let request = try Controlplane.decodeArtifactRequest(
      contentType: "application/json; charset=utf-8",
      body: Data("{\"endpoint_id\":\" endpoint-1 \",\"correlation\":{\"trace_id\":\" trace-1 \"}}".utf8)
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

  static func setHandler(
    _ handler: (@Sendable (URLRequest) throws -> (Int, Data))?
  ) {
    handlerStore.set(handler)
  }

  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

  override func startLoading() {
    do {
      let handler = try XCTUnwrap(Self.handlerStore.get())
      let (status, body) = try handler(request)
      let response = HTTPURLResponse(
        url: try XCTUnwrap(request.url),
        statusCode: status,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Type": "application/json"]
      )!
      client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
      client?.urlProtocol(self, didLoad: body)
      client?.urlProtocolDidFinishLoading(self)
    } catch {
      client?.urlProtocol(self, didFailWithError: error)
    }
  }

  override func stopLoading() {}
}

private final class ArtifactURLProtocolHandlerStore: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable (URLRequest) throws -> (Int, Data))?

  func set(_ handler: (@Sendable (URLRequest) throws -> (Int, Data))?) {
    lock.lock()
    self.handler = handler
    lock.unlock()
  }

  func get() -> (@Sendable (URLRequest) throws -> (Int, Data))? {
    lock.lock()
    defer { lock.unlock() }
    return handler
  }
}

private extension Data {
  init(hex: String) throws {
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
