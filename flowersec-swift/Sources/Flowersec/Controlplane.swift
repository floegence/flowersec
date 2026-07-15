import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct ControlplaneArtifactRequest: Codable, Equatable, Sendable {
  public var endpointID: String
  public var payload: ScopePayload?
  public var correlation: CorrelationInput?

  public init(endpointID: String, payload: ScopePayload? = nil, traceID: String? = nil) {
    self.endpointID = endpointID
    self.payload = payload
    self.correlation = traceID.map { CorrelationInput(traceID: $0) }
  }

  public struct CorrelationInput: Codable, Equatable, Sendable {
    public var traceID: String

    public init(traceID: String) { self.traceID = traceID }

    private enum CodingKeys: String, CodingKey { case traceID = "trace_id" }
  }

  private enum CodingKeys: String, CodingKey {
    case endpointID = "endpoint_id"
    case payload
    case correlation
  }
}

public struct ControlplaneRequestError: LocalizedError, Equatable, Sendable {
  public var status: Int
  public var code: String
  public var message: String
  public var responseBody: Data

  public var errorDescription: String? { message }
}

public struct ArtifactRequestOptions: Sendable {
  public var baseURL: URL
  public var path: String?
  public var endpointID: String
  public var payload: ScopePayload?
  public var traceID: String?
  public var headers: [String: String]
  public var maxResponseBodyBytes: Int

  public init(
    baseURL: URL,
    path: String? = nil,
    endpointID: String,
    payload: ScopePayload? = nil,
    traceID: String? = nil,
    headers: [String: String] = [:],
    maxResponseBodyBytes: Int = FlowersecSDKDefaults.Controlplane.maxResponseBodyBytes
  ) {
    self.baseURL = baseURL
    self.path = path
    self.endpointID = endpointID
    self.payload = payload
    self.traceID = traceID
    self.headers = headers
    self.maxResponseBodyBytes = maxResponseBodyBytes
  }
}

public enum Controlplane {
  public static let artifactPath = "/v1/connect/artifact"
  public static let entryArtifactPath = "/v1/connect/artifact/entry"

  public static func requestConnectArtifact(
    _ options: ArtifactRequestOptions,
    session: URLSession = .shared
  ) async throws -> ConnectArtifact {
    try await requestArtifact(options, entryTicket: nil, session: session)
  }

  public static func requestEntryConnectArtifact(
    _ options: ArtifactRequestOptions,
    entryTicket: String,
    session: URLSession = .shared
  ) async throws -> ConnectArtifact {
    let ticket = entryTicket.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !ticket.isEmpty else {
      throw ControlplaneRequestError(
        status: 0,
        code: "invalid_input",
        message: "Entry ticket is required.",
        responseBody: Data()
      )
    }
    return try await requestArtifact(options, entryTicket: ticket, session: session)
  }

  public static func decodeArtifactRequest(
    contentType: String,
    body: Data,
    maxBodyBytes: Int = FlowersecSDKDefaults.Controlplane.maxRequestBodyBytes
  ) throws -> ControlplaneArtifactRequest {
    guard contentType.split(separator: ";", maxSplits: 1).first?
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased() == "application/json"
    else {
      throw ControlplaneRequestError(
        status: 415,
        code: "unsupported_media_type",
        message: "Content-Type must be application/json.",
        responseBody: Data()
      )
    }
    guard body.count <= maxBodyBytes else {
      throw ControlplaneRequestError(
        status: 413,
        code: "body_too_large",
        message: "Request body exceeds \(maxBodyBytes) bytes.",
        responseBody: Data()
      )
    }
    do {
      var request = try JSONDecoder().decode(ControlplaneArtifactRequest.self, from: body)
      request.endpointID = request.endpointID.trimmingCharacters(in: .whitespacesAndNewlines)
      if var correlation = request.correlation {
        correlation.traceID = correlation.traceID.trimmingCharacters(in: .whitespacesAndNewlines)
        request.correlation = correlation
      }
      guard !request.endpointID.isEmpty else {
        throw ControlplaneRequestError(
          status: 400,
          code: "invalid_request",
          message: "endpoint_id is required.",
          responseBody: Data()
        )
      }
      return request
    } catch let error as ControlplaneRequestError {
      throw error
    } catch {
      throw ControlplaneRequestError(
        status: 400,
        code: "invalid_json",
        message: "Request body is not valid JSON.",
        responseBody: Data()
      )
    }
  }

  public static func encodeArtifactEnvelope(_ artifact: ConnectArtifact) throws -> Data {
    let artifactData = try JSONEncoder.flowersecWire.encode(artifact)
    let artifactObject = try JSONSerialization.jsonObject(with: artifactData)
    return try JSONSerialization.data(
      withJSONObject: ["connect_artifact": artifactObject],
      options: [.sortedKeys]
    )
  }

  public static func encodeErrorEnvelope(code: String, message: String) throws -> Data {
    try JSONSerialization.data(
      withJSONObject: ["error": ["code": code, "message": message]],
      options: [.sortedKeys]
    )
  }

  public static func bearerToken(_ authorization: String) -> String? {
    let value = authorization.trimmingCharacters(in: .whitespacesAndNewlines)
    guard value.hasPrefix("Bearer ") else { return nil }
    let token = value.dropFirst("Bearer ".count)
      .trimmingCharacters(in: .whitespacesAndNewlines)
    return token.isEmpty ? nil : token
  }

  private static func requestArtifact(
    _ options: ArtifactRequestOptions,
    entryTicket: String?,
    session: URLSession
  ) async throws -> ConnectArtifact {
    let endpointID = options.endpointID.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !endpointID.isEmpty, options.maxResponseBodyBytes > 0 else {
      throw ControlplaneRequestError(
        status: 0,
        code: "invalid_input",
        message: "Artifact request options are invalid.",
        responseBody: Data()
      )
    }
    let defaultPath = entryTicket == nil ? artifactPath : entryArtifactPath
    let path = options.path?.trimmingCharacters(in: .whitespacesAndNewlines)
    let url = try artifactURL(baseURL: options.baseURL, path: path?.isEmpty == false ? path! : defaultPath)
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    for (name, value) in options.headers { request.setValue(value, forHTTPHeaderField: name) }
    if let entryTicket { request.setValue("Bearer \(entryTicket)", forHTTPHeaderField: "Authorization") }
    request.httpBody = try JSONEncoder.flowersecWire.encode(
      ControlplaneArtifactRequest(
        endpointID: endpointID,
        payload: options.payload,
        traceID: options.traceID?.trimmingCharacters(in: .whitespacesAndNewlines)
      )
    )
    let (data, response) = try await session.data(for: request)
    guard let http = response as? HTTPURLResponse else {
      throw ControlplaneRequestError(status: 0, code: "transport_error", message: "Controlplane response was not HTTP.", responseBody: data)
    }
    guard data.count <= options.maxResponseBodyBytes else {
      throw ControlplaneRequestError(status: http.statusCode, code: "response_too_large", message: "Controlplane response is too large.", responseBody: Data())
    }
    guard (200..<300).contains(http.statusCode) else {
      let decoded = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
      let error = decoded?["error"] as? [String: Any]
      throw ControlplaneRequestError(
        status: http.statusCode,
        code: error?["code"] as? String ?? "request_failed",
        message: error?["message"] as? String ?? "Controlplane request failed.",
        responseBody: data
      )
    }
    guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let artifactObject = root["connect_artifact"]
    else {
      throw ControlplaneRequestError(status: http.statusCode, code: "invalid_response", message: "Controlplane response is missing connect_artifact.", responseBody: data)
    }
    let artifactData = try JSONSerialization.data(withJSONObject: artifactObject)
    return try JSONDecoder().decode(ConnectArtifact.self, from: artifactData)
  }

  private static func artifactURL(baseURL: URL, path: String) throws -> URL {
    guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
      throw ControlplaneRequestError(status: 0, code: "invalid_input", message: "Controlplane base URL is invalid.", responseBody: Data())
    }
    let basePath = components.path.hasSuffix("/") ? String(components.path.dropLast()) : components.path
    components.path = basePath + (path.hasPrefix("/") ? path : "/\(path)")
    guard let url = components.url else {
      throw ControlplaneRequestError(status: 0, code: "invalid_input", message: "Controlplane URL is invalid.", responseBody: Data())
    }
    return url
  }
}

public struct FST2TokenPayload: Codable, Equatable, Sendable {
  public var kid: String
  public var audience: String
  public var issuer: String
  public var channelID: String
  public var role: UInt8
  public var tokenID: String
  public var initExpiresAtUnixS: Int64
  public var idleTimeoutSeconds: Int32
  public var issuedAtUnixS: Int64
  public var expiresAtUnixS: Int64

  public init(
    kid: String = "",
    audience: String,
    issuer: String = "",
    channelID: String,
    role: UInt8,
    tokenID: String,
    initExpiresAtUnixS: Int64,
    idleTimeoutSeconds: Int32,
    issuedAtUnixS: Int64,
    expiresAtUnixS: Int64
  ) {
    self.kid = kid
    self.audience = audience
    self.issuer = issuer
    self.channelID = channelID
    self.role = role
    self.tokenID = tokenID
    self.initExpiresAtUnixS = initExpiresAtUnixS
    self.idleTimeoutSeconds = idleTimeoutSeconds
    self.issuedAtUnixS = issuedAtUnixS
    self.expiresAtUnixS = expiresAtUnixS
  }

  private enum CodingKeys: String, CodingKey {
    case kid
    case audience = "aud"
    case issuer = "iss"
    case channelID = "channel_id"
    case role
    case tokenID = "token_id"
    case initExpiresAtUnixS = "init_exp"
    case idleTimeoutSeconds = "idle_timeout_seconds"
    case issuedAtUnixS = "iat"
    case expiresAtUnixS = "exp"
  }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    kid = try container.decode(String.self, forKey: .kid)
    audience = try container.decode(String.self, forKey: .audience)
    issuer = try container.decodeIfPresent(String.self, forKey: .issuer) ?? ""
    channelID = try container.decode(String.self, forKey: .channelID)
    role = try container.decode(UInt8.self, forKey: .role)
    tokenID = try container.decode(String.self, forKey: .tokenID)
    initExpiresAtUnixS = try container.decode(Int64.self, forKey: .initExpiresAtUnixS)
    idleTimeoutSeconds = try container.decode(Int32.self, forKey: .idleTimeoutSeconds)
    issuedAtUnixS = try container.decode(Int64.self, forKey: .issuedAtUnixS)
    expiresAtUnixS = try container.decode(Int64.self, forKey: .expiresAtUnixS)
  }
}

public struct FST2VerifyOptions: Sendable {
  public var nowUnixS: Int64?
  public var audience: String?
  public var issuer: String?
  public var clockSkew: Duration

  public init(
    nowUnixS: Int64? = nil,
    audience: String? = nil,
    issuer: String? = nil,
    clockSkew: Duration = .zero
  ) {
    self.nowUnixS = nowUnixS
    self.audience = audience
    self.issuer = issuer
    self.clockSkew = clockSkew
  }
}

public enum FST2Token {
  public static let prefix = "FST2"

  public static func sign(
    privateKey: Curve25519.Signing.PrivateKey,
    payload: FST2TokenPayload
  ) throws -> String {
    let normalized = try validate(payload, signing: true)
    let payloadData = try orderedPayloadData(normalized)
    let signed = Data("\(prefix).\(payloadData.base64URLEncodedString())".utf8)
    let signature = try privateKey.signature(for: signed)
    return "\(String(decoding: signed, as: UTF8.self)).\(signature.base64URLEncodedString())"
  }

  public static func verify(
    _ token: String,
    keys: [String: Data],
    options: FST2VerifyOptions = FST2VerifyOptions()
  ) throws -> FST2TokenPayload {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3, parts[0] == Substring(prefix),
      let payloadData = Data(base64URLEncoded: String(parts[1])),
      let signature = Data(base64URLEncoded: String(parts[2]))
    else { throw FST2TokenError.invalidFormat }
    let payload: FST2TokenPayload
    do { payload = try JSONDecoder().decode(FST2TokenPayload.self, from: payloadData) }
    catch { throw FST2TokenError.invalidJSON }
    let normalized = try validate(payload, signing: false)
    guard let publicKeyData = keys[normalized.kid] else { throw FST2TokenError.unknownKey }
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
    let signed = Data("\(prefix).\(parts[1])".utf8)
    guard publicKey.isValidSignature(signature, for: signed) else {
      throw FST2TokenError.invalidSignature
    }
    if let audience = options.audience,
      !controlplaneConstantTimeEqual(Data(normalized.audience.utf8), Data(audience.utf8))
    { throw FST2TokenError.invalidAudience }
    if let issuer = options.issuer,
      !controlplaneConstantTimeEqual(Data(normalized.issuer.utf8), Data(issuer.utf8))
    { throw FST2TokenError.invalidIssuer }
    let skew = controlplaneDurationSecondsCeil(options.clockSkew)
    let now = options.nowUnixS ?? Int64(Date().timeIntervalSince1970)
    if normalized.issuedAtUnixS > now + skew { throw FST2TokenError.issuedInFuture }
    if normalized.initExpiresAtUnixS < now - skew { throw FST2TokenError.initExpired }
    if normalized.expiresAtUnixS < now - skew { throw FST2TokenError.expired }
    return normalized
  }

  private static func validate(
    _ payload: FST2TokenPayload,
    signing: Bool
  ) throws -> FST2TokenPayload {
    var payload = payload
    payload.kid = payload.kid.trimmingCharacters(in: .whitespacesAndNewlines)
    payload.audience = payload.audience.trimmingCharacters(in: .whitespacesAndNewlines)
    payload.issuer = payload.issuer.trimmingCharacters(in: .whitespacesAndNewlines)
    payload.channelID = payload.channelID.trimmingCharacters(in: .whitespacesAndNewlines)
    payload.tokenID = payload.tokenID.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !payload.kid.isEmpty, !payload.tokenID.isEmpty,
      !payload.channelID.isEmpty, payload.channelID.utf8.count <= 256,
      payload.role == 1 || payload.role == 2
    else { throw FST2TokenError.invalidFormat }
    guard !signing || !payload.audience.isEmpty else { throw FST2TokenError.invalidFormat }
    guard payload.idleTimeoutSeconds > 0 else { throw FST2TokenError.invalidIdleTimeout }
    guard !signing || (payload.initExpiresAtUnixS > 0 && payload.issuedAtUnixS > 0 && payload.expiresAtUnixS > 0) else {
      throw FST2TokenError.invalidFormat
    }
    guard payload.expiresAtUnixS <= payload.initExpiresAtUnixS else { throw FST2TokenError.expAfterInit }
    guard payload.issuedAtUnixS <= payload.expiresAtUnixS else { throw FST2TokenError.invalidFormat }
    return payload
  }

  private static func orderedPayloadData(_ payload: FST2TokenPayload) throws -> Data {
    var fields = [
      "\"kid\":\(try quoted(payload.kid))",
      "\"aud\":\(try quoted(payload.audience))",
    ]
    if !payload.issuer.isEmpty { fields.append("\"iss\":\(try quoted(payload.issuer))") }
    fields.append(contentsOf: [
      "\"channel_id\":\(try quoted(payload.channelID))",
      "\"role\":\(payload.role)",
      "\"token_id\":\(try quoted(payload.tokenID))",
      "\"init_exp\":\(payload.initExpiresAtUnixS)",
      "\"idle_timeout_seconds\":\(payload.idleTimeoutSeconds)",
      "\"iat\":\(payload.issuedAtUnixS)",
      "\"exp\":\(payload.expiresAtUnixS)",
    ])
    return Data("{\(fields.joined(separator: ","))}".utf8)
  }

  private static func quoted(_ value: String) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: [value])
    let text = String(decoding: data, as: UTF8.self)
    return String(text.dropFirst().dropLast())
  }
}

public enum FST2TokenError: Error, Equatable, Sendable {
  case invalidFormat
  case invalidJSON
  case unknownKey
  case invalidSignature
  case invalidAudience
  case invalidIssuer
  case issuedInFuture
  case initExpired
  case expired
  case expAfterInit
  case invalidIdleTimeout
}

public actor TokenIssuer {
  private var kid: String
  private var privateKey: Curve25519.Signing.PrivateKey

  public init(kid: String, privateKey: Curve25519.Signing.PrivateKey) throws {
    let kid = kid.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !kid.isEmpty else { throw FST2TokenError.invalidFormat }
    self.kid = kid
    self.privateKey = privateKey
  }

  public init(kid: String, seed: Data) throws {
    try self.init(
      kid: kid,
      privateKey: Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    )
  }

  public static func random(kid: String) throws -> TokenIssuer {
    try TokenIssuer(kid: kid, privateKey: Curve25519.Signing.PrivateKey())
  }

  public func currentKeyID() -> String { kid }

  public func publicKeys() -> [String: Data] {
    [kid: privateKey.publicKey.rawRepresentation]
  }

  public func sign(_ payload: FST2TokenPayload) throws -> String {
    var payload = payload
    payload.kid = kid
    return try FST2Token.sign(privateKey: privateKey, payload: payload)
  }

  public func rotate(kid: String, seed: Data) throws {
    let kid = kid.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !kid.isEmpty else { throw FST2TokenError.invalidFormat }
    self.kid = kid
    self.privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
  }

  public func exportTunnelKeyset() throws -> Data {
    try JSONSerialization.data(
      withJSONObject: [
        "keys": [[
          "kid": kid,
          "pubkey_b64u": privateKey.publicKey.rawRepresentation.base64URLEncodedString(),
        ]]
      ],
      options: [.prettyPrinted, .sortedKeys]
    )
  }
}

public struct ChannelInitParams: Equatable, Sendable {
  public var tunnelURL: URL
  public var tunnelAudience: String
  public var issuerID: String
  public var tokenExpirySeconds: Int64
  public var idleTimeoutSeconds: Int32
  public var clockSkew: Duration
  public var allowedSuites: [Suite]
  public var defaultSuite: Suite?

  public init(
    tunnelURL: URL,
    tunnelAudience: String,
    issuerID: String,
    tokenExpirySeconds: Int64 = 0,
    idleTimeoutSeconds: Int32 = 0,
    clockSkew: Duration = .zero,
    allowedSuites: [Suite] = [],
    defaultSuite: Suite? = nil
  ) {
    self.tunnelURL = tunnelURL
    self.tunnelAudience = tunnelAudience
    self.issuerID = issuerID
    self.tokenExpirySeconds = tokenExpirySeconds
    self.idleTimeoutSeconds = idleTimeoutSeconds
    self.clockSkew = clockSkew
    self.allowedSuites = allowedSuites
    self.defaultSuite = defaultSuite
  }
}

public actor ChannelInitService {
  public static let windowSeconds: Int64 = 120
  public static let defaultTokenExpirySeconds: Int64 = 60
  public static let defaultIdleTimeoutSeconds: Int32 = 60

  private let issuer: TokenIssuer
  private let params: ChannelInitParams
  private let now: @Sendable () -> Int64

  public init(
    issuer: TokenIssuer,
    params: ChannelInitParams,
    now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) }
  ) {
    self.issuer = issuer
    self.params = params
    self.now = now
  }

  public func issue(channelID: String) async throws -> (client: ChannelInitGrant, server: ChannelInitGrant) {
    let normalized = try normalizedParams()
    let channelID = try normalizedChannelID(channelID)
    var psk = try Data.secureRandom(count: 32)
    defer { psk.resetBytes(in: 0..<psk.count) }
    let issuedAt = now()
    let initExpiry = issuedAt + Self.windowSeconds
    let clientToken = try await roleToken(
      channelID: channelID,
      role: 1,
      initExpiry: initExpiry,
      issuedAt: issuedAt,
      params: normalized
    )
    let serverToken = try await roleToken(
      channelID: channelID,
      role: 2,
      initExpiry: initExpiry,
      issuedAt: issuedAt,
      params: normalized
    )
    let grant = { (role: UInt8, token: String) in
      ChannelInitGrant(
        tunnelURL: normalized.tunnelURL,
        channelID: channelID,
        channelInitExpiresAtUnixS: initExpiry,
        idleTimeoutSeconds: normalized.idleTimeoutSeconds,
        role: role,
        token: token,
        psk: psk,
        allowedSuites: normalized.allowedSuites,
        defaultSuite: normalized.defaultSuite!
      )
    }
    return (grant(1, clientToken), grant(2, serverToken))
  }

  public func reissue(_ grant: ChannelInitGrant) async throws -> ChannelInitGrant {
    let normalized = try normalizedParams()
    let issuedAt = now()
    guard issuedAt <= grant.channelInitExpiresAtUnixS + controlplaneDurationSecondsCeil(normalized.clockSkew),
      grant.idleTimeoutSeconds > 0,
      grant.role == 1 || grant.role == 2
    else { throw FST2TokenError.initExpired }
    var grant = grant
    grant.token = try await roleToken(
      channelID: try normalizedChannelID(grant.channelID),
      role: grant.role,
      initExpiry: grant.channelInitExpiresAtUnixS,
      issuedAt: issuedAt,
      params: normalized
    )
    return grant
  }

  private func roleToken(
    channelID: String,
    role: UInt8,
    initExpiry: Int64,
    issuedAt: Int64,
    params: ChannelInitParams
  ) async throws -> String {
    let iat = min(issuedAt, initExpiry)
    let exp = min(initExpiry, iat + params.tokenExpirySeconds)
    return try await issuer.sign(
      FST2TokenPayload(
        audience: params.tunnelAudience,
        issuer: params.issuerID,
        channelID: channelID,
        role: role,
        tokenID: try Data.secureRandom(count: 24).base64URLEncodedString(),
        initExpiresAtUnixS: initExpiry,
        idleTimeoutSeconds: params.idleTimeoutSeconds,
        issuedAtUnixS: iat,
        expiresAtUnixS: exp
      )
    )
  }

  private func normalizedParams() throws -> ChannelInitParams {
    var params = params
    params.tunnelAudience = params.tunnelAudience.trimmingCharacters(in: .whitespacesAndNewlines)
    params.issuerID = params.issuerID.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !params.tunnelAudience.isEmpty, !params.issuerID.isEmpty,
      params.tokenExpirySeconds >= 0,
      params.idleTimeoutSeconds >= 0,
      params.clockSkew >= .zero
    else { throw FST2TokenError.invalidFormat }
    if params.tokenExpirySeconds == 0 { params.tokenExpirySeconds = Self.defaultTokenExpirySeconds }
    if params.idleTimeoutSeconds == 0 { params.idleTimeoutSeconds = Self.defaultIdleTimeoutSeconds }
    if params.allowedSuites.isEmpty { params.allowedSuites = [.x25519HKDFSHA256AES256GCM] }
    params.allowedSuites = params.allowedSuites.reduce(into: []) { result, suite in
      if !result.contains(suite) { result.append(suite) }
    }
    let defaultSuite = params.defaultSuite ?? params.allowedSuites[0]
    guard params.allowedSuites.contains(defaultSuite) else { throw FST2TokenError.invalidFormat }
    params.defaultSuite = defaultSuite
    return params
  }

  private func normalizedChannelID(_ input: String) throws -> String {
    let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !value.isEmpty, value.utf8.count <= 256 else { throw FST2TokenError.invalidFormat }
    return value
  }
}

private func controlplaneDurationSecondsCeil(_ duration: Duration) -> Int64 {
  let components = duration.components
  return max(0, components.seconds + (components.attoseconds == 0 ? 0 : 1))
}

private func controlplaneConstantTimeEqual(_ left: Data, _ right: Data) -> Bool {
  var difference = left.count ^ right.count
  let count = max(left.count, right.count)
  for index in 0..<count {
    difference |= Int(index < left.count ? left[index] : 0) ^ Int(index < right.count ? right[index] : 0)
  }
  return difference == 0
}
