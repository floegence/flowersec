import Crypto
import Foundation

protocol TransportV2CarrierStream: Sendable {
  var carrierStreamID: UInt64 { get }

  func read(maxBytes: Int) async throws -> Data?
  func write(_ data: Data) async throws -> Int
  func closeWrite() async throws
  func reset(code: UInt16) async
  /// Synchronously initiates idempotent forced teardown. Pending and future
  /// stream operations must finish, but this call does not await cleanup.
  nonisolated func abort(code: UInt16)
  func close() async
}

protocol TransportV2CarrierSession: Sendable {
  var chosenCarrier: CarrierKind { get }
  /// Exact peer-initiated physical bidirectional-stream capacity available to
  /// Flowersec after admission. It includes control, RPC, and application slots.
  var inboundBidirectionalStreamCapacity: UInt16 { get }

  func openStream() async throws -> any TransportV2CarrierStream
  func acceptStream() async throws -> any TransportV2CarrierStream
  func close(code: UInt16, reason: String) async
  /// Synchronously initiates idempotent forced teardown. Pending and future
  /// session and stream operations must finish, but this call does not await cleanup.
  nonisolated func abort(code: UInt16, reason: String)
}

public enum TransportV2SessionError: Error, Equatable, Sendable {
  case invalidConfiguration
  case handshakeFailed
  case protocolViolation
  case closed
  case goingAway
  case resourceExhausted
  case openRejected(UInt16)
  case streamReset
  case rekeyFailed
  case livenessFailed
}

struct TransportV2SessionDeadlines: Sendable {
  static let production = TransportV2SessionDeadlines(
    establish: .seconds(30),
    rekeyPrepare: .seconds(10),
    rekeyCompletion: .seconds(30),
    liveness: .seconds(10),
    closeFlush: .seconds(2),
    idleOverride: nil
  )

  var establish: Duration
  var rekeyPrepare: Duration
  var rekeyCompletion: Duration
  var liveness: Duration
  var closeFlush: Duration
  var idleOverride: Duration?

  func validate() -> Bool {
    guard establish > .zero, rekeyPrepare > .zero, rekeyCompletion > .zero, liveness > .zero,
      closeFlush > .zero
    else { return false }
    return idleOverride.map { $0 > .zero } ?? true
  }
}

struct TransportV2SessionConfig: Sendable {
  let role: SessionRoleV2
  let path: PathKind
  let channelID: String
  let sessionContractHash: Data
  let suite: TransportCipherSuiteV2
  let psk: Data
  let maxInboundStreams: UInt16
  let idleTimeoutSeconds: UInt32
  let localAdmissionBinding: Data
  let peerAdmissionBinding: Data
  let localEndpointInstanceID: String
  let expectedPeerEndpointInstanceID: String
  var rpcRouter: RPCRouter?
  var rpcServerOptions: RPCServerOptions
  var deadlines: TransportV2SessionDeadlines

  init(
    role: SessionRoleV2,
    path: PathKind,
    channelID: String,
    sessionContractHash: Data,
    suite: TransportCipherSuiteV2,
    psk: Data,
    maxInboundStreams: UInt16,
    idleTimeoutSeconds: UInt32,
    localAdmissionBinding: Data,
    peerAdmissionBinding: Data,
    localEndpointInstanceID: String = "",
    expectedPeerEndpointInstanceID: String = "",
    rpcRouter: RPCRouter? = nil,
    rpcServerOptions: RPCServerOptions = RPCServerOptions()
  ) {
    self.role = role
    self.path = path
    self.channelID = channelID
    self.sessionContractHash = sessionContractHash
    self.suite = suite
    self.psk = psk
    self.maxInboundStreams = maxInboundStreams
    self.idleTimeoutSeconds = idleTimeoutSeconds
    self.localAdmissionBinding = localAdmissionBinding
    self.peerAdmissionBinding = peerAdmissionBinding
    self.localEndpointInstanceID = localEndpointInstanceID
    self.expectedPeerEndpointInstanceID = expectedPeerEndpointInstanceID
    self.rpcRouter = rpcRouter
    self.rpcServerOptions = rpcServerOptions
    deadlines = .production
  }

  var idleTimeout: Duration? {
    guard idleTimeoutSeconds != 0 else { return nil }
    return deadlines.idleOverride ?? .seconds(Int64(idleTimeoutSeconds))
  }
}

struct TransportV2HandshakeMaterial: Sendable {
  let h3: Data
  let sessionPRK: Data
}

struct TransportV2HandshakeVectorInput {
  let id: String
  let suite: TransportCipherSuiteV2
  let fsc2: Data
  let clientInit: Data
  let serverCore: Data
  let serverFinished: Data
  let clientCore: Data
  let clientFinished: Data
  let psk: Data
  let clientPrivate: Data
  let serverPrivate: Data
  let clientPublic: Data
  let serverPublic: Data
  let sharedSecret: Data
  let handshakePRK: Data
  let h0: Data
  let h1: Data
  let serverConfirm: Data
  let h2: Data
  let clientConfirm: Data
  let h3: Data
  let sessionPRK: Data
}

enum TransportV2Handshake {
  static let controlPrefaceBytes = 16
  static let frameHeaderBytes = 12
  static let maxPayloadBytes = 8_192

  static func verifyVectorForTesting(_ vector: TransportV2HandshakeVectorInput) throws {
    func require(_ condition: Bool) throws {
      guard condition else { throw TransportV2SessionError.handshakeFailed }
    }

    try require(vector.fsc2 == controlPreface())
    try require(vector.psk.count == 32)

    let clientInit = try decodeCanonical(
      ClientInitWire.self,
      frame: vector.clientInit,
      type: 1
    )
    _ = try decodeCanonical(
      ServerFinishedCoreWire.self,
      frame: vector.serverCore,
      type: 2
    )
    let serverFinished = try decodeCanonical(
      ServerFinishedWire.self,
      frame: vector.serverFinished,
      type: 2
    )
    let clientCore = try decodeCanonical(
      ClientFinishedCoreWire.self,
      frame: vector.clientCore,
      type: 3
    )
    let clientFinished = try decodeCanonical(
      ClientFinishedWire.self,
      frame: vector.clientFinished,
      type: 3
    )

    try require(clientInit.suite == vector.suite.rawValue)
    let encodedServerCore = try frame(type: 2, value: serverFinished.core)
    let encodedClientCore = try frame(type: 3, value: clientCore)
    try require(encodedServerCore == vector.serverCore)
    try require(encodedClientCore == vector.clientCore)
    try require(clientFinished.handshakeID == clientCore.handshakeID)
    try require(clientInit.clientEphPubB64u == vector.clientPublic.base64URLEncodedString())
    try require(serverFinished.serverEphPubB64u == vector.serverPublic.base64URLEncodedString())

    let clientKey = try EphemeralKey(suite: vector.suite, rawRepresentation: vector.clientPrivate)
    let serverKey = try EphemeralKey(suite: vector.suite, rawRepresentation: vector.serverPrivate)
    try require(clientKey.publicKey == vector.clientPublic)
    try require(serverKey.publicKey == vector.serverPublic)
    let clientShared = try clientKey.sharedSecret(
      peer: decodePublicKey(serverFinished.serverEphPubB64u, suite: vector.suite)
    )
    let serverShared = try serverKey.sharedSecret(
      peer: decodePublicKey(clientInit.clientEphPubB64u, suite: vector.suite)
    )
    try require(timingSafeEqual(clientShared, vector.sharedSecret))
    try require(timingSafeEqual(serverShared, vector.sharedSecret))

    let handshakePRK = FlowersecHKDF.extractSHA256(
      salt: vector.psk,
      inputKeyMaterial: clientShared
    )
    try require(timingSafeEqual(handshakePRK, vector.handshakePRK))
    let h0 = hash(
      Data("flowersec-v2-handshake\0".utf8),
      vector.fsc2,
      lengthPrefixed(vector.clientInit)
    )
    try require(h0 == vector.h0)
    let h1 = hash(h0, lengthPrefixed(vector.serverCore))
    try require(h1 == vector.h1)
    let serverConfirm = confirm(
      label: "flowersec v2 server finished",
      prk: handshakePRK,
      transcript: h1
    )
    try require(timingSafeEqual(serverConfirm, vector.serverConfirm))
    let encodedServerConfirm = try requireCanonicalBase64(
      serverFinished.serverConfirmB64u,
      range: 32...32
    )
    try require(timingSafeEqual(encodedServerConfirm, serverConfirm))
    let h2 = hash(
      h1,
      lengthPrefixed(vector.serverFinished),
      lengthPrefixed(vector.clientCore)
    )
    try require(h2 == vector.h2)
    let clientConfirm = confirm(
      label: "flowersec v2 client finished",
      prk: handshakePRK,
      transcript: h2
    )
    try require(timingSafeEqual(clientConfirm, vector.clientConfirm))
    let encodedClientConfirm = try requireCanonicalBase64(
      clientFinished.clientConfirmB64u,
      range: 32...32
    )
    try require(timingSafeEqual(encodedClientConfirm, clientConfirm))
    let h3 = hash(h2, lengthPrefixed(vector.clientFinished))
    try require(h3 == vector.h3)
    try require(
      timingSafeEqual(
        FlowersecHKDF.extractSHA256(salt: h3, inputKeyMaterial: handshakePRK),
        vector.sessionPRK
      )
    )
  }

  static func perform(
    carrier: any TransportV2CarrierSession,
    config: TransportV2SessionConfig
  ) async throws -> (any TransportV2CarrierStream, TransportV2HandshakeMaterial) {
    try validate(config: config, carrier: carrier)
    let control = try await config.role == .client ? carrier.openStream() : carrier.acceptStream()
    do {
      let material =
        try await config.role == .client
        ? clientHandshake(control: control, config: config)
        : serverHandshake(control: control, config: config)
      return (control, material)
    } catch {
      await control.reset(code: 6)
      throw TransportV2SessionError.handshakeFailed
    }
  }

  private static func validate(
    config: TransportV2SessionConfig,
    carrier: any TransportV2CarrierSession
  ) throws {
    guard
      validRegistryID(config.channelID, allowEmpty: false),
      config.sessionContractHash.count == 32,
      config.psk.count == 32,
      (1...128).contains(config.maxInboundStreams),
      carrier.inboundBidirectionalStreamCapacity == config.maxInboundStreams + 2,
      config.localAdmissionBinding.count == 32,
      config.peerAdmissionBinding.count == 32,
      config.deadlines.validate()
    else {
      throw TransportV2SessionError.invalidConfiguration
    }
    switch config.path {
    case .direct:
      guard
        config.localEndpointInstanceID.isEmpty,
        config.expectedPeerEndpointInstanceID.isEmpty
      else { throw TransportV2SessionError.invalidConfiguration }
    case .tunnel:
      guard
        validRegistryID(config.localEndpointInstanceID, allowEmpty: false),
        validRegistryID(config.expectedPeerEndpointInstanceID, allowEmpty: false)
      else { throw TransportV2SessionError.invalidConfiguration }
    }
  }

  private static func clientHandshake(
    control: any TransportV2CarrierStream,
    config: TransportV2SessionConfig
  ) async throws -> TransportV2HandshakeMaterial {
    let key = EphemeralKey(suite: config.suite)
    let fsc2 = controlPreface()
    let clientInit = ClientInitWire(
      clientAdmissionBindingB64u: config.localAdmissionBinding.base64URLEncodedString(),
      clientEndpointInstanceID: config.localEndpointInstanceID,
      clientEphPubB64u: key.publicKey.base64URLEncodedString(),
      clientRole: 1,
      channelID: config.channelID,
      maxInboundStreams: config.maxInboundStreams,
      nonceCB64u: try Data.secureRandom(count: 32).base64URLEncodedString(),
      profile: "flowersec/2",
      selectedFeatures: 0,
      sessionContractHashB64u: config.sessionContractHash.base64URLEncodedString(),
      suite: config.suite.rawValue
    )
    let initRaw = try frame(type: 1, value: clientInit)
    try await writeAll(fsc2, to: control)
    try await writeAll(initRaw, to: control)

    let serverRaw = try await readFrame(from: control, expectedType: 2)
    let server = try decodeCanonical(ServerFinishedWire.self, frame: serverRaw, type: 2)
    try validateServer(server, config: config)
    let serverPublic = try decodePublicKey(server.serverEphPubB64u, suite: config.suite)
    let shared = try key.sharedSecret(peer: serverPublic)
    let handshakePRK = FlowersecHKDF.extractSHA256(salt: config.psk, inputKeyMaterial: shared)
    let h0 = hash(Data("flowersec-v2-handshake\0".utf8), fsc2, lengthPrefixed(initRaw))
    let serverCoreRaw = try frame(type: 2, value: server.core)
    let h1 = hash(h0, lengthPrefixed(serverCoreRaw))
    guard
      let serverConfirm = canonicalBase64(server.serverConfirmB64u, count: 32),
      timingSafeEqual(
        serverConfirm,
        confirm(label: "flowersec v2 server finished", prk: handshakePRK, transcript: h1))
    else { throw TransportV2SessionError.handshakeFailed }

    let handshakeID = try requireCanonicalBase64(server.handshakeID, range: 16...32)
    let clientCoreRaw = try frame(
      type: 3,
      value: ClientFinishedCoreWire(handshakeID: handshakeID.base64URLEncodedString())
    )
    let h2 = hash(h1, lengthPrefixed(serverRaw), lengthPrefixed(clientCoreRaw))
    let finished = ClientFinishedWire(
      clientConfirmB64u: confirm(
        label: "flowersec v2 client finished",
        prk: handshakePRK,
        transcript: h2
      ).base64URLEncodedString(),
      handshakeID: handshakeID.base64URLEncodedString()
    )
    let finishedRaw = try frame(type: 3, value: finished)
    try await writeAll(finishedRaw, to: control)
    let h3 = hash(h2, lengthPrefixed(finishedRaw))
    return TransportV2HandshakeMaterial(
      h3: h3,
      sessionPRK: FlowersecHKDF.extractSHA256(salt: h3, inputKeyMaterial: handshakePRK)
    )
  }

  private static func serverHandshake(
    control: any TransportV2CarrierStream,
    config: TransportV2SessionConfig
  ) async throws -> TransportV2HandshakeMaterial {
    let fsc2 = try await readExact(controlPrefaceBytes, from: control)
    guard fsc2 == controlPreface() else { throw TransportV2SessionError.handshakeFailed }
    let clientRaw = try await readFrame(from: control, expectedType: 1)
    let client = try decodeCanonical(ClientInitWire.self, frame: clientRaw, type: 1)
    try validateClient(client, config: config)

    let key = EphemeralKey(suite: config.suite)
    let clientPublic = try decodePublicKey(client.clientEphPubB64u, suite: config.suite)
    let shared = try key.sharedSecret(peer: clientPublic)
    let handshakePRK = FlowersecHKDF.extractSHA256(salt: config.psk, inputKeyMaterial: shared)
    let core = ServerFinishedCoreWire(
      handshakeID: try Data.secureRandom(count: 16).base64URLEncodedString(),
      maxInboundStreams: config.maxInboundStreams,
      nonceSB64u: try Data.secureRandom(count: 32).base64URLEncodedString(),
      selectedFeatures: 0,
      serverAdmissionBindingB64u: config.localAdmissionBinding.base64URLEncodedString(),
      serverEndpointInstanceID: config.localEndpointInstanceID,
      serverEphPubB64u: key.publicKey.base64URLEncodedString(),
      sessionContractHashB64u: config.sessionContractHash.base64URLEncodedString()
    )
    let h0 = hash(Data("flowersec-v2-handshake\0".utf8), fsc2, lengthPrefixed(clientRaw))
    let coreRaw = try frame(type: 2, value: core)
    let h1 = hash(h0, lengthPrefixed(coreRaw))
    let server = ServerFinishedWire(
      core: core,
      serverConfirmB64u: confirm(
        label: "flowersec v2 server finished",
        prk: handshakePRK,
        transcript: h1
      ).base64URLEncodedString()
    )
    let serverRaw = try frame(type: 2, value: server)
    try await writeAll(serverRaw, to: control)

    let clientFinishedRaw = try await readFrame(from: control, expectedType: 3)
    let clientFinished = try decodeCanonical(
      ClientFinishedWire.self,
      frame: clientFinishedRaw,
      type: 3
    )
    guard clientFinished.handshakeID == core.handshakeID else {
      throw TransportV2SessionError.handshakeFailed
    }
    let clientCoreRaw = try frame(
      type: 3,
      value: ClientFinishedCoreWire(handshakeID: core.handshakeID)
    )
    let h2 = hash(h1, lengthPrefixed(serverRaw), lengthPrefixed(clientCoreRaw))
    guard
      let clientConfirm = canonicalBase64(clientFinished.clientConfirmB64u, count: 32),
      timingSafeEqual(
        clientConfirm,
        confirm(label: "flowersec v2 client finished", prk: handshakePRK, transcript: h2))
    else { throw TransportV2SessionError.handshakeFailed }
    let h3 = hash(h2, lengthPrefixed(clientFinishedRaw))
    return TransportV2HandshakeMaterial(
      h3: h3,
      sessionPRK: FlowersecHKDF.extractSHA256(salt: h3, inputKeyMaterial: handshakePRK)
    )
  }

  private static func validateClient(
    _ message: ClientInitWire,
    config: TransportV2SessionConfig
  ) throws {
    guard
      message.profile == "flowersec/2",
      message.channelID == config.channelID,
      message.clientRole == 1,
      message.suite == config.suite.rawValue,
      message.selectedFeatures == 0,
      message.maxInboundStreams == config.maxInboundStreams,
      canonicalBase64(message.nonceCB64u, count: 32) != nil,
      canonicalBase64(message.clientEphPubB64u, count: config.suite == .chacha20Poly1305 ? 32 : 65)
        != nil,
      bindingMatches(
        message.clientAdmissionBindingB64u, expected: config.peerAdmissionBinding, path: config.path
      ),
      timingSafeEqual(
        canonicalBase64(message.sessionContractHashB64u, count: 32) ?? Data(),
        config.sessionContractHash
      ),
      endpointMatches(
        message.clientEndpointInstanceID, expected: config.expectedPeerEndpointInstanceID,
        path: config.path)
    else { throw TransportV2SessionError.handshakeFailed }
  }

  private static func validateServer(
    _ message: ServerFinishedWire,
    config: TransportV2SessionConfig
  ) throws {
    guard
      message.maxInboundStreams == config.maxInboundStreams,
      message.selectedFeatures == 0,
      canonicalBase64(message.handshakeID, range: 16...32) != nil,
      canonicalBase64(message.nonceSB64u, count: 32) != nil,
      canonicalBase64(message.serverConfirmB64u, count: 32) != nil,
      canonicalBase64(message.serverEphPubB64u, count: config.suite == .chacha20Poly1305 ? 32 : 65)
        != nil,
      bindingMatches(
        message.serverAdmissionBindingB64u, expected: config.peerAdmissionBinding, path: config.path
      ),
      timingSafeEqual(
        canonicalBase64(message.sessionContractHashB64u, count: 32) ?? Data(),
        config.sessionContractHash
      ),
      endpointMatches(
        message.serverEndpointInstanceID, expected: config.expectedPeerEndpointInstanceID,
        path: config.path)
    else { throw TransportV2SessionError.handshakeFailed }
  }

  static func controlPreface() -> Data {
    var data = Data(repeating: 0, count: controlPrefaceBytes)
    data.replaceSubrange(0..<4, with: Data("FSC2".utf8))
    data[4] = 2
    data[5] = 1
    return data
  }

  static func writeAll(_ data: Data, to stream: any TransportV2CarrierStream) async throws {
    var offset = 0
    while offset < data.count {
      let written = try await stream.write(Data(data[offset...]))
      guard written > 0, written <= data.count - offset else {
        throw TransportV2SessionError.protocolViolation
      }
      offset += written
    }
  }

  static func readExact(
    _ count: Int,
    from stream: any TransportV2CarrierStream
  ) async throws -> Data {
    var result = Data()
    while result.count < count {
      guard let data = try await stream.read(maxBytes: count - result.count), !data.isEmpty else {
        throw TransportV2SessionError.closed
      }
      result.append(data)
    }
    return result
  }

  private static func readFrame(
    from stream: any TransportV2CarrierStream,
    expectedType: UInt8
  ) async throws -> Data {
    let header = try await readExact(frameHeaderBytes, from: stream)
    guard
      Data(header[0..<4]) == Data("FSH2".utf8),
      header[4] == 2,
      header[5] == expectedType,
      header[6] == 0,
      header[7] == 0
    else { throw TransportV2SessionError.handshakeFailed }
    let size = Int(header.readUInt32BE(at: 8))
    guard size > 0, size <= maxPayloadBytes else {
      throw TransportV2SessionError.handshakeFailed
    }
    var raw = header
    raw.append(try await readExact(size, from: stream))
    return raw
  }

  private static func frame<Value: Encodable>(type: UInt8, value: Value) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let payload = try encoder.encode(value)
    guard !payload.isEmpty, payload.count <= maxPayloadBytes else {
      throw TransportV2SessionError.handshakeFailed
    }
    var raw = Data("FSH2".utf8)
    raw.append(2)
    raw.append(type)
    raw.append(contentsOf: [0, 0])
    raw.appendUInt32BE(UInt32(payload.count))
    raw.append(payload)
    return raw
  }

  private static func decodeCanonical<Value: Codable>(
    _ type: Value.Type,
    frame raw: Data,
    type frameType: UInt8
  ) throws -> Value {
    guard raw.count >= frameHeaderBytes else { throw TransportV2SessionError.handshakeFailed }
    let value = try JSONDecoder().decode(Value.self, from: Data(raw[frameHeaderBytes...]))
    guard try frame(type: frameType, value: value) == raw else {
      throw TransportV2SessionError.handshakeFailed
    }
    return value
  }

  private static func confirm(label: String, prk: Data, transcript: Data) -> Data {
    var info = Data(label.utf8)
    info.append(transcript)
    let key = FlowersecHKDF.expandSHA256(
      pseudoRandomKey: prk,
      info: info,
      outputByteCount: 32
    )
    return Data(HMAC<SHA256>.authenticationCode(for: transcript, using: SymmetricKey(data: key)))
  }

  private static func hash(_ parts: Data...) -> Data {
    var hasher = SHA256()
    for part in parts { hasher.update(data: part) }
    return Data(hasher.finalize())
  }

  private static func lengthPrefixed(_ data: Data) -> Data {
    var result = Data()
    result.appendUInt32BE(UInt32(data.count))
    result.append(data)
    return result
  }

  private static func timingSafeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var difference: UInt8 = 0
    for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
    return difference == 0
  }

  private static func bindingMatches(_ actual: String, expected: Data, path: PathKind) -> Bool {
    guard let decoded = canonicalBase64(actual, count: 32) else { return false }
    if path == .direct || expected.contains(where: { $0 != 0 }) {
      return timingSafeEqual(decoded, expected)
    }
    return decoded.contains(where: { $0 != 0 })
  }

  private static func endpointMatches(_ actual: String, expected: String, path: PathKind) -> Bool {
    switch path {
    case .direct:
      return actual.isEmpty && expected.isEmpty
    case .tunnel:
      return validRegistryID(actual, allowEmpty: false)
        && validRegistryID(expected, allowEmpty: false)
        && timingSafeEqual(Data(actual.utf8), Data(expected.utf8))
    }
  }

  private static func validRegistryID(_ value: String, allowEmpty: Bool) -> Bool {
    if value.isEmpty { return allowEmpty }
    guard value.utf8.count <= 128 else { return false }
    return value.utf8.allSatisfy {
      ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57)
        || [45, 46, 95, 126].contains($0)
    }
  }

  private static func canonicalBase64(_ value: String, count: Int) -> Data? {
    canonicalBase64(value, range: count...count)
  }

  private static func canonicalBase64(_ value: String, range: ClosedRange<Int>) -> Data? {
    guard
      let decoded = Data(base64URLEncoded: value),
      range.contains(decoded.count),
      decoded.base64URLEncodedString() == value
    else { return nil }
    return decoded
  }

  private static func requireCanonicalBase64(
    _ value: String,
    range: ClosedRange<Int>
  ) throws -> Data {
    guard let decoded = canonicalBase64(value, range: range) else {
      throw TransportV2SessionError.handshakeFailed
    }
    return decoded
  }

  private static func decodePublicKey(
    _ value: String,
    suite: TransportCipherSuiteV2
  ) throws -> EphemeralPublicKey {
    guard
      let raw = canonicalBase64(value, count: suite == .chacha20Poly1305 ? 32 : 65)
    else { throw TransportV2SessionError.handshakeFailed }
    switch suite {
    case .chacha20Poly1305:
      return .x25519(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw))
    case .aes256GCM:
      guard raw.first == 4 else { throw TransportV2SessionError.handshakeFailed }
      return .p256(try P256.KeyAgreement.PublicKey(x963Representation: raw))
    }
  }
}

private enum EphemeralPublicKey {
  case x25519(Curve25519.KeyAgreement.PublicKey)
  case p256(P256.KeyAgreement.PublicKey)
}

private enum EphemeralKey {
  case x25519(Curve25519.KeyAgreement.PrivateKey)
  case p256(P256.KeyAgreement.PrivateKey)

  init(suite: TransportCipherSuiteV2) {
    switch suite {
    case .chacha20Poly1305:
      self = .x25519(Curve25519.KeyAgreement.PrivateKey())
    case .aes256GCM:
      self = .p256(P256.KeyAgreement.PrivateKey())
    }
  }

  init(suite: TransportCipherSuiteV2, rawRepresentation: Data) throws {
    guard rawRepresentation.count == 32 else {
      throw TransportV2SessionError.handshakeFailed
    }
    switch suite {
    case .chacha20Poly1305:
      self = .x25519(
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
      )
    case .aes256GCM:
      self = .p256(
        try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
      )
    }
  }

  var publicKey: Data {
    switch self {
    case .x25519(let key): return key.publicKey.rawRepresentation
    case .p256(let key): return key.publicKey.x963Representation
    }
  }

  func sharedSecret(peer: EphemeralPublicKey) throws -> Data {
    let secret: SharedSecret
    switch (self, peer) {
    case (.x25519(let key), .x25519(let peer)):
      secret = try key.sharedSecretFromKeyAgreement(with: peer)
    case (.p256(let key), .p256(let peer)):
      secret = try key.sharedSecretFromKeyAgreement(with: peer)
    default:
      throw TransportV2SessionError.handshakeFailed
    }
    let data = secret.withUnsafeBytes { Data($0) }
    guard data.count == 32, data.contains(where: { $0 != 0 }) else {
      throw TransportV2SessionError.handshakeFailed
    }
    return data
  }
}

private struct ClientInitWire: Codable {
  let clientAdmissionBindingB64u: String
  let clientEndpointInstanceID: String
  let clientEphPubB64u: String
  let clientRole: UInt8
  let channelID: String
  let maxInboundStreams: UInt16
  let nonceCB64u: String
  let profile: String
  let selectedFeatures: UInt32
  let sessionContractHashB64u: String
  let suite: UInt16

  enum CodingKeys: String, CodingKey {
    case clientAdmissionBindingB64u = "client_admission_binding_b64u"
    case clientEndpointInstanceID = "client_endpoint_instance_id"
    case clientEphPubB64u = "client_eph_pub_b64u"
    case clientRole = "client_role"
    case channelID = "channel_id"
    case maxInboundStreams = "max_inbound_streams"
    case nonceCB64u = "nonce_c_b64u"
    case profile
    case selectedFeatures = "selected_features"
    case sessionContractHashB64u = "session_contract_hash_b64u"
    case suite
  }
}

private struct ServerFinishedCoreWire: Codable {
  let handshakeID: String
  let maxInboundStreams: UInt16
  let nonceSB64u: String
  let selectedFeatures: UInt32
  let serverAdmissionBindingB64u: String
  let serverEndpointInstanceID: String
  let serverEphPubB64u: String
  let sessionContractHashB64u: String

  enum CodingKeys: String, CodingKey {
    case handshakeID = "handshake_id"
    case maxInboundStreams = "max_inbound_streams"
    case nonceSB64u = "nonce_s_b64u"
    case selectedFeatures = "selected_features"
    case serverAdmissionBindingB64u = "server_admission_binding_b64u"
    case serverEndpointInstanceID = "server_endpoint_instance_id"
    case serverEphPubB64u = "server_eph_pub_b64u"
    case sessionContractHashB64u = "session_contract_hash_b64u"
  }
}

private struct ServerFinishedWire: Codable {
  let handshakeID: String
  let maxInboundStreams: UInt16
  let nonceSB64u: String
  let selectedFeatures: UInt32
  let serverAdmissionBindingB64u: String
  let serverConfirmB64u: String
  let serverEndpointInstanceID: String
  let serverEphPubB64u: String
  let sessionContractHashB64u: String

  init(core: ServerFinishedCoreWire, serverConfirmB64u: String) {
    handshakeID = core.handshakeID
    maxInboundStreams = core.maxInboundStreams
    nonceSB64u = core.nonceSB64u
    selectedFeatures = core.selectedFeatures
    serverAdmissionBindingB64u = core.serverAdmissionBindingB64u
    self.serverConfirmB64u = serverConfirmB64u
    serverEndpointInstanceID = core.serverEndpointInstanceID
    serverEphPubB64u = core.serverEphPubB64u
    sessionContractHashB64u = core.sessionContractHashB64u
  }

  var core: ServerFinishedCoreWire {
    ServerFinishedCoreWire(
      handshakeID: handshakeID,
      maxInboundStreams: maxInboundStreams,
      nonceSB64u: nonceSB64u,
      selectedFeatures: selectedFeatures,
      serverAdmissionBindingB64u: serverAdmissionBindingB64u,
      serverEndpointInstanceID: serverEndpointInstanceID,
      serverEphPubB64u: serverEphPubB64u,
      sessionContractHashB64u: sessionContractHashB64u
    )
  }

  enum CodingKeys: String, CodingKey {
    case handshakeID = "handshake_id"
    case maxInboundStreams = "max_inbound_streams"
    case nonceSB64u = "nonce_s_b64u"
    case selectedFeatures = "selected_features"
    case serverAdmissionBindingB64u = "server_admission_binding_b64u"
    case serverConfirmB64u = "server_confirm_b64u"
    case serverEndpointInstanceID = "server_endpoint_instance_id"
    case serverEphPubB64u = "server_eph_pub_b64u"
    case sessionContractHashB64u = "session_contract_hash_b64u"
  }
}

private struct ClientFinishedCoreWire: Codable {
  let handshakeID: String
  enum CodingKeys: String, CodingKey { case handshakeID = "handshake_id" }
}

private struct ClientFinishedWire: Codable {
  let clientConfirmB64u: String
  let handshakeID: String

  enum CodingKeys: String, CodingKey {
    case clientConfirmB64u = "client_confirm_b64u"
    case handshakeID = "handshake_id"
  }
}
