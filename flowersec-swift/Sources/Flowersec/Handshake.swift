import Crypto
import Foundation

enum FlowersecHandshake {
  static func runClientHandshake(
    transport: any FlowersecBinaryTransport,
    info: DirectConnectInfo,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    maxOutboundBufferedBytes: Int = FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes,
    path: FlowersecPath = .direct,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil
  ) async throws -> FlowersecSecureChannel {
    do {
      try validate(info: info)
      let material = try ClientHandshakeMaterial(info: info)
      try await sendInit(material: material, transport: transport)
      let response = try await receiveResponse(transport: transport)
      let serverMaterial = try ServerHandshakeMaterial(
        response: response,
        suite: info.defaultSuite
      )
      let sessionKeys = try deriveSessionKeys(
        info: info,
        material: material,
        server: serverMaterial,
        serverFeatures: response.serverFeatures
      )
      try await sendAck(
        response: response,
        info: info,
        transcript: sessionKeys.transcript,
        transport: transport
      )
      try await verifyFinished(sessionKeys: sessionKeys, transport: transport)
      return secureChannel(
        transport: transport,
        sessionKeys: sessionKeys,
        outboundRecordChunkBytes: outboundRecordChunkBytes,
        maxOutboundBufferedBytes: maxOutboundBufferedBytes,
        path: path,
        onDiagnosticEvent: onDiagnosticEvent
      )
    } catch is CancellationError {
      throw CancellationError()
    } catch let error as FlowersecError {
      throw error.withPath(path)
    } catch {
      throw FlowersecError(
        path: path,
        stage: .handshake,
        code: .handshakeFailed,
        message: "The Flowersec handshake failed: \(error.localizedDescription)"
      )
    }
  }

  private static func validate(info: DirectConnectInfo) throws {
    guard info.psk.count == 32 else {
      throw FlowersecError.invalidConnectInfo("Invalid E2EE key.")
    }
    guard !info.channelID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw FlowersecError.invalidConnectInfo("Missing channel id.")
    }
    guard info.channelInitExpiresAtUnixS > Int64(Date().timeIntervalSince1970) else {
      throw FlowersecError.invalidConnectInfo("Connect artifact expired.")
    }
  }

  private static func sendInit(
    material: ClientHandshakeMaterial,
    transport: any FlowersecBinaryTransport
  ) async throws {
    let initJSON = try JSONEncoder.flowersecWire.encode(material.initMessage)
    try await transport.writeBinary(
      FlowersecHandshakeFrame.encode(type: FlowersecWire.handshakeTypeInit, payload: initJSON)
    )
  }

  private static func receiveResponse(
    transport: any FlowersecBinaryTransport
  ) async throws -> E2EEResponseMessage {
    let responseFrame = try await transport.readBinary()
    let responsePayload = try FlowersecHandshakeFrame.decode(
      responseFrame,
      expectedType: FlowersecWire.handshakeTypeResp
    )
    let response = try JSONDecoder().decode(E2EEResponseMessage.self, from: responsePayload)
    guard !response.handshakeID.isEmpty else {
      throw FlowersecError.invalidHandshake("The peer returned an empty handshake id.")
    }
    return response
  }

  private static func deriveSessionKeys(
    info: DirectConnectInfo,
    material: ClientHandshakeMaterial,
    server: ServerHandshakeMaterial,
    serverFeatures: UInt32
  ) throws -> FlowersecSessionKeys {
    let sharedSecret = try material.privateKey.sharedSecret(with: server.publicKey)
    let transcript = try transcriptHash(
      input: FlowersecHandshakeTranscriptInput(
        suite: info.defaultSuite,
        channelID: info.channelID,
        nonceC: material.nonce,
        nonceS: server.nonce,
        clientPublicKey: material.publicKey,
        serverPublicKey: server.publicKeyData,
        serverFeatures: serverFeatures
      )
    )
    return deriveSessionKeys(
      psk: info.psk,
      sharedSecret: sharedSecret.withUnsafeBytes { Data($0) },
      transcript: transcript
    )
  }

  private static func sendAck(
    response: E2EEResponseMessage,
    info: DirectConnectInfo,
    transcript: Data,
    transport: any FlowersecBinaryTransport
  ) async throws {
    let timestamp = UInt64(Date().timeIntervalSince1970)
    let authTag = try computeAuthTag(psk: info.psk, transcript: transcript, timestamp: timestamp)
    let ack = E2EEAckMessage(
      handshakeID: response.handshakeID,
      timestampUnixS: timestamp,
      authTagB64u: authTag.base64URLEncodedString()
    )
    let ackJSON = try JSONEncoder.flowersecWire.encode(ack)
    try await transport.writeBinary(
      FlowersecHandshakeFrame.encode(type: FlowersecWire.handshakeTypeAck, payload: ackJSON)
    )
  }

  private static func verifyFinished(
    sessionKeys: FlowersecSessionKeys,
    transport: any FlowersecBinaryTransport
  ) async throws {
    let finishedFrame = try await transport.readBinary()
    let finished = try FlowersecRecordCodec.decrypt(
      key: sessionKeys.s2cKey,
      noncePrefix: sessionKeys.s2cNoncePrefix,
      frame: finishedFrame,
      expectedSeq: 1
    )
    guard finished.flags == 1, finished.plaintext.isEmpty else {
      throw FlowersecError.invalidHandshake("The peer did not finish the handshake.")
    }
  }

  private static func secureChannel(
    transport: any FlowersecBinaryTransport,
    sessionKeys: FlowersecSessionKeys,
    outboundRecordChunkBytes: Int,
    maxOutboundBufferedBytes: Int,
    path: FlowersecPath,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
  ) -> FlowersecSecureChannel {
    FlowersecSecureChannel(
      transport: transport,
      keys: FlowersecRecordKeyState(
        sendKey: sessionKeys.c2sKey,
        recvKey: sessionKeys.s2cKey,
        sendNoncePrefix: sessionKeys.c2sNoncePrefix,
        recvNoncePrefix: sessionKeys.s2cNoncePrefix,
        rekeyBase: sessionKeys.rekeyBase,
        transcript: sessionKeys.transcript,
        sendDirection: 1,
        recvDirection: 2,
        sendSeq: 1,
        recvSeq: 2
      ),
      outboundRecordChunkBytes: outboundRecordChunkBytes,
      maxOutboundBufferedBytes: maxOutboundBufferedBytes,
      path: path,
      onDiagnosticEvent: onDiagnosticEvent
    )
  }

  static func transcriptHash(input: FlowersecHandshakeTranscriptInput) throws -> Data {
    let channelBytes = Data(input.channelID.utf8)
    guard
      channelBytes.count <= UInt16.max,
      input.clientPublicKey.count <= UInt16.max,
      input.serverPublicKey.count <= UInt16.max
    else {
      throw FlowersecError.invalidHandshake("Handshake transcript input is too large.")
    }
    var data = Data("flowersec-e2ee-v1".utf8)
    data.append(FlowersecWire.protocolVersion)
    data.appendUInt16BE(UInt16(input.suite.rawValue))
    data.append(1)
    data.appendUInt32BE(0)
    data.appendUInt32BE(input.serverFeatures)
    data.appendUInt16BE(UInt16(channelBytes.count))
    data.append(channelBytes)
    data.append(input.nonceC)
    data.append(input.nonceS)
    data.appendUInt16BE(UInt16(input.clientPublicKey.count))
    data.append(input.clientPublicKey)
    data.appendUInt16BE(UInt16(input.serverPublicKey.count))
    data.append(input.serverPublicKey)
    return Data(SHA256.hash(data: data))
  }

  static func deriveSessionKeys(
    psk: Data,
    sharedSecret: Data,
    transcript: Data
  ) -> FlowersecSessionKeys {
    var ikm = Data()
    ikm.append(sharedSecret)
    ikm.append(transcript)
    let prk = FlowersecHKDF.extractSHA256(salt: psk, inputKeyMaterial: ikm)
    return FlowersecSessionKeys(
      c2sKey: hkdfExpand(prk: prk, info: "flowersec-e2ee-v1:c2s:key", count: 32),
      s2cKey: hkdfExpand(prk: prk, info: "flowersec-e2ee-v1:s2c:key", count: 32),
      c2sNoncePrefix: hkdfExpand(
        prk: prk,
        info: "flowersec-e2ee-v1:c2s:nonce_prefix",
        count: 4
      ),
      s2cNoncePrefix: hkdfExpand(
        prk: prk,
        info: "flowersec-e2ee-v1:s2c:nonce_prefix",
        count: 4
      ),
      rekeyBase: hkdfExpand(prk: prk, info: "flowersec-e2ee-v1:rekey_base", count: 32),
      transcript: transcript
    )
  }

  private static func hkdfExpand(prk: Data, info: String, count: Int) -> Data {
    FlowersecHKDF.expandSHA256(
      pseudoRandomKey: prk,
      info: Data(info.utf8),
      outputByteCount: count
    )
  }

  static func computeAuthTag(psk: Data, transcript: Data, timestamp: UInt64) throws -> Data
  {
    guard transcript.count == 32 else {
      throw FlowersecError.invalidHandshake("Invalid transcript hash.")
    }
    var message = Data(transcript)
    message.appendUInt64BE(timestamp)
    let code = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: psk))
    return Data(code)
  }

  static func x25519SharedSecret(
    privateKey: Curve25519.KeyAgreement.PrivateKey,
    peerPublicKey: Curve25519.KeyAgreement.PublicKey
  ) throws -> SharedSecret {
    let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
    let isZero = sharedSecret.withUnsafeBytes { bytes in
      bytes.reduce(UInt8(0)) { $0 | $1 } == 0
    }
    guard !isZero else {
      throw FlowersecError.invalidHandshake("The peer returned a low-order X25519 key.")
    }
    return sharedSecret
  }
}

private struct ClientHandshakeMaterial {
  var privateKey: ClientAgreementPrivateKey
  var publicKey: Data
  var nonce: Data
  var initMessage: E2EEInitMessage

  init(info: DirectConnectInfo) throws {
    switch info.defaultSuite {
    case .x25519HKDFSHA256AES256GCM:
      let key = Curve25519.KeyAgreement.PrivateKey()
      privateKey = .x25519(key)
      publicKey = key.publicKey.rawRepresentation
    case .p256HKDFSHA256AES256GCM:
      let key = P256.KeyAgreement.PrivateKey()
      privateKey = .p256(key)
      publicKey = key.publicKey.x963Representation
    }
    nonce = try Data.secureRandom(count: 32)
    initMessage = E2EEInitMessage(
      channelID: info.channelID,
      role: 1,
      version: FlowersecWire.protocolVersion,
      suite: info.defaultSuite.rawValue,
      clientEphPubB64u: publicKey.base64URLEncodedString(),
      nonceCB64u: nonce.base64URLEncodedString(),
      clientFeatures: 0
    )
  }
}

private struct ServerHandshakeMaterial {
  var publicKeyData: Data
  var publicKey: ServerAgreementPublicKey
  var nonce: Data

  init(response: E2EEResponseMessage, suite: Suite) throws {
    guard let serverPublicKeyData = Data(base64URLEncoded: response.serverEphPubB64u) else {
      throw FlowersecError.invalidHandshake("The peer returned an invalid server key.")
    }
    guard let nonceS = Data(base64URLEncoded: response.nonceSB64u), nonceS.count == 32 else {
      throw FlowersecError.invalidHandshake("The peer returned an invalid server nonce.")
    }
    publicKeyData = serverPublicKeyData
    switch suite {
    case .x25519HKDFSHA256AES256GCM:
      guard serverPublicKeyData.count == 32 else {
        throw FlowersecError.invalidHandshake("The peer returned an invalid X25519 server key.")
      }
      publicKey = .x25519(try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKeyData))
    case .p256HKDFSHA256AES256GCM:
      publicKey = .p256(try P256.KeyAgreement.PublicKey(x963Representation: serverPublicKeyData))
    }
    nonce = nonceS
  }
}

struct FlowersecHandshakeTranscriptInput {
  var suite: Suite
  var channelID: String
  var nonceC: Data
  var nonceS: Data
  var clientPublicKey: Data
  var serverPublicKey: Data
  var serverFeatures: UInt32
}

private enum ClientAgreementPrivateKey {
  case x25519(Curve25519.KeyAgreement.PrivateKey)
  case p256(P256.KeyAgreement.PrivateKey)

  func sharedSecret(with publicKey: ServerAgreementPublicKey) throws -> SharedSecret {
    switch (self, publicKey) {
    case (.x25519(let privateKey), .x25519(let publicKey)):
      return try FlowersecHandshake.x25519SharedSecret(
        privateKey: privateKey,
        peerPublicKey: publicKey
      )
    case (.p256(let privateKey), .p256(let publicKey)):
      return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    default:
      throw FlowersecError.invalidHandshake("Handshake suite key type mismatch.")
    }
  }
}

private enum ServerAgreementPublicKey {
  case x25519(Curve25519.KeyAgreement.PublicKey)
  case p256(P256.KeyAgreement.PublicKey)
}
