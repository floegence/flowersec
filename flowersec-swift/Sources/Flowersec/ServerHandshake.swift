import Crypto
import Foundation

public actor EndpointHandshakeCache {
  fileprivate struct Entry {
    var fingerprint: Data
    var suite: Suite
    var privateKey: EndpointAgreementPrivateKey
    var publicKey: Data
    var nonce: Data
    var handshakeID: String
    var serverFeatures: UInt32
    var createdAt: ContinuousClock.Instant
  }

  private let ttl: Duration
  private let maxEntries: Int
  private let clock = ContinuousClock()
  private var entries: [Data: Entry] = [:]

  public init(ttl: Duration = .seconds(60), maxEntries: Int = 4096) {
    self.ttl = ttl
    self.maxEntries = maxEntries
  }

  fileprivate func getOrCreate(
    initMessage: E2EEInitMessage,
    suite: Suite,
    serverFeatures: UInt32
  ) throws -> Entry {
    let fingerprint = try Self.fingerprint(initMessage)
    let now = clock.now
    entries = entries.filter { now - $0.value.createdAt <= ttl }
    if let entry = entries[fingerprint] { return entry }
    guard maxEntries > 0, entries.count < maxEntries else {
      throw FlowersecError.resourceExhausted(
        path: .direct,
        stage: .handshake,
        "Too many pending endpoint handshakes."
      )
    }
    let privateKey = EndpointAgreementPrivateKey(suite: suite)
    let entry = Entry(
      fingerprint: fingerprint,
      suite: suite,
      privateKey: privateKey,
      publicKey: privateKey.publicKeyData,
      nonce: try Data.secureRandom(count: 32),
      handshakeID: try Data.secureRandom(count: 24).base64URLEncodedString(),
      serverFeatures: serverFeatures,
      createdAt: now
    )
    entries[fingerprint] = entry
    return entry
  }

  fileprivate func take(_ expected: Entry) throws -> Entry {
    guard let current = entries[expected.fingerprint],
      current.handshakeID == expected.handshakeID
    else {
      throw FlowersecError.invalidHandshake("Endpoint handshake state is unavailable.")
    }
    entries.removeValue(forKey: expected.fingerprint)
    return current
  }

  fileprivate static func fingerprint(_ initMessage: E2EEInitMessage) throws -> Data {
    Data(SHA256.hash(data: try JSONEncoder.flowersecWire.encode(initMessage)))
  }
}

struct EndpointServerHandshakeOptions {
  var channelID: String
  var suite: Suite
  var psk: Data
  var initExpiresAtUnixS: Int64
  var clockSkew: Duration
  var serverFeatures: UInt32
  var outboundRecordChunkBytes: Int
  var maxOutboundBufferedBytes: Int
  var path: FlowersecPath
  var onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
}

extension FlowersecHandshake {
  static func runServerHandshake(
    transport: any FlowersecBinaryTransport,
    cache: EndpointHandshakeCache,
    options: EndpointServerHandshakeOptions
  ) async throws -> FlowersecSecureChannel {
    do {
      guard options.psk.count == 32 else {
        throw FlowersecError.invalidConnectInfo("Invalid E2EE key.", path: options.path)
      }
      guard !options.channelID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw FlowersecError.invalidConnectInfo("Missing channel id.", path: options.path)
      }
      guard options.initExpiresAtUnixS > 0 else {
        throw FlowersecError.invalidConnectInfo("Missing channel init expiry.", path: options.path)
      }

      let initFrame = try await transport.readBinary()
      let initPayload = try FlowersecHandshakeFrame.decode(
        initFrame,
        expectedType: FlowersecWire.handshakeTypeInit
      )
      let initMessage = try JSONDecoder().decode(E2EEInitMessage.self, from: initPayload)
      guard initMessage.version == FlowersecWire.protocolVersion,
        initMessage.role == 1,
        initMessage.channelID == options.channelID,
        initMessage.suite == options.suite.rawValue
      else {
        throw FlowersecError.invalidHandshake("The endpoint handshake init is invalid.", path: options.path)
      }

      let clientMaterial = try EndpointClientHandshakeMaterial(
        initMessage: initMessage,
        suite: options.suite
      )
      let entry = try await cache.getOrCreate(
        initMessage: initMessage,
        suite: options.suite,
        serverFeatures: options.serverFeatures
      )
      let response = E2EEResponseMessage(
        handshakeID: entry.handshakeID,
        serverEphPubB64u: entry.publicKey.base64URLEncodedString(),
        nonceSB64u: entry.nonce.base64URLEncodedString(),
        serverFeatures: entry.serverFeatures
      )
      let responseFrame = FlowersecHandshakeFrame.encode(
        type: FlowersecWire.handshakeTypeResp,
        payload: try JSONEncoder.flowersecWire.encode(response)
      )
      try await transport.writeBinary(responseFrame)

      let expectedFingerprint = entry.fingerprint
      let ack: E2EEAckMessage
      while true {
        let frame = try await transport.readBinary()
        guard frame.count >= 6 else {
          throw FlowersecError.invalidHandshake("Endpoint handshake frame is too short.")
        }
        if frame[5] == FlowersecWire.handshakeTypeInit {
          let retryPayload = try FlowersecHandshakeFrame.decode(
            frame,
            expectedType: FlowersecWire.handshakeTypeInit
          )
          let retry = try JSONDecoder().decode(E2EEInitMessage.self, from: retryPayload)
          guard try EndpointHandshakeCache.fingerprint(retry) == expectedFingerprint else {
            throw FlowersecError.invalidHandshake("Endpoint handshake retry parameters changed.")
          }
          try await transport.writeBinary(responseFrame)
          continue
        }
        let ackPayload = try FlowersecHandshakeFrame.decode(
          frame,
          expectedType: FlowersecWire.handshakeTypeAck
        )
        _ = try await cache.take(entry)
        ack = try JSONDecoder().decode(E2EEAckMessage.self, from: ackPayload)
        break
      }
      guard ack.handshakeID == entry.handshakeID else {
        throw FlowersecError.invalidHandshake("Endpoint handshake id does not match.")
      }
      guard ack.timestampUnixS <= UInt64(Int64.max) else {
        throw FlowersecError.invalidHandshake("Endpoint handshake timestamp is invalid.")
      }
      let timestamp = Int64(ack.timestampUnixS)
      let now = Int64(Date().timeIntervalSince1970)
      let skewSeconds = durationSecondsCeil(options.clockSkew)
      guard timestamp <= now + skewSeconds, timestamp >= now - skewSeconds else {
        throw FlowersecError(
          path: options.path,
          stage: .handshake,
          code: .handshakeFailed,
          message: "Endpoint handshake timestamp is outside the allowed clock skew."
        )
      }
      guard timestamp <= options.initExpiresAtUnixS + skewSeconds else {
        throw FlowersecError(
          path: options.path,
          stage: .handshake,
          code: .handshakeFailed,
          message: "Endpoint handshake timestamp is after the init expiry."
        )
      }

      let transcript = try transcriptHash(
        input: FlowersecHandshakeTranscriptInput(
          suite: options.suite,
          channelID: options.channelID,
          nonceC: clientMaterial.nonce,
          nonceS: entry.nonce,
          clientPublicKey: clientMaterial.publicKeyData,
          serverPublicKey: entry.publicKey,
          serverFeatures: entry.serverFeatures
        )
      )
      let expectedTag = try computeAuthTag(
        psk: options.psk,
        transcript: transcript,
        timestamp: ack.timestampUnixS
      )
      guard let actualTag = Data(base64URLEncoded: ack.authTagB64u),
        constantTimeEqual(expectedTag, actualTag)
      else {
        throw FlowersecError(
          path: options.path,
          stage: .handshake,
          code: .authTagMismatch,
          message: "Endpoint handshake authentication failed."
        )
      }

      let sharedSecret = try entry.privateKey.sharedSecret(with: clientMaterial.publicKey)
      let sharedSecretData = sharedSecret.withUnsafeBytes { buffer in
        Data(bytes: buffer.baseAddress!, count: buffer.count)
      }
      let sessionKeys = deriveSessionKeys(
        psk: options.psk,
        sharedSecret: sharedSecretData,
        transcript: transcript
      )
      try await transport.writeBinary(
        FlowersecRecordCodec.encrypt(
          key: sessionKeys.s2cKey,
          noncePrefix: sessionKeys.s2cNoncePrefix,
          flags: 1,
          seq: 1,
          plaintext: Data()
        )
      )
      return FlowersecSecureChannel(
        transport: transport,
        keys: FlowersecRecordKeyState(
          sendKey: sessionKeys.s2cKey,
          recvKey: sessionKeys.c2sKey,
          sendNoncePrefix: sessionKeys.s2cNoncePrefix,
          recvNoncePrefix: sessionKeys.c2sNoncePrefix,
          rekeyBase: sessionKeys.rekeyBase,
          transcript: sessionKeys.transcript,
          sendDirection: 2,
          recvDirection: 1,
          sendSeq: 2,
          recvSeq: 1
        ),
        outboundRecordChunkBytes: options.outboundRecordChunkBytes,
        maxOutboundBufferedBytes: options.maxOutboundBufferedBytes,
        path: options.path,
        onDiagnosticEvent: options.onDiagnosticEvent
      )
    } catch is CancellationError {
      throw CancellationError()
    } catch let error as FlowersecError {
      throw error.withPath(options.path)
    } catch {
      throw FlowersecError(
        path: options.path,
        stage: .handshake,
        code: .handshakeFailed,
        message: "The endpoint handshake failed: \(error.localizedDescription)"
      )
    }
  }
}

private struct EndpointClientHandshakeMaterial {
  var publicKeyData: Data
  var publicKey: EndpointAgreementPublicKey
  var nonce: Data

  init(initMessage: E2EEInitMessage, suite: Suite) throws {
    guard let publicKeyData = Data(base64URLEncoded: initMessage.clientEphPubB64u),
      let nonce = Data(base64URLEncoded: initMessage.nonceCB64u),
      nonce.count == 32
    else {
      throw FlowersecError.invalidHandshake("The client handshake key material is invalid.")
    }
    self.publicKeyData = publicKeyData
    self.nonce = nonce
    switch suite {
    case .x25519HKDFSHA256AES256GCM:
      guard publicKeyData.count == 32 else {
        throw FlowersecError.invalidHandshake("The client X25519 key is invalid.")
      }
      publicKey = .x25519(
        try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)
      )
    case .p256HKDFSHA256AES256GCM:
      publicKey = .p256(try P256.KeyAgreement.PublicKey(x963Representation: publicKeyData))
    }
  }
}

fileprivate enum EndpointAgreementPrivateKey: Sendable {
  case x25519(Curve25519.KeyAgreement.PrivateKey)
  case p256(P256.KeyAgreement.PrivateKey)

  init(suite: Suite) {
    switch suite {
    case .x25519HKDFSHA256AES256GCM:
      self = .x25519(Curve25519.KeyAgreement.PrivateKey())
    case .p256HKDFSHA256AES256GCM:
      self = .p256(P256.KeyAgreement.PrivateKey())
    }
  }

  var publicKeyData: Data {
    switch self {
    case .x25519(let key): key.publicKey.rawRepresentation
    case .p256(let key): key.publicKey.x963Representation
    }
  }

  func sharedSecret(with publicKey: EndpointAgreementPublicKey) throws -> SharedSecret {
    switch (self, publicKey) {
    case (.x25519(let key), .x25519(let peer)):
      return try key.sharedSecretFromKeyAgreement(with: peer)
    case (.p256(let key), .p256(let peer)):
      return try key.sharedSecretFromKeyAgreement(with: peer)
    default:
      throw FlowersecError.invalidHandshake("Endpoint handshake suite key type mismatch.")
    }
  }
}

fileprivate enum EndpointAgreementPublicKey: Sendable {
  case x25519(Curve25519.KeyAgreement.PublicKey)
  case p256(P256.KeyAgreement.PublicKey)
}

private func durationSecondsCeil(_ duration: Duration) -> Int64 {
  let components = duration.components
  let rounded = components.seconds + (components.attoseconds == 0 ? 0 : 1)
  return max(0, rounded)
}

private func constantTimeEqual(_ left: Data, _ right: Data) -> Bool {
  var difference = left.count ^ right.count
  let count = max(left.count, right.count)
  for index in 0..<count {
    difference |= Int(index < left.count ? left[index] : 0) ^ Int(index < right.count ? right[index] : 0)
  }
  return difference == 0
}
