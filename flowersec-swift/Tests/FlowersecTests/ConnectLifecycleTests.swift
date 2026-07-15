import Crypto
import Foundation
import XCTest

@testable import Flowersec

final class ConnectLifecycleTests: XCTestCase {
  func testHandshakeTimeoutClosesTransport() async throws {
    let transport = BlockingHandshakeTransport()
    let options = ConnectOptions(
      handshakeTimeout: .milliseconds(20),
      liveness: .disabled
    )

    do {
      _ = try await Flowersec.establishConnection(
        validDirectInfo(),
        transport: transport,
        options: options,
        path: .direct,
        idleTimeout: nil
      )
      XCTFail("Expected the handshake to time out")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .timeout)
    }
    let isClosed = await transport.isClosed
    XCTAssertTrue(isClosed)
  }

  func testHandshakeCancellationClosesTransport() async throws {
    let transport = BlockingHandshakeTransport()
    let info = validDirectInfo()
    let task = Task {
      try await Flowersec.establishConnection(
        info,
        transport: transport,
        options: ConnectOptions(handshakeTimeout: .seconds(5), liveness: .disabled),
        path: .direct,
        idleTimeout: nil
      )
    }
    await transport.waitUntilReadStarted()
    task.cancel()

    do {
      _ = try await task.value
      XCTFail("Expected connection cancellation")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    let isClosed = await transport.isClosed
    XCTAssertTrue(isClosed)
  }

  func testHandshakeValidationFailureClosesTransport() async throws {
    let transport = BlockingHandshakeTransport()
    var invalidInfo = validDirectInfo()
    invalidInfo.psk = Data(repeating: 0x01, count: 31)

    do {
      _ = try await Flowersec.establishConnection(
        invalidInfo,
        transport: transport,
        options: ConnectOptions(liveness: .disabled),
        path: .direct,
        idleTimeout: nil
      )
      XCTFail("Expected handshake validation to fail")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .invalidInput)
    }
    let isClosed = await transport.isClosed
    XCTAssertTrue(isClosed)
  }

  func testHandshakeValidationFailureUsesTunnelPath() async throws {
    let transport = BlockingHandshakeTransport()
    var invalidInfo = validDirectInfo()
    invalidInfo.psk = Data(repeating: 0x01, count: 31)

    do {
      _ = try await Flowersec.establishConnection(
        invalidInfo,
        transport: transport,
        options: ConnectOptions(liveness: .disabled),
        path: .tunnel,
        idleTimeout: .seconds(30)
      )
      XCTFail("Expected handshake validation to fail")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .invalidInput)
    }
  }

  func testMalformedTunnelHandshakeUsesTunnelHandshakePath() async throws {
    let transport = MalformedHandshakeTransport()

    do {
      _ = try await Flowersec.establishConnection(
        validDirectInfo(),
        transport: transport,
        options: ConnectOptions(handshakeTimeout: .seconds(1), liveness: .disabled),
        path: .tunnel,
        idleTimeout: .seconds(30)
      )
      XCTFail("Expected malformed handshake response")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .handshake)
      XCTAssertEqual(error.code, .handshakeFailed)
    }
  }

  func testYamuxSetupFailureClosesEstablishedSecureChannel() async throws {
    let transport = ScriptedHandshakeTransport(failAtSecureWrite: 1)

    do {
      _ = try await Flowersec.establishConnection(
        validDirectInfo(),
        transport: transport,
        options: ConnectOptions(handshakeTimeout: .seconds(1), liveness: .disabled),
        path: .tunnel,
        idleTimeout: nil
      )
      XCTFail("Expected yamux setup to fail")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.code, .websocketFailed)
    }
    let isClosed = await transport.isClosed
    let secureWriteCount = await transport.secureWriteCount
    XCTAssertTrue(isClosed)
    XCTAssertEqual(secureWriteCount, 1)
  }

  func testRPCStreamSetupFailureClosesAllEstablishedLayers() async throws {
    let transport = ScriptedHandshakeTransport(failAtSecureWrite: 2)

    do {
      _ = try await Flowersec.establishConnection(
        validDirectInfo(),
        transport: transport,
        options: ConnectOptions(handshakeTimeout: .seconds(1), liveness: .disabled),
        path: .direct,
        idleTimeout: nil
      )
      XCTFail("Expected RPC stream setup to fail")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .websocketFailed)
    }
    let isClosed = await transport.isClosed
    let secureWriteCount = await transport.secureWriteCount
    XCTAssertTrue(isClosed)
    XCTAssertEqual(secureWriteCount, 2)
  }

  private func validDirectInfo() -> DirectConnectInfo {
    DirectConnectInfo(
      wsURL: URL(string: "wss://example.invalid/ws")!,
      channelID: "channel-lifecycle-test",
      psk: Data(repeating: 0x2a, count: 32),
      channelInitExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 60,
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
  }
}

private actor MalformedHandshakeTransport: FlowersecBinaryTransport {
  private var returnedResponse = false

  func writeBinary(_ data: Data) throws {}

  func readBinary() throws -> Data {
    guard !returnedResponse else { throw FlowersecError.closed }
    returnedResponse = true
    return FlowersecHandshakeFrame.encode(
      type: FlowersecWire.handshakeTypeResp,
      payload: Data("{".utf8)
    )
  }

  func close() {}
}

private actor BlockingHandshakeTransport: FlowersecBinaryTransport {
  private var closed = false
  private var readStarted = false
  private var readContinuations: [CheckedContinuation<Data, Error>] = []
  private var readStartContinuations: [CheckedContinuation<Void, Never>] = []

  func writeBinary(_ data: Data) throws {}

  func readBinary() async throws -> Data {
    guard !closed else { throw FlowersecError.closed }
    readStarted = true
    let starts = readStartContinuations
    readStartContinuations.removeAll()
    for continuation in starts {
      continuation.resume()
    }
    return try await withCheckedThrowingContinuation { continuation in
      readContinuations.append(continuation)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    let reads = readContinuations
    readContinuations.removeAll()
    for continuation in reads {
      continuation.resume(throwing: FlowersecError.closed)
    }
  }

  func waitUntilReadStarted() async {
    guard !readStarted else { return }
    await withCheckedContinuation { continuation in
      readStartContinuations.append(continuation)
    }
  }

  var isClosed: Bool { closed }
}

private actor ScriptedHandshakeTransport: FlowersecBinaryTransport {
  private let failAtSecureWrite: Int
  private var inbound: [Data] = []
  private var readers: [CheckedContinuation<Data, Error>] = []
  private var closed = false
  private var finishedKey: Data?
  private var finishedNoncePrefix: Data?
  private(set) var secureWriteCount = 0

  init(failAtSecureWrite: Int) {
    self.failAtSecureWrite = failAtSecureWrite
  }

  func writeBinary(_ data: Data) throws {
    if data.prefix(4) == FlowersecWire.handshakeMagic {
      switch data[5] {
      case FlowersecWire.handshakeTypeInit:
        try prepareResponse(from: data)
      case FlowersecWire.handshakeTypeAck:
        try prepareFinished()
      default:
        throw FlowersecError.invalidHandshake("Unexpected client handshake frame.")
      }
      return
    }

    secureWriteCount += 1
    if secureWriteCount == failAtSecureWrite {
      throw FlowersecError.webSocket("Scripted secure write failure.")
    }
  }

  func readBinary() async throws -> Data {
    if !inbound.isEmpty {
      return inbound.removeFirst()
    }
    guard !closed else { throw FlowersecError.closed }
    return try await withCheckedThrowingContinuation { continuation in
      readers.append(continuation)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    let waiting = readers
    readers.removeAll()
    for continuation in waiting {
      continuation.resume(throwing: FlowersecError.closed)
    }
  }

  var isClosed: Bool { closed }

  private func prepareResponse(from frame: Data) throws {
    let payload = try FlowersecHandshakeFrame.decode(
      frame,
      expectedType: FlowersecWire.handshakeTypeInit
    )
    let message = try JSONDecoder().decode(TestInitMessage.self, from: payload)
    guard message.suite == Suite.x25519HKDFSHA256AES256GCM.rawValue,
      let clientPublicKeyData = Data(base64URLEncoded: message.clientEphPubB64u),
      let clientNonce = Data(base64URLEncoded: message.nonceCB64u)
    else {
      throw FlowersecError.invalidHandshake("Invalid scripted client init.")
    }

    let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
    let serverPublicKey = serverPrivateKey.publicKey.rawRepresentation
    let clientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientPublicKeyData)
    let sharedSecret = try serverPrivateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
    let serverNonce = Data(repeating: 0x7b, count: 32)
    let transcript = try FlowersecHandshake.transcriptHash(
      input: FlowersecHandshakeTranscriptInput(
        suite: .x25519HKDFSHA256AES256GCM,
        channelID: message.channelID,
        nonceC: clientNonce,
        nonceS: serverNonce,
        clientPublicKey: clientPublicKeyData,
        serverPublicKey: serverPublicKey,
        serverFeatures: 0
      )
    )
    let keys = FlowersecHandshake.deriveSessionKeys(
      psk: Data(repeating: 0x2a, count: 32),
      sharedSecret: sharedSecret.withUnsafeBytes { Data($0) },
      transcript: transcript
    )
    finishedKey = keys.s2cKey
    finishedNoncePrefix = keys.s2cNoncePrefix

    let response = TestResponseMessage(
      handshakeID: "scripted-handshake",
      serverEphPubB64u: serverPublicKey.base64URLEncodedString(),
      nonceSB64u: serverNonce.base64URLEncodedString(),
      serverFeatures: 0
    )
    let responsePayload = try JSONEncoder.flowersecWire.encode(response)
    enqueue(
      FlowersecHandshakeFrame.encode(
        type: FlowersecWire.handshakeTypeResp,
        payload: responsePayload
      )
    )
  }

  private func prepareFinished() throws {
    guard let finishedKey, let finishedNoncePrefix else {
      throw FlowersecError.invalidHandshake("Missing scripted session keys.")
    }
    enqueue(
      try FlowersecRecordCodec.encrypt(
        key: finishedKey,
        noncePrefix: finishedNoncePrefix,
        flags: 1,
        seq: 1,
        plaintext: Data()
      )
    )
  }

  private func enqueue(_ data: Data) {
    if !readers.isEmpty {
      readers.removeFirst().resume(returning: data)
    } else {
      inbound.append(data)
    }
  }
}

private struct TestInitMessage: Decodable {
  var channelID: String
  var suite: Int
  var clientEphPubB64u: String
  var nonceCB64u: String

  private enum CodingKeys: String, CodingKey {
    case channelID = "channel_id"
    case suite
    case clientEphPubB64u = "client_eph_pub_b64u"
    case nonceCB64u = "nonce_c_b64u"
  }
}

private struct TestResponseMessage: Encodable {
  var handshakeID: String
  var serverEphPubB64u: String
  var nonceSB64u: String
  var serverFeatures: UInt32

  private enum CodingKeys: String, CodingKey {
    case handshakeID = "handshake_id"
    case serverEphPubB64u = "server_eph_pub_b64u"
    case nonceSB64u = "nonce_s_b64u"
    case serverFeatures = "server_features"
  }
}
