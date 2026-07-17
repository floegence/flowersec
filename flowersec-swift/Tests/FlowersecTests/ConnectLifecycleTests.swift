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
      XCTAssertEqual(error.stage, .yamux)
      XCTAssertEqual(error.code, .notConnected)
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
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .yamux)
      XCTAssertEqual(error.code, .notConnected)
    }
    let isClosed = await transport.isClosed
    let secureWriteCount = await transport.secureWriteCount
    XCTAssertTrue(isClosed)
    XCTAssertEqual(secureWriteCount, 2)
  }

  func testPreCanceledTunnelClientStopsBeforeTransportPolicy() async throws {
    let policyCalled = LifecycleFlag()
    let grant = validTunnelGrant()
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await Flowersec.connectTunnel(
        grant,
        options: ConnectOptions(
          transportSecurityPolicy: .custom { _ in
            await policyCalled.set()
            return true
          },
          liveness: .disabled
        )
      )
    }

    do {
      _ = try await task.value
      XCTFail("Expected pre-canceled tunnel client")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    let wasPolicyCalled = await policyCalled.value
    XCTAssertFalse(wasPolicyCalled)
  }

  func testCanceledTunnelClientPolicyPropagatesCancellation() async throws {
    let policyStarted = LifecycleFlag()
    let releasePolicy = LifecycleGate()
    let grant = validTunnelGrant()
    let task = Task {
      try await Flowersec.connectTunnel(
        grant,
        options: ConnectOptions(
          transportSecurityPolicy: .custom { _ in
            await policyStarted.set()
            await releasePolicy.wait()
            try Task.checkCancellation()
            return true
          },
          liveness: .disabled
        )
      )
    }
    await policyStarted.waitUntilSet()

    task.cancel()
    await releasePolicy.release()

    do {
      _ = try await task.value
      XCTFail("Expected canceled client transport policy")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
  }

  func testCanceledClientResumeActorHopDoesNotStartSocket() async throws {
    let resumeStarted = LifecycleFlag()
    let releaseResume = LifecycleGate()
    let socketStarted = LifecycleSynchronousFlag()
    let transport = FlowersecWebSocketBinaryTransport(
      url: URL(string: "wss://example.invalid/tunnel")!,
      origin: nil,
      connectTimeout: .seconds(1),
      path: .tunnel,
      beforeResume: {
        await resumeStarted.set()
        await releaseResume.wait()
      },
      resumeOverride: { socketStarted.set() }
    )
    let task = Task { try await Flowersec.resumeWebSocketTransport(transport) }
    await resumeStarted.waitUntilSet()

    task.cancel()
    await releaseResume.release()

    do {
      try await task.value
      XCTFail("Expected canceled client resume")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    XCTAssertFalse(socketStarted.value)
  }

  func testPreCanceledTunnelClientAttachDoesNotReachSubmissionBoundary() async throws {
    let transport = ClientAttachTransport(submitBeforeSuspension: false)
    let task = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      try await Flowersec.writeTunnelAttach(transport: transport, text: "one-time-token")
    }

    do {
      try await task.value
      XCTFail("Expected pre-canceled tunnel attach")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    let writeCallCount = await transport.writeCallCount
    let submittedTexts = await transport.submittedTexts
    XCTAssertEqual(writeCallCount, 0)
    XCTAssertEqual(submittedTexts, [])
    await transport.waitUntilClosed()
  }

  func testCanceledPendingTunnelClientAttachClosesBeforeSubmissionBoundary() async throws {
    let transport = ClientAttachTransport(submitBeforeSuspension: false)
    let task = Task {
      try await Flowersec.writeTunnelAttach(transport: transport, text: "one-time-token")
    }
    await transport.waitUntilWriteStarted()

    task.cancel()

    do {
      try await task.value
      XCTFail("Expected canceled tunnel attach")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    let writeCallCount = await transport.writeCallCount
    let submittedTexts = await transport.submittedTexts
    XCTAssertEqual(writeCallCount, 1)
    XCTAssertEqual(submittedTexts, [])
    await transport.waitUntilClosed()
  }

  func testCanceledSubmittedTunnelClientAttachCannotRetractToken() async throws {
    let transport = ClientAttachTransport(submitBeforeSuspension: true)
    let task = Task {
      try await Flowersec.writeTunnelAttach(transport: transport, text: "one-time-token")
    }
    await transport.waitUntilWriteStarted()

    task.cancel()

    do {
      try await task.value
      XCTFail("Expected canceled tunnel attach")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    let submittedTexts = await transport.submittedTexts
    XCTAssertEqual(submittedTexts, ["one-time-token"])
    await transport.waitUntilClosed()
  }

  func testCanceledProductionTransportQueueDoesNotReachSystemSend() async throws {
    let sendStarted = LifecycleFlag()
    let releaseSend = LifecycleGate()
    let systemSendCalled = LifecycleSynchronousFlag()
    let transport = FlowersecWebSocketBinaryTransport(
      url: URL(string: "wss://example.invalid/tunnel")!,
      origin: nil,
      connectTimeout: .seconds(1),
      path: .tunnel,
      beforeSystemSend: {
        await sendStarted.set()
        await releaseSend.wait()
      },
      systemSendOverride: { systemSendCalled.set() }
    )
    let task = Task {
      try await Flowersec.writeTunnelAttach(transport: transport, text: "one-time-token")
    }
    await sendStarted.waitUntilSet()

    task.cancel()
    await releaseSend.release()

    do {
      try await task.value
      XCTFail("Expected canceled queued system send")
    } catch is CancellationError {
      XCTAssertTrue(true)
    }
    XCTAssertFalse(systemSendCalled.value)
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

  private func validTunnelGrant() -> ChannelInitGrant {
    ChannelInitGrant(
      tunnelURL: URL(string: "wss://example.invalid/tunnel")!,
      channelID: "channel-lifecycle-test",
      channelInitExpiresAtUnixS: Int64(Date().timeIntervalSince1970) + 60,
      idleTimeoutSeconds: 60,
      role: 1,
      token: "one-time-token",
      psk: Data(repeating: 0x2a, count: 32),
      allowedSuites: [.x25519HKDFSHA256AES256GCM],
      defaultSuite: .x25519HKDFSHA256AES256GCM
    )
  }
}

private actor LifecycleFlag {
  private var stored = false
  private var waiters: [CheckedContinuation<Void, Never>] = []
  var value: Bool { stored }

  func set() {
    stored = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }

  func waitUntilSet() async {
    guard !stored else { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }
}

private actor LifecycleGate {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    guard !released else { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func release() {
    guard !released else { return }
    released = true
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}

private final class LifecycleSynchronousFlag: @unchecked Sendable {
  private let lock = NSLock()
  private var stored = false

  var value: Bool {
    lock.lock()
    defer { lock.unlock() }
    return stored
  }

  func set() {
    lock.lock()
    stored = true
    lock.unlock()
  }
}

private actor ClientAttachTransport: FlowersecTunnelAttachTransport {
  private let submitBeforeSuspension: Bool
  private var closed = false
  private var writes = 0
  private var submitted: [String] = []
  private var pendingWrite: CheckedContinuation<Void, Never>?
  private var writeStartWaiters: [CheckedContinuation<Void, Never>] = []
  private var closeWaiters: [CheckedContinuation<Void, Never>] = []

  init(submitBeforeSuspension: Bool) {
    self.submitBeforeSuspension = submitBeforeSuspension
  }

  func writeBinary(_ data: Data) async throws {}

  func readBinary() async throws -> Data {
    throw FlowersecError.closed(path: .tunnel)
  }

  func writeText(_ text: String) async throws {
    writes += 1
    if submitBeforeSuspension { submitted.append(text) }
    let waiters = writeStartWaiters
    writeStartWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      pendingWrite = continuation
    }
    guard !closed else { throw FlowersecError.closed(path: .tunnel) }
    if !submitBeforeSuspension { submitted.append(text) }
  }

  func close() async {
    guard !closed else { return }
    closed = true
    let write = pendingWrite
    pendingWrite = nil
    write?.resume()
    let starts = writeStartWaiters
    writeStartWaiters.removeAll()
    for waiter in starts { waiter.resume() }
    let closes = closeWaiters
    closeWaiters.removeAll()
    for waiter in closes { waiter.resume() }
  }

  func waitUntilWriteStarted() async {
    guard writes == 0 else { return }
    await withCheckedContinuation { continuation in
      writeStartWaiters.append(continuation)
    }
  }

  func waitUntilClosed() async {
    guard !closed else { return }
    await withCheckedContinuation { continuation in
      closeWaiters.append(continuation)
    }
  }

  var writeCallCount: Int { writes }
  var submittedTexts: [String] { submitted }
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
    let clientPublicKey = try Curve25519.KeyAgreement.PublicKey(
      rawRepresentation: clientPublicKeyData)
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
