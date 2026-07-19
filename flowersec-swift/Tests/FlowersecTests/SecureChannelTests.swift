import Foundation
import XCTest

@testable import Flowersec

final class FlowersecSecureChannelTests: XCTestCase {
  func testRecordKeyStateClearsLongLivedSecrets() {
    var keys = FlowersecRecordKeyState(
      sendKey: Data(repeating: 1, count: 32),
      recvKey: Data(repeating: 2, count: 32),
      sendNoncePrefix: Data(repeating: 3, count: 4),
      recvNoncePrefix: Data(repeating: 4, count: 4),
      rekeyBase: Data(repeating: 5, count: 32),
      transcript: Data(repeating: 6, count: 32),
      sendDirection: 1,
      recvDirection: 2,
      sendSeq: 1,
      recvSeq: 1
    )

    keys.clearKeyMaterial()

    XCTAssertTrue(keys.keyMaterialIsCleared)
    XCTAssertEqual(keys.sendNoncePrefix, Data(repeating: 3, count: 4))
    XCTAssertEqual(keys.recvNoncePrefix, Data(repeating: 4, count: 4))
    XCTAssertEqual(keys.transcript, Data(repeating: 6, count: 32))
  }

  func testCloseIsIdempotentAndClearsKeyMaterial() async {
    let transport = RecordingBinaryTransport()
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(
        key: Data(repeating: 0x31, count: 32),
        noncePrefix: Data([1, 2, 3, 4])
      )
    )

    await channel.close()
    await channel.close()

    let closeCount = await transport.closeCount()
    let keyMaterialIsCleared = await channel.keyMaterialIsCleared
    XCTAssertEqual(closeCount, 1)
    XCTAssertTrue(keyMaterialIsCleared)
  }

  func testCloseDuringPausedRekeyDoesNotRestoreClearedKeyMaterial() async {
    let transport = PausingBinaryTransport()
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(
        key: Data(repeating: 0x31, count: 32),
        noncePrefix: Data([1, 2, 3, 4])
      )
    )
    let rekey = Task { try await channel.rekey() }
    await transport.waitUntilFirstWriteIsPaused()

    await channel.close()

    do {
      try await rekey.value
      XCTFail("Expected the paused rekey to fail after close")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.stage, .close)
      XCTAssertEqual(error.code, .notConnected)
    } catch {
      XCTFail("Unexpected paused rekey error: \(error)")
    }
    let keyMaterialIsCleared = await channel.keyMaterialIsCleared
    XCTAssertTrue(keyMaterialIsCleared)
  }

  func testReadFailureClosesTransportAndClearsKeyMaterial() async {
    let transport = RecordingBinaryTransport()
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(
        key: Data(repeating: 0x31, count: 32),
        noncePrefix: Data([1, 2, 3, 4])
      )
    )

    do {
      _ = try await channel.readExact(1)
      XCTFail("Expected the transport read failure")
    } catch {
      // The transport failure is the behavior under test.
    }

    let firstCloseCount = await transport.closeCount()
    let keyMaterialIsCleared = await channel.keyMaterialIsCleared
    XCTAssertEqual(firstCloseCount, 1)
    XCTAssertTrue(keyMaterialIsCleared)
    await channel.close()
    let finalCloseCount = await transport.closeCount()
    XCTAssertEqual(finalCloseCount, 1)
  }

  func testOutboundRecordsUsePreferredChunkSize() async throws {
    let transport = RecordingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: FlowersecRecordKeyState(
        sendKey: key,
        recvKey: key,
        sendNoncePrefix: noncePrefix,
        recvNoncePrefix: noncePrefix,
        rekeyBase: Data(repeating: 0x42, count: 32),
        transcript: Data(repeating: 0x53, count: 32),
        sendDirection: 1,
        recvDirection: 2,
        sendSeq: 1,
        recvSeq: 1
      ),
      outboundRecordChunkBytes: 64 * 1024
    )

    try await channel.write(Data(repeating: 0x61, count: 150 * 1024))
    let frames = await transport.frames()
    XCTAssertEqual(frames.count, 3)

    var sizes: [Int] = []
    for (index, frame) in frames.enumerated() {
      let record = try FlowersecRecordCodec.decrypt(
        key: key,
        noncePrefix: noncePrefix,
        frame: frame,
        expectedSeq: UInt64(index + 1)
      )
      sizes.append(record.plaintext.count)
    }
    XCTAssertEqual(sizes, [64 * 1024, 64 * 1024, 22 * 1024])
    await channel.close()
  }

  func testConcurrentWritesDoNotInterleaveOutboundRecords() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix),
      outboundRecordChunkBytes: 4
    )

    let first = Task { try await channel.write(Data("abcdefgh".utf8)) }
    await transport.waitUntilFirstWriteIsPaused()
    let secondStarted = expectation(description: "second write started")
    let second = Task {
      secondStarted.fulfill()
      try await channel.write(Data("WXYZ".utf8))
    }
    await fulfillment(of: [secondStarted], timeout: 1)
    let deadline = ContinuousClock.now.advanced(by: .seconds(1))
    while await channel.queuedWriteCount < 2 {
      guard ContinuousClock.now < deadline else {
        XCTFail("The concurrent write did not enter the secure-channel queue")
        break
      }
      await Task.yield()
    }
    await transport.resumeFirstWrite()
    try await first.value
    try await second.value

    let frames = await transport.frames()
    var plaintexts: [Data] = []
    for (index, frame) in frames.enumerated() {
      let record = try FlowersecRecordCodec.decrypt(
        key: key,
        noncePrefix: noncePrefix,
        frame: frame,
        expectedSeq: UInt64(index + 1)
      )
      plaintexts.append(record.plaintext)
    }
    XCTAssertEqual(plaintexts, [Data("abcd".utf8), Data("efgh".utf8), Data("WXYZ".utf8)])
    await channel.close()
  }

  func testOutboundWriteBudgetRejectsExcessWithoutClosingChannel() async throws {
    let transport = PausingBinaryTransport()
    let diagnostics = DiagnosticRecorder()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix),
      outboundRecordChunkBytes: 8,
      maxOutboundBufferedBytes: 8,
      path: .tunnel,
      onDiagnosticEvent: diagnostics.record
    )

    let first = Task { try await channel.write(Data("abcdefgh".utf8)) }
    await transport.waitUntilFirstWriteIsPaused()
    let initialQueuedBytes = await channel.queuedWriteBytes
    XCTAssertEqual(initialQueuedBytes, 8)

    do {
      try await channel.write(Data("x".utf8))
      XCTFail("Expected the secure-channel write budget to reject the write")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .secure)
      XCTAssertEqual(error.code, .resourceExhausted)
    }
    let rejectedQueuedBytes = await channel.queuedWriteBytes
    XCTAssertEqual(rejectedQueuedBytes, 8)

    let event = try XCTUnwrap(diagnostics.events().last)
    XCTAssertEqual(event.code, "resource_limit_reached")
    XCTAssertEqual(event.resource, "secure_channel_pending_write_bytes")
    XCTAssertEqual(event.current, 9)
    XCTAssertEqual(event.limit, 8)

    await transport.resumeFirstWrite()
    try await first.value
    let drainedQueuedBytes = await channel.queuedWriteBytes
    XCTAssertEqual(drainedQueuedBytes, 0)
    try await channel.write(Data("y".utf8))
    await channel.close()
  }

  func testCanceledQueuedWriteReleasesBudgetWithoutSending() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix),
      outboundRecordChunkBytes: 8,
      maxOutboundBufferedBytes: 12
    )

    let first = Task { try await channel.write(Data("abcdefgh".utf8)) }
    await transport.waitUntilFirstWriteIsPaused()
    let canceled = Task { try await channel.write(Data("WXYZ".utf8)) }
    while await channel.queuedWriteCount < 2 { await Task.yield() }
    canceled.cancel()
    do {
      try await canceled.value
      XCTFail("Expected queued secure write cancellation")
    } catch is CancellationError {
      // Expected.
    }
    let queuedWriteCount = await channel.queuedWriteCount
    let queuedWriteBytes = await channel.queuedWriteBytes
    XCTAssertEqual(queuedWriteCount, 1)
    XCTAssertEqual(queuedWriteBytes, 8)

    await transport.resumeFirstWrite()
    try await first.value
    try await channel.write(Data("next".utf8))
    let frames = await transport.frames()
    XCTAssertEqual(frames.count, 2)
    XCTAssertEqual(
      try FlowersecRecordCodec.decrypt(
        key: key, noncePrefix: noncePrefix, frame: frames[1], expectedSeq: 2
      ).plaintext,
      Data("next".utf8)
    )
    await channel.close()
  }

  func testCanceledActiveWriteFinishesTransportBeforeReturningCancellation() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix),
      outboundRecordChunkBytes: 4
    )

    let canceled = Task { try await channel.write(Data("abcdefgh".utf8)) }
    await transport.waitUntilFirstWriteIsPaused()
    canceled.cancel()
    let nextCompleted = expectation(description: "next write completed")
    let next = Task {
      defer { nextCompleted.fulfill() }
      try await channel.write(Data("next".utf8))
    }
    let enqueueDeadline = ContinuousClock.now.advanced(by: .seconds(1))
    while await channel.queuedWriteCount < 2 {
      guard ContinuousClock.now < enqueueDeadline else {
        XCTFail("The next write did not queue behind the canceled active write")
        break
      }
      await Task.yield()
    }
    await transport.resumeFirstWrite()
    do {
      try await canceled.value
      XCTFail("Expected active secure write cancellation after transport completion")
    } catch is CancellationError {
      // Expected.
    }
    await fulfillment(of: [nextCompleted], timeout: 1)
    await channel.close()
    try await next.value
    let frames = await transport.frames()
    XCTAssertEqual(frames.count, 3)
    for (index, expected) in [Data("abcd".utf8), Data("efgh".utf8), Data("next".utf8)]
      .enumerated()
    {
      XCTAssertEqual(
        try FlowersecRecordCodec.decrypt(
          key: key,
          noncePrefix: noncePrefix,
          frame: frames[index],
          expectedSeq: UInt64(index + 1)
        ).plaintext,
        expected
      )
    }
  }

  func testCanceledQueuedRekeyDoesNotAdvanceKeyState() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix),
      outboundRecordChunkBytes: 4
    )

    let first = Task { try await channel.write(Data("abcd".utf8)) }
    await transport.waitUntilFirstWriteIsPaused()
    let canceled = Task { try await channel.rekey() }
    while await channel.queuedWriteCount < 2 { await Task.yield() }
    canceled.cancel()
    do {
      try await canceled.value
      XCTFail("Expected queued rekey cancellation")
    } catch is CancellationError {
      // Expected.
    }

    await transport.resumeFirstWrite()
    try await first.value
    try await channel.write(Data("WXYZ".utf8))
    let frames = await transport.frames()
    XCTAssertEqual(frames.count, 2)
    for (index, expected) in [Data("abcd".utf8), Data("WXYZ".utf8)].enumerated() {
      let record = try FlowersecRecordCodec.decrypt(
        key: key,
        noncePrefix: noncePrefix,
        frame: frames[index],
        expectedSeq: UInt64(index + 1)
      )
      XCTAssertEqual(record.flags, 0)
      XCTAssertEqual(record.plaintext, expected)
    }
    await channel.close()
  }

  func testCanceledActiveRekeyCompletesKeyTransitionBeforeReturningCancellation() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let rekeyBase = Data(repeating: 0x42, count: 32)
    let transcript = Data(repeating: 0x53, count: 32)
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix),
      outboundRecordChunkBytes: 8
    )

    let canceled = Task { try await channel.rekey() }
    await transport.waitUntilFirstWriteIsPaused()
    canceled.cancel()
    let nextCompleted = expectation(description: "post-rekey write completed")
    let next = Task {
      defer { nextCompleted.fulfill() }
      try await channel.write(Data("next".utf8))
    }
    let enqueueDeadline = ContinuousClock.now.advanced(by: .seconds(1))
    while await channel.queuedWriteCount < 2 {
      guard ContinuousClock.now < enqueueDeadline else {
        XCTFail("The next write did not queue behind the canceled active rekey")
        break
      }
      await Task.yield()
    }
    await transport.resumeFirstWrite()
    do {
      try await canceled.value
      XCTFail("Expected active rekey cancellation after transport completion")
    } catch is CancellationError {
      // Expected.
    }
    await fulfillment(of: [nextCompleted], timeout: 1)
    await channel.close()
    try await next.value
    let frames = await transport.frames()
    XCTAssertEqual(frames.count, 2)
    let rekeyRecord = try FlowersecRecordCodec.decrypt(
      key: key,
      noncePrefix: noncePrefix,
      frame: frames[0],
      expectedSeq: 1
    )
    XCTAssertEqual(rekeyRecord.flags, 2)
    XCTAssertTrue(rekeyRecord.plaintext.isEmpty)
    let rekeyedKey = try FlowersecRecordCodec.deriveRekeyKey(
      rekeyBase: rekeyBase,
      transcript: transcript,
      seq: 1,
      direction: 1
    )
    XCTAssertEqual(
      try FlowersecRecordCodec.decrypt(
        key: rekeyedKey,
        noncePrefix: noncePrefix,
        frame: frames[1],
        expectedSeq: 2
      ).plaintext,
      Data("next".utf8)
    )
  }

  func testClientRekeyPreservesCancellationAfterCompletingKeyTransition() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix)
    )
    let yamux = FlowersecYamuxClient(channel: channel)
    let client = FlowersecClient(
      rpc: RPCClient(stream: RekeyTestRPCStream()),
      secure: channel,
      yamux: yamux,
      path: .direct
    )

    try await assertPublicRekeyCancellation(
      rekey: { try await client.rekey() },
      transport: transport,
      key: key,
      noncePrefix: noncePrefix
    )
    await channel.close()
  }

  func testEndpointRekeyPreservesCancellationAfterCompletingKeyTransition() async throws {
    let transport = PausingBinaryTransport()
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])
    let channel = FlowersecSecureChannel(
      transport: transport,
      keys: keyState(key: key, noncePrefix: noncePrefix)
    )
    let yamux = FlowersecYamuxClient(channel: channel)
    let session = EndpointSession(
      path: .tunnel,
      endpointInstanceID: "rekey-test",
      secure: channel,
      yamux: yamux
    )

    try await assertPublicRekeyCancellation(
      rekey: { try await session.rekey() },
      transport: transport,
      key: key,
      noncePrefix: noncePrefix
    )
    await channel.close()
  }

  func testOutboundAdmissionMatchesSharedRuntimeVectors() async throws {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let data = try Data(
      contentsOf: root.appendingPathComponent("testdata/runtime_contract_vectors.json")
    )
    let vectors = try JSONDecoder().decode(RuntimeAdmissionVectors.self, from: data)
    let key = Data(repeating: 0x31, count: 32)
    let noncePrefix = Data([1, 2, 3, 4])

    for item in vectors.outboundBufferAdmission {
      let transport = VectorPausingBinaryTransport(blockFirstWrite: !item.unfinished.isEmpty)
      let channel = FlowersecSecureChannel(
        transport: transport,
        keys: keyState(key: key, noncePrefix: noncePrefix),
        outboundRecordChunkBytes: item.limit,
        maxOutboundBufferedBytes: item.limit
      )
      let unfinished = item.unfinished.map { size in
        Task { try await channel.write(Data(repeating: 0x61, count: size)) }
      }
      if !unfinished.isEmpty {
        await transport.waitUntilFirstWriteIsPaused()
      }

      let next = Task {
        try await channel.write(Data(repeating: 0x62, count: item.next))
      }
      if item.result == "resource_exhausted" {
        do {
          try await next.value
          XCTFail("Expected resource exhaustion for \(item.id)")
        } catch let error as FlowersecError {
          XCTAssertEqual(error.stage, .secure, item.id)
          XCTAssertEqual(error.code, .resourceExhausted, item.id)
        }
      }

      await transport.resumeFirstWrite()
      for write in unfinished {
        try await write.value
      }
      if item.result == "accepted" {
        try await next.value
      }
      await channel.close()
    }
  }

  private func keyState(key: Data, noncePrefix: Data) -> FlowersecRecordKeyState {
    FlowersecRecordKeyState(
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: Data(repeating: 0x42, count: 32),
      transcript: Data(repeating: 0x53, count: 32),
      sendDirection: 1,
      recvDirection: 2,
      sendSeq: 1,
      recvSeq: 1
    )
  }

  private func assertPublicRekeyCancellation(
    rekey: @escaping @Sendable () async throws -> Void,
    transport: PausingBinaryTransport,
    key: Data,
    noncePrefix: Data
  ) async throws {
    let canceled = Task { try await rekey() }
    await transport.waitUntilFirstWriteIsPaused()
    canceled.cancel()
    await transport.resumeFirstWrite()
    do {
      try await canceled.value
      XCTFail("Expected public rekey cancellation")
    } catch is CancellationError {
      // Expected.
    }

    try await rekey()
    let frames = await transport.frames()
    XCTAssertEqual(frames.count, 2)
    let first = try FlowersecRecordCodec.decrypt(
      key: key,
      noncePrefix: noncePrefix,
      frame: frames[0],
      expectedSeq: 1
    )
    XCTAssertEqual(first.flags, 2)
    let rekeyedKey = try FlowersecRecordCodec.deriveRekeyKey(
      rekeyBase: Data(repeating: 0x42, count: 32),
      transcript: Data(repeating: 0x53, count: 32),
      seq: 1,
      direction: 1
    )
    let second = try FlowersecRecordCodec.decrypt(
      key: rekeyedKey,
      noncePrefix: noncePrefix,
      frame: frames[1],
      expectedSeq: 2
    )
    XCTAssertEqual(second.flags, 2)
  }
}

private struct RuntimeAdmissionVectors: Decodable {
  struct Admission: Decodable {
    var id: String
    var limit: Int
    var unfinished: [Int]
    var next: Int
    var result: String
  }

  var outboundBufferAdmission: [Admission]

  private enum CodingKeys: String, CodingKey {
    case outboundBufferAdmission = "outbound_buffer_admission"
  }
}

private final class DiagnosticRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: [DiagnosticEvent] = []

  func record(_ event: DiagnosticEvent) {
    lock.lock()
    stored.append(event)
    lock.unlock()
  }

  func events() -> [DiagnosticEvent] {
    lock.lock()
    defer { lock.unlock() }
    return stored
  }
}

private actor RecordingBinaryTransport: FlowersecBinaryTransport {
  private var written: [Data] = []
  private var closed = 0

  func writeBinary(_ data: Data) { written.append(data) }
  func readBinary() async throws -> Data { throw FlowersecError.closed }
  func close() { closed += 1 }
  func frames() -> [Data] { written }
  func closeCount() -> Int { closed }
}

private actor RekeyTestRPCStream: FlowersecRPCStream {
  func write(_ data: Data) async throws {}
  func readExact(_ length: Int) async throws -> Data { throw FlowersecError.closed() }
  func close() async {}
  func reset() async throws {}
}

private actor PausingBinaryTransport: FlowersecBinaryTransport {
  private var written: [Data] = []
  private var firstWritePaused = false
  private var firstWriteWaiters: [CheckedContinuation<Void, Never>] = []
  private var resumeFirstWriteContinuation: CheckedContinuation<Void, Never>?

  func writeBinary(_ data: Data) async {
    written.append(data)
    guard written.count == 1 else { return }
    firstWritePaused = true
    let waiters = firstWriteWaiters
    firstWriteWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      resumeFirstWriteContinuation = continuation
    }
  }

  func readBinary() async throws -> Data { throw FlowersecError.closed }
  func close() { resumeFirstWrite() }
  func frames() -> [Data] { written }

  func waitUntilFirstWriteIsPaused() async {
    guard !firstWritePaused else { return }
    await withCheckedContinuation { continuation in
      firstWriteWaiters.append(continuation)
    }
  }

  func resumeFirstWrite() {
    resumeFirstWriteContinuation?.resume()
    resumeFirstWriteContinuation = nil
  }
}

private actor VectorPausingBinaryTransport: FlowersecBinaryTransport {
  private let blockFirstWrite: Bool
  private var firstWritePaused = false
  private var firstWriteWaiters: [CheckedContinuation<Void, Never>] = []
  private var resumeContinuation: CheckedContinuation<Void, Never>?

  init(blockFirstWrite: Bool) {
    self.blockFirstWrite = blockFirstWrite
  }

  func writeBinary(_ data: Data) async {
    _ = data
    guard blockFirstWrite, !firstWritePaused else { return }
    firstWritePaused = true
    let waiters = firstWriteWaiters
    firstWriteWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      resumeContinuation = continuation
    }
  }

  func readBinary() async throws -> Data { throw FlowersecError.closed }
  func close() { resumeFirstWrite() }

  func waitUntilFirstWriteIsPaused() async {
    guard !firstWritePaused else { return }
    await withCheckedContinuation { continuation in
      firstWriteWaiters.append(continuation)
    }
  }

  func resumeFirstWrite() {
    resumeContinuation?.resume()
    resumeContinuation = nil
  }
}
