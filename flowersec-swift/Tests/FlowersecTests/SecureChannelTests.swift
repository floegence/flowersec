import Foundation
import XCTest

@testable import Flowersec

final class FlowersecSecureChannelTests: XCTestCase {
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
}

private actor RecordingBinaryTransport: FlowersecBinaryTransport {
  private var written: [Data] = []

  func writeBinary(_ data: Data) { written.append(data) }
  func readBinary() async throws -> Data { throw FlowersecError.closed }
  func close() {}
  func frames() -> [Data] { written }
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
