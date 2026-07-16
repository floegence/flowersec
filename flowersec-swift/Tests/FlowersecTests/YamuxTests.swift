import Foundation
import XCTest

@testable import Flowersec

final class FlowersecYamuxTests: XCTestCase {
  func testStreamCloseWritesFinAndWaitsForRemoteFinish() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()

    let syn = await channel.nextWrittenFrame()
    XCTAssertEqual(syn[1], 1)
    XCTAssertEqual(syn.readUInt16BE(at: 2), 1)
    XCTAssertEqual(syn.readUInt32BE(at: 4), 1)
    XCTAssertEqual(syn.readUInt32BE(at: 8), 0)

    await stream.close()

    let fin = await channel.nextWrittenFrame()
    XCTAssertEqual(fin[1], 1)
    XCTAssertEqual(fin.readUInt16BE(at: 2), 4)
    XCTAssertEqual(fin.readUInt32BE(at: 4), 1)
    XCTAssertEqual(fin.readUInt32BE(at: 8), 0)

    await channel.feed(header(type: 1, flags: 4, streamID: 1, length: 0))
    await client.close()
  }

  func testActiveStreamLimitIsReleasedOnClose() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(maxActiveStreams: 1, maxInboundStreams: 1)
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    let first = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    do {
      _ = try await client.openStream()
      XCTFail("Expected the active stream limit")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .resourceExhausted)
    }

    await first.close()
    _ = await channel.nextWrittenFrame()
    await channel.feed(header(type: 1, flags: 4, streamID: 1, length: 0))
    await channel.waitForReads(2)
    let second = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    await second.close()
    await client.close()
  }

  func testOversizedDataLengthClosesBeforePayloadRead() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    _ = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    await channel.feed(header(type: 0, flags: 0, streamID: 1, length: UInt32.max))
    await channel.waitUntilClosed()

    let readLengths = await channel.requestedReadLengths()
    XCTAssertEqual(readLengths, [12])
    do {
      _ = try await client.acceptStream()
      XCTFail("Expected the terminal frame limit error")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .direct)
      XCTAssertEqual(error.stage, .yamux)
      XCTAssertEqual(error.code, .resourceExhausted)
    }
  }

  func testPreferredOutboundFrameLimitChunksData() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(
      maxFrameBytes: 4 * 1024,
      preferredOutboundFrameBytes: 1024,
      maxStreamReceiveBytes: 256 * 1024
    )
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    try await stream.write(Data(repeating: 0x41, count: 2500))
    let first = await channel.nextWrittenFrame()
    let second = await channel.nextWrittenFrame()
    let third = await channel.nextWrittenFrame()
    XCTAssertEqual(first.readUInt32BE(at: 8), 1024)
    XCTAssertEqual(second.readUInt32BE(at: 8), 1024)
    XCTAssertEqual(third.readUInt32BE(at: 8), 452)
    await client.close()
  }

  func testStreamReceiveLimitResetsStreamAndReleasesResources() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(
      maxActiveStreams: 1,
      maxInboundStreams: 1,
      maxFrameBytes: 200 * 1024,
      preferredOutboundFrameBytes: 64 * 1024,
      maxStreamReceiveBytes: 256 * 1024,
      maxSessionReceiveBytes: 512 * 1024
    )
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    _ = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    var incoming = header(type: 0, flags: 0, streamID: 1, length: 200 * 1024)
    incoming.append(Data(repeating: 0x61, count: 200 * 1024))
    incoming.append(header(type: 0, flags: 0, streamID: 1, length: 100 * 1024))
    incoming.append(Data(repeating: 0x62, count: 100 * 1024))
    await channel.feed(incoming)

    let reset = await channel.nextWrittenFrame()
    XCTAssertEqual(reset.readUInt16BE(at: 2), 8)
    XCTAssertEqual(reset.readUInt32BE(at: 4), 1)

    let replacement = try await client.openStream()
    let replacementSYN = await channel.nextWrittenFrame()
    XCTAssertEqual(replacementSYN.readUInt32BE(at: 4), 3)
    await replacement.close()
    await client.close()
  }

  func testSessionReceiveLimitClosesBeforeOverflowPayloadRead() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(
      maxActiveStreams: 2,
      maxInboundStreams: 1,
      maxFrameBytes: 200 * 1024,
      preferredOutboundFrameBytes: 64 * 1024,
      maxStreamReceiveBytes: 256 * 1024,
      maxSessionReceiveBytes: 300 * 1024
    )
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    _ = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    _ = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    var incoming = header(type: 0, flags: 0, streamID: 1, length: 200 * 1024)
    incoming.append(Data(repeating: 0x61, count: 200 * 1024))
    incoming.append(header(type: 0, flags: 0, streamID: 3, length: 200 * 1024))
    await channel.feed(incoming)
    await channel.waitUntilClosed()

    let reads = await channel.requestedReadLengths()
    XCTAssertEqual(reads, [12, 200 * 1024, 12])
  }

  func testProbeCorrelatesAckAndReturnsRoundTripTime() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let probe = Task { try await client.probeLiveness(timeout: .seconds(1)) }
    let ping = await channel.nextWrittenFrame()
    XCTAssertEqual(ping[1], 2)
    XCTAssertEqual(ping.readUInt16BE(at: 2), 1)
    let id = ping.readUInt32BE(at: 8)
    await channel.feed(header(type: 2, flags: 2, streamID: 0, length: id))

    let rtt = try await probe.value
    XCTAssertGreaterThanOrEqual(rtt, .zero)
    await client.close()
  }

  func testProbeTimeoutClosesSessionAndIgnoresLateAck() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let first = Task { try await client.probeLiveness(timeout: .milliseconds(20)) }
    let ping = await channel.nextWrittenFrame()
    let firstID = ping.readUInt32BE(at: 8)
    do {
      _ = try await first.value
      XCTFail("Expected liveness timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .timeout)
    }

    await channel.feed(header(type: 2, flags: 2, streamID: 0, length: firstID))
    do {
      _ = try await client.probeLiveness(timeout: .seconds(1))
      XCTFail("Expected the timed-out session to remain closed")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.code, .notConnected)
    }
  }

  func testTunnelProbeTimeoutUsesTunnelYamuxPath() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel, path: .tunnel)
    let probe = Task { try await client.probeLiveness(timeout: .milliseconds(20)) }
    _ = await channel.nextWrittenFrame()

    do {
      _ = try await probe.value
      XCTFail("Expected liveness timeout")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .yamux)
      XCTAssertEqual(error.code, .timeout)
    }
  }

  func testTunnelProbeValidationUsesTunnelPath() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel, path: .tunnel)

    do {
      _ = try await client.probeLiveness(timeout: .zero)
      XCTFail("Expected liveness timeout validation to fail")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .validate)
      XCTAssertEqual(error.code, .invalidInput)
    }
  }

  func testConcurrentProbesShareOnePing() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let first = Task { try await client.probeLiveness(timeout: .seconds(1)) }
    let ping = await channel.nextWrittenFrame()

    let second = Task { try await client.probeLiveness(timeout: .seconds(1)) }
    try await Task.sleep(for: .milliseconds(5))
    let probeWriteCount = await channel.writeCount()
    XCTAssertEqual(probeWriteCount, 1)

    await channel.feed(
      header(type: 2, flags: 2, streamID: 0, length: ping.readUInt32BE(at: 8))
    )
    let firstRTT = try await first.value
    let secondRTT = try await second.value
    XCTAssertEqual(firstRTT, secondRTT)
    await client.close()
  }

  func testConcurrentStreamWritesDoNotOvercommitInitialWindow() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    let first = Task { try await stream.write(Data(repeating: 0x61, count: 200 * 1024)) }
    let second = Task { try await stream.write(Data(repeating: 0x62, count: 200 * 1024)) }
    await channel.waitForWrites(5)
    let payloadBeforeCredit = await channel.payloadBytesWritten()
    XCTAssertEqual(payloadBeforeCredit, 256 * 1024)
    try await Task.sleep(for: .milliseconds(5))
    let payloadStillBlocked = await channel.payloadBytesWritten()
    XCTAssertEqual(payloadStillBlocked, 256 * 1024)

    await channel.feed(header(type: 1, flags: 0, streamID: 1, length: 144 * 1024))
    try await first.value
    try await second.value
    let payloadAfterCredit = await channel.payloadBytesWritten()
    XCTAssertEqual(payloadAfterCredit, 400 * 1024)
    await client.close()
  }

  func testDataWithFinDeliversPayloadBeforeEndOfStream() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(maxActiveStreams: 1, maxInboundStreams: 1)
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    let read = Task { try await stream.readExact(3) }

    var incoming = header(type: 0, flags: 4, streamID: 1, length: 3)
    incoming.append(Data("end".utf8))
    await channel.feed(incoming)
    let finalPayload = try await read.value
    XCTAssertEqual(finalPayload, Data("end".utf8))

    await stream.close()
    _ = await channel.nextWrittenFrame()
    let replacement = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    await replacement.close()
    await client.close()
  }

  func testLimitValidation() throws {
    XCTAssertThrowsError(try YamuxLimits(maxActiveStreams: 1, maxInboundStreams: 2).validate())
    XCTAssertThrowsError(
      try YamuxLimits(maxFrameBytes: 4096, preferredOutboundFrameBytes: 8192).validate()
    )
    XCTAssertThrowsError(
      try YamuxLimits(maxFrameBytes: 1024, maxStreamReceiveBytes: 1024).validate()
    )
    XCTAssertNoThrow(try YamuxLimits().validate())
  }

  func testWindowUpdateOverflowClosesSession() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    _ = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    await channel.feed(header(type: 1, flags: 0, streamID: 1, length: 1))
    await channel.waitUntilClosed()
  }

  func testTerminationWaiterReceivesReaderFailure() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    await client.start()
    let termination = Task { await client.terminated() }

    await channel.feed(header(type: 99, flags: 0, streamID: 0, length: 0))
    let error = await termination.value as? FlowersecError
    XCTAssertEqual(error?.path, .direct)
    XCTAssertEqual(error?.stage, .yamux)
    XCTAssertEqual(error?.code, .openStreamFailed)
  }

  func testPostHandshakeTransportWriteFailureUsesStableYamuxTermination() async {
    let client = FlowersecYamuxClient(channel: FailingWriteYamuxChannel(), path: .tunnel)
    do {
      _ = try await client.openStream()
      XCTFail("Expected the transport write to fail")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.path, .tunnel)
      XCTAssertEqual(error.stage, .yamux)
      XCTAssertEqual(error.code, .notConnected)
    } catch {
      XCTFail("Expected FlowersecError, got \(error)")
    }
  }

  private func header(type: UInt8, flags: UInt16, streamID: UInt32, length: UInt32) -> Data {
    var data = Data([0, type])
    data.appendUInt16BE(flags)
    data.appendUInt32BE(streamID)
    data.appendUInt32BE(length)
    return data
  }
}

private final class FailingWriteYamuxChannel: FlowersecYamuxChannel, @unchecked Sendable {
  func write(_ data: Data) async throws {
    _ = data
    throw POSIXError(.ENOTCONN)
  }

  func readExact(_ length: Int) async throws -> Data {
    _ = length
    try await Task.sleep(for: .seconds(30))
    throw CancellationError()
  }

  func close() async {}
}

private final class InMemoryYamuxChannel: FlowersecYamuxChannel, @unchecked Sendable {
  private let state = InMemoryYamuxChannelState()

  func write(_ data: Data) async throws { await state.write(data) }
  func readExact(_ length: Int) async throws -> Data { try await state.readExact(length) }
  func close() async { await state.close() }
  func nextWrittenFrame() async -> Data { await state.nextWrittenFrame() }
  func feed(_ data: Data) async { await state.feed(data) }
  func waitUntilClosed() async { await state.waitUntilClosed() }
  func requestedReadLengths() async -> [Int] { await state.requestedReadLengths() }
  func writeCount() async -> Int { await state.writeCount() }
  func payloadBytesWritten() async -> Int { await state.payloadBytesWritten() }
  func waitForWrites(_ count: Int) async { await state.waitForWrites(count) }
  func waitForReads(_ count: Int) async { await state.waitForReads(count) }
}

private actor InMemoryYamuxChannelState {
  private var writes: [Data] = []
  private var incoming = Data()
  private var readLengths: [Int] = []
  private var totalWrites = 0
  private var closed = false
  private var readWaiters: [CheckedContinuation<Void, Never>] = []
  private var readCountWaiters: [CheckedContinuation<Void, Never>] = []
  private var writeWaiters: [CheckedContinuation<Void, Never>] = []
  private var closeWaiters: [CheckedContinuation<Void, Never>] = []

  func write(_ data: Data) {
    writes.append(data)
    totalWrites += 1
    resume(&writeWaiters)
  }

  func feed(_ data: Data) {
    incoming.append(data)
    resume(&readWaiters)
  }

  func readExact(_ length: Int) async throws -> Data {
    readLengths.append(length)
    resume(&readCountWaiters)
    while incoming.count < length && !closed {
      await waitForRead()
    }
    guard incoming.count >= length else { throw FlowersecError.closed }
    let data = Data(incoming.prefix(length))
    incoming.removeFirst(length)
    return data
  }

  func close() {
    closed = true
    resume(&readWaiters)
    resume(&writeWaiters)
    resume(&closeWaiters)
  }

  func nextWrittenFrame() async -> Data {
    while writes.isEmpty && !closed {
      await waitForWrite()
    }
    return writes.removeFirst()
  }

  func waitUntilClosed() async {
    while !closed { await waitForClose() }
  }

  func requestedReadLengths() -> [Int] { readLengths }

  func writeCount() -> Int { totalWrites }

  func payloadBytesWritten() -> Int {
    writes.reduce(into: 0) { total, frame in
      guard frame.count >= 12, frame[1] == 0 else { return }
      total += Int(frame.readUInt32BE(at: 8))
    }
  }

  func waitForWrites(_ count: Int) async {
    while writes.count < count && !closed { await waitForWrite() }
  }

  func waitForReads(_ count: Int) async {
    while readLengths.count < count && !closed {
      await withCheckedContinuation { continuation in
        readCountWaiters.append(continuation)
      }
    }
  }

  private func waitForRead() async {
    await withCheckedContinuation { continuation in readWaiters.append(continuation) }
  }

  private func waitForWrite() async {
    await withCheckedContinuation { continuation in writeWaiters.append(continuation) }
  }

  private func waitForClose() async {
    await withCheckedContinuation { continuation in closeWaiters.append(continuation) }
  }

  private func resume(_ waiters: inout [CheckedContinuation<Void, Never>]) {
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }
}
