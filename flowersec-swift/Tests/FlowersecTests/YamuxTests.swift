import Foundation
import XCTest

@testable import Flowersec

final class FlowersecYamuxTests: XCTestCase {
  func testDirectTerminalWriteDeliversFinalDataAndFINInOneProviderWrite() async throws {
    let wire = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: wire, limits: YamuxLimits(preferredOutboundFrameBytes: 1024))
    let stream = try await client.openStream()
    _ = await wire.nextWrittenFrame()
    let payload = Data(repeating: 0x61, count: 1025)
    try await stream.write(payload, finishing: true)
    try await stream.closeWrite()
    let writes = await wire.writeCount()
    XCTAssertEqual(writes, 3)
    guard writes == 3 else { await client.close(); return }
    let first = await wire.nextWrittenFrame()
    let last = await wire.nextWrittenFrame()
    XCTAssertEqual(first, header(type: 0, flags: 0, streamID: 1, length: 1024) + payload.prefix(1024))
    XCTAssertEqual(last, header(type: 0, flags: 0, streamID: 1, length: 1) + payload.suffix(1)
      + header(type: 1, flags: 4, streamID: 1, length: 0))
    await client.close()
  }

  func testCloseWaitsForPendingDataCreditAndFINWrites() async throws {
    for kind in ["data", "credit", "fin"] {
      let wire = InMemoryYamuxChannel()
      let payload = Data([42])
      let dataFrame = header(type: 0, flags: 0, streamID: 1, length: 1) + payload
      let target = kind == "data" ? dataFrame : header(type: 1, flags: kind == "fin" ? 4 : 0,
        streamID: 1, length: kind == "credit" ? 1 : 0)
      let entered = expectation(description: "provider started \(kind) write")
      let earlyReturn = expectation(description: "closed with an outstanding \(kind) write")
      earlyReturn.isInverted = true
      let provider = GatedYamuxWrite(wire: wire, target: target, entered: entered)
      let client = FlowersecYamuxClient(channel: provider)
      let stream = try await client.openStream()
      if kind == "credit" { await wire.feed(dataFrame) }
      let operation = Task {
        switch kind {
        case "data": try await stream.write(payload)
        case "credit": _ = try await stream.read(maxBytes: 1)
        default: await stream.close()
        }
      }
      await fulfillment(of: [entered], timeout: 2)
      let shutdown = Task {
        await client.close()
        if !(await provider.writeExited) { earlyReturn.fulfill() }
      }
      await wire.waitUntilClosed()
      await fulfillment(of: [earlyReturn], timeout: 0.1)
      await provider.release()
      _ = await operation.result
      await shutdown.value
      let cause = await client.terminated()
      XCTAssertNil(cause, "the late \(kind) error must not replace the original close")
    }
  }

  func testConcurrentCloseWaitsForChannelAndReaderExit() async {
    let readStarted = expectation(description: "reader entered the provider")
    let closeStarted = expectation(description: "channel started closing")
    let earlyReturn = expectation(description: "a close or termination observer returned with I/O outstanding")
    earlyReturn.isInverted = true
    let channel = ClosingYamuxChannel(readStarted: readStarted, closeStarted: closeStarted)
    let client = FlowersecYamuxClient(channel: channel)
    await client.start()
    await fulfillment(of: [readStarted], timeout: 2)
    let first = Task {
      await client.close()
      await channel.checkCompletion(earlyReturn)
    }
    await fulfillment(of: [closeStarted], timeout: 2)
    let second = Task {
      await client.close()
      await channel.checkCompletion(earlyReturn)
    }
    let observer = Task {
      let cause = await client.terminated()
      await channel.checkCompletion(earlyReturn)
      return cause
    }
    // A provider may return from close while its outstanding read is still unwinding.
    await channel.allowClose()
    await fulfillment(of: [earlyReturn], timeout: 0.1)
    await channel.allowReadExit()
    await first.value
    await second.value
    let cause = await observer.value
    XCTAssertNil(cause)
    let closes = await channel.closeCount
    XCTAssertEqual(closes, 1)
  }

  func testInFlightWindowCreditDoesNotResetHalfClosedReply() async throws {
    let requestWire = InMemoryYamuxChannel(), replyWire = InMemoryYamuxChannel()
    let limits = YamuxLimits(maxActiveStreams: 1, maxInboundStreams: 1)
    let client = FlowersecYamuxClient(channel: requestWire, limits: limits)
    let server = FlowersecYamuxClient(channel: replyWire, limits: limits, client: false)
    let request = try await client.openStream()
    await replyWire.feed(await requestWire.nextWrittenFrame())
    let reply = try await server.acceptStream()
    await requestWire.feed(await replyWire.nextWrittenFrame())

    await request.close()
    await replyWire.feed(await requestWire.nextWrittenFrame())
    let requestEOF = try await reply.read(maxBytes: 1)
    XCTAssertNil(requestEOF)
    try await reply.write(Data("world".utf8))
    await requestWire.feed(await replyWire.nextWrittenFrame())
    let prefix = try await request.readExact(2)
    XCTAssertEqual(prefix, Data("wo".utf8))
    let inFlightCredit = await requestWire.nextWrittenFrame()
    XCTAssertEqual(inFlightCredit, header(type: 1, flags: 0, streamID: 1, length: 2))

    await reply.close()
    await requestWire.feed(await replyWire.nextWrittenFrame())
    let ping = header(type: 2, flags: 1, streamID: 0, length: 42)
    let pong = header(type: 2, flags: 2, streamID: 0, length: 42)
    await replyWire.feed(inFlightCredit + ping)
    var response = await replyWire.nextWrittenFrame()
    while response != pong {
      XCTFail("A retired stream replied to in-flight window credit: \(response as NSData)")
      await requestWire.feed(response)
      response = await replyWire.nextWrittenFrame()
    }
    await requestWire.feed(ping)
    let fence = await requestWire.nextWrittenFrame()
    XCTAssertEqual(fence, pong)

    let beforeDrain = await requestWire.writeCount()
    let middle = try await request.readExact(1)
    let tail = try await request.read(maxBytes: 5)
    let eof = try await request.read(maxBytes: 1)
    XCTAssertEqual(middle, Data("r".utf8))
    XCTAssertEqual(tail, Data("ld".utf8))
    XCTAssertNil(eof)
    let afterDrain = await requestWire.writeCount()
    XCTAssertEqual(afterDrain, beforeDrain)
    _ = try await client.openStream()
    _ = try await server.openStream()
    await client.close()
    await server.close()
  }

  func testPeerResetStillAbortsHalfClosedReadWithoutEchoingDuplicateReset() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    await stream.close()
    _ = await channel.nextWrittenFrame()
    let reset = header(type: 1, flags: 8, streamID: 1, length: 0)
    let ping = header(type: 2, flags: 1, streamID: 0, length: 23)
    await channel.feed(reset + reset + ping)
    let fence = await channel.nextWrittenFrame()
    XCTAssertEqual(fence, header(type: 2, flags: 2, streamID: 0, length: 23))
    do {
      _ = try await stream.read(maxBytes: 1)
      XCTFail("Expected the peer reset")
    } catch is FlowersecStreamResetError {}
    await client.close()
  }

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

  func testStreamWriteQueueRejectsAggregateOverflow() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(maxStreamWriteQueueBytes: 300 * 1024)
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    let first = Task { try await stream.write(Data(repeating: 0x61, count: 300 * 1024)) }
    await channel.waitForWrites(4)
    do {
      try await stream.write(Data(repeating: 0x62, count: 1))
      XCTFail("Expected the stream write queue limit")
    } catch let error as FlowersecError {
      XCTAssertEqual(error.stage, .yamux)
      XCTAssertEqual(error.code, .resourceExhausted)
    }

    await channel.feed(header(type: 1, flags: 0, streamID: 1, length: 44 * 1024))
    try await first.value
    await client.close()
  }

  func testCanceledQueuedWriteReleasesStreamBudget() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(maxStreamWriteQueueBytes: 400 * 1024)
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    let first = Task { try await stream.write(Data(repeating: 0x61, count: 300 * 1024)) }
    await channel.waitForWrites(4)
    let canceled = Task { try await stream.write(Data(repeating: 0x62, count: 100 * 1024)) }
    try await Task.sleep(for: .milliseconds(5))
    canceled.cancel()
    do {
      try await canceled.value
      XCTFail("Expected queued write cancellation")
    } catch is CancellationError {
      // Expected.
    }

    let replacement = Task {
      try await stream.write(Data(repeating: 0x63, count: 100 * 1024))
    }
    await channel.feed(header(type: 1, flags: 0, streamID: 1, length: 144 * 1024))
    try await first.value
    try await replacement.value
    await client.close()
  }

  func testCanceledWindowBlockedWriteReleasesTurnAndBudget() async throws {
    let channel = InMemoryYamuxChannel()
    let limits = YamuxLimits(maxStreamWriteQueueBytes: 300 * 1024)
    let client = FlowersecYamuxClient(channel: channel, limits: limits)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    let canceled = Task { try await stream.write(Data(repeating: 0x61, count: 300 * 1024)) }
    await channel.waitForWrites(4)
    canceled.cancel()
    do {
      try await canceled.value
      XCTFail("Expected window-blocked write cancellation")
    } catch is CancellationError {
      // Expected.
    }

    let replacement = Task {
      try await stream.write(Data(repeating: 0x62, count: 100 * 1024))
    }
    await channel.feed(header(type: 1, flags: 0, streamID: 1, length: 144 * 1024))
    try await replacement.value
    let payloadBytes = await channel.payloadBytesWritten()
    XCTAssertEqual(payloadBytes, 356 * 1024)
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

  func testStreamReadBufferPreservesFragmentedFramesAndClearsAfterFullConsumption() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()

    var incoming = header(type: 0, flags: 0, streamID: 1, length: 3)
    incoming.append(Data("abc".utf8))
    incoming.append(header(type: 0, flags: 0, streamID: 1, length: 5))
    incoming.append(Data("defgh".utf8))
    await channel.feed(incoming)

    let first = try await stream.readExact(5)
    let second = try await stream.readExact(3)
    XCTAssertEqual(first, Data("abcde".utf8))
    XCTAssertEqual(second, Data("fgh".utf8))
    await assertReadBuffer(stream, storageCount: 0, offset: 0)
    await client.close()
  }

  func testStreamReadBufferCompactsOnlyAfterConsumedPrefixReachesThresholdAndHalfStorage()
    async throws
  {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    let payload = Data((0..<(160 * 1024)).map { UInt8($0 % 251) })
    var incoming = header(type: 0, flags: 0, streamID: 1, length: UInt32(payload.count))
    incoming.append(payload)
    await channel.feed(incoming)

    let first = try await stream.readExact(32 * 1024)
    XCTAssertEqual(first, payload.subdata(in: 0..<(32 * 1024)))
    await assertReadBuffer(stream, storageCount: 160 * 1024, offset: 32 * 1024)

    let second = try await stream.readExact(32 * 1024)
    XCTAssertEqual(second, payload.subdata(in: (32 * 1024)..<(64 * 1024)))
    await assertReadBuffer(stream, storageCount: 160 * 1024, offset: 64 * 1024)

    let third = try await stream.readExact(16 * 1024)
    XCTAssertEqual(third, payload.subdata(in: (64 * 1024)..<(80 * 1024)))
    await assertReadBuffer(stream, storageCount: 80 * 1024, offset: 0)

    let fourth = try await stream.readExact(80 * 1024)
    XCTAssertEqual(fourth, payload.subdata(in: (80 * 1024)..<(160 * 1024)))
    await assertReadBuffer(stream, storageCount: 0, offset: 0)
    await client.close()
  }

  func testStreamReadBufferOffsetResetsOnResetFailureAndSessionClose() async throws {
    do {
      let (_, client, stream) = try await partiallyConsumedStream()
      try await stream.reset()
      await assertReadBuffer(stream, storageCount: 0, offset: 0)
      await client.close()
    }

    do {
      let (channel, _, stream) = try await partiallyConsumedStream()
      await channel.feed(header(type: 99, flags: 0, streamID: 0, length: 0))
      await channel.waitUntilClosed()
      await assertReadBuffer(stream, storageCount: 0, offset: 0)
    }

    do {
      let (_, client, stream) = try await partiallyConsumedStream()
      await client.close()
      await assertReadBuffer(stream, storageCount: 0, offset: 0)
    }
  }

  func testLimitValidation() throws {
    XCTAssertThrowsError(try YamuxLimits(maxActiveStreams: 1, maxInboundStreams: 2).validate())
    XCTAssertThrowsError(
      try YamuxLimits(maxFrameBytes: 4096, preferredOutboundFrameBytes: 8192).validate()
    )
    XCTAssertNoThrow(
      try YamuxLimits(
        preferredOutboundFrameBytes: 64 * 1024,
        maxStreamWriteQueueBytes: 32 * 1024
      ).validate()
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
    XCTAssertEqual(error?.code, .muxFailed)
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

  private func partiallyConsumedStream() async throws -> (
    InMemoryYamuxChannel, FlowersecYamuxClient, FlowersecYamuxStream
  ) {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()
    _ = await channel.nextWrittenFrame()
    let payload = Data(repeating: 0x61, count: 48 * 1024)
    var incoming = header(type: 0, flags: 0, streamID: 1, length: UInt32(payload.count))
    incoming.append(payload)
    await channel.feed(incoming)
    _ = try await stream.readExact(16 * 1024)
    return (channel, client, stream)
  }

  private func assertReadBuffer(
    _ stream: FlowersecYamuxStream,
    storageCount: Int,
    offset: Int,
    file: StaticString = #filePath,
    line: UInt = #line
  ) async {
    let actualStorageCount = await stream.bufferedReadStorageCount
    let actualOffset = await stream.bufferedReadOffset
    XCTAssertEqual(actualStorageCount, storageCount, file: file, line: line)
    XCTAssertEqual(actualOffset, offset, file: file, line: line)
  }
}

private actor GatedYamuxWrite: FlowersecYamuxChannel {
  let wire: InMemoryYamuxChannel
  let target: Data
  let entered: XCTestExpectation
  private var gate: CheckedContinuation<Void, Never>?
  private(set) var writeExited = false

  init(wire: InMemoryYamuxChannel, target: Data, entered: XCTestExpectation) {
    self.wire = wire
    self.target = target
    self.entered = entered
  }

  func write(_ data: Data) async throws {
    guard data == target else { try await wire.write(data); return }
    await withCheckedContinuation { gate = $0; entered.fulfill() }
    writeExited = true
    throw POSIXError(.ENOTCONN)
  }

  func readExact(_ length: Int) async throws -> Data { try await wire.readExact(length) }
  func close() async { await wire.close() }
  func release() { gate?.resume(); gate = nil }
}

private actor ClosingYamuxChannel: FlowersecYamuxChannel {
  let readStarted: XCTestExpectation
  let closeStarted: XCTestExpectation
  private var readGate: CheckedContinuation<Void, Never>?
  private var closeGate: CheckedContinuation<Void, Never>?
  private var readExited = false
  private var closeExited = false
  private(set) var closeCount = 0
  private var reportedEarlyReturn = false

  func checkCompletion(_ earlyReturn: XCTestExpectation) {
    if !(readExited && closeExited) && !reportedEarlyReturn {
      reportedEarlyReturn = true
      earlyReturn.fulfill()
    }
  }

  init(readStarted: XCTestExpectation, closeStarted: XCTestExpectation) {
    self.readStarted = readStarted
    self.closeStarted = closeStarted
  }

  func write(_ data: Data) async throws {}

  func readExact(_ length: Int) async throws -> Data {
    await withCheckedContinuation { readGate = $0; readStarted.fulfill() }
    readExited = true
    throw POSIXError(.ENOTCONN)
  }

  func close() async {
    closeCount += 1
    await withCheckedContinuation { closeGate = $0; closeStarted.fulfill() }
    closeExited = true
  }

  func allowClose() { closeGate?.resume(); closeGate = nil }
  func allowReadExit() { readGate?.resume(); readGate = nil }
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

private final class PendingRPCStream: FlowersecRPCStream, @unchecked Sendable {
  func write(_ data: Data) async throws { _ = data }
  func readExact(_ length: Int) async throws -> Data {
    _ = length
    try await Task.sleep(for: .seconds(30))
    return Data()
  }
  func close() async {}
  func reset() async throws {}
}

private actor NoopBinaryTransport: FlowersecBinaryTransport {
  func writeBinary(_ data: Data) async throws { _ = data }
  func readBinary() async throws -> Data { Data() }
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
    guard incoming.count >= length else { throw FlowersecError.closed() }
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
