import Foundation
import XCTest

@testable import Flowersec

final class FlowersecYamuxTests: XCTestCase {
  func testStreamCloseWritesFinAndRemovesStream() async throws {
    let channel = InMemoryYamuxChannel()
    let client = FlowersecYamuxClient(channel: channel)
    let stream = try await client.openStream()

    let syn = await channel.nextWrittenFrame()
    XCTAssertEqual(syn[1], 1)
    XCTAssertEqual(syn.readUInt16BE(at: 2), 1)
    XCTAssertEqual(syn.readUInt32BE(at: 4), 1)

    await stream.close()

    let fin = await channel.nextWrittenFrame()
    XCTAssertEqual(fin[1], 1)
    XCTAssertEqual(fin.readUInt16BE(at: 2), 4)
    XCTAssertEqual(fin.readUInt32BE(at: 4), 1)
    XCTAssertEqual(fin.readUInt32BE(at: 8), 0)
    await client.close()
  }
}

private final class InMemoryYamuxChannel: FlowersecYamuxChannel, @unchecked Sendable {
  private let state = InMemoryYamuxChannelState()

  func write(_ data: Data) async throws {
    await state.write(data)
  }

  func readExact(_ length: Int) async throws -> Data {
    try await state.readExact(length)
  }

  func close() async {
    await state.close()
  }

  func nextWrittenFrame() async -> Data {
    await state.nextWrittenFrame()
  }
}

private actor InMemoryYamuxChannelState {
  private var writes: [Data] = []
  private var closed = false
  private var readWaiters: [CheckedContinuation<Void, Never>] = []
  private var writeWaiters: [CheckedContinuation<Void, Never>] = []

  func write(_ data: Data) {
    writes.append(data)
    resumeWriteWaiters()
  }

  func readExact(_: Int) async throws -> Data {
    while !closed {
      await waitForRead()
    }
    throw FlowersecError.closed
  }

  func close() {
    closed = true
    resumeReadWaiters()
    resumeWriteWaiters()
  }

  func nextWrittenFrame() async -> Data {
    while writes.isEmpty && !closed {
      await waitForWrite()
    }
    return writes.removeFirst()
  }

  private func waitForWrite() async {
    await withCheckedContinuation { continuation in
      writeWaiters.append(continuation)
    }
  }

  private func waitForRead() async {
    await withCheckedContinuation { continuation in
      readWaiters.append(continuation)
    }
  }

  private func resumeReadWaiters() {
    let current = readWaiters
    readWaiters.removeAll()
    for waiter in current {
      waiter.resume()
    }
  }

  private func resumeWriteWaiters() {
    let current = writeWaiters
    writeWaiters.removeAll()
    for waiter in current {
      waiter.resume()
    }
  }
}
