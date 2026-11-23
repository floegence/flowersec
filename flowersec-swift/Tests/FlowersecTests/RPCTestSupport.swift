import Foundation

@testable import Flowersec

final class InMemoryRPCStream: FlowersecRPCStream, @unchecked Sendable {
  private let state = InMemoryRPCStreamState()

  func write(_ data: Data) async throws {
    await state.write(data)
  }

  func readExact(_ length: Int) async throws -> Data {
    await state.readExact(length)
  }

  func close() async {
    await state.close()
  }

  func reset() async throws {
    await state.close()
  }

  func pushEnvelope(_ envelope: RPCEnvelope) async throws {
    try await pushFrame(envelope.encoded())
  }

  func pushRawFrame(_ payload: Data) async throws {
    try await pushFrame(payload)
  }

  func nextWrittenEnvelope() async throws -> RPCEnvelope {
    let frame = await state.nextWrittenFrame()
    let length = Int(frame.prefix(4).readUInt32BE(at: 0))
    return try RPCEnvelope(data: Data(frame.dropFirst(4).prefix(length)))
  }

  private func pushFrame(_ payload: Data) async throws {
    var frame = Data()
    frame.appendUInt32BE(UInt32(payload.count))
    frame.append(payload)
    await state.pushFrame(frame)
  }
}

private actor InMemoryRPCStreamState {
  private var inbound = Data()
  private var writes: [Data] = []
  private var closed = false
  private var inboundWaiters: [CheckedContinuation<Void, Never>] = []
  private var writeWaiters: [CheckedContinuation<Void, Never>] = []

  func write(_ data: Data) {
    writes.append(data)
    let waiters = writeWaiters
    writeWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }

  func readExact(_ length: Int) async -> Data {
    while true {
      if inbound.count >= length {
        let out = Data(inbound.prefix(length))
        inbound.removeFirst(length)
        return out
      }
      if closed {
        return Data()
      }
      await waitForInbound()
    }
  }

  func close() {
    closed = true
    resumeInboundWaiters()
    resumeWriteWaiters()
  }

  func pushFrame(_ frame: Data) {
    inbound.append(frame)
    resumeInboundWaiters()
  }

  func nextWrittenFrame() async -> Data {
    while true {
      if !writes.isEmpty {
        return writes.removeFirst()
      }
      await waitForWrite()
    }
  }

  private func waitForInbound() async {
    await withCheckedContinuation { continuation in
      inboundWaiters.append(continuation)
    }
  }

  private func waitForWrite() async {
    await withCheckedContinuation { continuation in
      writeWaiters.append(continuation)
    }
  }

  private func resumeInboundWaiters() {
    let waiters = inboundWaiters
    inboundWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }

  private func resumeWriteWaiters() {
    let waiters = writeWaiters
    writeWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }
}

final class InMemoryByteStream: FlowersecByteStream, @unchecked Sendable {
  private let state = InMemoryByteStreamState()

  func write(_ data: Data) async throws {
    await state.write(data)
  }

  func readExact(_ length: Int) async throws -> Data {
    await state.readExact(length)
  }

  func close() async {
    await state.close()
  }

  func reset() async throws {
    await state.close()
  }

  func nextWrittenJSONFrame() async throws -> Data {
    let frame = await state.nextWrittenFrame()
    let length = Int(frame.prefix(4).readUInt32BE(at: 0))
    return Data(frame.dropFirst(4).prefix(length))
  }

  func pushJSONFrame(_ payload: Data) async throws {
    var frame = Data()
    frame.appendUInt32BE(UInt32(payload.count))
    frame.append(payload)
    await state.pushBytes(frame)
  }

  func pushBytes(_ data: Data) async {
    await state.pushBytes(data)
  }

  func waitForClose() async {
    await state.waitForClose()
  }

  func waitForReadWait() async {
    await state.waitForReadWait()
  }

  func finishInbound() async {
    await state.finishInbound()
  }

  func closeCallCount() async -> Int {
    await state.closeCallCount()
  }
}

private actor InMemoryByteStreamState {
  private var inbound = Data()
  private var writes: [Data] = []
  private var inboundFinished = false
  private var readWaitCount = 0
  private var closeCount = 0
  private var inboundWaiters: [CheckedContinuation<Void, Never>] = []
  private var writeWaiters: [CheckedContinuation<Void, Never>] = []
  private var closeWaiters: [CheckedContinuation<Void, Never>] = []
  private var readWaiters: [CheckedContinuation<Void, Never>] = []

  func write(_ data: Data) {
    writes.append(data)
    let waiters = writeWaiters
    writeWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }

  func readExact(_ length: Int) async -> Data {
    while true {
      if inbound.count >= length {
        let out = Data(inbound.prefix(length))
        inbound.removeFirst(length)
        return out
      }
      if inboundFinished {
        return Data()
      }
      readWaitCount += 1
      resumeReadWaiters()
      await waitForInbound()
    }
  }

  func close() {
    inboundFinished = true
    closeCount += 1
    resumeInboundWaiters()
    resumeCloseWaiters()
  }

  func pushBytes(_ data: Data) {
    inbound.append(data)
    resumeInboundWaiters()
  }

  func finishInbound() {
    inboundFinished = true
    resumeInboundWaiters()
  }

  func nextWrittenFrame() async -> Data {
    while true {
      if !writes.isEmpty {
        return writes.removeFirst()
      }
      await waitForWrite()
    }
  }

  func waitForClose() async {
    if closeCount > 0 { return }
    await withCheckedContinuation { continuation in
      closeWaiters.append(continuation)
    }
  }

  func waitForReadWait() async {
    if readWaitCount > 0 { return }
    await withCheckedContinuation { continuation in
      readWaiters.append(continuation)
    }
  }

  func closeCallCount() -> Int {
    closeCount
  }

  private func waitForInbound() async {
    await withCheckedContinuation { continuation in
      inboundWaiters.append(continuation)
    }
  }

  private func waitForWrite() async {
    await withCheckedContinuation { continuation in
      writeWaiters.append(continuation)
    }
  }

  private func resumeInboundWaiters() {
    let waiters = inboundWaiters
    inboundWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }

  private func resumeCloseWaiters() {
    let waiters = closeWaiters
    closeWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }

  private func resumeReadWaiters() {
    let waiters = readWaiters
    readWaiters.removeAll()
    for waiter in waiters {
      waiter.resume()
    }
  }
}

extension JSONEncoder {
  static var flowersecRPCTest: JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }
}
