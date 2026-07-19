import Foundation

protocol FlowersecYamuxChannel: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
}

actor FlowersecSecureChannel: FlowersecYamuxChannel {
  private enum PendingOperation {
    case application(Data)
    case rekey

    var byteCount: Int {
      switch self {
      case .application(let data): data.count
      case .rekey: 0
      }
    }
  }

  private struct PendingWrite {
    var id: UInt64
    var operation: PendingOperation
    var cancellation: PendingWriteCancellation
    var continuation: CheckedContinuation<Void, Error>
  }

  private final class PendingWriteCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var canceled = false
    private var completed = false

    func cancel() {
      lock.lock()
      if !completed {
        canceled = true
      }
      lock.unlock()
    }

    func completeWrite() -> Bool {
      lock.lock()
      defer { lock.unlock() }
      completed = true
      return canceled
    }

    var isCanceled: Bool {
      lock.lock()
      defer { lock.unlock() }
      return canceled
    }
  }

  private let transport: any FlowersecBinaryTransport
  private var keys: FlowersecRecordKeyState
  private var readBuffer = Data()
  private var pendingWrites: [PendingWrite] = []
  private var nextPendingWriteID: UInt64 = 1
  private var activeWriteID: UInt64?
  private var pendingWriteBytes = 0
  private var writeInProgress = false
  private var closed = false
  private let outboundRecordChunkBytes: Int
  private let maxOutboundBufferedBytes: Int
  private let path: FlowersecPath
  private let onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?

  init(
    transport: any FlowersecBinaryTransport,
    keys: FlowersecRecordKeyState,
    outboundRecordChunkBytes: Int = FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes,
    maxOutboundBufferedBytes: Int = FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes,
    path: FlowersecPath = .direct,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil
  ) {
    self.transport = transport
    self.keys = keys
    self.outboundRecordChunkBytes = outboundRecordChunkBytes
    self.maxOutboundBufferedBytes = maxOutboundBufferedBytes
    self.path = path
    self.onDiagnosticEvent = onDiagnosticEvent
  }

  func write(_ data: Data) async throws {
    try Task.checkCancellation()
    guard !closed else { throw FlowersecError.closed(path: path) }
    let availableBytes =
      maxOutboundBufferedBytes > pendingWriteBytes
      ? maxOutboundBufferedBytes - pendingWriteBytes : 0
    guard maxOutboundBufferedBytes > 0, data.count <= availableBytes else {
      let (currentBytes, overflow) = pendingWriteBytes.addingReportingOverflow(data.count)
      let current = overflow ? Int.max : currentBytes
      onDiagnosticEvent?(
        DiagnosticEvent(
          path: path,
          stage: .secure,
          codeDomain: .event,
          code: "resource_limit_reached",
          result: .fail,
          resource: "secure_channel_pending_write_bytes",
          current: current,
          limit: maxOutboundBufferedBytes
        )
      )
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .secure,
        "The secure-channel pending write limit was reached."
      )
    }
    pendingWriteBytes += data.count
    try await enqueue(.application(data))
  }

  func rekey() async throws {
    try Task.checkCancellation()
    guard !closed else { throw FlowersecError.closed(path: path) }
    try await enqueue(.rekey)
  }

  var queuedWriteCount: Int { pendingWrites.count }
  var queuedWriteBytes: Int { pendingWriteBytes }
  var keyMaterialIsCleared: Bool { keys.keyMaterialIsCleared }

  private func writeRecords(_ data: Data) async throws {
    var offset = 0
    while offset < data.count {
      guard !closed else { throw FlowersecError.closed(path: path) }
      let end = min(data.count, offset + outboundRecordChunkBytes)
      let chunk = data.subdata(in: offset..<end)
      try await writeRecord(chunk)
      offset = end
    }
  }

  func readExact(_ length: Int) async throws -> Data {
    guard length >= 0 else {
      throw FlowersecError.invalidRecord("Negative read length.", path: path)
    }
    do {
      while readBuffer.count < length {
        try await receiveNextApplicationRecord()
      }
    } catch {
      await terminateAfterReadFailure(error)
      throw error
    }
    let out = readBuffer.prefix(length)
    readBuffer.removeFirst(length)
    return Data(out)
  }

  func close() async {
    guard !closed else { return }
    closed = true
    keys.clearKeyMaterial()
    failPendingWrites(with: FlowersecError.closed(path: path))
    await transport.close()
  }

  private func startWriteIfNeeded() {
    guard !closed, !writeInProgress else { return }
    while let write = pendingWrites.first, write.cancellation.isCanceled {
      pendingWrites.removeFirst()
      pendingWriteBytes -= write.operation.byteCount
      write.continuation.resume(throwing: CancellationError())
    }
    guard let write = pendingWrites.first else { return }
    writeInProgress = true
    activeWriteID = write.id
    Task {
      do {
        switch write.operation {
        case .application(let data): try await writeRecords(data)
        case .rekey: try await writeRekeyRecord()
        }
        finishWrite(writeID: write.id, result: .success(()))
      } catch {
        finishWrite(writeID: write.id, result: .failure(error))
      }
    }
  }

  private func finishWrite(writeID: UInt64, result: Result<Void, Error>) {
    guard pendingWrites.first?.id == writeID else {
      writeInProgress = false
      activeWriteID = nil
      return
    }
    let write = pendingWrites.removeFirst()
    pendingWriteBytes -= write.operation.byteCount
    writeInProgress = false
    activeWriteID = nil
    let callerCanceled = write.cancellation.completeWrite()
    switch result {
    case .success:
      if callerCanceled {
        write.continuation.resume(throwing: CancellationError())
      } else {
        write.continuation.resume()
      }
      startWriteIfNeeded()
    case .failure(let error):
      closed = true
      keys.clearKeyMaterial()
      write.continuation.resume(throwing: error)
      failPendingWrites(with: error)
      Task { await transport.close() }
    }
  }

  private func failPendingWrites(with error: Error) {
    let writes = pendingWrites
    pendingWrites.removeAll()
    pendingWriteBytes = 0
    writeInProgress = false
    activeWriteID = nil
    for write in writes {
      write.continuation.resume(throwing: error)
    }
  }

  private func terminateAfterReadFailure(_ error: Error) async {
    guard !closed else { return }
    closed = true
    keys.clearKeyMaterial()
    failPendingWrites(with: error)
    await transport.close()
  }

  private func enqueue(_ operation: PendingOperation) async throws {
    let writeID = nextPendingWriteID
    nextPendingWriteID += 1
    let cancellation = PendingWriteCancellation()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        if Task.isCancelled {
          cancellation.cancel()
          pendingWriteBytes -= operation.byteCount
          continuation.resume(throwing: CancellationError())
          return
        }
        pendingWrites.append(
          PendingWrite(
            id: writeID,
            operation: operation,
            cancellation: cancellation,
            continuation: continuation
          )
        )
        startWriteIfNeeded()
      }
    } onCancel: {
      cancellation.cancel()
      Task { await self.cancelPendingWrite(writeID) }
    }
  }

  private func cancelPendingWrite(_ writeID: UInt64) {
    guard activeWriteID != writeID,
      let index = pendingWrites.firstIndex(where: { $0.id == writeID })
    else { return }
    let write = pendingWrites.remove(at: index)
    pendingWriteBytes -= write.operation.byteCount
    write.continuation.resume(throwing: CancellationError())
  }

  private func writeRecord(_ plaintext: Data) async throws {
    do {
      let seq = keys.sendSeq
      keys.sendSeq += 1
      let frame = try FlowersecRecordCodec.encrypt(
        key: keys.sendKey,
        noncePrefix: keys.sendNoncePrefix,
        flags: 0,
        seq: seq,
        plaintext: plaintext
      )
      try await transport.writeBinary(frame)
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
  }

  private func writeRekeyRecord() async throws {
    do {
      let seq = keys.sendSeq
      keys.sendSeq += 1
      let frame = try FlowersecRecordCodec.encrypt(
        key: keys.sendKey,
        noncePrefix: keys.sendNoncePrefix,
        flags: 2,
        seq: seq,
        plaintext: Data()
      )
      try await transport.writeBinary(frame)
      guard !closed else { throw FlowersecError.closed(path: path) }
      keys.sendKey = try FlowersecRecordCodec.deriveRekeyKey(
        rekeyBase: keys.rekeyBase,
        transcript: keys.transcript,
        seq: seq,
        direction: keys.sendDirection
      )
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
  }

  private func receiveNextApplicationRecord() async throws {
    guard !closed else { throw FlowersecError.closed(path: path) }
    let record = try await readRecord()
    switch record.flags {
    case 0:
      readBuffer.append(record.plaintext)
    case 1:
      break
    case 2:
      try applyRekey(record)
    default:
      throw FlowersecError.invalidRecord("Unsupported record flag.", path: path)
    }
  }

  private func readRecord() async throws -> FlowersecRecord {
    do {
      let frame = try await transport.readBinary()
      guard !closed else { throw FlowersecError.closed(path: path) }
      let record = try FlowersecRecordCodec.decrypt(
        key: keys.recvKey,
        noncePrefix: keys.recvNoncePrefix,
        frame: frame,
        expectedSeq: keys.recvSeq
      )
      keys.recvSeq += 1
      return record
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
  }

  private func applyRekey(_ record: FlowersecRecord) throws {
    do {
      keys.recvKey = try FlowersecRecordCodec.deriveRekeyKey(
        rekeyBase: keys.rekeyBase,
        transcript: keys.transcript,
        seq: record.seq,
        direction: keys.recvDirection
      )
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
  }
}
