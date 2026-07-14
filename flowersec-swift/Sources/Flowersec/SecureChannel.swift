import Foundation

protocol FlowersecYamuxChannel: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
}

actor FlowersecSecureChannel: FlowersecYamuxChannel {
  private struct PendingWrite {
    var data: Data
    var continuation: CheckedContinuation<Void, Error>
  }

  private let transport: any FlowersecBinaryTransport
  private var keys: FlowersecRecordKeyState
  private var readBuffer = Data()
  private var pendingWrites: [PendingWrite] = []
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
    outboundRecordChunkBytes: Int = 64 * 1024,
    maxOutboundBufferedBytes: Int = 4 * 1024 * 1024,
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
    guard !closed else { throw FlowersecError.closed }
    let availableBytes = maxOutboundBufferedBytes > pendingWriteBytes
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
    try await withCheckedThrowingContinuation { continuation in
      pendingWrites.append(PendingWrite(data: data, continuation: continuation))
      startWriteIfNeeded()
    }
  }

  var queuedWriteCount: Int { pendingWrites.count }
  var queuedWriteBytes: Int { pendingWriteBytes }

  private func writeRecords(_ data: Data) async throws {
    var offset = 0
    while offset < data.count {
      guard !closed else { throw FlowersecError.closed }
      let end = min(data.count, offset + outboundRecordChunkBytes)
      let chunk = data.subdata(in: offset..<end)
      try await writeRecord(chunk)
      offset = end
    }
  }

  func readExact(_ length: Int) async throws -> Data {
    guard length >= 0 else {
      throw FlowersecError.invalidRecord("Negative read length.")
    }
    while readBuffer.count < length {
      try await receiveNextApplicationRecord()
    }
    let out = readBuffer.prefix(length)
    readBuffer.removeFirst(length)
    return Data(out)
  }

  func close() async {
    guard !closed else { return }
    closed = true
    failPendingWrites(with: FlowersecError.closed)
    await transport.close()
  }

  private func startWriteIfNeeded() {
    guard !closed, !writeInProgress, let write = pendingWrites.first else { return }
    writeInProgress = true
    Task {
      do {
        try await writeRecords(write.data)
        finishWrite(result: .success(()))
      } catch {
        finishWrite(result: .failure(error))
      }
    }
  }

  private func finishWrite(result: Result<Void, Error>) {
    guard !pendingWrites.isEmpty else {
      writeInProgress = false
      return
    }
    let write = pendingWrites.removeFirst()
    pendingWriteBytes -= write.data.count
    writeInProgress = false
    switch result {
    case .success:
      write.continuation.resume()
      startWriteIfNeeded()
    case .failure(let error):
      closed = true
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
    for write in writes {
      write.continuation.resume(throwing: error)
    }
  }

  private func writeRecord(_ plaintext: Data) async throws {
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
  }

  private func receiveNextApplicationRecord() async throws {
    guard !closed else { throw FlowersecError.closed }
    let record = try await readRecord()
    switch record.flags {
    case 0:
      readBuffer.append(record.plaintext)
    case 1:
      break
    case 2:
      try applyRekey(record)
    default:
      throw FlowersecError.invalidRecord("Unsupported record flag.")
    }
  }

  private func readRecord() async throws -> FlowersecRecord {
    let frame = try await transport.readBinary()
    let record = try FlowersecRecordCodec.decrypt(
      key: keys.recvKey,
      noncePrefix: keys.recvNoncePrefix,
      frame: frame,
      expectedSeq: keys.recvSeq
    )
    keys.recvSeq += 1
    return record
  }

  private func applyRekey(_ record: FlowersecRecord) throws {
    keys.recvKey = try FlowersecRecordCodec.deriveRekeyKey(
      rekeyBase: keys.rekeyBase,
      transcript: keys.transcript,
      seq: record.seq,
      direction: keys.recvDirection
    )
  }
}
