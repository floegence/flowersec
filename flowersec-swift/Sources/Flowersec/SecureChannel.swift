import Foundation

protocol FlowersecYamuxChannel: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
}

actor FlowersecSecureChannel: FlowersecYamuxChannel {
  private let transport: FlowersecWebSocketBinaryTransport
  private var keys: FlowersecRecordKeyState
  private var readBuffer = Data()
  private var closed = false

  init(transport: FlowersecWebSocketBinaryTransport, keys: FlowersecRecordKeyState) {
    self.transport = transport
    self.keys = keys
  }

  func write(_ data: Data) async throws {
    guard !closed else { throw FlowersecError.closed }
    let maxPlaintext = max(1, FlowersecWire.maxRecordBytes - 18 - 16)
    var offset = 0
    while offset < data.count {
      let end = min(data.count, offset + maxPlaintext)
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
    closed = true
    await transport.close()
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
