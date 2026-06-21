import Foundation

actor FlowersecYamuxClient {
  private let channel: any FlowersecYamuxChannel
  private var nextStreamID: UInt32 = 1
  private var streams: [UInt32: FlowersecYamuxStream] = [:]
  private var readerTask: Task<Void, Never>?
  private var closed = false

  init(channel: any FlowersecYamuxChannel) {
    self.channel = channel
  }

  func openStream() async throws -> FlowersecYamuxStream {
    guard !closed else { throw FlowersecError.closed }
    let streamID = nextStreamID
    nextStreamID += 2
    let stream = FlowersecYamuxStream(id: streamID, session: self)
    streams[streamID] = stream
    if readerTask == nil {
      readerTask = Task { await self.readLoop() }
    }
    try await writeFrame(
      FlowersecYamuxFrame(
        type: FlowersecYamuxConstants.typeWindowUpdate,
        flags: FlowersecYamuxConstants.flagSYN,
        streamID: streamID,
        length: FlowersecYamuxConstants.initialStreamWindow,
        payload: Data()
      )
    )
    return stream
  }

  func close() async {
    closed = true
    readerTask?.cancel()
    readerTask = nil
    for stream in streams.values {
      await stream.closeFromSession()
    }
    streams.removeAll()
    await channel.close()
  }

  fileprivate func writeData(streamID: UInt32, data: Data) async throws {
    guard !closed else { throw FlowersecError.closed }
    var offset = 0
    while offset < data.count {
      let remaining = data.count - offset
      let chunkSize = min(remaining, Int(FlowersecYamuxConstants.maxDataFrameBytes))
      let chunk = data.subdata(in: offset..<(offset + chunkSize))
      try await writeFrame(
        FlowersecYamuxFrame(
          type: FlowersecYamuxConstants.typeData,
          flags: 0,
          streamID: streamID,
          length: UInt32(chunk.count),
          payload: chunk
        )
      )
      offset += chunkSize
    }
  }

  fileprivate func sendWindowUpdate(streamID: UInt32, bytes: UInt32) async throws {
    guard bytes > 0 else { return }
    try await writeFrame(
      FlowersecYamuxFrame(
        type: FlowersecYamuxConstants.typeWindowUpdate,
        flags: 0,
        streamID: streamID,
        length: bytes,
        payload: Data()
      )
    )
  }

  fileprivate func closeStream(streamID: UInt32) async {
    guard streams.removeValue(forKey: streamID) != nil else { return }
    do {
      try await writeFrame(
        FlowersecYamuxFrame(
          type: FlowersecYamuxConstants.typeWindowUpdate,
          flags: FlowersecYamuxConstants.flagFIN,
          streamID: streamID,
          length: 0,
          payload: Data()
        )
      )
    } catch {}
  }

  private func readLoop() async {
    do {
      while !Task.isCancelled && !closed {
        let frame = try await readFrame()
        try await handle(frame)
      }
    } catch {
      closed = true
      for stream in streams.values {
        await stream.fail(error)
      }
      streams.removeAll()
      await channel.close()
    }
  }

  private func handle(_ frame: FlowersecYamuxFrame) async throws {
    switch frame.type {
    case FlowersecYamuxConstants.typeData:
      try await handleDataFrame(frame)
    case FlowersecYamuxConstants.typeWindowUpdate:
      try await handleWindowUpdateFrame(frame)
    case FlowersecYamuxConstants.typePing:
      try await handlePingFrame(frame)
    case FlowersecYamuxConstants.typeGoAway:
      throw FlowersecError.invalidYamux("The peer closed the yamux session.")
    default:
      throw FlowersecError.invalidYamux("Unsupported yamux frame type.")
    }
  }

  private func handleDataFrame(_ frame: FlowersecYamuxFrame) async throws {
    guard let stream = streams[frame.streamID] else { return }
    guard await applyStreamFlags(frame, stream: stream) else { return }
    if !frame.payload.isEmpty {
      await stream.receive(frame.payload)
    }
  }

  private func handleWindowUpdateFrame(_ frame: FlowersecYamuxFrame) async throws {
    guard let stream = streams[frame.streamID] else { return }
    guard await applyStreamFlags(frame, stream: stream) else { return }
    if frame.length > 0 {
      await stream.increaseSendWindow(frame.length)
    }
  }

  private func applyStreamFlags(
    _ frame: FlowersecYamuxFrame,
    stream: FlowersecYamuxStream
  ) async -> Bool {
    if frame.flags & FlowersecYamuxConstants.flagRST != 0 {
      await stream.fail(FlowersecError.invalidYamux("The peer reset the stream."))
      streams.removeValue(forKey: frame.streamID)
      return false
    }
    if frame.flags & FlowersecYamuxConstants.flagACK != 0 {
      await stream.markEstablished()
    }
    if frame.flags & FlowersecYamuxConstants.flagFIN != 0 {
      await stream.finishRemote()
      if await stream.isLocallyClosed {
        streams.removeValue(forKey: frame.streamID)
      }
    }
    return true
  }

  private func handlePingFrame(_ frame: FlowersecYamuxFrame) async throws {
    guard frame.flags & FlowersecYamuxConstants.flagSYN != 0 else { return }
    try await writeFrame(
      FlowersecYamuxFrame(
        type: FlowersecYamuxConstants.typePing,
        flags: FlowersecYamuxConstants.flagACK,
        streamID: 0,
        length: frame.length,
        payload: Data()
      )
    )
  }

  private func readFrame() async throws -> FlowersecYamuxFrame {
    let header = try await channel.readExact(FlowersecYamuxConstants.headerSize)
    let frame = try FlowersecYamuxFrame(header: header)
    let payload: Data
    if frame.type == FlowersecYamuxConstants.typeData, frame.length > 0 {
      payload = try await channel.readExact(Int(frame.length))
    } else {
      payload = Data()
    }
    return FlowersecYamuxFrame(
      type: frame.type,
      flags: frame.flags,
      streamID: frame.streamID,
      length: frame.length,
      payload: payload
    )
  }

  private func writeFrame(_ frame: FlowersecYamuxFrame) async throws {
    var data = frame.encodedHeader()
    data.append(frame.payload)
    try await channel.write(data)
  }
}

actor FlowersecYamuxStream: FlowersecRPCStream, FlowersecByteStream {
  let id: UInt32
  private weak var session: FlowersecYamuxClient?
  private var readBuffer = Data()
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var windowWaiters: [CheckedContinuation<Void, Error>] = []
  private var sendWindow = FlowersecYamuxConstants.initialStreamWindow
  private var established = false
  private var remoteFinished = false
  private var closed = false
  private var failure: Error?

  init(id: UInt32, session: FlowersecYamuxClient) {
    self.id = id
    self.session = session
  }

  func write(_ data: Data) async throws {
    guard !closed else { throw FlowersecError.closed }
    guard let session else { throw FlowersecError.closed }
    var offset = 0
    while offset < data.count {
      while sendWindow == 0 {
        try await waitForWindow()
      }
      let available = min(
        data.count - offset,
        Int(sendWindow),
        Int(FlowersecYamuxConstants.maxDataFrameBytes)
      )
      let chunk = data.subdata(in: offset..<(offset + available))
      try await session.writeData(streamID: id, data: chunk)
      sendWindow -= UInt32(available)
      offset += available
    }
  }

  func readExact(_ length: Int) async throws -> Data {
    guard length >= 0 else {
      throw FlowersecError.invalidYamux("Negative stream read length.")
    }
    while readBuffer.count < length {
      if let failure {
        throw failure
      }
      if remoteFinished {
        throw FlowersecError.closed
      }
      let chunk = try await waitForData()
      readBuffer.append(chunk)
    }
    let out = Data(readBuffer.prefix(length))
    readBuffer.removeFirst(length)
    try await session?.sendWindowUpdate(streamID: id, bytes: UInt32(out.count))
    return out
  }

  func close() async {
    guard !closed else { return }
    closed = true
    resumeWaiters(error: FlowersecError.closed)
    resumeWindowWaiters(error: FlowersecError.closed)
    await session?.closeStream(streamID: id)
  }

  fileprivate func receive(_ data: Data) {
    guard !closed, !data.isEmpty else { return }
    if let waiter = waiters.first {
      waiters.removeFirst()
      waiter.resume(returning: data)
    } else {
      readBuffer.append(data)
    }
  }

  fileprivate func increaseSendWindow(_ delta: UInt32) {
    sendWindow = min(UInt32.max, sendWindow &+ delta)
    resumeWindowWaiters()
  }

  fileprivate func markEstablished() {
    established = true
  }

  fileprivate func finishRemote() {
    remoteFinished = true
    resumeWaiters(error: FlowersecError.closed)
  }

  fileprivate func fail(_ error: Error) {
    failure = error
    resumeWaiters(error: error)
    resumeWindowWaiters(error: error)
  }

  fileprivate func closeFromSession() {
    closed = true
    resumeWaiters(error: FlowersecError.closed)
    resumeWindowWaiters(error: FlowersecError.closed)
  }

  fileprivate var isLocallyClosed: Bool {
    closed
  }

  private func waitForData() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      waiters.append(continuation)
    }
  }

  private func waitForWindow() async throws {
    if let failure {
      throw failure
    }
    guard !closed else { throw FlowersecError.closed }
    try await withCheckedThrowingContinuation { continuation in
      windowWaiters.append(continuation)
    }
  }

  private func resumeWaiters(error: Error) {
    let current = waiters
    waiters.removeAll()
    for waiter in current {
      waiter.resume(throwing: error)
    }
  }

  private func resumeWindowWaiters(error: Error? = nil) {
    let current = windowWaiters
    windowWaiters.removeAll()
    for waiter in current {
      if let error {
        waiter.resume(throwing: error)
      } else {
        waiter.resume()
      }
    }
  }
}

private enum FlowersecYamuxConstants {
  static let version: UInt8 = 0
  static let typeData: UInt8 = 0
  static let typeWindowUpdate: UInt8 = 1
  static let typePing: UInt8 = 2
  static let typeGoAway: UInt8 = 3
  static let flagSYN: UInt16 = 1
  static let flagACK: UInt16 = 2
  static let flagFIN: UInt16 = 4
  static let flagRST: UInt16 = 8
  static let headerSize = 12
  static let initialStreamWindow: UInt32 = 256 * 1024
  static let maxDataFrameBytes: UInt32 = 64 * 1024
}

private struct FlowersecYamuxFrame {
  var type: UInt8
  var flags: UInt16
  var streamID: UInt32
  var length: UInt32
  var payload: Data

  init(type: UInt8, flags: UInt16, streamID: UInt32, length: UInt32, payload: Data) {
    self.type = type
    self.flags = flags
    self.streamID = streamID
    self.length = length
    self.payload = payload
  }

  init(header: Data) throws {
    guard header.count == FlowersecYamuxConstants.headerSize else {
      throw FlowersecError.invalidYamux("Yamux frame header length is invalid.")
    }
    guard header[0] == FlowersecYamuxConstants.version else {
      throw FlowersecError.invalidYamux("Yamux frame version is invalid.")
    }
    let type = header[1]
    guard type <= FlowersecYamuxConstants.typeGoAway else {
      throw FlowersecError.invalidYamux("Yamux frame type is invalid.")
    }
    self.type = type
    flags = header.readUInt16BE(at: 2)
    streamID = header.readUInt32BE(at: 4)
    length = header.readUInt32BE(at: 8)
    payload = Data()
  }

  func encodedHeader() -> Data {
    var data = Data()
    data.append(FlowersecYamuxConstants.version)
    data.append(type)
    data.appendUInt16BE(flags)
    data.appendUInt32BE(streamID)
    data.appendUInt32BE(length)
    return data
  }
}
