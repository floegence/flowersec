import Foundation

public struct YamuxLimits: Equatable, Sendable {
  public var maxActiveStreams: Int
  public var maxInboundStreams: Int
  public var maxFrameBytes: Int
  public var preferredOutboundFrameBytes: Int
  public var maxStreamWriteQueueBytes: Int
  public var maxStreamReceiveBytes: Int
  public var maxSessionReceiveBytes: Int

  public init(
    maxActiveStreams: Int = FlowersecSDKDefaults.Yamux.maxActiveStreams,
    maxInboundStreams: Int = FlowersecSDKDefaults.Yamux.maxInboundStreams,
    maxFrameBytes: Int = FlowersecSDKDefaults.Yamux.maxFrameBytes,
    preferredOutboundFrameBytes: Int = FlowersecSDKDefaults.Yamux.preferredOutboundFrameBytes,
    maxStreamWriteQueueBytes: Int = FlowersecSDKDefaults.Yamux.maxStreamWriteQueueBytes,
    maxStreamReceiveBytes: Int = FlowersecSDKDefaults.Yamux.maxStreamReceiveBytes,
    maxSessionReceiveBytes: Int = FlowersecSDKDefaults.Yamux.maxSessionReceiveBytes
  ) {
    self.maxActiveStreams = maxActiveStreams
    self.maxInboundStreams = maxInboundStreams
    self.maxFrameBytes = maxFrameBytes
    self.preferredOutboundFrameBytes = preferredOutboundFrameBytes
    self.maxStreamWriteQueueBytes = maxStreamWriteQueueBytes
    self.maxStreamReceiveBytes = maxStreamReceiveBytes
    self.maxSessionReceiveBytes = maxSessionReceiveBytes
  }

  func validate() throws {
    guard maxActiveStreams > 0, maxInboundStreams > 0 else {
      throw FlowersecError.invalidConnectInfo("Yamux stream limits must be positive.")
    }
    guard maxInboundStreams <= maxActiveStreams else {
      throw FlowersecError.invalidConnectInfo(
        "Yamux maxInboundStreams must not exceed maxActiveStreams."
      )
    }
    guard maxFrameBytes >= 1024, preferredOutboundFrameBytes >= 1024 else {
      throw FlowersecError.invalidConnectInfo("Yamux frame limits must be at least 1024 bytes.")
    }
    guard preferredOutboundFrameBytes <= maxFrameBytes else {
      throw FlowersecError.invalidConnectInfo(
        "Yamux preferredOutboundFrameBytes must not exceed maxFrameBytes."
      )
    }
    guard maxFrameBytes <= maxStreamReceiveBytes else {
      throw FlowersecError.invalidConnectInfo(
        "Yamux maxFrameBytes must not exceed maxStreamReceiveBytes."
      )
    }
    guard maxStreamReceiveBytes >= Int(FlowersecYamuxConstants.initialStreamWindow) else {
      throw FlowersecError.invalidConnectInfo(
        "Yamux maxStreamReceiveBytes must cover the 256 KiB initial stream window."
      )
    }
    guard maxStreamReceiveBytes <= maxSessionReceiveBytes else {
      throw FlowersecError.invalidConnectInfo(
        "Yamux maxStreamReceiveBytes must not exceed maxSessionReceiveBytes."
      )
    }
    guard maxFrameBytes <= Int(UInt32.max), preferredOutboundFrameBytes <= Int(UInt32.max) else {
      throw FlowersecError.invalidConnectInfo("Yamux frame limits exceed the wire format.")
    }
  }
}

public enum LivenessOptions: Equatable, Sendable {
  case pathDefault
  case disabled
  case enabled(interval: Duration, timeout: Duration)
}

actor FlowersecYamuxClient {
  private struct PendingPing {
    var id: UInt32
    var startedAt: ContinuousClock.Instant
    var continuation: CheckedContinuation<Duration, Error>
    var timeoutTask: Task<Void, Never>
  }

  private let channel: any FlowersecYamuxChannel
  private let limits: YamuxLimits
  private let automaticLiveness: (interval: Duration, timeout: Duration)?
  private let path: FlowersecPath
  private let client: Bool
  private let onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
  private let clock = ContinuousClock()
  private var nextStreamID: UInt32
  private var nextPingID: UInt32 = 1
  private var streams: [UInt32: FlowersecYamuxStream] = [:]
  private var inboundStreamIDs: Set<UInt32> = []
  private var incomingStreams: [FlowersecYamuxStream] = []
  private var incomingWaiters: [CheckedContinuation<FlowersecYamuxStream, Error>] = []
  private var queuedBytesByStream: [UInt32: Int] = [:]
  private var sessionQueuedBytes = 0
  private var pendingPing: PendingPing?
  private var pendingProbe: (id: UInt64, task: Task<Duration, Error>)?
  private var nextProbeID: UInt64 = 1
  private var readerTask: Task<Void, Never>?
  private var livenessTask: Task<Void, Never>?
  private var terminationError: (any Error)?
  private var terminationWaiters: [CheckedContinuation<(any Error)?, Never>] = []
  private var closed = false
  private var terminationFinished = false

  init(
    channel: any FlowersecYamuxChannel,
    limits: YamuxLimits = YamuxLimits(),
    automaticLiveness: (interval: Duration, timeout: Duration)? = nil,
    path: FlowersecPath = .direct,
    client: Bool = true,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil
  ) {
    self.channel = channel
    self.limits = limits
    self.automaticLiveness = automaticLiveness
    self.path = path
    self.client = client
    self.nextStreamID = client ? 1 : 2
    self.onDiagnosticEvent = onDiagnosticEvent
  }

  func start() {
    ensureReaderStarted()
    guard livenessTask == nil, let automaticLiveness else { return }
    livenessTask = Task { [weak self] in
      while !Task.isCancelled {
        do {
          try await Task.sleep(for: automaticLiveness.interval)
          guard let self else { return }
          _ = try await self.probeLiveness(timeout: automaticLiveness.timeout)
        } catch is CancellationError {
          return
        } catch {
          guard let self else { return }
          await self.closeAfterLivenessFailure()
          return
        }
      }
    }
  }

  func openStream() async throws -> FlowersecYamuxStream {
    guard !closed else { throw FlowersecError.closed(path: path) }
    guard streams.count < limits.maxActiveStreams else {
      diagnostic(
        code: "resource_limit_reached",
        resource: "yamux_active_streams",
        current: streams.count,
        limit: limits.maxActiveStreams
      )
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .yamux,
        "The yamux active stream limit was reached."
      )
    }
    ensureReaderStarted()
    guard nextStreamID <= UInt32.max - 2 else {
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .yamux,
        "The yamux stream identifier space was exhausted."
      )
    }
    let streamID = nextStreamID
    nextStreamID += 2
    let stream = FlowersecYamuxStream(
      id: streamID,
      session: self,
      path: path,
      maxWriteQueueBytes: limits.maxStreamWriteQueueBytes
    )
    streams[streamID] = stream
    queuedBytesByStream[streamID] = 0
    do {
      try await writeFrame(
        FlowersecYamuxFrame(
          type: FlowersecYamuxConstants.typeWindowUpdate,
          flags: FlowersecYamuxConstants.flagSYN,
          streamID: streamID,
          length: 0,
          payload: Data()
        )
      )
    } catch {
      removeStream(streamID)
      throw error
    }
    return stream
  }

  func acceptStream() async throws -> FlowersecYamuxStream {
    if closed {
      throw terminationError ?? FlowersecError.closed(path: path)
    }
    ensureReaderStarted()
    if !incomingStreams.isEmpty {
      return incomingStreams.removeFirst()
    }
    return try await withCheckedThrowingContinuation { continuation in
      incomingWaiters.append(continuation)
    }
  }

  func probeLiveness(timeout: Duration) async throws -> Duration {
    guard timeout > .zero else {
      throw FlowersecError.invalidConnectInfo(
        "The liveness timeout must be positive.",
        path: path
      )
    }
    guard !closed else { throw FlowersecError.closed(path: path) }
    if let pendingProbe {
      return try await pendingProbe.task.value
    }
    let probeID = nextProbeID
    nextProbeID &+= 1
    let task = Task { try await self.performLivenessProbe(timeout: timeout) }
    pendingProbe = (probeID, task)
    do {
      let result = try await task.value
      clearPendingProbe(probeID)
      return result
    } catch {
      clearPendingProbe(probeID)
      if error is CancellationError {
        throw error
      }
      if let flowersec = error as? FlowersecError,
        flowersec.code == .timeout || flowersec.code == .resourceExhausted
      {
        throw flowersec.withPath(path)
      }
      throw FlowersecError(
        path: path,
        stage: .yamux,
        code: .pingFailed,
        message: "The yamux liveness probe failed: \(error.localizedDescription)"
      )
    }
  }

  private func performLivenessProbe(timeout: Duration) async throws -> Duration {
    guard !closed else { throw FlowersecError.closed(path: path) }
    ensureReaderStarted()
    let pingID = nextPingID
    nextPingID = nextPingID == UInt32.max ? 1 : nextPingID + 1
    let startedAt = clock.now

    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let timeoutTask = Task { [weak self] in
          do {
            try await Task.sleep(for: timeout)
            await self?.timeoutPing(pingID)
          } catch is CancellationError {
            return
          } catch {
            await self?.failPing(pingID, error: error)
          }
        }
        pendingPing = PendingPing(
          id: pingID,
          startedAt: startedAt,
          continuation: continuation,
          timeoutTask: timeoutTask
        )
        Task {
          do {
            try await self.writeFrame(
              FlowersecYamuxFrame(
                type: FlowersecYamuxConstants.typePing,
                flags: FlowersecYamuxConstants.flagSYN,
                streamID: 0,
                length: pingID,
                payload: Data()
              )
            )
          } catch {
            self.failPing(pingID, error: error)
          }
        }
      }
    } onCancel: {
      Task { await self.failPing(pingID, error: CancellationError()) }
    }
  }

  func close() async {
    guard !closed else { return }
    closed = true
    readerTask?.cancel()
    readerTask = nil
    livenessTask?.cancel()
    livenessTask = nil
    failPendingPing(FlowersecError.closed(path: path))
    failIncomingWaiters(FlowersecError.closed(path: path))
    for stream in streams.values {
      await stream.closeFromSession()
    }
    streams.removeAll()
    queuedBytesByStream.removeAll()
    sessionQueuedBytes = 0
    await channel.close()
    finishTermination(nil)
  }

  func terminated() async -> (any Error)? {
    if terminationFinished { return terminationError }
    return await withCheckedContinuation { continuation in
      terminationWaiters.append(continuation)
    }
  }

  fileprivate func writeData(streamID: UInt32, data: Data) async throws {
    guard !closed, streams[streamID] != nil else { throw FlowersecError.closed(path: path) }
    var offset = 0
    while offset < data.count {
      let remaining = data.count - offset
      let chunkSize = min(remaining, limits.preferredOutboundFrameBytes)
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
    guard !closed, streams[streamID] != nil else { throw FlowersecError.closed(path: path) }
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

  fileprivate func releaseReceiveBytes(streamID: UInt32, bytes: Int) {
    guard bytes > 0, let queued = queuedBytesByStream[streamID] else { return }
    let released = min(bytes, queued)
    queuedBytesByStream[streamID] = queued - released
    sessionQueuedBytes -= released
  }

  fileprivate func closeStream(streamID: UInt32) async {
    guard let stream = streams[streamID] else { return }
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
    } catch {
      await terminate(with: sessionTransportError(error))
      return
    }
    if await stream.isFullyDrained {
      _ = removeStream(streamID)
    }
  }

  fileprivate func finalizeDrainedStream(streamID: UInt32) async {
    guard let stream = streams[streamID], await stream.isFullyDrained else { return }
    _ = removeStream(streamID)
  }

  private func ensureReaderStarted() {
    guard readerTask == nil else { return }
    readerTask = Task { await self.readLoop() }
  }

  private func closeAfterLivenessFailure() async {
    await close()
  }

  private func timeoutPing(_ pingID: UInt32) async {
    guard pendingPing?.id == pingID else { return }
    diagnostic(code: "liveness_timeout")
    failPing(pingID, error: FlowersecError.livenessTimeout(path: path))
    await close()
  }

  private func clearPendingProbe(_ probeID: UInt64) {
    guard pendingProbe?.id == probeID else { return }
    pendingProbe = nil
  }

  private func failPing(_ pingID: UInt32, error: Error) {
    guard let ping = pendingPing, ping.id == pingID else { return }
    pendingPing = nil
    ping.timeoutTask.cancel()
    ping.continuation.resume(throwing: error)
  }

  private func failPendingPing(_ error: Error) {
    guard let ping = pendingPing else { return }
    pendingPing = nil
    ping.timeoutTask.cancel()
    ping.continuation.resume(throwing: error)
  }

  private func readLoop() async {
    do {
      while !Task.isCancelled && !closed {
        guard let frame = try await readFrame() else { continue }
        try await handle(frame)
      }
    } catch {
      await terminate(with: sessionTransportError(error))
    }
  }

  private func terminate(with failure: any Error) async {
    guard !closed else { return }
    closed = true
    readerTask?.cancel()
    readerTask = nil
    livenessTask?.cancel()
    livenessTask = nil
    failPendingPing(failure)
    failIncomingWaiters(failure)
    for stream in streams.values {
      await stream.fail(failure)
    }
    streams.removeAll()
    queuedBytesByStream.removeAll()
    sessionQueuedBytes = 0
    await channel.close()
    finishTermination(failure)
  }

  private func finishTermination(_ error: (any Error)?) {
    terminationError = error
    terminationFinished = true
    let waiters = terminationWaiters
    terminationWaiters.removeAll()
    for waiter in waiters { waiter.resume(returning: error) }
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
      throw FlowersecError.invalidYamux("The peer closed the yamux session.", path: path)
    default:
      throw FlowersecError.invalidYamux("Unsupported yamux frame type.", path: path)
    }
  }

  private func handleDataFrame(_ frame: FlowersecYamuxFrame) async throws {
    let stream: FlowersecYamuxStream
    if let existing = streams[frame.streamID] {
      guard frame.flags & FlowersecYamuxConstants.flagSYN == 0 else {
        try await rejectStream(frame.streamID, reason: "The peer repeated a stream SYN.")
        return
      }
      stream = existing
    } else {
      guard frame.flags & FlowersecYamuxConstants.flagSYN != 0 else {
        try await rejectUnknownStream(frame.streamID)
        return
      }
      do {
        stream = try await acceptInboundStream(frame.streamID)
      } catch let error as FlowersecError where error.code == .resourceExhausted {
        return
      }
    }
    guard await applyResetAndAckFlags(frame, stream: stream) else { return }
    if !frame.payload.isEmpty {
      guard await stream.receive(frame.payload) else {
        throw FlowersecError.invalidYamux(
          "The peer sent DATA after finishing the stream.",
          path: path
        )
      }
    }
    if frame.flags & FlowersecYamuxConstants.flagFIN != 0 {
      await stream.finishRemote()
      if await stream.isFullyDrained {
        _ = removeStream(frame.streamID)
      }
    }
  }

  private func handleWindowUpdateFrame(_ frame: FlowersecYamuxFrame) async throws {
    let stream: FlowersecYamuxStream
    if let existing = streams[frame.streamID] {
      guard frame.flags & FlowersecYamuxConstants.flagSYN == 0 else {
        try await rejectStream(frame.streamID, reason: "The peer repeated a stream SYN.")
        return
      }
      stream = existing
    } else {
      guard frame.flags & FlowersecYamuxConstants.flagSYN != 0 else {
        try await rejectUnknownStream(frame.streamID)
        return
      }
      do {
        stream = try await acceptInboundStream(frame.streamID)
      } catch let error as FlowersecError where error.code == .resourceExhausted {
        return
      }
    }
    guard await applyResetAndAckFlags(frame, stream: stream) else { return }
    if frame.flags & FlowersecYamuxConstants.flagFIN != 0 {
      await stream.finishRemote()
      if await stream.isFullyDrained {
        _ = removeStream(frame.streamID)
      }
    }
    if frame.length > 0 {
      guard await stream.increaseSendWindow(frame.length) else {
        throw FlowersecError.invalidYamux(
          "The peer exceeded the yamux send window.",
          path: path
        )
      }
    }
  }

  private func applyResetAndAckFlags(
    _ frame: FlowersecYamuxFrame,
    stream: FlowersecYamuxStream
  ) async -> Bool {
    if frame.flags & FlowersecYamuxConstants.flagRST != 0 {
      _ = removeStream(frame.streamID)
      await stream.fail(FlowersecStreamResetError(path: path))
      return false
    }
    if frame.flags & FlowersecYamuxConstants.flagACK != 0 {
      await stream.markEstablished()
    }
    return true
  }

  private func handlePingFrame(_ frame: FlowersecYamuxFrame) async throws {
    if frame.flags & FlowersecYamuxConstants.flagSYN != 0 {
      try await writeFrame(
        FlowersecYamuxFrame(
          type: FlowersecYamuxConstants.typePing,
          flags: FlowersecYamuxConstants.flagACK,
          streamID: 0,
          length: frame.length,
          payload: Data()
        )
      )
      return
    }
    guard frame.flags & FlowersecYamuxConstants.flagACK != 0,
      let ping = pendingPing,
      ping.id == frame.length
    else { return }
    pendingPing = nil
    ping.timeoutTask.cancel()
    ping.continuation.resume(returning: ping.startedAt.duration(to: clock.now))
  }

  private func readFrame() async throws -> FlowersecYamuxFrame? {
    let header = try await channel.readExact(FlowersecYamuxConstants.headerSize)
    let frame: FlowersecYamuxFrame
    do {
      frame = try FlowersecYamuxFrame(header: header)
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
    guard frame.type == FlowersecYamuxConstants.typeData else {
      return frame
    }
    guard frame.length <= UInt32(limits.maxFrameBytes) else {
      diagnostic(
        code: "resource_limit_reached",
        resource: "yamux_frame_bytes",
        current: Int(frame.length),
        limit: limits.maxFrameBytes
      )
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .yamux,
        "The peer declared a DATA frame larger than maxFrameBytes."
      )
    }
    var dataFlags = frame.flags
    if streams[frame.streamID] == nil, frame.flags & FlowersecYamuxConstants.flagSYN != 0 {
      _ = try await acceptInboundStream(frame.streamID)
      dataFlags &= ~FlowersecYamuxConstants.flagSYN
    }
    guard streams[frame.streamID] != nil, let queued = queuedBytesByStream[frame.streamID] else {
      try await discardExact(Int(frame.length))
      try await rejectUnknownStream(frame.streamID)
      return nil
    }
    let length = Int(frame.length)
    guard queued <= limits.maxStreamReceiveBytes - length else {
      diagnostic(
        code: "resource_limit_reached",
        resource: "yamux_stream_receive_bytes",
        current: queued + length,
        limit: limits.maxStreamReceiveBytes
      )
      try await discardExact(length)
      try await rejectStream(
        frame.streamID,
        reason: "The yamux stream receive limit was reached."
      )
      return nil
    }
    guard sessionQueuedBytes <= limits.maxSessionReceiveBytes - length else {
      diagnostic(
        code: "resource_limit_reached",
        resource: "yamux_session_receive_bytes",
        current: sessionQueuedBytes + length,
        limit: limits.maxSessionReceiveBytes
      )
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .yamux,
        "The yamux session receive limit was reached."
      )
    }
    queuedBytesByStream[frame.streamID] = queued + length
    sessionQueuedBytes += length
    do {
      let payload = length > 0 ? try await channel.readExact(length) : Data()
      return FlowersecYamuxFrame(
        type: frame.type,
        flags: dataFlags,
        streamID: frame.streamID,
        length: frame.length,
        payload: payload
      )
    } catch {
      releaseReceiveBytes(streamID: frame.streamID, bytes: length)
      throw error
    }
  }

  private func discardExact(_ length: Int) async throws {
    var remaining = length
    while remaining > 0 {
      let count = min(remaining, 16 * 1024)
      _ = try await channel.readExact(count)
      remaining -= count
    }
  }

  private func rejectUnknownStream(_ streamID: UInt32) async throws {
    try await writeReset(streamID)
  }

  private func acceptInboundStream(_ streamID: UInt32) async throws -> FlowersecYamuxStream {
    guard streamID != 0, isInboundStreamIDValid(streamID) else {
      try await rejectUnknownStream(streamID)
      throw FlowersecError.invalidYamux(
        "The peer used an invalid inbound stream identifier.", path: path)
    }
    guard streams.count < limits.maxActiveStreams,
      inboundStreamIDs.count < limits.maxInboundStreams
    else {
      diagnostic(
        code: "resource_limit_reached",
        resource: "yamux_inbound_streams",
        current: inboundStreamIDs.count,
        limit: limits.maxInboundStreams
      )
      try await rejectUnknownStream(streamID)
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .yamux,
        "The yamux inbound stream limit was reached."
      )
    }
    let stream = FlowersecYamuxStream(
      id: streamID,
      session: self,
      path: path,
      maxWriteQueueBytes: limits.maxStreamWriteQueueBytes
    )
    streams[streamID] = stream
    inboundStreamIDs.insert(streamID)
    queuedBytesByStream[streamID] = 0
    await stream.markEstablished()
    try await writeFrame(
      FlowersecYamuxFrame(
        type: FlowersecYamuxConstants.typeWindowUpdate,
        flags: FlowersecYamuxConstants.flagACK,
        streamID: streamID,
        length: 0,
        payload: Data()
      )
    )
    if incomingWaiters.isEmpty {
      incomingStreams.append(stream)
    } else {
      incomingWaiters.removeFirst().resume(returning: stream)
    }
    return stream
  }

  private func isInboundStreamIDValid(_ streamID: UInt32) -> Bool {
    streamID & 1 == (client ? 0 : 1)
  }

  private func failIncomingWaiters(_ error: Error) {
    let waiters = incomingWaiters
    incomingWaiters.removeAll()
    incomingStreams.removeAll()
    for waiter in waiters { waiter.resume(throwing: error) }
  }

  private func rejectStream(_ streamID: UInt32, reason: String) async throws {
    diagnostic(code: "stream_rejected", resource: "yamux_streams")
    if let stream = removeStream(streamID) {
      await stream.fail(FlowersecError.resourceExhausted(path: path, stage: .yamux, reason))
    }
    try await writeReset(streamID)
  }

  private func writeReset(_ streamID: UInt32) async throws {
    try await writeFrame(
      FlowersecYamuxFrame(
        type: FlowersecYamuxConstants.typeWindowUpdate,
        flags: FlowersecYamuxConstants.flagRST,
        streamID: streamID,
        length: 0,
        payload: Data()
      )
    )
  }

  fileprivate func resetStream(_ streamID: UInt32) async throws {
    _ = removeStream(streamID)
    try await writeReset(streamID)
  }

  @discardableResult
  private func removeStream(_ streamID: UInt32) -> FlowersecYamuxStream? {
    let stream = streams.removeValue(forKey: streamID)
    inboundStreamIDs.remove(streamID)
    if let queued = queuedBytesByStream.removeValue(forKey: streamID) {
      sessionQueuedBytes -= queued
    }
    return stream
  }

  private func writeFrame(_ frame: FlowersecYamuxFrame) async throws {
    var data = frame.encodedHeader()
    data.append(frame.payload)
    do {
      try await channel.write(data)
    } catch {
      let terminal = sessionTransportError(error)
      await terminate(with: terminal)
      throw terminal
    }
  }

  private func sessionTransportError(_ error: any Error) -> FlowersecError {
    if let flowersec = error as? FlowersecError {
      if flowersec.code != .dialFailed || flowersec.stage != .connect {
        return flowersec.withPath(path)
      }
    }
    return FlowersecError(
      path: path,
      stage: .yamux,
      code: .notConnected,
      message: "The yamux transport terminated: \(error.localizedDescription)"
    )
  }

  private func diagnostic(
    code: String,
    resource: String? = nil,
    current: Int? = nil,
    limit: Int? = nil
  ) {
    onDiagnosticEvent?(
      DiagnosticEvent(
        path: path,
        stage: .yamux,
        codeDomain: .event,
        code: code,
        result: .fail,
        resource: resource,
        current: current,
        limit: limit
      )
    )
  }
}

actor FlowersecYamuxStream: FlowersecRPCStream, FlowersecByteStream {
  private struct WindowWaiter {
    var id: UInt64
    var continuation: CheckedContinuation<Void, Error>
  }

  private struct WriteTurnWaiter {
    var id: UInt64
    var continuation: CheckedContinuation<Void, Error>
  }

  let id: UInt32
  private weak var session: FlowersecYamuxClient?
  private let path: FlowersecPath
  private let maxWriteQueueBytes: Int
  private var readBuffer = Data()
  private var readOffset = 0
  private var waiters: [CheckedContinuation<Void, Error>] = []
  private var windowWaiters: [WindowWaiter] = []
  private var nextWindowWaiterID: UInt64 = 1
  private var writeTurnWaiters: [WriteTurnWaiter] = []
  private var nextWriteTurnWaiterID: UInt64 = 1
  private var pendingWriteBytes = 0
  private var writeInProgress = false
  private var sendWindow = FlowersecYamuxConstants.initialStreamWindow
  private var established = false
  private var remoteFinished = false
  private var localFinished = false
  private var terminalClosed = false
  private var failure: Error?

  init(
    id: UInt32,
    session: FlowersecYamuxClient,
    path: FlowersecPath,
    maxWriteQueueBytes: Int
  ) {
    self.id = id
    self.session = session
    self.path = path
    self.maxWriteQueueBytes = maxWriteQueueBytes
  }

  func write(_ data: Data) async throws {
    try reserveWriteBytes(data.count)
    defer { releaseWriteBytes(data.count) }
    try await acquireWriteTurn()
    defer { releaseWriteTurn() }
    try Task.checkCancellation()
    guard !localFinished, !terminalClosed else { throw FlowersecError.closed(path: path) }
    if let failure { throw failure }
    guard let session else { throw FlowersecError.closed(path: path) }
    var offset = 0
    while offset < data.count {
      try Task.checkCancellation()
      while sendWindow == 0 {
        try await waitForWindow()
      }
      try Task.checkCancellation()
      let available = min(data.count - offset, Int(sendWindow))
      let chunk = data.subdata(in: offset..<(offset + available))
      sendWindow -= UInt32(available)
      do {
        try await session.writeData(streamID: id, data: chunk)
      } catch {
        sendWindow += UInt32(available)
        throw error
      }
      offset += available
    }
  }

  func readExact(_ length: Int) async throws -> Data {
    guard length >= 0 else {
      throw FlowersecError.invalidYamux("Negative stream read length.", path: path)
    }
    var out = Data()
    out.reserveCapacity(length)
    while out.count < length {
      if let failure { throw failure }
      let available = readBuffer.count - readOffset
      if available > 0 {
        let count = min(length - out.count, available)
        let end = readOffset + count
        out.append(readBuffer[readOffset..<end])
        readOffset = end
        compactReadBufferAfterConsumption()
        await session?.releaseReceiveBytes(streamID: id, bytes: count)
        try await session?.sendWindowUpdate(streamID: id, bytes: UInt32(count))
        if readBuffer.isEmpty, localFinished, remoteFinished {
          await session?.finalizeDrainedStream(streamID: id)
        }
        continue
      }
      if remoteFinished { throw FlowersecError.closed(path: path) }
      try await waitForData()
    }
    return out
  }

  func close() async {
    guard !localFinished, !terminalClosed else { return }
    localFinished = true
    resumeWindowWaiters(error: FlowersecError.closed(path: path))
    resumeWriteTurnWaiters(error: FlowersecError.closed(path: path))
    await session?.closeStream(streamID: id)
  }

  func reset() async throws {
    guard !terminalClosed else { return }
    terminalClosed = true
    localFinished = true
    clearReadBuffer()
    resumeWaiters(error: FlowersecError.closed(path: path))
    resumeWindowWaiters(error: FlowersecError.closed(path: path))
    resumeWriteTurnWaiters(error: FlowersecError.closed(path: path))
    guard let session else { throw FlowersecError.closed(path: path) }
    try await session.resetStream(id)
  }

  fileprivate func receive(_ data: Data) -> Bool {
    guard !terminalClosed, failure == nil, !remoteFinished else { return false }
    guard !data.isEmpty else { return true }
    readBuffer.append(data)
    if let waiter = waiters.first {
      waiters.removeFirst()
      waiter.resume()
    }
    return true
  }

  fileprivate func increaseSendWindow(_ delta: UInt32) -> Bool {
    let (sum, overflow) = sendWindow.addingReportingOverflow(delta)
    guard !overflow, sum <= FlowersecYamuxConstants.initialStreamWindow else { return false }
    sendWindow = sum
    resumeWindowWaiters()
    return true
  }

  fileprivate func markEstablished() {
    established = true
  }

  fileprivate func finishRemote() {
    remoteFinished = true
    resumeWaiters()
  }

  fileprivate func fail(_ error: Error) {
    failure = error
    terminalClosed = true
    clearReadBuffer()
    resumeWaiters(error: error)
    resumeWindowWaiters(error: error)
    resumeWriteTurnWaiters(error: error)
  }

  fileprivate func closeFromSession() {
    terminalClosed = true
    clearReadBuffer()
    resumeWaiters(error: FlowersecError.closed(path: path))
    resumeWindowWaiters(error: FlowersecError.closed(path: path))
    resumeWriteTurnWaiters(error: FlowersecError.closed(path: path))
  }

  fileprivate var isFullyDrained: Bool {
    localFinished && remoteFinished && readBuffer.isEmpty
  }

  var bufferedReadStorageCount: Int { readBuffer.count }
  var bufferedReadOffset: Int { readOffset }

  private func compactReadBufferAfterConsumption() {
    let available = readBuffer.count - readOffset
    if available == 0 {
      clearReadBuffer()
    } else if readOffset >= 64 * 1024, available <= readOffset {
      readBuffer.removeSubrange(0..<readOffset)
      readOffset = 0
    }
  }

  private func clearReadBuffer() {
    readBuffer.removeAll()
    readOffset = 0
  }

  private func waitForData() async throws {
    try await withCheckedThrowingContinuation { continuation in
      waiters.append(continuation)
    }
  }

  private func waitForWindow() async throws {
    try Task.checkCancellation()
    if let failure { throw failure }
    guard !localFinished, !terminalClosed else { throw FlowersecError.closed(path: path) }
    let waiterID = nextWindowWaiterID
    nextWindowWaiterID += 1
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else {
          windowWaiters.append(WindowWaiter(id: waiterID, continuation: continuation))
        }
      }
    } onCancel: {
      Task { await self.cancelWindowWaiter(waiterID) }
    }
  }

  private func cancelWindowWaiter(_ waiterID: UInt64) {
    guard let index = windowWaiters.firstIndex(where: { $0.id == waiterID }) else { return }
    windowWaiters.remove(at: index).continuation.resume(throwing: CancellationError())
  }

  private func resumeWaiters(error: Error) {
    let current = waiters
    waiters.removeAll()
    for waiter in current {
      waiter.resume(throwing: error)
    }
  }

  private func resumeWaiters() {
    let current = waiters
    waiters.removeAll()
    for waiter in current { waiter.resume() }
  }

  private func reserveWriteBytes(_ count: Int) throws {
    guard count <= maxWriteQueueBytes - pendingWriteBytes else {
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .yamux,
        "The yamux stream write queue limit was reached."
      )
    }
    pendingWriteBytes += count
  }

  private func releaseWriteBytes(_ count: Int) {
    pendingWriteBytes -= count
  }

  private func acquireWriteTurn() async throws {
    try Task.checkCancellation()
    if !writeInProgress {
      writeInProgress = true
      return
    }
    let waiterID = nextWriteTurnWaiterID
    nextWriteTurnWaiterID += 1
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else {
          writeTurnWaiters.append(
            WriteTurnWaiter(id: waiterID, continuation: continuation)
          )
        }
      }
    } onCancel: {
      Task { await self.cancelWriteTurnWaiter(waiterID) }
    }
  }

  private func cancelWriteTurnWaiter(_ waiterID: UInt64) {
    guard let index = writeTurnWaiters.firstIndex(where: { $0.id == waiterID }) else { return }
    writeTurnWaiters.remove(at: index).continuation.resume(throwing: CancellationError())
  }

  private func releaseWriteTurn() {
    if writeTurnWaiters.isEmpty {
      writeInProgress = false
      return
    }
    writeTurnWaiters.removeFirst().continuation.resume()
  }

  private func resumeWriteTurnWaiters(error: Error) {
    let current = writeTurnWaiters
    writeTurnWaiters.removeAll()
    for waiter in current {
      waiter.continuation.resume(throwing: error)
    }
  }

  private func resumeWindowWaiters(error: Error? = nil) {
    let current = windowWaiters
    windowWaiters.removeAll()
    for waiter in current {
      if let error {
        waiter.continuation.resume(throwing: error)
      } else {
        waiter.continuation.resume()
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
