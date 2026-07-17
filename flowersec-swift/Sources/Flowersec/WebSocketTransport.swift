import Foundation

#if canImport(FoundationNetworking)
  import FoundationNetworking
#endif

/// A binary transport used by Flowersec handshakes and secure channels.
///
/// `close()` may be invoked by an SDK-owned cleanup task after a timed-out or canceled call has
/// already returned. Custom implementations must make close idempotent, promptly release pending
/// I/O, and cooperate with task cancellation.
public protocol FlowersecBinaryTransport: Sendable {
  func writeBinary(_ data: Data) async throws
  func readBinary() async throws -> Data
  func close() async
}

actor FlowersecWebSocketBinaryTransport: FlowersecBinaryTransport {
  private enum OutboundMessage {
    case binary(Data)
    case text(String)

    var byteCount: Int {
      switch self {
      case .binary(let data): data.count
      case .text(let text): text.utf8.count
      }
    }

    var webSocketMessage: URLSessionWebSocketTask.Message {
      switch self {
      case .binary(let data): .data(data)
      case .text(let text): .string(text)
      }
    }
  }

  private struct PendingWrite {
    var id: UInt64
    var message: OutboundMessage
    var cancellation: WebSocketPendingWriteCancellation
    var continuation: CheckedContinuation<Void, Error>
  }

  private static let maxPendingWriteBytes = 4 * 1024 * 1024
  private let path: FlowersecPath
  private let onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
  private let session: URLSession
  private let task: URLSessionWebSocketTask
  private let beforeResume: (@Sendable () async -> Void)?
  private let resumeOverride: (@Sendable () -> Void)?
  private let beforeSystemSend: (@Sendable () async -> Void)?
  private let systemSendOverride: (@Sendable () async throws -> Void)?
  private var pendingWrites: [PendingWrite] = []
  private var pendingWriteBytes = 0
  private var writeInProgress = false
  private var nextWriteID: UInt64 = 1
  private var closed = false

  init(
    url: URL,
    origin: String?,
    connectTimeout: Duration,
    path: FlowersecPath = .direct,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil,
    beforeResume: (@Sendable () async -> Void)? = nil,
    resumeOverride: (@Sendable () -> Void)? = nil,
    beforeSystemSend: (@Sendable () async -> Void)? = nil,
    systemSendOverride: (@Sendable () async throws -> Void)? = nil
  ) {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.httpCookieAcceptPolicy = .never
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.timeoutIntervalForRequest = connectTimeout.timeInterval
    configuration.timeoutIntervalForResource = 30
    self.session = URLSession(configuration: configuration)
    self.path = path
    self.onDiagnosticEvent = onDiagnosticEvent
    self.beforeResume = beforeResume
    self.resumeOverride = resumeOverride
    self.beforeSystemSend = beforeSystemSend
    self.systemSendOverride = systemSendOverride

    var request = URLRequest(url: url)
    request.cachePolicy = .reloadIgnoringLocalCacheData
    request.timeoutInterval = connectTimeout.timeInterval
    if let origin {
      request.setValue(origin, forHTTPHeaderField: "Origin")
    }
    request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
    request.setValue("no-cache", forHTTPHeaderField: "Pragma")
    self.task = session.webSocketTask(with: request)
  }

  func resume() async throws {
    if let beforeResume { await beforeResume() }
    try Task.checkCancellation()
    if let resumeOverride {
      resumeOverride()
    } else {
      task.resume()
    }
  }

  func writeBinary(_ data: Data) async throws {
    try await enqueue(.binary(data))
  }

  func writeText(_ text: String) async throws {
    try await enqueue(.text(text))
  }

  func readBinary() async throws -> Data {
    do {
      let message = try await task.receive()
      switch message {
      case .data(let data):
        return data
      case .string:
        throw FlowersecError.webSocket("The peer returned a text WebSocket frame.", path: path)
      @unknown default:
        throw FlowersecError.webSocket(
          "The peer returned an unknown WebSocket frame.",
          path: path
        )
      }
    } catch let error as FlowersecError {
      throw error.withPath(path)
    } catch {
      throw FlowersecError.webSocket(error.localizedDescription, path: path)
    }
  }

  func close() {
    guard !closed else { return }
    closed = true
    task.cancel(with: .goingAway, reason: nil)
    session.invalidateAndCancel()
    failPendingWrites(with: FlowersecError.closed(path: path))
  }

  private func enqueue(_ message: OutboundMessage) async throws {
    try Task.checkCancellation()
    guard !closed else { throw FlowersecError.closed(path: path) }
    guard message.byteCount <= Self.maxPendingWriteBytes - pendingWriteBytes else {
      let current = pendingWriteBytes + message.byteCount
      onDiagnosticEvent?(
        DiagnosticEvent(
          path: path,
          stage: .transport,
          codeDomain: .event,
          code: "resource_limit_reached",
          result: .fail,
          resource: "websocket_pending_write_bytes",
          current: current,
          limit: Self.maxPendingWriteBytes
        )
      )
      let error = FlowersecError.resourceExhausted(
        path: path,
        stage: .connect,
        "The WebSocket pending write limit was reached."
      )
      closed = true
      task.cancel(with: .goingAway, reason: nil)
      session.invalidateAndCancel()
      failPendingWrites(with: error)
      throw error
    }
    let id = nextWriteID
    nextWriteID &+= 1
    let cancellation = WebSocketPendingWriteCancellation()
    try await withTaskCancellationHandler {
      try Task.checkCancellation()
      try await withCheckedThrowingContinuation { continuation in
        pendingWriteBytes += message.byteCount
        pendingWrites.append(
          PendingWrite(
            id: id,
            message: message,
            cancellation: cancellation,
            continuation: continuation
          )
        )
        startWriteIfNeeded()
      }
      try Task.checkCancellation()
    } onCancel: {
      if cancellation.cancel() {
        Task { await self.cancelPendingWrite(id: id) }
      }
    }
  }

  private func startWriteIfNeeded() {
    guard !closed, !writeInProgress, let write = pendingWrites.first else { return }
    writeInProgress = true
    Task {
      if let beforeSystemSend { await beforeSystemSend() }
      guard write.cancellation.claimSubmission() else {
        cancelPendingWrite(id: write.id)
        return
      }
      do {
        if let systemSendOverride {
          try await systemSendOverride()
        } else {
          try await task.send(write.message.webSocketMessage)
        }
        finishWrite(id: write.id, result: .success(()))
      } catch {
        finishWrite(
          id: write.id,
          result: .failure(FlowersecError.webSocket(error.localizedDescription, path: path))
        )
      }
    }
  }

  private func cancelPendingWrite(id: UInt64) {
    guard let index = pendingWrites.firstIndex(where: { $0.id == id }) else { return }
    let wasActive = index == 0 && writeInProgress
    let write = pendingWrites.remove(at: index)
    pendingWriteBytes -= write.message.byteCount
    if wasActive { writeInProgress = false }
    write.continuation.resume(throwing: CancellationError())
    if wasActive { startWriteIfNeeded() }
  }

  private func finishWrite(id: UInt64, result: Result<Void, Error>) {
    guard let first = pendingWrites.first, first.id == id else {
      writeInProgress = false
      startWriteIfNeeded()
      return
    }
    let write = pendingWrites.removeFirst()
    pendingWriteBytes -= write.message.byteCount
    writeInProgress = false
    switch result {
    case .success:
      write.continuation.resume()
      startWriteIfNeeded()
    case .failure(let error):
      closed = true
      task.cancel(with: .goingAway, reason: nil)
      session.invalidateAndCancel()
      write.continuation.resume(throwing: error)
      failPendingWrites(with: error)
    }
  }

  private func failPendingWrites(with error: Error) {
    let writes = pendingWrites
    pendingWrites.removeAll()
    pendingWriteBytes = 0
    writeInProgress = false
    for write in writes {
      _ = write.cancellation.cancel()
      write.continuation.resume(throwing: error)
    }
  }
}

private final class WebSocketPendingWriteCancellation: @unchecked Sendable {
  private enum State: Equatable {
    case pending
    case canceled
    case submitted
  }

  private let lock = NSLock()
  private var state = State.pending

  func cancel() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard state == .pending else { return false }
    state = .canceled
    return true
  }

  func claimSubmission() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard state == .pending else { return false }
    state = .submitted
    return true
  }
}

extension Duration {
  fileprivate var timeInterval: TimeInterval {
    let parts = components
    return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1_000_000_000_000_000_000
  }
}
