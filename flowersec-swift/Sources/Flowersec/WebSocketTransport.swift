import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

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
    var message: OutboundMessage
    var continuation: CheckedContinuation<Void, Error>
  }

  private static let maxPendingWriteBytes = 4 * 1024 * 1024
  private let path: FlowersecPath
  private let onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)?
  private let session: URLSession
  private let task: URLSessionWebSocketTask
  private var pendingWrites: [PendingWrite] = []
  private var pendingWriteBytes = 0
  private var writeInProgress = false
  private var closed = false

  init(
    url: URL,
    origin: String?,
    connectTimeout: Duration,
    path: FlowersecPath = .direct,
    onDiagnosticEvent: (@Sendable (DiagnosticEvent) -> Void)? = nil
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

  func resume() {
    task.resume()
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
        stage: .transport,
        "The WebSocket pending write limit was reached."
      )
      closed = true
      task.cancel(with: .goingAway, reason: nil)
      session.invalidateAndCancel()
      failPendingWrites(with: error)
      throw error
    }
    pendingWriteBytes += message.byteCount
    try await withCheckedThrowingContinuation { continuation in
      pendingWrites.append(PendingWrite(message: message, continuation: continuation))
      startWriteIfNeeded()
    }
  }

  private func startWriteIfNeeded() {
    guard !closed, !writeInProgress, let write = pendingWrites.first else { return }
    writeInProgress = true
    Task {
      do {
        try await task.send(write.message.webSocketMessage)
        finishWrite(result: .success(()))
      } catch {
        finishWrite(
          result: .failure(FlowersecError.webSocket(error.localizedDescription, path: path))
        )
      }
    }
  }

  private func finishWrite(result: Result<Void, Error>) {
    guard !pendingWrites.isEmpty else {
      writeInProgress = false
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
      write.continuation.resume(throwing: error)
    }
  }
}

extension Duration {
  fileprivate var timeInterval: TimeInterval {
    let parts = components
    return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1_000_000_000_000_000_000
  }
}
