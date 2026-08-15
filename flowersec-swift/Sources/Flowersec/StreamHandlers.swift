import Foundation

public typealias StreamHandler = @Sendable (IncomingStream) async throws -> Void

public struct StreamHandlerOptions: Sendable {
  public var maxConcurrentStreams: Int
  public var onError: (@Sendable (SessionError) -> Void)?

  public init(
    maxConcurrentStreams: Int = 64,
    onError: (@Sendable (SessionError) -> Void)? = nil
  ) {
    self.maxConcurrentStreams = maxConcurrentStreams
    self.onError = onError
  }
}

public enum HandlerRegistrationError: Error, Equatable, Sendable {
  case invalidHandler
  case alreadyRegistered
  case frozen
}

/// Carrier-neutral application-stream registry and dispatcher for an established session.
public final class StreamHandlers: @unchecked Sendable {
  private struct Snapshot: Sendable {
    let maxConcurrentStreams: Int
    let handlers: [String: StreamHandler]
    let onError: (@Sendable (SessionError) -> Void)?
  }

  private let lock = NSLock()
  private let options: StreamHandlerOptions
  private var handlers: [String: StreamHandler] = [:]
  private var snapshot: Snapshot?

  public init(options: StreamHandlerOptions = StreamHandlerOptions()) throws {
    guard (1...128).contains(options.maxConcurrentStreams) else {
      throw HandlerRegistrationError.invalidHandler
    }
    self.options = options
  }

  public func handleStream(
    kind: String,
    handler: @escaping StreamHandler
  ) throws {
    guard OpenPayloadV2.validKind(kind), kind != "flowersec.rpc.v2" else {
      throw HandlerRegistrationError.invalidHandler
    }
    try lock.withLock {
      guard snapshot == nil else { throw HandlerRegistrationError.frozen }
      guard handlers[kind] == nil else { throw HandlerRegistrationError.alreadyRegistered }
      handlers[kind] = handler
    }
  }

  /// Serves streams until cancellation or session termination, then closes the
  /// session and waits for every active handler task to finish.
  public func serve(session: any Session) async throws {
    let frozen = lock.withLock {
      if let snapshot { return snapshot }
      let snapshot = Snapshot(
        maxConcurrentStreams: options.maxConcurrentStreams,
        handlers: handlers,
        onError: options.onError
      )
      self.snapshot = snapshot
      return snapshot
    }
    let active = ActiveStreamTasks(limit: frozen.maxConcurrentStreams)
    let closer = SessionCloseBarrier(session: session)

    try await withTaskCancellationHandler {
      let result: Result<Void, Error>
      do {
        while true {
          try Task.checkCancellation()
          let incoming = try await session.acceptStream()
          guard let handler = frozen.handlers[incoming.kind] else {
            try? await incoming.stream.reset()
            frozen.onError?(.streamRejected)
            continue
          }
          let started = await active.start {
            do {
              try await handler(incoming)
              try await incoming.stream.closeWrite()
            } catch {
              try? await incoming.stream.reset()
              frozen.onError?(.operationFailed)
            }
          }
          if !started {
            try? await incoming.stream.reset()
            frozen.onError?(.resourceExhausted)
          }
        }
      } catch {
        result = .failure(Task.isCancelled ? CancellationError() : error)
      }

      await closer.close()
      let tasks = await active.drain()
      for task in tasks { task.cancel() }
      for task in tasks { await task.value }
      try result.get()
    } onCancel: {
      Task { await closer.close() }
    }
  }
}

private actor SessionCloseBarrier {
  private let session: any Session
  private var closing: Task<Void, Never>?

  init(session: any Session) {
    self.session = session
  }

  func close() async {
    if closing == nil {
      closing = Task { [session] in
        try? await session.close()
      }
    }
    await closing?.value
  }
}

private actor ActiveStreamTasks {
  private let limit: Int
  private var tasks: [UUID: Task<Void, Never>] = [:]

  init(limit: Int) {
    self.limit = limit
  }

  func start(_ operation: @escaping @Sendable () async -> Void) -> Bool {
    guard tasks.count < limit else { return false }
    let id = UUID()
    tasks[id] = Task { [weak self] in
      await operation()
      await self?.finished(id)
    }
    return true
  }

  func drain() -> [Task<Void, Never>] {
    let active = Array(tasks.values)
    tasks.removeAll(keepingCapacity: false)
    return active
  }

  private func finished(_ id: UUID) {
    tasks.removeValue(forKey: id)
  }
}
