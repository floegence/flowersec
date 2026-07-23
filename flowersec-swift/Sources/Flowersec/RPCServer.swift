import Foundation

internal struct RPCServerOptions: Equatable, Sendable {
  internal var maxConcurrentRequests: Int
  internal var maxQueuedRequests: Int
  internal var maxQueuedNotifications: Int

  internal init(
    maxConcurrentRequests: Int = FlowersecSDKDefaults.RPC.maxConcurrentRequests,
    maxQueuedRequests: Int = FlowersecSDKDefaults.RPC.maxQueuedRequests,
    maxQueuedNotifications: Int = FlowersecSDKDefaults.RPC.maxQueuedNotifications
  ) {
    self.maxConcurrentRequests = maxConcurrentRequests
    self.maxQueuedRequests = maxQueuedRequests
    self.maxQueuedNotifications = maxQueuedNotifications
  }

  fileprivate func validate() throws {
    guard maxConcurrentRequests > 0,
      maxQueuedRequests >= 0,
      maxQueuedNotifications >= 0
    else {
      throw FlowersecError.invalidRPC("RPC server limits are invalid.")
    }
  }
}

internal typealias RPCHandler = @Sendable (Data) async throws -> Data

internal actor RPCRouter {
  private var handlers: [UInt32: RPCHandler] = [:]

  internal init() {}

  internal func register(_ typeID: UInt32, handler: @escaping RPCHandler) {
    handlers[typeID] = handler
  }

  internal func register<Request: Decodable & Sendable, Response: Encodable & Sendable>(
    _ typeID: UInt32,
    handler: @escaping @Sendable (Request) async throws -> Response
  ) {
    handlers[typeID] = { payload in
      let request = try JSONDecoder.flowersecRPC.decode(Request.self, from: payload)
      let response = try await handler(request)
      return try JSONEncoder.flowersecRPC.encode(response)
    }
  }

  fileprivate func handler(for typeID: UInt32) -> RPCHandler? {
    handlers[typeID]
  }
}

internal actor RPCServer {
  private let stream: any FlowersecByteStream
  private let router: RPCRouter
  private let options: RPCServerOptions
  private let path: FlowersecPath
  private var requestQueue: [RPCEnvelope] = []
  private var notificationQueue: [RPCEnvelope] = []
  private var activeRequests = 0
  private var requestTasks: [UInt64: Task<Void, Never>] = [:]
  private var notificationTask: Task<Void, Never>?
  private var nextTaskID: UInt64 = 1
  private var writeTail: (id: UInt64, task: Task<Void, Error>)?
  private var nextWriteID: UInt64 = 1
  private var terminalError: FlowersecError?
  private var closed = false

  internal init(
    stream: any FlowersecByteStream,
    router: RPCRouter,
    options: RPCServerOptions = RPCServerOptions(),
    path: FlowersecPath = .direct
  ) throws {
    try options.validate()
    self.stream = stream
    self.router = router
    self.options = options
    self.path = path
  }

  internal func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    guard !closed else { throw FlowersecError.closed(path: path) }
    let envelope = RPCEnvelope(
      typeID: typeID,
      requestID: 0,
      responseTo: 0,
      payload: try JSONEncoder.flowersecRPC.encode(payload),
      error: nil
    )
    try await writeEnvelope(envelope)
  }

  internal func serve() async throws {
    do {
      while !Task.isCancelled && !closed {
        let frame = try await FlowersecJSONFrame.read(from: stream)
        let envelope = try RPCEnvelope(data: frame)
        guard envelope.responseTo == 0 else { continue }
        if envelope.requestID == 0 {
          try enqueueNotification(envelope)
        } else {
          try await enqueueRequest(envelope)
        }
      }
    } catch is CancellationError {
      await close()
      throw CancellationError()
    } catch {
      let failure = terminalError ?? serverError(error)
      await close()
      throw failure
    }
  }

  internal func close() async {
    guard !closed else { return }
    closed = true
    requestQueue.removeAll()
    notificationQueue.removeAll()
    let requests = Array(requestTasks.values)
    requestTasks.removeAll()
    let notification = notificationTask
    notificationTask = nil
    let write = writeTail?.task
    writeTail = nil
    for task in requests { task.cancel() }
    notification?.cancel()
    write?.cancel()
    await stream.close()
    for task in requests { await task.value }
    if let notification { await notification.value }
    if let write {
      do {
        try await write.value
      } catch is CancellationError {
      } catch {
        if terminalError == nil { terminalError = serverError(error) }
      }
    }
  }

  private func enqueueRequest(_ envelope: RPCEnvelope) async throws {
    if activeRequests < options.maxConcurrentRequests {
      startRequest(envelope)
      return
    }
    guard requestQueue.count < options.maxQueuedRequests else {
      try await writeResponse(
        to: envelope,
        payload: Data("null".utf8),
        error: RPCErrorPayload(code: 429, message: "server overloaded")
      )
      return
    }
    requestQueue.append(envelope)
  }

  private func enqueueNotification(_ envelope: RPCEnvelope) throws {
    guard notificationQueue.count < options.maxQueuedNotifications else {
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .rpc,
        "The RPC notification queue is full."
      )
    }
    notificationQueue.append(envelope)
    startNotificationWorkerIfNeeded()
  }

  private func startRequest(_ envelope: RPCEnvelope) {
    activeRequests += 1
    let taskID = nextTaskID
    nextTaskID &+= 1
    let task = Task {
      let handler = await router.handler(for: envelope.typeID)
      let result: Result<Data, Error>
      if let handler {
        do {
          result = .success(try await handler(envelope.payload))
        } catch {
          result = .failure(error)
        }
      } else {
        result = .failure(FlowersecRPCError(code: 404, message: "handler not found"))
      }
      await finishRequest(taskID: taskID, envelope: envelope, result: result)
    }
    requestTasks[taskID] = task
  }

  private func finishRequest(
    taskID: UInt64,
    envelope: RPCEnvelope,
    result: Result<Data, Error>
  ) async {
    activeRequests = max(0, activeRequests - 1)
    guard !closed else {
      requestTasks.removeValue(forKey: taskID)
      return
    }
    do {
      switch result {
      case .success(let payload):
        try await writeResponse(to: envelope, payload: payload, error: nil)
      case .failure(let error as FlowersecRPCError):
        try await writeResponse(
          to: envelope,
          payload: Data("null".utf8),
          error: RPCErrorPayload(code: error.code, message: error.message)
        )
      case .failure:
        try await writeResponse(
          to: envelope,
          payload: Data("null".utf8),
          error: RPCErrorPayload(code: 500, message: "internal error")
        )
      }
    } catch {
      requestTasks.removeValue(forKey: taskID)
      await fail(error)
      return
    }
    if !requestQueue.isEmpty {
      startRequest(requestQueue.removeFirst())
    }
    requestTasks.removeValue(forKey: taskID)
  }

  private func startNotificationWorkerIfNeeded() {
    guard notificationTask == nil else { return }
    notificationTask = Task { await runNotificationWorker() }
  }

  private func runNotificationWorker() async {
    while !Task.isCancelled, !closed, !notificationQueue.isEmpty {
      let envelope = notificationQueue.removeFirst()
      if let handler = await router.handler(for: envelope.typeID) {
        do {
          _ = try await handler(envelope.payload)
        } catch is CancellationError {
          break
        } catch {
          await fail(error)
          break
        }
      }
    }
    notificationTask = nil
  }

  private func writeResponse(
    to request: RPCEnvelope,
    payload: Data,
    error: RPCErrorPayload?
  ) async throws {
    let envelope = RPCEnvelope(
      typeID: request.typeID,
      requestID: 0,
      responseTo: request.requestID,
      payload: payload,
      error: error
    )
    try await writeEnvelope(envelope)
  }

  private func writeEnvelope(_ envelope: RPCEnvelope) async throws {
    let previous = writeTail?.task
    let writeID = nextWriteID
    nextWriteID &+= 1
    let task = Task {
      if let previous { try await previous.value }
      try await FlowersecJSONFrame.write(envelope.encoded(), to: stream)
    }
    writeTail = (writeID, task)
    try await task.value
    if writeTail?.id == writeID { writeTail = nil }
  }

  private func fail(_ error: Error) async {
    guard terminalError == nil else { return }
    terminalError = serverError(error)
    await stream.close()
  }

  private func serverError(_ error: Error) -> FlowersecError {
    if let error = error as? FlowersecError {
      return error.withPath(path)
    }
    return FlowersecError(
      path: path,
      stage: .rpc,
      code: .rpcFailed,
      message: "The RPC server failed: \(error.localizedDescription)"
    )
  }
}
