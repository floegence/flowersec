import Foundation

public struct RPCServerOptions: Equatable, Sendable {
  public var maxConcurrentRequests: Int
  public var maxQueuedRequests: Int
  public var maxQueuedNotifications: Int

  public init(
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

public typealias RPCHandler = @Sendable (Data) async throws -> Data

public actor RPCRouter {
  private var handlers: [UInt32: RPCHandler] = [:]

  public init() {}

  public func register(_ typeID: UInt32, handler: @escaping RPCHandler) {
    handlers[typeID] = handler
  }

  public func register<Request: Decodable & Sendable, Response: Encodable & Sendable>(
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

public actor RPCServer {
  private let stream: any FlowersecByteStream
  private let router: RPCRouter
  private let options: RPCServerOptions
  private let path: FlowersecPath
  private var requestQueue: [RPCEnvelope] = []
  private var notificationQueue: [RPCEnvelope] = []
  private var activeRequests = 0
  private var notificationWorkerRunning = false
  private var writeTail: (id: UInt64, task: Task<Void, Error>)?
  private var nextWriteID: UInt64 = 1
  private var closed = false

  public init(
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

  public func notify<Payload: Encodable & Sendable>(
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

  public func serve() async throws {
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
    } catch let error as FlowersecError {
      await close()
      throw error.withPath(path)
    } catch {
      await close()
      throw FlowersecError(
        path: path,
        stage: .rpc,
        code: .rpcFailed,
        message: "The RPC server failed: \(error.localizedDescription)"
      )
    }
  }

  public func close() async {
    guard !closed else { return }
    closed = true
    requestQueue.removeAll()
    notificationQueue.removeAll()
    writeTail?.task.cancel()
    writeTail = nil
    await stream.close()
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
    Task {
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
      await finishRequest(envelope, result: result)
    }
  }

  private func finishRequest(_ envelope: RPCEnvelope, result: Result<Data, Error>) async {
    activeRequests = max(0, activeRequests - 1)
    guard !closed else { return }
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
      await close()
      return
    }
    if !requestQueue.isEmpty {
      startRequest(requestQueue.removeFirst())
    }
  }

  private func startNotificationWorkerIfNeeded() {
    guard !notificationWorkerRunning else { return }
    notificationWorkerRunning = true
    Task { await runNotificationWorker() }
  }

  private func runNotificationWorker() async {
    while !closed, !notificationQueue.isEmpty {
      let envelope = notificationQueue.removeFirst()
      if let handler = await router.handler(for: envelope.typeID) {
        _ = try? await handler(envelope.payload)
      }
    }
    notificationWorkerRunning = false
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
}
