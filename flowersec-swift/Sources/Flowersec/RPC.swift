import CoreFoundation
import Foundation

internal struct FlowersecRPCError: LocalizedError, Equatable, Sendable {
  internal var code: UInt32
  internal var message: String

  internal init(code: UInt32, message: String) {
    self.code = code
    self.message = message
  }

  internal var errorDescription: String? { message }
}

internal struct FlowersecStreamResetError: LocalizedError, Equatable, Sendable {
  internal var path: FlowersecPath

  internal init(path: FlowersecPath) {
    self.path = path
  }

  internal var errorDescription: String? { "The peer reset the stream." }
}

internal struct RPCSubscription: Sendable {
  private let cancelHandler: @Sendable () -> Void

  internal init(cancelHandler: @escaping @Sendable () -> Void) {
    self.cancelHandler = cancelHandler
  }

  internal func cancel() {
    cancelHandler()
  }
}

internal protocol FlowersecRPCStream: AnyObject, FlowersecByteStream {}

internal protocol FlowersecByteStream: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
  func reset() async throws
}

internal actor RPCClient {
  static let maximumPortableRequestID: UInt64 = 9_007_199_254_740_991

  private struct PendingCall {
    var continuation: CheckedContinuation<Data, Error>
    var timeoutTask: Task<Void, Never>
  }

  private struct NotificationWork {
    var payload: Data
    var handlers: [@Sendable (Data) async -> Void]
  }

  private let stream: any FlowersecRPCStream
  private let path: FlowersecPath
  private var nextRequestID: UInt64 = 1
  private var pending: [UInt64: PendingCall] = [:]
  private var notifyHandlers: [UInt32: [UUID: @Sendable (Data) async -> Void]] = [:]
  private var notificationQueue: [NotificationWork] = []
  private var notificationTask: Task<Void, Never>?
  private var readTask: Task<Void, Never>?
  private var closed = false

  internal init(stream: any FlowersecRPCStream, path: FlowersecPath = .direct) {
    self.stream = stream
    self.path = path
  }

  init(
    stream: any FlowersecRPCStream,
    path: FlowersecPath = .direct,
    nextRequestID: UInt64
  ) {
    self.stream = stream
    self.path = path
    self.nextRequestID = nextRequestID
  }

  internal func start() {
    guard !closed, readTask == nil else { return }
    readTask = Task { await self.readLoop() }
  }

  internal func call<Request: Encodable, Response: Decodable>(
    _ typeID: UInt32,
    _ request: Request,
    timeout: Duration = .seconds(8)
  ) async throws -> Response {
    guard !closed else { throw FlowersecError.closed(path: path) }
    if Task.isCancelled {
      throw CancellationError()
    }
    guard nextRequestID <= Self.maximumPortableRequestID else {
      throw FlowersecError.invalidRPC("The RPC request ID range is exhausted.", path: path)
    }
    let requestID = nextRequestID
    nextRequestID += 1
    let payload = try JSONEncoder.flowersecRPC.encode(request)
    let envelope = RPCEnvelope(
      typeID: typeID,
      requestID: requestID,
      responseTo: 0,
      payload: payload,
      error: nil
    )
    let responsePayload: Data = try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let timeoutTask = Task {
          do {
            try await Task.sleep(for: timeout)
            self.finishRequest(
              requestID,
              result: .failure(FlowersecError.timeout(path: self.path, stage: .rpc))
            )
          } catch is CancellationError {
            return
          } catch {
            self.finishRequest(requestID, result: .failure(error))
          }
        }
        if Task.isCancelled {
          timeoutTask.cancel()
          continuation.resume(throwing: CancellationError())
          return
        }
        pending[requestID] = PendingCall(continuation: continuation, timeoutTask: timeoutTask)
        Task {
          do {
            try await self.writeEnvelope(envelope)
          } catch {
            self.finishRequest(requestID, result: .failure(error))
          }
        }
      }
    } onCancel: {
      Task {
        await self.finishRequest(requestID, result: .failure(CancellationError()))
      }
    }
    do {
      return try JSONDecoder.flowersecRPC.decode(Response.self, from: responsePayload)
    } catch let error as FlowersecError {
      throw error.withPath(path)
    } catch {
      throw FlowersecError(
        path: path,
        stage: .rpc,
        code: .rpcFailed,
        message: "The RPC response payload was invalid: \(error.localizedDescription)"
      )
    }
  }

  internal func notify<Payload: Encodable>(_ typeID: UInt32, _ payload: Payload) async throws {
    let envelope = RPCEnvelope(
      typeID: typeID,
      requestID: 0,
      responseTo: 0,
      payload: try JSONEncoder.flowersecRPC.encode(payload),
      error: nil
    )
    try await writeEnvelope(envelope)
  }

  internal nonisolated func onNotify(
    _ typeID: UInt32,
    handler: @escaping @Sendable (Data) async -> Void
  ) -> RPCSubscription {
    let id = UUID()
    Task { await self.addNotifyHandler(typeID: typeID, id: id, handler: handler) }
    return RPCSubscription {
      Task { await self.removeNotifyHandler(typeID: typeID, id: id) }
    }
  }

  private func addNotifyHandler(
    typeID: UInt32,
    id: UUID,
    handler: @escaping @Sendable (Data) async -> Void
  ) {
    guard !closed else { return }
    var handlers = notifyHandlers[typeID, default: [:]]
    handlers[id] = handler
    notifyHandlers[typeID] = handlers
  }

  internal func close() async {
    terminate(with: FlowersecError.closed(path: path))
  }

  private func removeNotifyHandler(typeID: UInt32, id: UUID) {
    notifyHandlers[typeID]?.removeValue(forKey: id)
    if notifyHandlers[typeID]?.isEmpty == true {
      notifyHandlers.removeValue(forKey: typeID)
    }
  }

  private func writeEnvelope(_ envelope: RPCEnvelope) async throws {
    guard !closed else { throw FlowersecError.closed(path: path) }
    do {
      try await FlowersecJSONFrame.write(envelope.encoded(), to: stream)
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
  }

  private func readLoop() async {
    do {
      while !Task.isCancelled && !closed {
        let frame = try await FlowersecJSONFrame.read(from: stream)
        let envelope = try RPCEnvelope(data: frame)
        try await handle(envelope)
      }
    } catch {
      let failure: Error
      if error is CancellationError {
        failure = error
      } else if let flowersecError = error as? FlowersecError {
        failure = flowersecError.withPath(path)
      } else {
        failure = FlowersecError(
          path: path,
          stage: .rpc,
          code: .rpcFailed,
          message: "The RPC response was invalid: \(error.localizedDescription)"
        )
      }
      terminate(with: failure)
    }
  }

  private func handle(_ envelope: RPCEnvelope) async throws {
    if envelope.responseTo != 0 {
      if let error = envelope.error {
        _ = finishRequest(
          envelope.responseTo,
          result: .failure(FlowersecRPCError(code: error.code, message: error.message))
        )
      } else {
        _ = finishRequest(envelope.responseTo, result: .success(envelope.payload))
      }
      return
    }
    guard envelope.requestID == 0 else {
      throw FlowersecError.invalidRPC(
        "The peer sent an RPC request to the client.",
        path: path
      )
    }
    let handlers: [@Sendable (Data) async -> Void]
    if let values = notifyHandlers[envelope.typeID]?.values {
      handlers = Array(values)
    } else {
      handlers = []
    }
    guard !handlers.isEmpty else { return }
    guard notificationQueue.count < FlowersecSDKDefaults.RPC.maxQueuedNotifications else {
      throw FlowersecError.resourceExhausted(
        path: path,
        stage: .rpc,
        "The RPC notification queue is full."
      )
    }
    notificationQueue.append(NotificationWork(payload: envelope.payload, handlers: handlers))
    startNotificationWorkerIfNeeded()
  }

  private func startNotificationWorkerIfNeeded() {
    guard notificationTask == nil else { return }
    notificationTask = Task { await self.runNotificationWorker() }
  }

  private func runNotificationWorker() async {
    while !Task.isCancelled, !closed, !notificationQueue.isEmpty {
      let work = notificationQueue.removeFirst()
      for handler in work.handlers {
        guard !Task.isCancelled, !closed else { break }
        await handler(work.payload)
      }
    }
    notificationTask = nil
  }

  private func terminate(with failure: Error) {
    guard !closed else { return }
    closed = true
    readTask?.cancel()
    readTask = nil
    notificationQueue.removeAll()
    notificationTask?.cancel()
    notifyHandlers.removeAll()
    let current = pending
    pending.removeAll()
    for call in current.values {
      call.timeoutTask.cancel()
      call.continuation.resume(throwing: failure)
    }
  }

  @discardableResult
  private func finishRequest(_ requestID: UInt64, result: Result<Data, Error>) -> Bool {
    guard let call = pending.removeValue(forKey: requestID) else { return false }
    call.timeoutTask.cancel()
    call.continuation.resume(with: result)
    return true
  }
}

internal struct RPCEnvelope: Equatable, Sendable {
  static let maximumPortableID: UInt64 = 9_007_199_254_740_991

  internal var typeID: UInt32
  internal var requestID: UInt64
  internal var responseTo: UInt64
  internal var payload: Data
  internal var error: RPCErrorPayload?

  internal init(
    typeID: UInt32, requestID: UInt64, responseTo: UInt64, payload: Data, error: RPCErrorPayload?
  ) {
    self.typeID = typeID
    self.requestID = requestID
    self.responseTo = responseTo
    self.payload = payload
    self.error = error
  }

  internal init(data: Data) throws {
    guard
      let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let typeNumber = root["type_id"] as? NSNumber,
      let requestID = Self.portableID(root["request_id"]),
      let responseTo = Self.portableID(root["response_to"])
    else {
      throw FlowersecError.invalidRPC("RPC envelope is invalid.")
    }
    typeID = typeNumber.uint32Value
    self.requestID = requestID
    self.responseTo = responseTo
    if let errorObject = root["error"] as? [String: Any],
      let code = errorObject["code"] as? NSNumber
    {
      let message = (errorObject["message"] as? String) ?? "RPC request failed."
      error = RPCErrorPayload(code: code.uint32Value, message: message)
    } else {
      error = nil
    }
    payload = try Self.encodeRawJSONObject(root["payload"] ?? [:])
  }

  internal func encoded() throws -> Data {
    guard requestID <= Self.maximumPortableID, responseTo <= Self.maximumPortableID else {
      throw FlowersecError.invalidRPC("RPC envelope IDs exceed the portable JSON range.")
    }
    var root: [String: Any] = [
      "type_id": NSNumber(value: typeID),
      "request_id": NSNumber(value: requestID),
      "response_to": NSNumber(value: responseTo),
      "payload": try Self.decodeRawJSONObject(payload),
    ]
    if let error {
      root["error"] = [
        "code": NSNumber(value: error.code),
        "message": error.message,
      ]
    }
    return try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
  }

  private static func decodeRawJSONObject(_ data: Data) throws -> Any {
    guard !data.isEmpty else { return [:] }
    return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
  }

  private static func encodeRawJSONObject(_ object: Any) throws -> Data {
    if object is NSNull {
      return Data("null".utf8)
    }
    guard JSONSerialization.isValidJSONObject(object) else {
      throw FlowersecError.invalidRPC("RPC payload JSON is invalid.")
    }
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }

  private static func portableID(_ value: Any?) -> UInt64? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return nil }
    let double = number.doubleValue
    guard double.isFinite, double >= 0, double <= Double(maximumPortableID),
      double.rounded(.towardZero) == double
    else { return nil }
    let integer = number.uint64Value
    return Double(integer) == double ? integer : nil
  }
}

internal struct RPCErrorPayload: Equatable, Sendable {
  internal var code: UInt32
  internal var message: String

  internal init(code: UInt32, message: String) {
    self.code = code
    self.message = message
  }
}

private struct StreamHello {
  var kind: String
  var version: UInt32

  func encoded() throws -> Data {
    try JSONSerialization.data(
      withJSONObject: ["kind": kind, "v": NSNumber(value: version)],
      options: [.sortedKeys]
    )
  }
}

internal enum FlowersecJSONFrame {
  internal static func write(_ data: Data, to stream: any FlowersecByteStream) async throws {
    guard data.count <= FlowersecWire.jsonFrameMaxBytes else {
      throw FlowersecError.invalidRPC("JSON frame is too large.")
    }
    var frame = Data()
    frame.appendUInt32BE(UInt32(data.count))
    frame.append(data)
    try await stream.write(frame)
  }

  internal static func read(from stream: any FlowersecByteStream) async throws -> Data {
    let header = try await stream.readExact(4)
    guard header.count == 4 else {
      throw FlowersecError.invalidRPC("JSON frame ended before the length header.")
    }
    let length = Int(header.readUInt32BE(at: 0))
    guard length <= FlowersecWire.jsonFrameMaxBytes else {
      throw FlowersecError.invalidRPC("JSON frame is too large.")
    }
    let payload = try await stream.readExact(length)
    guard payload.count == length else {
      throw FlowersecError.invalidRPC("JSON frame ended before the declared length.")
    }
    return payload
  }
}

extension JSONEncoder {
  static var flowersecRPC: JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return encoder
  }
}

extension JSONDecoder {
  static var flowersecRPC: JSONDecoder {
    JSONDecoder()
  }
}
