import CoreFoundation
import Foundation

internal struct FlowersecRPCError: LocalizedError, Equatable, Sendable {
  internal var code: UInt32
  internal var message: String?

  internal init(code: UInt32, message: String? = nil) {
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

internal final class RPCSubscription: RPCNotificationSubscription, @unchecked Sendable {
  private let lock = NSLock()
  private var cancelHandler: (@Sendable () async -> Void)?

  internal init(cancelHandler: @escaping @Sendable () async -> Void) {
    self.cancelHandler = cancelHandler
  }

  internal func cancel() async {
    let handler = lock.withLock {
      let current = cancelHandler
      cancelHandler = nil
      return current
    }
    await handler?()
  }

  deinit {
    let handler = lock.withLock {
      let current = cancelHandler
      cancelHandler = nil
      return current
    }
    if let handler {
      Task { await handler() }
    }
  }
}

internal protocol FlowersecRPCStream: AnyObject, FlowersecByteStream {}

internal final class RPCWriteAdmission: @unchecked Sendable {
  @TaskLocal static var current: RPCWriteAdmission?
  struct Withdrawn: Error {}
  private let lock = NSLock()
  private let deadline: ContinuousClock.Instant
  private var committed = false
  private var withdrawn = false

  init(deadline: ContinuousClock.Instant) { self.deadline = deadline }

  func withdraw() { lock.withLock { withdrawn = true } }

  func commit() throws {
    try lock.withLock {
      guard !committed else { return }
      guard !withdrawn, ContinuousClock.now < deadline else { throw Withdrawn() }
      committed = true
    }
  }
}

internal protocol FlowersecByteStream: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
  func reset() async throws
}

internal actor RPCClient {
  static let maximumPortableRequestID: UInt64 = 9_007_199_254_740_991

  private final class PendingCall {
    let typeID: UInt32
    let deadline: ContinuousClock.Instant
    let admission: RPCWriteAdmission
    init(typeID: UInt32, deadline: ContinuousClock.Instant) {
      self.typeID = typeID; self.deadline = deadline
      admission = RPCWriteAdmission(deadline: deadline)
    }
    var continuation: CheckedContinuation<Data, Error>?
    var timeoutTask: Task<Void, Never>?
    var writer: Task<Void, Never>?
  }

  private struct NotificationWork {
    var payload: Data
    var handlers: [@Sendable (Data) async -> Void]
  }

  private let stream: any FlowersecRPCStream
  private let frameLimits: RPCFrameLimits
  private let maxConcurrentRequests: Int
  private let path: FlowersecPath
  private var nextRequestID: UInt64 = 1
  private var pending: [UInt64: PendingCall] = [:]
  private var closingWriters: [Task<Void, Never>] = []
  private var notifyHandlers: [UInt32: [UUID: @Sendable (Data) async -> Void]] = [:]
  private var notificationQueue: [NotificationWork] = []
  private var notificationTask: Task<Void, Never>?
  private var readTask: Task<Void, Never>?
  private var closed = false

  internal init(stream: any FlowersecRPCStream, path: FlowersecPath = .direct,
                frameLimits: RPCFrameLimits = .standard,
                maxConcurrentRequests: Int = FlowersecSDKDefaults.RPC.maxConcurrentRequests) {
    self.stream = stream
    self.frameLimits = frameLimits
    self.maxConcurrentRequests = maxConcurrentRequests
    self.path = path
  }

  init(
    stream: any FlowersecRPCStream,
    path: FlowersecPath = .direct,
    nextRequestID: UInt64
  ) {
    frameLimits = .standard
    maxConcurrentRequests = FlowersecSDKDefaults.RPC.maxConcurrentRequests
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
    try await call(typeID, request, deadline: ContinuousClock.now.advanced(by: timeout))
  }

  internal func call<Request: Encodable, Response: Decodable>(
    _ typeID: UInt32,
    _ request: Request,
    deadline: ContinuousClock.Instant
  ) async throws -> Response {
    guard !closed else { throw FlowersecError.closed(path: path) }
    if Task.isCancelled {
      throw CancellationError()
    }
    guard ContinuousClock.now < deadline else { throw FlowersecError.timeout(path: path, stage: .rpc) }
    guard nextRequestID <= Self.maximumPortableRequestID else {
      throw FlowersecError.invalidRPC("The RPC request ID range is exhausted.", path: path)
    }
    guard pending.count < maxConcurrentRequests else {
      throw FlowersecError.resourceExhausted(path: path, stage: .rpc, "The RPC request limit is reached.")
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
    guard ContinuousClock.now < deadline else { throw FlowersecError.timeout(path: path, stage: .rpc) }
    pending[requestID] = PendingCall(typeID: typeID, deadline: deadline)
    let responsePayload: Data = try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        guard let call = pending[requestID] else {
          continuation.resume(throwing: FlowersecError.closed(path: path))
          return
        }
        guard !Task.isCancelled else {
          pending.removeValue(forKey: requestID)
          continuation.resume(throwing: CancellationError())
          return
        }
        call.continuation = continuation
        call.timeoutTask = Task {
          do {
            try await Task.sleep(until: deadline, clock: .continuous)
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
        call.writer = Task {
          defer {
            call.writer = nil
            if call.continuation == nil { pending.removeValue(forKey: requestID) }
          }
          guard !closed, call.continuation != nil else { return }
          do {
            guard ContinuousClock.now < deadline else { throw FlowersecError.timeout(path: path, stage: .rpc) }
            try await RPCWriteAdmission.$current.withValue(call.admission) {
              try await self.writeEnvelope(envelope, deadline: deadline)
            }
          } catch is RPCWriteAdmission.Withdrawn {
            self.finishRequest(requestID, result: .failure(FlowersecError.timeout(path: path, stage: .rpc)))
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

  internal func subscribeNotification(
    _ typeID: UInt32,
    handler: @escaping @Sendable (Data) async -> Void
  ) throws -> RPCSubscription {
    guard !closed else { throw FlowersecError.closed(path: path) }
    let id = UUID()
    addNotifyHandler(typeID: typeID, id: id, handler: handler)
    return RPCSubscription {
      await self.removeNotifyHandler(typeID: typeID, id: id)
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

  internal func waitForWorkers() async {
    let writers = closingWriters
    for writer in writers { await writer.value }
    closingWriters.removeAll()
    await readTask?.value
    await notificationTask?.value
  }

  private func removeNotifyHandler(typeID: UInt32, id: UUID) {
    notifyHandlers[typeID]?.removeValue(forKey: id)
    if notifyHandlers[typeID]?.isEmpty == true {
      notifyHandlers.removeValue(forKey: typeID)
    }
  }

  private func writeEnvelope(_ envelope: RPCEnvelope, deadline: ContinuousClock.Instant? = nil) async throws {
    guard !closed else { throw FlowersecError.closed(path: path) }
    do {
      let bytes = try envelope.encoded()
      try Task.checkCancellation()
      if let deadline, ContinuousClock.now >= deadline { throw FlowersecError.timeout(path: path, stage: .rpc) }
      try await FlowersecJSONFrame.write(bytes, to: stream, limit: frameLimits.send)
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
  }

  private func readLoop() async {
    do {
      while !Task.isCancelled && !closed {
        let frame = try await FlowersecJSONFrame.read(from: stream, limit: frameLimits.receive)
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
      guard let call = pending[envelope.responseTo], call.continuation != nil else { return }
      if ContinuousClock.now >= call.deadline {
        _ = finishRequest(envelope.responseTo, result: .failure(FlowersecError.timeout(path: path, stage: .rpc)))
        return
      }
      if call.typeID != envelope.typeID {
        throw FlowersecError.invalidRPC("The RPC response type does not match the request.", path: path)
      }
      if let error = envelope.error {
        _ = finishRequest(
          envelope.responseTo,
          result: .failure(
            FlowersecRPCError(code: error.code, message: error.message))
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
    if !closed, !notificationQueue.isEmpty {
      startNotificationWorkerIfNeeded()
    }
  }

  private func terminate(with failure: Error) {
    guard !closed else { return }
    closed = true
    readTask?.cancel()
    notificationQueue.removeAll()
    notificationTask?.cancel()
    notifyHandlers.removeAll()
    let current = pending
    pending.removeAll()
    for call in current.values {
      if let writer = call.writer { closingWriters.append(writer); writer.cancel() }
      call.timeoutTask?.cancel()
      call.continuation?.resume(throwing: failure)
      call.continuation = nil
    }
  }

  @discardableResult
  private func finishRequest(_ requestID: UInt64, result: Result<Data, Error>) -> Bool {
    guard let call = pending[requestID], let continuation = call.continuation else { return false }
    call.admission.withdraw()
    call.continuation = nil
    call.timeoutTask?.cancel()
    call.timeoutTask = nil
    if call.writer == nil { pending.removeValue(forKey: requestID) }
    continuation.resume(with: result)
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
      let typeID = Self.portableUInt32(root["type_id"]),
      typeID != 0,
      let requestID = Self.portableID(root["request_id"]),
      let responseTo = Self.portableID(root["response_to"]),
      root.keys.contains("payload"),
      Set(root.keys).isSubset(of: ["type_id", "request_id", "response_to", "payload", "error"]),
      root.count == (root.keys.contains("error") ? 5 : 4),
      requestID == 0 || responseTo == 0
    else {
      throw FlowersecError.invalidRPC("RPC envelope is invalid.")
    }
    self.typeID = typeID
    self.requestID = requestID
    self.responseTo = responseTo
    if let rawError = root["error"], !(rawError is NSNull) {
      guard requestID == 0, responseTo != 0 else {
        throw FlowersecError.invalidRPC("RPC error is only valid on a response.")
      }
      guard let errorObject = rawError as? [String: Any],
        Set(errorObject.keys).isSubset(of: ["code", "message"]),
        let code = Self.portableUInt32(errorObject["code"]),
        code != 0
      else {
        throw FlowersecError.invalidRPC("RPC error payload is invalid.")
      }
      if let rawMessage = errorObject["message"], !(rawMessage is String) {
        throw FlowersecError.invalidRPC("RPC error message is invalid.")
      }
      error = try RPCErrorPayload(validatingCode: code, message: errorObject["message"] as? String)
    } else {
      error = nil
    }
    payload = try Self.encodeRawJSONObject(root["payload"] as Any)
  }

  internal func encoded() throws -> Data {
    guard typeID != 0 else { throw FlowersecError.invalidRPC("Invalid RPC method ID.") }
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
      let error = error.sanitizedForWire
      var errorObject: [String: Any] = ["code": NSNumber(value: error.code)]
      if let message = error.message { errorObject["message"] = message }
      root["error"] = errorObject
    }
    return try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .withoutEscapingSlashes])
  }

  private static func decodeRawJSONObject(_ data: Data) throws -> Any {
    guard !data.isEmpty else { return [:] }
    return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
  }

  private static func encodeRawJSONObject(_ object: Any) throws -> Data {
    do {
      return try JSONSerialization.data(
        withJSONObject: object,
        options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes]
      )
    } catch {
      throw FlowersecError.invalidRPC("RPC payload JSON is invalid.")
    }
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

  private static func portableUInt32(_ value: Any?) -> UInt32? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { return nil }
    let double = number.doubleValue
    guard double.isFinite, double >= 0, double <= Double(UInt32.max),
      double.rounded(.towardZero) == double
    else { return nil }
    let integer = number.uint32Value
    return Double(integer) == double ? integer : nil
  }
}

internal struct RPCErrorPayload: Equatable, Sendable {
  private static let maximumMessageBytes = 1_024
  private static let internalError = RPCErrorPayload(code: 500, message: "internal error")

  internal var code: UInt32
  internal var message: String?

  internal init(code: UInt32, message: String? = nil) {
    self.code = code
    self.message = message
  }

  internal init(validatingCode code: UInt32, message: String?) throws {
    guard code != 0, (message?.utf8.count ?? 0) <= Self.maximumMessageBytes else {
      throw FlowersecError.invalidRPC("RPC error payload is invalid.")
    }
    self.init(code: code, message: message)
  }

  internal var sanitizedForWire: RPCErrorPayload {
    guard code != 0, (message?.utf8.count ?? 0) <= Self.maximumMessageBytes else {
      return Self.internalError
    }
    return self
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
  internal static func write(_ data: Data, to stream: any FlowersecByteStream,
                             limit: Int = FlowersecWire.jsonFrameMaxBytes) async throws {
    guard data.count <= limit else {
      throw FlowersecError.invalidRPC("JSON frame is too large.")
    }
    var frame = Data()
    frame.appendUInt32BE(UInt32(data.count))
    frame.append(data)
    try await stream.write(frame)
  }

  internal static func read(from stream: any FlowersecByteStream,
                            limit: Int = FlowersecWire.jsonFrameMaxBytes) async throws -> Data {
    let header = try await stream.readExact(4)
    guard header.count == 4 else {
      throw FlowersecError.invalidRPC("JSON frame ended before the length header.")
    }
    let length = Int(header.readUInt32BE(at: 0))
    guard length <= limit else {
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
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return encoder
  }
}

extension JSONDecoder {
  static var flowersecRPC: JSONDecoder {
    JSONDecoder()
  }
}
