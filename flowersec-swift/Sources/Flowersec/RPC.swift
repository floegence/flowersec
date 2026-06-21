import Foundation

public struct FlowersecRPCError: LocalizedError, Equatable, Sendable {
  public var code: UInt32
  public var message: String

  public init(code: UInt32, message: String) {
    self.code = code
    self.message = message
  }

  public var errorDescription: String? { message }
}

public struct RPCSubscription: Sendable {
  private let cancelHandler: @Sendable () -> Void

  public init(cancelHandler: @escaping @Sendable () -> Void) {
    self.cancelHandler = cancelHandler
  }

  public func cancel() {
    cancelHandler()
  }
}

protocol FlowersecRPCStream: AnyObject, FlowersecByteStream {}

public protocol FlowersecByteStream: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
}

public actor RPCClient {
  private struct PendingCall {
    var continuation: CheckedContinuation<Data, Error>
    var timeoutTask: Task<Void, Never>
  }

  private let stream: any FlowersecRPCStream
  private var nextRequestID: UInt64 = 1
  private var pending: [UInt64: PendingCall] = [:]
  private var notifyHandlers: [UInt32: [UUID: @Sendable (Data) async -> Void]] = [:]
  private var readTask: Task<Void, Never>?
  private var closed = false

  init(stream: any FlowersecRPCStream) {
    self.stream = stream
  }

  func start() {
    guard readTask == nil else { return }
    readTask = Task { await self.readLoop() }
  }

  public func call<Request: Encodable, Response: Decodable>(
    _ typeID: UInt32,
    _ request: Request,
    timeout: Duration = .seconds(8)
  ) async throws -> Response {
    guard !closed else { throw FlowersecError.closed }
    if Task.isCancelled {
      throw CancellationError()
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
            self.finishRequest(requestID, result: .failure(FlowersecError.timeout))
          } catch {}
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
    return try JSONDecoder.flowersecRPC.decode(Response.self, from: responsePayload)
  }

  public func notify<Payload: Encodable>(_ typeID: UInt32, _ payload: Payload) async throws {
    let envelope = RPCEnvelope(
      typeID: typeID,
      requestID: 0,
      responseTo: 0,
      payload: try JSONEncoder.flowersecRPC.encode(payload),
      error: nil
    )
    try await writeEnvelope(envelope)
  }

  public nonisolated func onNotify(
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
    var handlers = notifyHandlers[typeID, default: [:]]
    handlers[id] = handler
    notifyHandlers[typeID] = handlers
  }

  public func close() async {
    closed = true
    readTask?.cancel()
    readTask = nil
    let current = pending
    pending.removeAll()
    for call in current.values {
      call.timeoutTask.cancel()
      call.continuation.resume(throwing: FlowersecError.closed)
    }
  }

  private func removeNotifyHandler(typeID: UInt32, id: UUID) {
    notifyHandlers[typeID]?.removeValue(forKey: id)
  }

  private func writeEnvelope(_ envelope: RPCEnvelope) async throws {
    guard !closed else { throw FlowersecError.closed }
    try await FlowersecJSONFrame.write(envelope.encoded(), to: stream)
  }

  private func readLoop() async {
    do {
      while !Task.isCancelled && !closed {
        let frame = try await FlowersecJSONFrame.read(from: stream)
        let envelope = try RPCEnvelope(data: frame)
        try await handle(envelope)
      }
    } catch {
      closed = true
      let current = pending
      pending.removeAll()
      for call in current.values {
        call.timeoutTask.cancel()
        call.continuation.resume(throwing: error)
      }
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
      throw FlowersecError.invalidRPC("The peer sent an RPC request to the client.")
    }
    let handlers: [@Sendable (Data) async -> Void]
    if let values = notifyHandlers[envelope.typeID]?.values {
      handlers = Array(values)
    } else {
      handlers = []
    }
    for handler in handlers {
      let payload = envelope.payload
      Task { await handler(payload) }
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

public final class FlowersecClient: @unchecked Sendable {
  public let rpc: RPCClient
  private let yamux: FlowersecYamuxClient

  init(rpc: RPCClient, yamux: FlowersecYamuxClient) {
    self.rpc = rpc
    self.yamux = yamux
  }

  public func close() async {
    await rpc.close()
    await yamux.close()
  }

  public func openStream(kind: String) async throws -> any FlowersecByteStream {
    let trimmedKind = kind.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmedKind.isEmpty else {
      throw FlowersecError.invalidRPC("Stream kind is empty.")
    }
    let stream = try await yamux.openStream()
    try await FlowersecJSONFrame.write(
      StreamHello(kind: trimmedKind, version: 1).encoded(),
      to: stream
    )
    return stream
  }
}

public enum Flowersec {
  public static func connect(
    _ artifact: ConnectArtifact,
    options: ConnectOptions = ConnectOptions()
  ) async throws -> FlowersecClient {
    switch artifact {
    case .direct(let info, metadata: _):
      return try await connectDirect(info, options: options)
    case .tunnel(let grant, metadata: _):
      return try await connectTunnel(grant, options: options)
    }
  }

  public static func connectDirect(
    info: DirectConnectInfo,
    origin: String
  ) async throws -> FlowersecClient {
    let options = DirectConnectOptions(origin: origin)
    return try await connectDirect(info, options: options)
  }

  public static func connectDirect(
    _ info: DirectConnectInfo,
    options: DirectConnectOptions = DirectConnectOptions()
  ) async throws -> FlowersecClient {
    let transport = FlowersecWebSocketBinaryTransport(
      url: info.wsURL,
      origin: options.origin,
      connectTimeout: options.connectTimeout
    )
    await transport.resume()
    let secure = try await FlowersecHandshake.runClientHandshake(transport: transport, info: info)
    let yamux = FlowersecYamuxClient(channel: secure)
    let stream = try await yamux.openStream()
    try await FlowersecJSONFrame.write(StreamHello(kind: "rpc", version: 1).encoded(), to: stream)
    let rpc = RPCClient(stream: stream)
    await rpc.start()
    return FlowersecClient(rpc: rpc, yamux: yamux)
  }

  public static func connectTunnel(
    _ grant: ChannelInitGrant,
    options: TunnelConnectOptions = TunnelConnectOptions()
  ) async throws -> FlowersecClient {
    guard grant.role == 1 else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidInput,
        message: "Tunnel client grants must use the client role."
      )
    }
    guard grant.allowedSuites.contains(grant.defaultSuite) else {
      throw FlowersecError(
        path: .tunnel,
        stage: .validate,
        code: .invalidSuite,
        message: "Default suite must be included in allowed_suites."
      )
    }
    let transport = FlowersecWebSocketBinaryTransport(
      url: grant.tunnelURL,
      origin: options.origin,
      connectTimeout: options.connectTimeout
    )
    await transport.resume()
    try await transport.writeText(
      TunnelAttach(
        v: 1,
        channelID: grant.channelID,
        role: grant.role,
        token: grant.token,
        endpointInstanceID: Data.secureRandom(count: 16).base64URLEncodedString(),
        caps: nil
      ).encoded()
    )
    return try await connectDirect(
      DirectConnectInfo(
        wsURL: grant.tunnelURL,
        channelID: grant.channelID,
        psk: grant.psk,
        channelInitExpiresAtUnixS: grant.channelInitExpiresAtUnixS,
        defaultSuite: grant.defaultSuite
      ),
      transport: transport
    )
  }

  private static func connectDirect(
    _ info: DirectConnectInfo,
    transport: FlowersecWebSocketBinaryTransport
  ) async throws -> FlowersecClient {
    let secure = try await FlowersecHandshake.runClientHandshake(transport: transport, info: info)
    let yamux = FlowersecYamuxClient(channel: secure)
    let stream = try await yamux.openStream()
    try await FlowersecJSONFrame.write(StreamHello(kind: "rpc", version: 1).encoded(), to: stream)
    let rpc = RPCClient(stream: stream)
    await rpc.start()
    return FlowersecClient(rpc: rpc, yamux: yamux)
  }
}

struct RPCEnvelope {
  var typeID: UInt32
  var requestID: UInt64
  var responseTo: UInt64
  var payload: Data
  var error: RPCErrorPayload?

  init(
    typeID: UInt32, requestID: UInt64, responseTo: UInt64, payload: Data, error: RPCErrorPayload?
  ) {
    self.typeID = typeID
    self.requestID = requestID
    self.responseTo = responseTo
    self.payload = payload
    self.error = error
  }

  init(data: Data) throws {
    guard
      let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      let typeNumber = root["type_id"] as? NSNumber,
      let requestNumber = root["request_id"] as? NSNumber,
      let responseNumber = root["response_to"] as? NSNumber
    else {
      throw FlowersecError.invalidRPC("RPC envelope is invalid.")
    }
    typeID = typeNumber.uint32Value
    requestID = requestNumber.uint64Value
    responseTo = responseNumber.uint64Value
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

  func encoded() throws -> Data {
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
    return try JSONSerialization.jsonObject(with: data)
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
}

struct RPCErrorPayload {
  var code: UInt32
  var message: String
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

enum FlowersecJSONFrame {
  static func write(_ data: Data, to stream: any FlowersecByteStream) async throws {
    guard data.count <= FlowersecWire.jsonFrameMaxBytes else {
      throw FlowersecError.invalidRPC("JSON frame is too large.")
    }
    var frame = Data()
    frame.appendUInt32BE(UInt32(data.count))
    frame.append(data)
    try await stream.write(frame)
  }

  static func read(from stream: any FlowersecByteStream) async throws -> Data {
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
