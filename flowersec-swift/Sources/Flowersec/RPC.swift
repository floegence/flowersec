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

public protocol FlowersecRPCStream: AnyObject, FlowersecByteStream {}

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
  private let path: FlowersecPath
  private var nextRequestID: UInt64 = 1
  private var pending: [UInt64: PendingCall] = [:]
  private var notifyHandlers: [UInt32: [UUID: @Sendable (Data) async -> Void]] = [:]
  private var readTask: Task<Void, Never>?
  private var closed = false

  public init(stream: any FlowersecRPCStream, path: FlowersecPath = .direct) {
    self.stream = stream
    self.path = path
  }

  public func start() {
    guard readTask == nil else { return }
    readTask = Task { await self.readLoop() }
  }

  public func call<Request: Encodable, Response: Decodable>(
    _ typeID: UInt32,
    _ request: Request,
    timeout: Duration = .seconds(8)
  ) async throws -> Response {
    guard !closed else { throw FlowersecError.closed(path: path) }
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
            self.finishRequest(
              requestID,
              result: .failure(FlowersecError.timeout(path: self.path, stage: .rpc))
            )
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
      call.continuation.resume(throwing: FlowersecError.closed(path: path))
    }
  }

  private func removeNotifyHandler(typeID: UInt32, id: UUID) {
    notifyHandlers[typeID]?.removeValue(forKey: id)
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
      closed = true
      let current = pending
      pending.removeAll()
      for call in current.values {
        call.timeoutTask.cancel()
        call.continuation.resume(throwing: failure)
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
  private let path: FlowersecPath

  init(rpc: RPCClient, yamux: FlowersecYamuxClient, path: FlowersecPath) {
    self.rpc = rpc
    self.yamux = yamux
    self.path = path
  }

  public func close() async {
    await rpc.close()
    await yamux.close()
  }

  public func probeLiveness(timeout: Duration = .seconds(10)) async throws -> Duration {
    try await yamux.probeLiveness(timeout: timeout)
  }

  public func terminated() async -> (any Error)? {
    await yamux.terminated()
  }

  public func openStream(kind: String) async throws -> any FlowersecByteStream {
    let trimmedKind = kind.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmedKind.isEmpty else {
      throw FlowersecError.invalidRPC("Stream kind is empty.", path: path)
    }
    let stream = try await yamux.openStream()
    do {
      try await FlowersecJSONFrame.write(
        StreamHello(kind: trimmedKind, version: 1).encoded(),
        to: stream
      )
    } catch let error as FlowersecError {
      throw error.withPath(path)
    }
    return stream
  }
}

private enum HandshakeRaceResult: @unchecked Sendable {
  case completed(FlowersecSecureChannel)
  case failed(any Error)
  case timedOut
}

public enum Flowersec {
  public static func connect(
    _ artifact: ConnectArtifact,
    options: ConnectOptions = ConnectOptions()
  ) async throws -> FlowersecClient {
    switch artifact {
    case .direct(let info, metadata: let metadata):
      return try await connectDirect(
        info,
        options: try await artifactOptions(options, metadata: metadata, path: .direct)
      )
    case .tunnel(let grant, metadata: let metadata):
      return try await connectTunnel(
        grant,
        options: try await artifactOptions(options, metadata: metadata, path: .tunnel)
      )
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
    try validate(options: options, path: .direct)
    try await FlowersecTransportSecurity.enforce(url: info.wsURL, path: .direct, options: options)
    let transport = FlowersecWebSocketBinaryTransport(
      url: info.wsURL,
      origin: options.origin,
      connectTimeout: options.connectTimeout,
      path: .direct,
      onDiagnosticEvent: options.onDiagnosticEvent
    )
    await transport.resume()
    return try await establishConnection(
      info,
      transport: transport,
      options: options,
      path: .direct,
      idleTimeout: nil
    )
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
    try validate(options: options, path: .tunnel)
    try await FlowersecTransportSecurity.enforce(url: grant.tunnelURL, path: .tunnel, options: options)
    let transport = FlowersecWebSocketBinaryTransport(
      url: grant.tunnelURL,
      origin: options.origin,
      connectTimeout: options.connectTimeout,
      path: .tunnel,
      onDiagnosticEvent: options.onDiagnosticEvent
    )
    await transport.resume()
    do {
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
    } catch {
      await transport.close()
      throw error
    }
    return try await establishConnection(
      DirectConnectInfo(
        wsURL: grant.tunnelURL,
        channelID: grant.channelID,
        psk: grant.psk,
        channelInitExpiresAtUnixS: grant.channelInitExpiresAtUnixS,
        defaultSuite: grant.defaultSuite
      ),
      transport: transport,
      options: options,
      path: .tunnel,
      idleTimeout: .seconds(max(0, grant.idleTimeoutSeconds))
    )
  }

  static func establishConnection(
    _ info: DirectConnectInfo,
    transport: any FlowersecBinaryTransport,
    options: ConnectOptions,
    path: FlowersecPath,
    idleTimeout: Duration?
  ) async throws -> FlowersecClient {
    var secure: FlowersecSecureChannel?
    var yamux: FlowersecYamuxClient?
    var stream: FlowersecYamuxStream?
    var rpc: RPCClient?
    do {
      let automaticLiveness = try resolvedLiveness(
        options.liveness,
        path: path,
        idleTimeout: idleTimeout
      )
      let establishedSecure = try await runHandshake(
        transport: transport,
        info: info,
        options: options,
        path: path
      )
      secure = establishedSecure
      let establishedYamux = FlowersecYamuxClient(
        channel: establishedSecure,
        limits: options.yamuxLimits,
        automaticLiveness: automaticLiveness,
        path: path,
        onDiagnosticEvent: options.onDiagnosticEvent
      )
      yamux = establishedYamux
      let establishedStream = try await establishedYamux.openStream()
      stream = establishedStream
      do {
        try await FlowersecJSONFrame.write(
          StreamHello(kind: "rpc", version: 1).encoded(),
          to: establishedStream
        )
      } catch let error as FlowersecError {
        throw error.withPath(path)
      }
      let establishedRPC = RPCClient(stream: establishedStream, path: path)
      rpc = establishedRPC
      await establishedRPC.start()
      await establishedYamux.start()
      try Task.checkCancellation()
      return FlowersecClient(rpc: establishedRPC, yamux: establishedYamux, path: path)
    } catch {
      await rpc?.close()
      await stream?.close()
      await yamux?.close()
      await secure?.close()
      await transport.close()
      if Task.isCancelled {
        throw CancellationError()
      }
      throw error
    }
  }

  private static func validate(options: ConnectOptions, path: FlowersecPath) throws {
    let maxPlaintext = FlowersecWire.maxRecordBytes - 18 - 16
    guard options.outboundRecordChunkBytes > 0,
      options.outboundRecordChunkBytes <= maxPlaintext
    else {
      throw FlowersecError(
        path: path,
        stage: .validate,
        code: .invalidOption,
        message: "outboundRecordChunkBytes must fit within the record plaintext limit."
      )
    }
    guard options.handshakeTimeout > .zero else {
      throw FlowersecError(
        path: path,
        stage: .validate,
        code: .invalidOption,
        message: "handshakeTimeout must be positive."
      )
    }
    guard options.maxOutboundBufferedBytes > 0 else {
      throw FlowersecError(
        path: path,
        stage: .validate,
        code: .invalidOption,
        message: "maxOutboundBufferedBytes must be positive."
      )
    }
    do {
      try options.yamuxLimits.validate()
      _ = try resolvedLiveness(options.liveness, path: path, idleTimeout: .seconds(1))
    } catch var error as FlowersecError {
      error.path = path
      error.stage = .validate
      error.code = .invalidOption
      throw error
    }
  }

  private static func runHandshake(
    transport: any FlowersecBinaryTransport,
    info: DirectConnectInfo,
    options: ConnectOptions,
    path: FlowersecPath
  ) async throws -> FlowersecSecureChannel {
    try await withTaskCancellationHandler {
      try await withThrowingTaskGroup(of: HandshakeRaceResult.self) { group in
        group.addTask {
          do {
            return .completed(
              try await FlowersecHandshake.runClientHandshake(
                transport: transport,
                info: info,
                outboundRecordChunkBytes: options.outboundRecordChunkBytes,
                maxOutboundBufferedBytes: options.maxOutboundBufferedBytes,
                path: path,
                onDiagnosticEvent: options.onDiagnosticEvent
              )
            )
          } catch {
            return .failed(error)
          }
        }
        group.addTask {
          do {
            try await Task.sleep(for: options.handshakeTimeout)
            return .timedOut
          } catch {
            return .failed(error)
          }
        }

        guard let result = try await group.next() else {
          throw FlowersecError(
            path: path,
            stage: .handshake,
            code: .handshakeFailed,
            message: "The Flowersec handshake ended without a result."
          )
        }
        group.cancelAll()
        if Task.isCancelled {
          await transport.close()
          throw CancellationError()
        }
        switch result {
        case .completed(let channel):
          return channel
        case .failed(let error):
          throw error
        case .timedOut:
          await transport.close()
          throw FlowersecError(
            path: path,
            stage: .handshake,
            code: .timeout,
            message: "The Flowersec handshake timed out."
          )
        }
      }
    } onCancel: {
      Task { await transport.close() }
    }
  }

  private static func artifactOptions(
    _ options: ConnectOptions,
    metadata: ConnectArtifactMetadata,
    path: FlowersecPath
  ) async throws -> ConnectOptions {
    var resolved = options
    if let correlation = metadata.correlation, let observer = options.onDiagnosticEvent {
      resolved.onDiagnosticEvent = { event in
        var correlated = event
        if let traceID = correlation.traceID {
          correlated.traceID = traceID
        }
        if let sessionID = correlation.sessionID {
          correlated.sessionID = sessionID
        }
        observer(correlated)
      }
    }
    for entry in metadata.scoped {
      guard let resolver = options.scopeResolvers[entry.scope] else {
        if entry.critical {
          throw FlowersecError(
            path: path,
            stage: .validate,
            code: .resolveFailed,
            message: "Missing scope resolver for \(entry.scope)@\(entry.scopeVersion)."
          )
        }
        resolved.onDiagnosticEvent?(
          DiagnosticEvent(
            path: path,
            stage: .scope,
            codeDomain: .event,
            code: "scope_ignored_missing_resolver",
            result: .skip
          )
        )
        continue
      }
      do {
        try await resolver(entry)
      } catch {
        if !entry.critical, options.relaxedOptionalScopeValidation {
          resolved.onDiagnosticEvent?(
            DiagnosticEvent(
              path: path,
              stage: .scope,
              codeDomain: .event,
              code: "scope_ignored_relaxed_validation",
              result: .skip
            )
          )
          continue
        }
        throw FlowersecError(
          path: path,
          stage: .validate,
          code: .resolveFailed,
          message: "Scope validation failed for \(entry.scope)@\(entry.scopeVersion)."
        )
      }
    }
    return resolved
  }

  private static func resolvedLiveness(
    _ options: LivenessOptions,
    path: FlowersecPath,
    idleTimeout: Duration?
  ) throws -> (interval: Duration, timeout: Duration)? {
    switch options {
    case .disabled:
      return nil
    case .pathDefault:
      guard path == .tunnel, let idleTimeout, idleTimeout > .zero else { return nil }
      let interval = max(.milliseconds(500), idleTimeout / 2)
      return (interval, min(.seconds(10), interval))
    case .enabled(let interval, let timeout):
      guard interval > .zero, timeout > .zero else {
        throw FlowersecError.invalidConnectInfo(
          "Liveness interval and timeout must both be positive."
        )
      }
      return (interval, timeout)
    }
  }
}

public struct RPCEnvelope: Equatable, Sendable {
  public var typeID: UInt32
  public var requestID: UInt64
  public var responseTo: UInt64
  public var payload: Data
  public var error: RPCErrorPayload?

  public init(
    typeID: UInt32, requestID: UInt64, responseTo: UInt64, payload: Data, error: RPCErrorPayload?
  ) {
    self.typeID = typeID
    self.requestID = requestID
    self.responseTo = responseTo
    self.payload = payload
    self.error = error
  }

  public init(data: Data) throws {
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

  public func encoded() throws -> Data {
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

public struct RPCErrorPayload: Equatable, Sendable {
  public var code: UInt32
  public var message: String

  public init(code: UInt32, message: String) {
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

public enum FlowersecJSONFrame {
  public static func write(_ data: Data, to stream: any FlowersecByteStream) async throws {
    guard data.count <= FlowersecWire.jsonFrameMaxBytes else {
      throw FlowersecError.invalidRPC("JSON frame is too large.")
    }
    var frame = Data()
    frame.appendUInt32BE(UInt32(data.count))
    frame.append(data)
    try await stream.write(frame)
  }

  public static func read(from stream: any FlowersecByteStream) async throws -> Data {
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
