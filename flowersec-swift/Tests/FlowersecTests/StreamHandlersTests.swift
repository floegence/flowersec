import Foundation
import Testing

@testable import Flowersec

@Test
func streamHandlersServeEstablishedEndpointClientSession() async throws {
  let signal = StreamHandlerSignal()
  let stream = StreamHandlerTestByteStream()
  let session = StreamHandlerTestSession(stream: stream)
  let handlers = try StreamHandlers(options: StreamHandlerOptions(maxConcurrentStreams: 2))
  try handlers.handleStream(kind: "files/read") { _ in
    await signal.fire()
  }

  let serving = Task {
    try await handlers.serve(session: session)
  }
  await signal.wait()
  #expect(throws: HandlerRegistrationError.frozen) {
    try handlers.handleStream(kind: "late") { _ in }
  }
  serving.cancel()
  do {
    try await serving.value
    Issue.record("stream serving unexpectedly succeeded after cancellation")
  } catch is CancellationError {
    // Expected public task cancellation.
  }
  #expect(await stream.writeClosed)
  #expect(!(await stream.wasReset))
  #expect(await session.closeCount == 1)
}

@Test
func streamHandlersApplySharedOpenKindContract() throws {
  for version in [2, 3] {
    let url = packageRoot().appendingPathComponent(
      "testdata/transport_v\(version)/session_handler_vectors.json")
    let vectors = try JSONDecoder().decode(
      StreamHandlerRegistrationVectors.self,
      from: Data(contentsOf: url)
    )

    for vector in vectors.streamKinds {
      let handlers = try StreamHandlers()
      let kind = String(repeating: vector.unit, count: vector.repetitions) + vector.suffix
      do {
        try handlers.handleStream(kind: kind) { _ in }
        #expect(vector.valid, "unexpected valid v\(version) stream kind: \(vector.id)")
      } catch let error as HandlerRegistrationError {
        #expect(!vector.valid, "unexpected invalid v\(version) stream kind: \(vector.id)")
        #expect(error == .invalidHandler)
      }
    }
  }

  #expect(throws: HandlerRegistrationError.invalidHandler) {
    _ = try StreamHandlers(options: StreamHandlerOptions(maxConcurrentStreams: 0))
  }
  #expect(throws: HandlerRegistrationError.invalidHandler) {
    _ = try StreamHandlers(options: StreamHandlerOptions(maxConcurrentStreams: 129))
  }

  let duplicate = try StreamHandlers()
  try duplicate.handleStream(kind: "files/read") { _ in }
  #expect(throws: HandlerRegistrationError.alreadyRegistered) {
    try duplicate.handleStream(kind: "files/read") { _ in }
  }
}

@Test
func streamHandlersIsolateFailuresAndContinueDispatch() async throws {
  let success = StreamHandlerTestByteStream(kind: "success")
  let failure = StreamHandlerTestByteStream(kind: "failure")
  let closeFailure = StreamHandlerTestByteStream(
    kind: "close-failure",
    closeWriteError: .operationFailed
  )
  let unknown = StreamHandlerTestByteStream(kind: "unknown")
  let session = StreamHandlerTestSession(
    streams: [success, failure, closeFailure, unknown],
    terminalError: .closed
  )
  let handlers = try StreamHandlers(options: StreamHandlerOptions(maxConcurrentStreams: 4))
  try handlers.handleStream(kind: "success") { _ in }
  try handlers.handleStream(kind: "failure") { _ in
    throw SessionError.operationFailed
  }
  try handlers.handleStream(kind: "close-failure") { _ in }

  do {
    try await handlers.serve(session: session)
    Issue.record("stream serving unexpectedly succeeded after Session close")
  } catch let error as SessionError {
    #expect(error == .closed)
  }

  #expect(await success.closeWriteCount == 1)
  #expect(await success.resetCount == 0)
  #expect(await failure.resetCount == 1)
  #expect(await closeFailure.closeWriteCount == 1)
  #expect(await closeFailure.resetCount == 1)
  #expect(await unknown.resetCount == 1)
  #expect(await session.closeCount == 1)
}

@Test
func streamHandlersEnforceConcurrencyAndCloseBeforeWaitingForCancellation() async throws {
  let events = StreamHandlerEventRecorder()
  let active = StreamHandlerTestByteStream(kind: "held")
  let excess = StreamHandlerTestByteStream(kind: "held")
  let session = StreamHandlerTestSession(
    streams: [active, excess],
    terminalError: .closed,
    events: events
  )
  let handlers = try StreamHandlers(options: StreamHandlerOptions(maxConcurrentStreams: 1))
  try handlers.handleStream(kind: "held") { _ in
    while !Task.isCancelled { await Task.yield() }
    await events.append("handler-canceled")
  }

  do {
    try await handlers.serve(session: session)
    Issue.record("stream serving unexpectedly succeeded after Session close")
  } catch let error as SessionError {
    #expect(error == .closed)
  }

  #expect(await active.closeWriteCount == 1)
  #expect(await excess.resetCount == 1)
  #expect(await session.closeCount == 1)
  #expect(await events.values == ["session-close", "handler-canceled"])
}

private struct StreamHandlerRegistrationVectors: Decodable {
  let streamKinds: [StreamHandlerRegistrationVector]

  private enum CodingKeys: String, CodingKey {
    case streamKinds = "stream_kinds"
  }
}

private struct StreamHandlerRegistrationVector: Decodable {
  let id: String
  let unit: String
  let repetitions: Int
  let suffix: String
  let valid: Bool

  private enum CodingKeys: String, CodingKey {
    case id, unit, suffix, valid
    case repetitions = "repeat"
  }
}

private actor StreamHandlerSignal {
  private var fired = false
  private var waiter: CheckedContinuation<Void, Never>?

  func fire() {
    fired = true
    waiter?.resume()
    waiter = nil
  }

  func wait() async {
    if fired { return }
    await withCheckedContinuation { waiter = $0 }
  }
}

private actor StreamHandlerEventRecorder {
  private(set) var values: [String] = []

  func append(_ value: String) {
    values.append(value)
  }
}

private actor StreamHandlerTestByteStream: ByteStream {
  nonisolated let kind: String
  private let closeWriteError: SessionError?
  private(set) var closeWriteCount = 0
  private(set) var resetCount = 0

  init(kind: String = "files/read", closeWriteError: SessionError? = nil) {
    self.kind = kind
    self.closeWriteError = closeWriteError
  }

  var writeClosed: Bool { closeWriteCount > 0 }
  var wasReset: Bool { resetCount > 0 }

  func read(maxBytes: Int) async throws -> Data? {
    _ = maxBytes
    return nil
  }

  func write(_ data: Data) async throws -> Int { data.count }
  func closeWrite() async throws {
    closeWriteCount += 1
    if let closeWriteError { throw closeWriteError }
  }

  func reset() async throws { resetCount += 1 }
  func close() async throws { resetCount += 1 }
  func terminalError() async -> SessionError? { nil }
}

private actor StreamHandlerTestSession: Session {
  nonisolated let rpc: any RPCPeer = StreamHandlerTestRPCPeer()
  private let outboundStream: any ByteStream
  private var incoming: [IncomingStream]
  private let terminalError: SessionError?
  private let events: StreamHandlerEventRecorder?
  private var closed = false
  private var waiter: CheckedContinuation<IncomingStream, Error>?
  private(set) var closeCount = 0

  init(stream: StreamHandlerTestByteStream) {
    self.outboundStream = stream
    self.incoming = [IncomingStream(kind: stream.kind, metadata: .empty, stream: stream)]
    self.terminalError = nil
    self.events = nil
  }

  init(
    streams: [StreamHandlerTestByteStream],
    terminalError: SessionError?,
    events: StreamHandlerEventRecorder? = nil
  ) {
    precondition(!streams.isEmpty)
    self.outboundStream = streams[0]
    self.incoming = streams.map {
      IncomingStream(kind: $0.kind, metadata: .empty, stream: $0)
    }
    self.terminalError = terminalError
    self.events = events
  }

  func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
    _ = kind
    _ = metadata
    return outboundStream
  }

  func acceptStream() async throws -> IncomingStream {
    if closed { throw SessionError.closed }
    if !incoming.isEmpty { return incoming.removeFirst() }
    if let terminalError { throw terminalError }
    return try await withCheckedThrowingContinuation { waiter = $0 }
  }

  func rekey() async throws {}
  func probeLiveness() async throws -> Duration { .zero }
  func waitTermination() async -> SessionTermination {
    SessionTermination(error: .closed)
  }

  func close() async throws {
    closeCount += 1
    await events?.append("session-close")
    closed = true
    waiter?.resume(throwing: SessionError.closed)
    waiter = nil
  }
}

private actor StreamHandlerTestRPCPeer: RPCPeer {
  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response {
    _ = typeID
    _ = request
    _ = responseType
    _ = timeout
    throw SessionError.operationFailed
  }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    _ = typeID
    _ = payload
  }

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription {
    _ = typeID
    _ = payloadType
    _ = handler
    return StreamHandlerTestSubscription()
  }
}

private struct StreamHandlerTestSubscription: RPCNotificationSubscription {
  func cancel() async {}
}
