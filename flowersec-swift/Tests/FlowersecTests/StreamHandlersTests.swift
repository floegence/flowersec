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
func streamHandlersApplyRawMetadataContractBeforeHandler() async throws {
  let signal = StreamHandlerSignal()
  let stream = StreamHandlerTestByteStream(kind: "files/read")
  let metadata = try StreamMetadata(["message": .string("hello")])
  let session = StreamHandlerTestSession(stream: stream, metadata: metadata)
  let contract = try RawStreamMetadataContract(
    contractID: "code.raw.v1", namespace: "application/json", version: 1,
    fields: [RawStreamMetadataField(name: "message", type: .string, required: true)])
  let handlers = try StreamHandlers()
  try handlers.handleStream(kind: "files/read", metadataContract: contract) { incoming in
    do {
      #expect(try incoming.metadata.descriptorValues()["message"] == .string("hello"))
    } catch {
      Issue.record("metadata projection missing")
    }
    await signal.fire()
  }
  let serving = Task { try await handlers.serve(session: session) }
  await signal.wait()
  serving.cancel()
  _ = await serving.result
  #expect(await stream.resetCount == 0)
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
  private let outboundStream: any ByteStream
  private var incoming: [IncomingStream]
  private let terminalError: SessionError?
  private let events: StreamHandlerEventRecorder?
  private var closed = false
  private var waiter: CheckedContinuation<IncomingStream, Error>?
  private(set) var closeCount = 0

  init(stream: StreamHandlerTestByteStream, metadata: StreamMetadata = .empty) {
    self.outboundStream = stream
    self.incoming = [IncomingStream(kind: stream.kind, metadata: metadata, stream: stream)]
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
