import Foundation

public struct ServiceStreamBinding: Sendable {
  public let method: MethodDefinition
  public let kind: String
  public let metadata: StreamMetadata
  public init(method: MethodDefinition, kind: String, metadata: StreamMetadata = .empty) throws {
    guard method.shape == .serverStreaming, (1...128).contains(kind.utf8.count),
      !kind.hasPrefix("flowersec."), !kind.hasPrefix("flowersec/"), metadata.namespace != "flowersec/typed-message" else {
      throw ServiceFailure.configurationCapacity
    }
    self.method = method; self.kind = kind; self.metadata = metadata
  }
}

final class V4DeferredServiceStream: V4RPCTransport, V4MessageStreamWriter, @unchecked Sendable {
  let kind: String
  private let gate = NSLock()
  private var source: (any V4RPCTransport)?
  private var closed = false
  init(kind: String) { self.kind = kind }
  func bind(_ source: any V4RPCTransport) throws {
    try gate.withLock {
      guard !closed, self.source == nil else { throw ServiceFailure.closed }; self.source = source
    }
  }
  private func original() throws -> any V4RPCTransport {
    try gate.withLock { guard !closed, let source else { throw ServiceFailure.closed }; return source }
  }
  func read(maxBytes: Int) async throws -> Data? { try await original().read(maxBytes: maxBytes) }
  func write(_ bytes: Data) async throws -> Int { try await original().write(bytes) }
  func writeRPCChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int {
    try await original().writeRPCChunk(bytes, beforeAccept: beforeAccept, accepted: accepted)
  }
  func writeRPCPublicationChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void, completed: @escaping @Sendable (Int, Bool) -> Void) async throws -> Int {
    try await original().writeRPCPublicationChunk(bytes, beforeAccept: beforeAccept, accepted: accepted, completed: completed)
  }
  func writeMessageChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int {
    try await writeRPCChunk(bytes, beforeAccept: beforeAccept, accepted: accepted)
  }
  func closeWrite() async throws { try await original().closeWrite() }
  func finish() async throws { try await original().finish() }
  func terminalError() async -> SessionError? { try? await original().terminalError() }
  func reset() async throws { try await close() }
  func close() async throws {
    let original = gate.withLock { () -> (any V4RPCTransport)? in
      guard !closed else { return nil }; closed = true; defer { source = nil }; return source
    }
    try await original?.close()
  }
}

private final class V4ServiceStreamCursorSource: ReaderCursorSource, @unchecked Sendable {
  let cursorGate: NSRecursiveLock
  let startOffset: UInt64
  let initialStatus = ReadStreamStatus.open
  let initialError: ReadStreamError? = nil
  private let core: TypedMessageStreamCore
  private let target: Int
  private let prefix: Bool
  private let finalBody: Bool
  private var storage: V4CryptoReservation?
  private var received = 0
  private var status = ReadStreamStatus.open
  private var error: ReadStreamError?
  private var stopped = false
  private var released = false
  private var releasing = false
  private var reading = false
  init(core: TypedMessageStreamCore, target: Int, prefix: Bool, finalBody: Bool, storage: V4CryptoReservation? = nil) throws {
    try core.beginOperation(); self.core = core; self.target = target; self.prefix = prefix; self.finalBody = finalBody
    self.storage = storage; cursorGate = core.lock; startOffset = core.startOffset
  }
  func currentState() -> (ReadStreamStatus, ReadStreamError?) { cursorGate.withLock { (status, error) } }
  func read(maxBytes: Int, transfer: @escaping @Sendable (CursorReadChunk) -> Void) async {
    let allowed = cursorGate.withLock { () -> Bool in
      guard !stopped, !releasing, !reading else { return false }; reading = true; return true
    }
    guard allowed else { transfer(CursorReadChunk(data: Data(), status: .aborted, error: nil)); return }
    defer { cursorGate.withLock { reading = false; collect() } }
    do {
      try core.check()
      let bytes = try await core.read(maxBytes: maxBytes)
      try cursorGate.withLock {
        guard !stopped else { transfer(CursorReadChunk(data: Data(), status: .aborted, error: nil)); return }
        guard let bytes else { status = .eof; transfer(CursorReadChunk(data: Data(), status: .eof, error: nil)); return }
        guard !bytes.isEmpty, bytes.count <= maxBytes else { throw ServiceFailure.protocolFailure }
        try core.check(); received += bytes.count
        try core.noteInput(count: bytes.count, prefix: prefix, complete: finalBody && received == target)
        try core.advance(by: bytes.count)
        transfer(CursorReadChunk(data: bytes, status: .open, error: nil))
      }
    } catch {
      cursorGate.withLock {
        status = .error; self.error = ReadStreamError(code: .streamDataInvalid, scope: .stream, retryDisposition: .preserveFacts)
        transfer(CursorReadChunk(data: Data(), status: .error, error: self.error))
      }
    }
  }
  func stopRead() { cursorGate.withLock { stopped = true } }
  func release() { cursorGate.withLock { releasing = true; collect() } }
  private func collect() {
    guard releasing, !reading, !released else { return }; released = true; storage = nil; core.endWorker()
  }
  deinit { release() }
}

private final class V4StreamReadiness: @unchecked Sendable {
  private let gate = NSLock()
  private var outcome: Result<Void, ServiceFailure>?
  private var waiter: (UUID, CheckedContinuation<Void, any Error>)?
  func finish(_ result: Result<Void, ServiceFailure>) {
    let waiting = gate.withLock { () -> CheckedContinuation<Void, any Error>? in
      guard outcome == nil else { return nil }; outcome = result
      defer { waiter = nil }; return waiter?.1
    }
    waiting?.resume(with: result.mapError { $0 as any Error })
  }
  func wait() async throws {
    let token = UUID()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
        let result: Result<Void, any Error>? = gate.withLock {
          if Task.isCancelled { return .failure(CancellationError()) }
          if let outcome { return outcome.mapError { $0 as any Error } }
          guard waiter == nil else { return .failure(ServiceFailure.resourceExhausted) }
          waiter = (token, continuation); return nil
        }
        if let result { continuation.resume(with: result) }
      }
    } onCancel: {
      let waiting = self.gate.withLock { () -> CheckedContinuation<Void, any Error>? in
        guard self.waiter?.0 == token else { return nil }; defer { self.waiter = nil }; return self.waiter?.1
      }
      waiting?.resume(throwing: CancellationError())
    }
  }
}

private struct V4ServiceItemResources<Item: Sendable>: Sendable {
  let body: V4CryptoReservation
  let completion: V4MessageCompletion<Item>?
}

private final class V4ServiceRequestPosition: @unchecked Sendable {
  private let gate = NSLock()
  private var channel: V4RPCChannel?
  private var position: UInt64?
  private var released = false
  init(channel: V4RPCChannel) { self.channel = channel }
  func bind(_ position: UInt64) {
    let channel = gate.withLock { () -> V4RPCChannel? in
      if released { return self.channel }; self.position = position; return nil
    }
    if let channel { Task { await channel.releaseDedicatedRequest(position) } }
  }
  func release() {
    let original = gate.withLock { () -> (V4RPCChannel, UInt64)? in
      guard !released else { return nil }; released = true
      guard let channel, let position else { return nil }
      self.channel = nil; self.position = nil; return (channel, position)
    }
    if let (channel, position) = original { Task { await channel.releaseDedicatedRequest(position) } }
  }
}

private actor V4ServiceStreamMessages<Item: Sendable> {
  private enum Phase {
    case prefix(ReaderCursor)
    case header(Int, ReaderCursor)
    case awaitingBody(V4ApplicationHeader)
    case body(V4ApplicationHeader, ReaderCursor, V4CryptoReservation)
    case candidate(V4ApplicationHeader, Data, V4CryptoReservation)
    case decoding(V4MessageCompletion<Item>)
    case terminalBoundary(any Error, ReaderCursor)
  }
  private let core: TypedMessageStreamCore
  private let environment: V4EnvironmentFoundation
  private let request: V4ApplicationHeader
  private let snapshot: ServiceContractSnapshot
  private let method: MethodDefinition
  private let codec: any MessageCodec<Item>
  private let registry: V4ApplicationWireRegistry
  private let ready: V4StreamReadiness
  private var phase: Phase?
  private var reading = false
  private var closed = false
  private var eof = false
  private var items: UInt64 = 0
  private var bytes: UInt64 = 0
  private var terminal: (any Error)?
  private var started: ContinuousClock.Instant?
  private var durationTimer: Task<Void, Never>?
  private var pendingCompletion: V4MessageCompletion<Item>?
  private let terminalInput: @Sendable () -> Void
  private let terminalOutcome: @Sendable (Result<Void, any Error>) -> Void
  init(core: TypedMessageStreamCore, environment: V4EnvironmentFoundation, request: V4ApplicationHeader, snapshot: ServiceContractSnapshot,
    method: MethodDefinition, codec: any MessageCodec<Item>, registry: V4ApplicationWireRegistry,
    ready: V4StreamReadiness, terminalInput: @escaping @Sendable () -> Void,
    terminalOutcome: @escaping @Sendable (Result<Void, any Error>) -> Void) {
    self.core = core; self.environment = environment; self.request = request; self.snapshot = snapshot; self.method = method
    self.codec = codec; self.registry = registry; self.ready = ready; self.terminalInput = terminalInput
    self.terminalOutcome = terminalOutcome
  }
  private func cursor(size: Int, prefix: Bool, finalBody: Bool, storage: V4CryptoReservation? = nil) throws -> ReaderCursor {
    let source = try V4ServiceStreamCursorSource(core: core, target: size, prefix: prefix, finalBody: finalBody, storage: storage)
    let cursor = try ReaderCursor(source: source, options: ReaderCursorOptions(exact: UInt64(size)), capacity: UInt64(size))
    core.attachCursor(cursor); return cursor
  }
  private func read(_ cursor: ReaderCursor) async throws -> ReadResult {
    do {
      let result = try await cursor.readExactly(); try core.check()
      if result.waitStatus == .waitCanceled { throw SessionError.canceled }
      return result
    }
    catch { try core.check(); throw error }
  }
  private func waitRefused(_ error: any Error) -> Bool {
    error is CancellationError || error as? SessionError == .canceled ||
      error as? SessionError == .resourceExhausted || error as? ServiceFailure == .resourceExhausted ||
      error as? V4ResourceFailure == .capacity || (error as? ReadMethodFailure)?.reason == .readInProgress ||
      error is MessageResultModeConflict || error is ApplicationInvocationFailure
  }
  func startDuration() throws {
    guard started == nil, !closed else { return }
    let duration = try snapshot.contract.uint(26)
    let deadline = try request.uint(5)
    try core.beginOperation()
    started = ContinuousClock.now
    let start = started!
    durationTimer = Task { [weak self, core, environment] in
      defer { core.endWorker() }
      while !Task.isCancelled {
        let elapsed = start.duration(to: .now).components
        let elapsedMS = UInt64(max(0, elapsed.seconds)) * 1000 + UInt64(max(0, elapsed.attoseconds)) / 1_000_000_000_000_000
        guard let interval = environment.clock.sample().interval, interval.upperMS < deadline, elapsedMS < duration else {
          await self?.expire(); return
        }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
      }
    }
  }
  private func expire() async {
    guard !closed, !eof else { return }
    terminal = ServiceFailure.deadlineExceeded
    terminalOutcome(.failure(ServiceFailure.deadlineExceeded))
    await close()
  }
  private func candidate(typed: Bool, context: ApplicationInvocationContext?) async throws -> (V4ApplicationHeader, Data, V4CryptoReservation)? {
    try await ready.wait()
    while true {
      try core.check(); try context?.checkCancellation(); try Task.checkCancellation()
      if let terminal { throw terminal }
      if eof { return nil }
      let duration = try snapshot.contract.uint(26)
      let elapsed = (started ?? .now).duration(to: .now).components
      let elapsedMS = UInt64(max(0, elapsed.seconds)) * 1000 + UInt64(max(0, elapsed.attoseconds)) / 1_000_000_000_000_000
      guard elapsedMS < duration else { throw ServiceFailure.deadlineExceeded }
      switch phase {
      case nil:
        phase = .prefix(try cursor(size: 2, prefix: true, finalBody: false))
      case .prefix(let cursor):
        let result = try await read(cursor)
        if result.data.isEmpty, result.streamStatus == .eof {
          cursor.close(); core.endAssembly(); eof = true
          terminalOutcome(.success(()))
          durationTimer?.cancel(); durationTimer = nil
          try? await core.closeStream(); terminalInput(); return nil
        }
        guard result.data.count == 2 else { throw ServiceFailure.protocolFailure }
        let length = result.data.reduce(0) { $0 << 8 | Int($1) }
        guard (1...512).contains(length) else { throw ServiceFailure.protocolFailure }
        cursor.close(); phase = .header(length, try self.cursor(size: length, prefix: false, finalBody: false))
      case .header(let length, let cursor):
        let result = try await read(cursor)
        guard result.data.count == length else { throw ServiceFailure.protocolFailure }
        let header = try V4ApplicationHeader(encoded: result.data, registry: registry)
        try header.checkResponse(to: request, registry: registry)
        guard ["execution_stream_item", "transient_stream_item", "execution_stream_application_error", "transient_stream_application_error", "execution_stream_sdk_error", "transient_stream_sdk_error"].contains(header.kind) else {
          throw ServiceFailure.protocolFailure
        }
        let payloadLength = try header.payloadBytes
        let sdkError = registry.variants[header.kind]?.sdkError == true
        let applicationError = header.fields[10] != nil
        guard (sdkError ? payloadLength <= 256 : payloadLength <= (try request.uint(8))),
          try sdkError || applicationError || (UInt64(payloadLength) <= snapshot.contract.uint(25) - bytes
            && items < snapshot.contract.uint(24)) else { throw ServiceFailure.protocolFailure }
        cursor.close(); phase = .awaitingBody(header)
      case .awaitingBody(let header):
        let count = try header.payloadBytes
        let normal = registry.variants[header.kind]?.sdkError != true && header.fields[10] == nil
        let dependent = try core.completionDependent(context)
        let resources = try await core.acquireResources(tryNow: dependent) { [core, codec] in
          let body = try core.reservePayload(bytes: count, encoding: false)
          let completion: V4MessageCompletion<Item>? = typed && normal
            ? try core.makeCompletion(bytes: count, codec: codec, definition: codec.definition, context: context) : nil
          return V4ServiceItemResources(body: body, completion: completion)
        }
        let storage = resources.body; pendingCompletion = resources.completion
        if count == 0 { core.endAssembly(); phase = .candidate(header, Data(), storage) }
        else { phase = .body(header, try cursor(size: count, prefix: false, finalBody: true, storage: storage), storage) }
      case .body(let header, let cursor, let storage):
        if typed && pendingCompletion == nil && registry.variants[header.kind]?.sdkError != true && header.fields[10] == nil {
          let dependent = try core.completionDependent(context)
          pendingCompletion = try await core.acquireResources(tryNow: dependent) { [core, codec] in
            try core.makeCompletion(bytes: try header.payloadBytes, codec: codec, definition: codec.definition, context: context)
          }
        }
        let result = try await read(cursor)
        guard result.data.count == (try header.payloadBytes) else { throw ServiceFailure.protocolFailure }
        cursor.close(); phase = .candidate(header, result.data, storage)
      case .candidate(let header, let payload, let storage):
        if registry.variants[header.kind]?.sdkError == true {
          let failure = try snapshot.contract.decodeServiceFailure(payload)
          phase = .terminalBoundary(failure, try cursor(size: 1, prefix: false, finalBody: false)); continue
        }
        if let scalar = header.fields[10], case .uint(let code) = scalar {
          guard let error = method.options.errors.first(where: { $0.code == code }), payload.count <= error.maxPayloadBytes else {
            throw ServiceFailure.protocolFailure
          }
          let failure = ServiceApplicationError(code: UInt32(code), payload: payload, definition: MessageCodecIdentity(error.message))
          phase = .terminalBoundary(failure, try cursor(size: 1, prefix: false, finalBody: false)); continue
        }
        return (header, payload, storage)
      case .terminalBoundary(let failure, let cursor):
        let result = try await read(cursor)
        guard result.data.isEmpty, result.streamStatus == .eof else { throw ServiceFailure.protocolFailure }
        cursor.close(); phase = nil; terminal = failure; durationTimer?.cancel(); durationTimer = nil
        terminalOutcome(.failure(failure))
        await close(); throw failure
      case .decoding: return nil
      }
    }
  }
  func readNext(context: ApplicationInvocationContext?) async throws -> MessageReceived<Item>? {
    guard !reading, !closed else { throw ServiceFailure.resourceExhausted }; reading = true
    defer { reading = false }
    do {
      let completion: V4MessageCompletion<Item>
      if case .decoding(let current) = phase { completion = current }
      else {
        guard let (header, payload, storage) = try await candidate(typed: true, context: context) else { return nil }
        if pendingCompletion == nil {
          let dependent = try core.completionDependent(context)
          pendingCompletion = try await core.acquireResources(tryNow: dependent) { [core, codec] in
            try core.makeCompletion(bytes: payload.count, codec: codec, definition: codec.definition, context: context)
          }
        }
        guard let original = pendingCompletion else { throw ServiceFailure.closed }
        completion = original; pendingCompletion = nil
        try completion.bind(encoded: payload, storage: storage)
        phase = .decoding(completion); bytes += UInt64(payload.count); items += 1
        _ = header
      }
      let result = try await completion.take(context: context)
      phase = nil; return result
    } catch {
      if waitRefused(error) { throw error }
      if error is MessageReceiveError {
        if case .decoding(let completion) = phase, completion.deliveryCommitted { phase = nil }
        throw error
      }
      terminal = error; terminalOutcome(.failure(error)); try? await core.closeStream(); terminalInput(); throw error
    }
  }
  func readNextEncoded(context: ApplicationInvocationContext?) async throws -> EncodedMessageReceived? {
    guard !reading, !closed else { throw ServiceFailure.resourceExhausted }; reading = true
    defer { reading = false }
    do {
      if case .decoding(let completion) = phase {
        let payload = try completion.takeEncoded(context: context); phase = nil
        return EncodedMessageReceived(payload: payload, codec: MessageCodecIdentity(codec.definition))
      }
      guard let (_, payload, storage) = try await candidate(typed: false, context: context) else { return nil }
      if let completion = pendingCompletion {
        try completion.bind(encoded: payload, storage: storage)
        pendingCompletion = nil; phase = .decoding(completion)
        let encoded = try completion.takeEncoded(context: context)
        phase = nil; bytes += UInt64(encoded.count); items += 1
        return EncodedMessageReceived(payload: encoded, codec: MessageCodecIdentity(codec.definition))
      }
      phase = nil; bytes += UInt64(payload.count); items += 1
      return EncodedMessageReceived(payload: payload, codec: MessageCodecIdentity(codec.definition))
    } catch {
      if waitRefused(error) { throw error }
      terminal = error; terminalOutcome(.failure(error)); try? await core.closeStream(); terminalInput(); throw error
    }
  }
  func close() async {
    guard !closed else { return }; closed = true
    durationTimer?.cancel(); durationTimer = nil
    pendingCompletion?.close(); pendingCompletion = nil
    if case .decoding(let completion) = phase { completion.close() }
    phase = nil; try? await core.closeStream(); terminalInput()
  }
}

public final class ServiceStreamingOperation<Item: Sendable>: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private var client: ServiceClient?
  private let token: UUID
  private let binding: ServiceStreamBinding
  private let snapshot: ServiceContractSnapshot
  private var payload: Data?
  private let options: ServiceCallOptions
  private let request: V4PreparedServiceRequest
  private let stream: V4DeferredServiceStream
  private let core: TypedMessageStreamCore
  private let messages: V4ServiceStreamMessages<Item>
  private let readiness = V4StreamReadiness()
  private var storage: V4CryptoReservation?
  private let positionOwner: V4ServiceRequestPosition
  private var worker: Task<Void, Never>?
  private var timer: Task<Void, Never>?
  private var began = false
  private var submitted = false
  private var closed = false
  private var iteratorClaimed = false
  private var requiredDependency: V4RequiredServiceStream?
  #if os(macOS) || os(iOS)
  private let diagnostic: V4DiagnosticContext?
  #endif
  public var reference: OperationReference? { request.reference }
  init(client: ServiceClient, token: UUID, method: MethodDefinition, snapshot: ServiceContractSnapshot,
    binding: ServiceStreamBinding, payload: Data, codec: any MessageCodec<Item>, options: ServiceCallOptions,
    storage: V4CryptoReservation, dependency: V4RequiredServiceStream? = nil) throws {
    requiredDependency = dependency
    self.client = client; self.token = token; self.binding = binding; self.snapshot = snapshot
    self.payload = payload; self.options = options; self.storage = storage; gate = client.environment.gate
    #if os(macOS) || os(iOS)
    diagnostic = client.environment.diagnosticContext(.application)
    #endif
    request = try V4PreparedServiceRequest(client: client, method: method, snapshot: snapshot, payload: payload, options: options)
    stream = V4DeferredServiceStream(kind: binding.kind)
    let core = TypedMessageStreamCore(prepared: V4PreparedMessageStream(stream: stream,
      storage: try dependency?.messageStorage ?? client.environment.messageStreamStorage(),
      prepaidPayload: dependency?.itemStorage, prepaidCompletion: dependency?.completionReservation, check: { [weak client] in
        guard let client else { throw ServiceFailure.closed }; try client.check()
      }), options: .standard)
    self.core = core
    positionOwner = V4ServiceRequestPosition(channel: client.channel)
    let positionOwner = self.positionOwner
    core.onProtocolExit { positionOwner.release() }
    let gate = self.gate
    let release: @Sendable () -> Void = { [weak client] in
      guard let client else { return }
      // Position release is completed by the original close/EOF path below;
      // this observer only ends this binding's application handle ownership.
      gate.withLock { client.release(token) }
    }
    #if os(macOS) || os(iOS)
    let diagnostic = self.diagnostic
    #endif
    messages = V4ServiceStreamMessages(core: core, environment: client.environment, request: request.header, snapshot: snapshot, method: method,
      codec: codec, registry: client.channel.registry, ready: readiness, terminalInput: release, terminalOutcome: { outcome in
        #if os(macOS) || os(iOS)
        switch outcome {
        case .success: diagnostic?.emit(.succeeded)
        case .failure(let error): diagnostic?.failed(error)
        }
        #endif
      })
    let tail = try storage.executionTail()
    let maximum = ContinuousClock.now.advanced(by: .seconds(60))
    timer = Task { [weak self] in
      defer { tail.release() }
      while !Task.isCancelled {
        guard let self else { return }
        let stop = gate.withLock { () -> Bool in
          if closed || submitted { timer = nil; return true }
          guard let interval = client.environment.clock.sample().interval,
            interval.upperMS < request.preparationEnd, ContinuousClock.now < maximum else {
            failAndClose(ServiceFailure.deadlineExceeded); return true
          }
          return false
        }
        if stop { return }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
      }
    }
  }
  var preparationExpired: Bool { gate.withLock { closed } }
  public var submission: OperationSubmission { gate.withLock { submitted ? .submitted : .notSubmitted } }
  public func start() async throws {
    #if os(macOS) || os(iOS)
    diagnostic?.emit(.started)
    #endif
    try await startOriginal()
  }
  private func failAndClose(_ error: any Error) {
    #if os(macOS) || os(iOS)
    diagnostic?.failed(error)
    #endif
    close()
  }
  private func startOriginal() async throws {
    let client = try gate.withLock { () -> ServiceClient in
      guard !closed, !began, let client = self.client else { throw ServiceFailure.closed }
      try client.checkAdmission(); try options.context?.checkCancellation(); began = true
      return client
    }
    let position: UInt64
    let acceptedSource: (any V4RPCTransport)?
    do {
      if let dependency = requiredDependency {
        let original = try dependency.take(); acceptedSource = original.0; position = original.1
      } else {
        acceptedSource = nil; position = try await client.channel.reserveDedicatedRequest()
      }
    } catch { failAndClose(error); throw error }
    let accepted = gate.withLock { () -> Bool in
      guard !closed else { return false }; positionOwner.bind(position); return true
    }
    if !accepted {
      try? await acceptedSource?.close(); await client.channel.releaseDedicatedRequest(position)
      throw ServiceFailure.closed
    }
    let input: (V4ResourceReference, Data)
    do {
      input = try gate.withLock {
        guard let storage = self.storage, let payload = self.payload else { throw ServiceFailure.closed }
        return (try storage.executionTail(), payload)
      }
    } catch { try? await acceptedSource?.close(); positionOwner.release(); failAndClose(error); throw error }
    do { try core.beginOperation() }
    catch { input.0.release(); try? await acceptedSource?.close(); positionOwner.release(); failAndClose(error); throw error }
    let tail = input.0; let payload = input.1
    let publisher = Task { [self, client] in
      defer { tail.release(); gate.withLock { worker = nil; self.payload = nil }; core.endWorker() }
      do {
        let opened: any ByteStream
        if let acceptedSource { opened = acceptedSource }
        else { opened = try await client.session.openStream(kind: binding.kind, metadata: binding.metadata) }
        guard let source = opened as? any V4RPCTransport else { try? await opened.close(); throw ServiceFailure.serviceUnavailable }
        do { try stream.bind(source) } catch { try? await source.close(); throw error }
        let encoded = request.header.encoded()
        let prefix = V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded
        var offset = 0
        while offset < prefix.count {
          let count = try await source.writeRPCChunk(Data(prefix.dropFirst(offset)), beforeAccept: { [self] in
            try gate.withLock {
              guard !closed else { throw ServiceFailure.closed }; try client.checkAdmission()
              if !submitted {
                try options.context?.checkCancellation()
                guard let interval = client.environment.clock.sample().interval, interval.upperMS < options.deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
                if let reference, let offer = snapshot.offer {
                  try offer.check(contract: snapshot.contract, cutoff: reference.admissionNotAfterMS, environment: client.environment)
                }
              }
            }
          }, accepted: { [self] count in if count > 0 { gate.withLock { submitted = true; timer?.cancel(); timer = nil } } })
          guard count > 0, count <= prefix.count - offset else { throw ServiceFailure.protocolFailure }; offset += count
        }
        offset = 0
        while offset < payload.count {
          let count = try await source.writeRPCChunk(Data(payload[offset..<min(payload.count, offset + 16_384)]), beforeAccept: { [self] in
            try gate.withLock { guard !closed else { throw ServiceFailure.closed }; try client.check() }
          }, accepted: { _ in })
          guard count > 0, count <= payload.count - offset else { throw ServiceFailure.protocolFailure }; offset += count
        }
        try await source.closeWrite()
        try await messages.startDuration()
        readiness.finish(.success(()))
      } catch {
        #if os(macOS) || os(iOS)
        diagnostic?.failed(error)
        #endif
        readiness.finish(.failure(error as? ServiceFailure ?? .serviceUnavailable))
        await messages.close()
      }
    }
    gate.withLock { worker = publisher; if closed { publisher.cancel() } }
  }
  public func readNext(context: ApplicationInvocationContext? = nil) async throws -> MessageReceived<Item>? {
    try await messages.readNext(context: context)
  }
  public func readNextEncoded(context: ApplicationInvocationContext? = nil) async throws -> EncodedMessageReceived? {
    try await messages.readNextEncoded(context: context)
  }
  public func items(context: ApplicationInvocationContext? = nil) -> ServiceItemSequence<Item> {
    ServiceItemSequence(operation: self, context: context)
  }
  fileprivate func claimIterator() throws {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      guard !iteratorClaimed else { throw ServiceFailure.resourceExhausted }
      iteratorClaimed = true
    }
  }
  public func consumeItems(context: ApplicationInvocationContext? = nil,
    _ body: @escaping @Sendable (MessageReceived<Item>) async throws -> Bool) async throws {
    defer { close() }
    while let item = try await readNext(context: context) {
      let keepGoing = try await body(item)
      if !keepGoing { return }
    }
  }
  public func cleanupStatus() -> CleanupStatus { core.cleanupStatus() }
  public func waitCleanup() async throws -> CleanupStatus { try await core.waitCleanup() }
  public func close() {
    #if os(macOS) || os(iOS)
    diagnostic?.emit(.closed)
    #endif
    let client = gate.withLock { () -> ServiceClient? in
      guard !closed else { return nil }; closed = true; timer?.cancel(); timer = nil; worker?.cancel()
      defer { self.client = nil; storage = nil; payload = nil }; return self.client
    }
    guard let client else { return }
    readiness.finish(.failure(.closed))
    Task { [self] in await messages.close(); client.release(token) }
  }
  deinit { close() }
}

/// One iteration scope owns the original output stream. Leaving a `for await`
/// loop closes that scope, while actual decoder/transport tails keep their
/// original responsibilities until they return.
public struct ServiceItemSequence<Item: Sendable>: AsyncSequence, Sendable {
  public typealias Element = MessageReceived<Item>
  private let operation: ServiceStreamingOperation<Item>
  private let context: ApplicationInvocationContext?
  fileprivate init(operation: ServiceStreamingOperation<Item>, context: ApplicationInvocationContext?) {
    self.operation = operation; self.context = context
  }
  public func makeAsyncIterator() -> AsyncIterator {
    AsyncIterator(scope: V4ServiceIterationScope(operation: operation, context: context))
  }
  public struct AsyncIterator: AsyncIteratorProtocol {
    private let scope: V4ServiceIterationScope<Item>
    fileprivate init(scope: V4ServiceIterationScope<Item>) { self.scope = scope }
    public mutating func next() async throws -> MessageReceived<Item>? { try await scope.next() }
  }
}

fileprivate final class V4ServiceIterationScope<Item: Sendable>: @unchecked Sendable {
  private let gate = NSLock()
  private var operation: ServiceStreamingOperation<Item>?
  private var context: ApplicationInvocationContext?
  private let admissionFailure: ServiceFailure?
  init(operation: ServiceStreamingOperation<Item>, context: ApplicationInvocationContext?) {
    do {
      try operation.claimIterator()
      self.operation = operation; self.context = context; admissionFailure = nil
    } catch { admissionFailure = error as? ServiceFailure ?? .closed }
  }
  func next() async throws -> MessageReceived<Item>? {
    let original = try gate.withLock { () -> (ServiceStreamingOperation<Item>, ApplicationInvocationContext?)? in
      if let admissionFailure { throw admissionFailure }
      guard let operation else { return nil }; return (operation, context)
    }
    guard let original else { return nil }
    do {
      let item = try await original.0.readNext(context: original.1)
      if item == nil { close() }
      return item
    } catch { close(); throw error }
  }
  private func close() {
    let original = gate.withLock { () -> ServiceStreamingOperation<Item>? in
      defer { operation = nil; context = nil }; return operation
    }
    original?.close()
  }
  deinit { close() }
}
