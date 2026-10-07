import Foundation

#if os(macOS) || os(iOS)
func v4ServiceSDKPayload(_ error: any Error) -> Data {
  let code: UInt64
  switch error as? ServiceFailure {
  case .contractMismatch: code = 3
  case .contractPolicyRejected: code = 4
  case .resourceExhausted: code = 5
  case .permissionDenied: code = 7
  case .deadlineExceeded: code = 8
  case .operationConflict: code = 11
  case .resultExpired: code = 12
  case .serviceFailed: code = 9
  default: code = 6
  }
  return V4Crypto.map([(0, V4NamespaceValue.head(0, code))])
}

public struct ServiceServerCaller: Sendable {
  public let subject: String
  public let identityDigest: Data
  public let executionAuthority: Data
  public init(subject: String, identityDigest: Data, executionAuthority: Data) throws {
    guard V4NamespaceRegistry.securityID(subject.utf8), identityDigest.count == 32,
      executionAuthority.count == 32, identityDigest.contains(where: { $0 != 0 }),
      executionAuthority.contains(where: { $0 != 0 }) else { throw ServiceFailure.configurationCapacity }
    self.subject = subject; self.identityDigest = Data(identityDigest); self.executionAuthority = Data(executionAuthority)
  }
}
public struct ServiceRegistryConfiguration: Sendable {
  public let authority: String
  public let maximumMethods: Int
  public let queryBinding: ServiceContractQueryBinding
  public let maximumOfferWindowMS: UInt64
  public let executionStore: SQLiteServiceExecutionStore?
  public let maintenanceOwner: ServiceMaintenanceOwner?
  public init(authority: String, maximumMethods: Int = 16, queryBinding: ServiceContractQueryBinding,
    maximumOfferWindowMS: UInt64 = 30_000, executionStore: SQLiteServiceExecutionStore? = nil, maintenanceOwner: ServiceMaintenanceOwner? = nil) throws {
    guard V4NamespaceRegistry.securityID(authority.utf8), (1...256).contains(maximumMethods), maximumOfferWindowMS > 0 else { throw ServiceFailure.configurationCapacity }
    self.authority = authority; self.maximumMethods = maximumMethods; self.queryBinding = queryBinding
    self.maximumOfferWindowMS = maximumOfferWindowMS; self.executionStore = executionStore; self.maintenanceOwner = maintenanceOwner
  }
}
public struct ServiceServerApplicationError: Error, Sendable {
  public let code: UInt32
  public let payload: Data
  public init(code: UInt32, payload: Data) { self.code = code; self.payload = payload.withUnsafeBytes { Data($0) } }
}

typealias V4ServiceCheckpointReissuer = @Sendable (OperationReference, ServiceContract, ApplicationCheckpointToken, UInt64) async throws -> IssuedServiceCheckpoint

private struct V4ServiceStreamFailure: Error {
  let underlying: any Error
  let terminalAccepted: Bool
}

public final class ServiceServerStreamWriter<Item: Sendable>: @unchecked Sendable {
  private let environment: V4EnvironmentFoundation
  private let context: ApplicationInvocationContext
  private let invocation: ServiceServerInvocation
  private let source: any V4RPCTransport
  private let request: V4ApplicationHeader
  private let contract: ServiceContract
  private let codec: any MessageCodec<Item>
  private let method: MethodDefinition
  private let registry: V4ApplicationWireRegistry
  private let registryStorage: V4CryptoReservation
  private let terminalStorage: V4CryptoReservation
  private let gate: NSRecursiveLock
  private var writing = false
  private var closed = false
  private var finished = false
  private var items: UInt64 = 0
  private var bytes: UInt64 = 0
  init(environment: V4EnvironmentFoundation, context: ApplicationInvocationContext, invocation: ServiceServerInvocation,
    source: any V4RPCTransport, request: V4ApplicationHeader, contract: ServiceContract, method: MethodDefinition,
    codec: any MessageCodec<Item>, registry: V4ApplicationWireRegistry, registryStorage: V4CryptoReservation,
    terminalStorage: V4CryptoReservation) {
    self.environment = environment; self.context = context; self.invocation = invocation; self.source = source
    self.request = request; self.contract = contract; self.method = method; self.codec = codec; gate = environment.gate
    self.registryStorage = registryStorage; self.registry = registry; self.terminalStorage = terminalStorage
  }
  public func write(_ value: Item) async throws {
    let maximum = try gate.withLock { () -> Int in
      guard !closed, !writing else { throw ServiceFailure.resourceExhausted }; try registryStorage.check(); try invocation.checkCancellation()
      guard items < (try contract.uint(24)), bytes <= (try contract.uint(25)) else { throw ServiceFailure.resourceExhausted }
      writing = true; return Int(try request.uint(8))
    }
    defer { gate.withLock { writing = false } }
    let storage = try environment.serviceOperationStorage(requestBytes: maximum, responseBytes: 0)
    let tail = V4ServiceInputTail(try storage.executionTail()); defer { withExtendedLifetime(tail) {} }
    var encoded = Data(count: maximum)
    let count: Int
    if let asynchronous = codec as? any AsyncMessageCodec<Item> { count = try await asynchronous.encodeAsync(value, context: context, into: &encoded) }
    else { count = try codec.encode(value, context: context, into: &encoded) }
    try gate.withLock {
      try invocation.checkCancellation()
      guard !closed, count >= 0, count <= maximum, count <= encoded.count, UInt64(count) <= (try contract.uint(25)) - bytes else { throw ServiceFailure.resourceExhausted }
      guard let started = invocation.enteredAt else { throw ServiceFailure.protocolFailure }
      let elapsed = started.duration(to: .now).components
      let milliseconds = UInt64(max(0, elapsed.seconds)) * 1000 + UInt64(max(0, elapsed.attoseconds)) / 1_000_000_000_000_000
      guard milliseconds < (try contract.uint(26)) else { throw ServiceFailure.deadlineExceeded }
    }
    let kind = contract.semantics == .execution ? "execution_stream_item" : "transient_stream_item"
    guard let variant = registry.variants[kind] else { throw ServiceFailure.protocolFailure }
    var fields: [Int: V4ApplicationHeader.Scalar] = [:]
    for id in variant.fields where id != 0 { fields[id] = id == 3 ? .uint(UInt64(count)) : request.fields[id] }
    let header = try V4ApplicationHeader(kind: kind, fields: fields, registry: registry).encoded()
    // A lawful capacity refusal before output publication leaves the writer
    // open so the application can choose its declared terminal behavior.
    try await invocation.reserveStreamItem(bytes: count)
    do {
      try await publish(V4Crypto.integer(UInt64(header.count), width: 2) + header)
      try await publish(Data(encoded.prefix(count)))
      gate.withLock { items += 1; bytes += UInt64(count) }
    } catch { gate.withLock { closed = true }; try? await source.close(); throw error }
  }
  public func saveContent(position: Data, payload: Data) async throws -> StreamContentObservation {
    try gate.withLock { guard !closed, !writing else { throw ServiceFailure.closed }; try invocation.checkCancellation(); writing = true }
    defer { gate.withLock { writing = false } }
    return try await invocation.saveContent(position: position, payload: payload)
  }
  private func publish(_ data: Data, terminal: Bool = false) async throws {
    var offset = 0
    while offset < data.count {
      let chunk = Data(data[offset..<min(data.count, offset + 16_384)])
      let before: @Sendable () throws -> Void = { [invocation] in
        if terminal { try invocation.checkPublication() } else { try invocation.checkCancellation() }
      }
      let count: Int
      if let diagnostic = context.diagnosticLifetime {
        count = try await source.writeRPCPublicationChunk(chunk, beforeAccept: before, accepted: { _ in },
          completed: { [diagnostic] _, _ in withExtendedLifetime(diagnostic) {} })
      } else { count = try await source.writeRPCChunk(chunk, beforeAccept: before, accepted: { _ in }) }
      guard count > 0, count <= data.count - offset else { throw ServiceFailure.protocolFailure }; offset += count
    }
  }
  func fail(_ error: any Error) async throws {
    let canPublish = gate.withLock { () -> Bool in
      guard !closed else { return false }; closed = true; return !writing
    }
    guard canPublish else { if !gate.withLock({ finished }) { try? await source.close() }; return }
    let payload: Data
    let applicationCode: UInt32
    if let failure = error as? ServiceServerApplicationError,
      let declared = method.options.errors.first(where: { $0.code == failure.code }),
      failure.payload.count <= declared.maxPayloadBytes, failure.payload.count <= (try request.uint(8)) {
      payload = failure.payload; applicationCode = failure.code
    } else { payload = v4ServiceSDKPayload(error); applicationCode = 0 }
    let prefix = contract.semantics == .execution ? "execution_stream_" : "transient_stream_"
    let kind = prefix + (applicationCode == 0 ? "sdk_error" : "application_error")
    guard let variant = registry.variants[kind] else { throw ServiceFailure.protocolFailure }
    try terminalStorage.check()
    defer { withExtendedLifetime(terminalStorage) {} }
    var fields: [Int: V4ApplicationHeader.Scalar] = [:]
    for id in variant.fields where id != 0 {
      if id == 3 { fields[id] = .uint(UInt64(payload.count)) }
      else if id == 10 { fields[id] = .uint(UInt64(applicationCode)) }
      else { fields[id] = request.fields[id] }
    }
    let header = try V4ApplicationHeader(kind: kind, fields: fields, registry: registry).encoded()
    do {
      try await publish(V4Crypto.integer(UInt64(header.count), width: 2) + header, terminal: true)
      try await publish(payload, terminal: true)
      try await source.closeWrite(); try await source.finish(); gate.withLock { finished = true }
    } catch { try? await source.close(); throw error }
  }
  var terminalAccepted: Bool { gate.withLock { finished } }
  public func finish() async throws {
    let start = try gate.withLock { () -> Bool in
      if finished { return false }; guard !closed, !writing else { throw ServiceFailure.closed }; try invocation.checkCancellation(); closed = true; return true
    }
    guard start else { return }; try await source.closeWrite(); try await source.finish(); gate.withLock { finished = true }
  }
}

/// A borrowed real invocation. Saving it after the callback returns cannot
/// issue checkpoints or acquire new execution authority.
public final class ServiceServerInvocation: @unchecked Sendable {
  private let context: ApplicationInvocationContext
  private let checkSource: @Sendable () throws -> Void
  private let store: SQLiteServiceExecutionStore?
  private let selector: V4ServerExecutionSelector?
  private let contract: ServiceContract
  private let resumed: Bool
  public let responsePublication: ResponsePublication
  fileprivate let stream: (any V4RPCTransport)?
  fileprivate let request: V4ApplicationHeader?
  private let gate: NSLock = NSLock()
  private var dispatched = false
  private var dispatchPrepared = false
  private var dispatchPreparing = false
  private var executionRunDeadlineMS: UInt64?
  private var checkpointPending = false
  private var contentPending = false
  private let contentSave: (@Sendable (Data, Data) async throws -> StreamContentObservation)?
  private let contentRead: (@Sendable (StreamContentTarget, Data, Int) async throws -> RetainedStreamContent)?
  private let checkpointPolicy: (@Sendable () throws -> (Int, UInt64))?
  private let checkpointReissue: V4ServiceCheckpointReissuer?
  private let entrySource: @Sendable () -> Void
  private let entryTime: @Sendable () -> ContinuousClock.Instant?
  var enteredAt: ContinuousClock.Instant? { entryTime() }
  fileprivate let outputStorage: V4CryptoReservation?
  private let deadlineAtMS: UInt64?
  init(context: ApplicationInvocationContext, check: @escaping @Sendable () throws -> Void,
    store: SQLiteServiceExecutionStore?, selector: V4ServerExecutionSelector?, contract: ServiceContract, checkpointPolicy: (@Sendable () throws -> (Int, UInt64))? = nil,
    responsePublication: ResponsePublication = .notApplicable,
    checkpointReissue: V4ServiceCheckpointReissuer? = nil,
    contentSave: (@Sendable (Data, Data) async throws -> StreamContentObservation)? = nil,
    contentRead: (@Sendable (StreamContentTarget, Data, Int) async throws -> RetainedStreamContent)? = nil, outputStorage: V4CryptoReservation? = nil, deadlineAtMS: UInt64? = nil, enter: @escaping @Sendable () -> Void, enteredAt: @escaping @Sendable () -> ContinuousClock.Instant?, resumed: Bool = false, stream: (any V4RPCTransport)? = nil, request: V4ApplicationHeader? = nil) {
    self.context = context; checkSource = check; self.store = store; self.selector = selector; self.contract = contract; self.checkpointPolicy = checkpointPolicy; self.checkpointReissue = checkpointReissue; self.contentSave = contentSave; self.contentRead = contentRead; self.outputStorage = outputStorage; self.deadlineAtMS = deadlineAtMS; entrySource = enter; entryTime = enteredAt; self.responsePublication = responsePublication; self.resumed = resumed; self.stream = stream; self.request = request
  }
  public func checkCancellation() throws {
    try context.checkCancellation(); try checkSource()
    if let deadline = try deadlineAtMS ?? request?.uint(5) {
      let effective = gate.withLock { min(deadline, executionRunDeadlineMS ?? deadline) }
      guard let now = contract.environment().clock.sample().interval, now.upperMS < effective else { throw ServiceFailure.deadlineExceeded }
    }
  }
  func checkPublication() throws { try checkSource() }
  func decode<Value: Sendable>(_ codec: any MessageCodec<Value>, source: Data) async throws -> Value {
    try checkCancellation()
    if let adapter = codec as? any V4ServiceAsyncCodecEntry<Value> {
      let entry = ApplicationCallbackEntry(context: context, check: checkCancellation, prepare: prepareDispatch, mark: enterDispatch)
      let value = try await adapter.decodeEntered(source, context: context, entry: entry)
      try entry.requireEntered(); try checkCancellation(); return value
    }
    if let cooperative = codec as? any EntryAwareAsyncMessageCodec<Value> {
      let entry = ApplicationCallbackEntry(context: context, check: checkCancellation, prepare: prepareDispatch, mark: enterDispatch)
      let value = try await cooperative.decodeAsync(source, context: context, entry: entry)
      try entry.requireEntered(); try checkCancellation(); return value
    }
    if codec is any AsyncMessageCodec<Value> {
      // Registration must retain the concrete entry before requests arrive.
      // Never execute an application property getter on the admission path.
      throw ApplicationCallbackEntryError.asyncDecoderEntryUnavailable
    }
    if !(codec is any V4SDKServiceMessageCodec) { try await prepareDispatch(); enterDispatch() }
    let value = try codec.decode(source, context: context); try checkCancellation(); return value
  }
  func prepareDispatch() async throws {
    try checkCancellation()
    let first = try gate.withLock { () -> Bool in
      if dispatchPrepared { return false }
      guard !dispatchPreparing else { throw ServiceFailure.resourceExhausted }
      dispatchPreparing = true; return true
    }
    guard first else { return }
    defer { gate.withLock { dispatchPreparing = false } }
    if let selector, let store {
      if resumed { try await store.enteredRecovery(selector) }
      else { try await store.started(selector) }
      let maximum = min(try contract.uint(18), contract.shape == .serverStreaming ? try contract.uint(26) : .max)
      let deadline = try await store.runDeadline(selector, maximumRunMS: maximum)
      gate.withLock { executionRunDeadlineMS = deadline }
    }
    gate.withLock { dispatchPrepared = true }
    try checkCancellation()
  }
  func enterDispatch() {
    // Called on the registered callback's executor, after the durable start
    // returns to that executor. There is no queued actor hop before entry.
    entrySource(); gate.withLock { dispatched = true }
  }
  func reserveStreamItem(bytes: Int) async throws {
    try checkCancellation()
    if let selector, let store, contract.semantics == .execution {
      try await store.reserveStreamItem(selector, bytes: bytes, maximumItems: contract.uint(24), maximumBytes: contract.uint(25))
    }
    try checkCancellation()
  }
  public func saveContent(position: Data, payload: Data) async throws -> StreamContentObservation {
    try checkCancellation()
    guard let contentSave else { throw ServiceFailure.contractMismatch }
    try gate.withLock { guard dispatched, !contentPending else { throw ServiceFailure.resourceExhausted }; contentPending = true }
    defer { gate.withLock { contentPending = false } }
    let result = try await contentSave(position, payload); try checkCancellation(); return result
  }
  public func readRetainedContent(_ target: StreamContentTarget, position: Data, maximumBytes: Int) async throws -> RetainedStreamContent {
    try checkCancellation()
    guard let contentRead else { throw ServiceFailure.contractMismatch }
    try gate.withLock { guard dispatched, !contentPending else { throw ServiceFailure.resourceExhausted }; contentPending = true }
    defer { gate.withLock { contentPending = false } }
    let result = try await contentRead(target, position, maximumBytes); try checkCancellation(); return result
  }
  /// Called only from an independently admitted durable application method.
  /// It replaces a consumed token after confirmation loss, before the original
  /// continuation entered. A reference alone grants no signing authority.
  public func reissueCheckpoint(_ reference: OperationReference, originalContract: ServiceContract,
    previousToken: ApplicationCheckpointToken, lifetimeMS: UInt64) async throws -> IssuedServiceCheckpoint {
    try checkCancellation()
    guard !resumed, contract.semantics == .execution, try contract.uint(13) == 1,
      let checkpointReissue else { throw ServiceFailure.permissionDenied }
    try gate.withLock {
      guard dispatched, !checkpointPending else { throw ServiceFailure.resourceExhausted }; checkpointPending = true
    }
    defer { gate.withLock { checkpointPending = false } }
    let result = try await checkpointReissue(reference, originalContract, previousToken, lifetimeMS)
    try checkCancellation(); return result
  }
  public func issueCheckpoint(_ checkpoint: ApplicationCheckpoint, lifetimeMS: UInt64) async throws -> IssuedServiceCheckpoint {
    try checkCancellation()
    guard let checkpointPolicy, let selector, let store,
      try contract.checkpointFormat() == checkpoint.format, try contract.uint(13) == 1 else { throw ServiceFailure.contractMismatch }
    let (maximumBytes, maximumDuration) = try checkpointPolicy()
    try gate.withLock {
      guard dispatched, !checkpointPending else { throw ServiceFailure.resourceExhausted }; checkpointPending = true
    }
    defer { gate.withLock { checkpointPending = false } }
    let result = try await store.issue(selector, checkpoint: checkpoint, lifetimeMS: lifetimeMS,
      maximumIssuedDurationMS: maximumDuration, maximumTokenBytes: maximumBytes,
      maximumOriginalRunMS: min(try contract.uint(18), contract.shape == .serverStreaming ? try contract.uint(26) : .max))
    try checkCancellation(); return result
  }
}
fileprivate struct V4ServiceServerOutcome: Sendable {
  let payload: Data
  let applicationCode: UInt32
  let publication: ResponsePublication?
  init(payload: Data, applicationCode: UInt32, publication: ResponsePublication? = nil) {
    self.payload = payload; self.applicationCode = applicationCode; self.publication = publication
  }
}
fileprivate enum V4ServiceServerRole: Equatable, Sendable { case unary, notify, streaming, resultRead, resume }
fileprivate final class V4ServiceServerEntry: @unchecked Sendable {
  let definition: ServiceDefinition
  let method: MethodDefinition
  let contract: ServiceContract
  let callers: [ServiceServerCaller]
  let role: V4ServiceServerRole
  let streamKind: String?
  let originalContract: ServiceContract?
  let resume: (@Sendable (ApplicationInvocationContext, ServiceServerInvocation, ApplicationCheckpoint, any ByteStream, Int) async throws -> V4ServiceServerOutcome)?
  let invoke: @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Data, Int) async throws -> V4ServiceServerOutcome
  init(definition: ServiceDefinition, method: MethodDefinition, contract: ServiceContract, callers: [ServiceServerCaller],
    role: V4ServiceServerRole? = nil, streamKind: String? = nil, originalContract: ServiceContract? = nil,
    resume: (@Sendable (ApplicationInvocationContext, ServiceServerInvocation, ApplicationCheckpoint, any ByteStream, Int) async throws -> V4ServiceServerOutcome)? = nil,
    invoke: @escaping @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Data, Int) async throws -> V4ServiceServerOutcome) {
    self.definition = definition; self.method = method; self.contract = contract; self.callers = callers; self.invoke = invoke
    self.role = role ?? (method.shape == .notify ? .notify : .unary); self.streamKind = streamKind; self.originalContract = originalContract; self.resume = resume
  }
  func caller(_ identity: ServiceCallerIdentity) throws -> ServiceServerCaller {
    guard let caller = callers.first(where: { $0.subject == identity.peerSubject && $0.identityDigest == identity.peerIdentityDigest }) else { throw ServiceFailure.permissionDenied }
    return caller
  }
}

/// Trusted local registration fixes dispatch, codecs and caller authority.
/// The original pre-READY admission freezes the complete real registry.
public final class ServiceRegistry: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  let configuration: ServiceRegistryConfiguration
  private let storage: V4CryptoReservation
  private let gate: NSRecursiveLock
  private var entries: [UInt32: V4ServiceServerEntry] = [:]
  private var sealed = false
  private var closed = false
  init(environment: V4EnvironmentFoundation, configuration: ServiceRegistryConfiguration) throws {
    if let store = configuration.executionStore {
      guard store.environment === environment, store.authority == configuration.authority else { throw ServiceFailure.permissionDenied }
    }
    self.environment = environment; self.configuration = configuration; gate = environment.gate
    storage = try environment.serviceRegistryStorage(methods: configuration.maximumMethods)
    entries.reserveCapacity(configuration.maximumMethods)
  }
  private func install(_ entry: V4ServiceServerEntry) throws {
    try gate.withLock {
      guard !closed, !sealed, entries.count < configuration.maximumMethods, entries[entry.method.typeID] == nil,
        !entry.callers.isEmpty, entry.callers.count <= 16 else { throw ServiceFailure.configurationCapacity }
      try storage.check(); try entry.contract.checkEnvironment(environment); try entry.contract.checkMethod(entry.method, in: entry.definition)
      guard entry.method.semantics != .execution || configuration.executionStore != nil else { throw ServiceFailure.serviceUnavailable }
      if entry.method.options.restartFlushDeadlineMS != nil {
        guard let owner = configuration.maintenanceOwner, owner.environment === environment else { throw ServiceFailure.configurationCapacity }
        try owner.check()
      }
      entries[entry.method.typeID] = entry
    }
  }
  private func registryContentStoreSupports(_ policy: V4ServiceStreamContentPolicy) -> Bool {
    configuration.executionStore?.supportsContent(policy) == true
  }
  public func registerUnary<Request: Sendable, Response: Sendable>(_ method: MethodDefinition, in definition: ServiceDefinition,
    contract: ServiceContract, callers: [ServiceServerCaller], requestCodec: any MessageCodec<Request>, responseCodec: any MessageCodec<Response>,
    @_inheritActorContext handler: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Request) async throws -> Response) throws {
    guard method.shape == .unary, requestCodec.definition == method.options.request,
      responseCodec.definition == method.options.response else { throw ServiceFailure.contractMismatch }
    let requestCodec = try v4ServiceCaptureRequestCodec(requestCodec)
    try install(V4ServiceServerEntry(definition: definition, method: method, contract: contract, callers: callers,
      invoke: { context, invocation, bytes, limit in
        let privateInput = bytes.withUnsafeBytes { Data($0) }
        let input = try await invocation.decode(requestCodec, source: privateInput)
        let output = try await v4ServiceDispatch(isolation: handler.isolation, handler: handler,
          context: context, invocation: invocation, input: input)
        try invocation.checkCancellation()
        var encoded = Data(count: limit)
        let count: Int
        if let codec = responseCodec as? any AsyncMessageCodec<Response> { count = try await codec.encodeAsync(output, context: context, into: &encoded) }
        else { count = try responseCodec.encode(output, context: context, into: &encoded) }
        guard count >= 0, count <= limit, count <= encoded.count else { throw ServiceFailure.resourceExhausted }
        try invocation.checkCancellation(); return V4ServiceServerOutcome(payload: Data(encoded.prefix(count)), applicationCode: 0)
      }))
  }
  public func registerNotify<Request: Sendable>(_ method: MethodDefinition, in definition: ServiceDefinition,
    contract: ServiceContract, callers: [ServiceServerCaller], codec: any MessageCodec<Request>,
    @_inheritActorContext handler: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Request) async throws -> Void) throws {
    guard method.shape == .notify, codec.definition == method.options.request else { throw ServiceFailure.contractMismatch }
    let codec = try v4ServiceCaptureRequestCodec(codec)
    try install(V4ServiceServerEntry(definition: definition, method: method, contract: contract, callers: callers,
      invoke: { context, invocation, bytes, _ in
        let privateInput = bytes.withUnsafeBytes { Data($0) }
        let input = try await invocation.decode(codec, source: privateInput)
        try await v4ServiceDispatch(isolation: handler.isolation, handler: handler,
          context: context, invocation: invocation, input: input)
        return V4ServiceServerOutcome(payload: Data(), applicationCode: 0)
      }))
  }
  public func registerResultRead(_ method: MethodDefinition, in definition: ServiceDefinition,
    binding: OperationResultReadBinding, callers: [ServiceServerCaller]) throws {
    guard method.shape == .unary, method.semantics == .transient else { throw ServiceFailure.contractMismatch }
    try install(V4ServiceServerEntry(definition: definition, method: method, contract: binding.contract, callers: callers,
      role: .resultRead, invoke: { _, _, _, _ in throw ServiceFailure.protocolFailure }))
  }
  public func registerStream<Request: Sendable, Item: Sendable>(_ binding: ServiceStreamBinding, in definition: ServiceDefinition,
    contract: ServiceContract, callers: [ServiceServerCaller], requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>,
    @_inheritActorContext handler: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Request, ServiceServerStreamWriter<Item>) async throws -> Void) throws {
    let method = binding.method
    guard method.shape == .serverStreaming, requestCodec.definition == method.options.request,
      itemCodec.definition == method.options.response else { throw ServiceFailure.contractMismatch }
    let requestCodec = try v4ServiceCaptureRequestCodec(requestCodec)
    if let policy = try contract.streamContentPolicy(method.options.content) {
      guard registryContentStoreSupports(policy) else { throw ServiceFailure.configurationCapacity }
    }
    let wireStorage = try environment.serviceApplicationRegistryStorage()
    let wire = try V4ApplicationWireRegistry()
    try install(V4ServiceServerEntry(definition: definition, method: method, contract: contract, callers: callers,
      role: .streaming, streamKind: binding.kind, invoke: { context, invocation, bytes, _ in
        guard let source = invocation.stream, let request = invocation.request, let outputStorage = invocation.outputStorage else { throw ServiceFailure.protocolFailure }
        let output = ServiceServerStreamWriter(environment: contract.environment(), context: context, invocation: invocation,
          source: source, request: request, contract: contract, method: method, codec: itemCodec,
          registry: wire, registryStorage: wireStorage, terminalStorage: outputStorage)
        do {
          let privateInput = bytes.withUnsafeBytes { Data($0) }
          let value = try await invocation.decode(requestCodec, source: privateInput)
          try await v4ServiceDispatchStream(isolation: handler.isolation, handler: handler,
            context: context, invocation: invocation, input: value, writer: output)
          try await output.finish()
          return V4ServiceServerOutcome(payload: Data(), applicationCode: 0)
        } catch {
          let failure = error
          do { try await output.fail(failure) }
          catch { throw V4ServiceStreamFailure(underlying: failure, terminalAccepted: false) }
          if let application = failure as? ServiceServerApplicationError,
            method.options.errors.contains(where: { $0.code == application.code && application.payload.count <= $0.maxPayloadBytes }),
            application.payload.count <= (try request.uint(8)) { throw application }
          throw V4ServiceStreamFailure(underlying: failure, terminalAccepted: output.terminalAccepted)
        }
      }))
  }

  public func registerResume<OriginalResponse: Sendable>(_ method: MethodDefinition, in definition: ServiceDefinition,
    contract: ServiceContract, originalContract: ServiceContract, streamKind: String, callers: [ServiceServerCaller],
    originalResponseCodec: any MessageCodec<OriginalResponse>,
    @_inheritActorContext handler: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, ApplicationCheckpoint, any ByteStream) async throws -> OriginalResponse) throws {
    guard method.shape == .unary, method.semantics == .execution, method.options.requireDurable,
      originalContract.shape == .unary, originalContract.semantics == .execution, try originalContract.uint(13) == 1,
      try originalContract.checkpointFormat() == method.options.checkpointFormat,
      originalContract.namespace == definition.namespace,
      V4NamespaceRegistry.securityID(streamKind.utf8), !streamKind.hasPrefix("flowersec."), !streamKind.hasPrefix("flowersec/"),
      originalResponseCodec.definition.revision == (try originalContract.responseRevision()),
      method.options.maxResponseBytes >= 4248 else { throw ServiceFailure.contractMismatch }
    try originalContract.checkEnvironment(environment)
    try gate.withLock {
      guard !closed, !sealed, let original = entries[originalContract.typeID], original.role == .unary,
        original.contract.digest == originalContract.digest,
        original.method.options.response == originalResponseCodec.definition else { throw ServiceFailure.contractMismatch }
    }
    try install(V4ServiceServerEntry(definition: definition, method: method, contract: contract, callers: callers,
      role: .resume, streamKind: streamKind, originalContract: originalContract,
      resume: { context, invocation, checkpoint, source, limit in
        let result = try await v4ServiceDispatchResume(isolation: handler.isolation, handler: handler,
          context: context, invocation: invocation, checkpoint: checkpoint, source: source)
        try invocation.checkCancellation(); var bytes = Data(count: limit)
        let count: Int
        if let asynchronous = originalResponseCodec as? any AsyncMessageCodec<OriginalResponse> { count = try await asynchronous.encodeAsync(result, context: context, into: &bytes) }
        else { count = try originalResponseCodec.encode(result, context: context, into: &bytes) }
        guard count >= 0, count <= limit, count <= bytes.count else { throw ServiceFailure.resourceExhausted }
        return V4ServiceServerOutcome(payload: Data(bytes.prefix(count)), applicationCode: 0)
      }, invoke: { _, _, _, _ in throw ServiceFailure.protocolFailure }))
  }

  /// Resumes the original durable typed stream on an explicitly accepted new
  /// target. Its original header, item bound, counters, and content promises
  /// remain owned by the original execution; no initial request is replayed.
  public func registerStreamingResume<Item: Sendable>(_ method: MethodDefinition, in definition: ServiceDefinition,
    contract: ServiceContract, originalContract: ServiceContract, streamKind: String, callers: [ServiceServerCaller],
    itemCodec: any MessageCodec<Item>,
    @_inheritActorContext handler: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, ApplicationCheckpoint, ServiceServerStreamWriter<Item>) async throws -> Void) throws {
    guard method.shape == .unary, method.semantics == .execution, method.options.requireDurable,
      originalContract.shape == .serverStreaming, originalContract.semantics == .execution, try originalContract.uint(13) == 1,
      try originalContract.checkpointFormat() == method.options.checkpointFormat,
      originalContract.namespace == definition.namespace, method.options.maxResponseBytes >= 4248,
      V4NamespaceRegistry.securityID(streamKind.utf8), !streamKind.hasPrefix("flowersec."), !streamKind.hasPrefix("flowersec/"),
      itemCodec.definition.revision == (try originalContract.responseRevision()) else { throw ServiceFailure.contractMismatch }
    try originalContract.checkEnvironment(environment)
    let original = try gate.withLock { () -> V4ServiceServerEntry in
      guard !closed, !sealed, let original = entries[originalContract.typeID], original.role == .streaming,
        original.contract.digest == originalContract.digest, original.method.options.response == itemCodec.definition else { throw ServiceFailure.contractMismatch }
      return original
    }
    let wireStorage = try environment.serviceApplicationRegistryStorage(); let wire = try V4ApplicationWireRegistry()
    try install(V4ServiceServerEntry(definition: definition, method: method, contract: contract, callers: callers,
      role: .resume, streamKind: streamKind, originalContract: originalContract,
      resume: { context, invocation, checkpoint, _, _ in
        guard let source = invocation.stream, let request = invocation.request, let outputStorage = invocation.outputStorage else { throw ServiceFailure.protocolFailure }
        let output = ServiceServerStreamWriter(environment: originalContract.environment(), context: context, invocation: invocation,
          source: source, request: request, contract: originalContract, method: original.method, codec: itemCodec,
          registry: wire, registryStorage: wireStorage, terminalStorage: outputStorage)
        do {
          try await v4ServiceDispatchStreamingResume(isolation: handler.isolation, handler: handler,
            context: context, invocation: invocation, checkpoint: checkpoint, writer: output)
          try await output.finish(); return V4ServiceServerOutcome(payload: Data(), applicationCode: 0)
        } catch {
          let failure = error
          do { try await output.fail(failure) }
          catch { throw V4ServiceStreamFailure(underlying: failure, terminalAccepted: false) }
          if let application = failure as? ServiceServerApplicationError,
            original.method.options.errors.contains(where: { $0.code == application.code && application.payload.count <= $0.maxPayloadBytes }),
            application.payload.count <= (try request.uint(8)) {
            // The resumed stream has published the original method's declared
            // terminal error. Preserve that application fact in its history.
            return V4ServiceServerOutcome(payload: application.payload, applicationCode: application.code)
          }
          throw V4ServiceStreamFailure(underlying: failure, terminalAccepted: output.terminalAccepted)
        }
      }, invoke: { _, _, _, _ in throw ServiceFailure.protocolFailure }))
  }

  var needsManagementStorage: Bool { configuration.executionStore != nil }

  func freezeSessionPlan() throws {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      try storage.check(); sealed = true
    }
  }

  func admission(identity: ServiceCallerIdentity, execution: Bool, maximumGeneral: Int,
    checkpointPolicy: (@Sendable () throws -> (Int, UInt64))? = nil, prepaid: V4PrepaidSessionResources? = nil,
    check: @escaping @Sendable () throws -> Void) throws -> V4ServiceServerSession {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }; try storage.check()
      for stream in entries.values where stream.method.options.content != nil {
        guard let definition = stream.method.options.content, let reader = entries[definition.readTypeID], reader.role == .unary,
          reader.method.shape == .unary, reader.definition.namespace == stream.definition.namespace,
          let expected = stream.definition.methods.first(where: { $0.method.typeID == definition.readTypeID }),
          expected.method === reader.method else { throw ServiceFailure.contractMismatch }
      }
      sealed = true
      if !execution, entries.values.contains(where: { $0.method.semantics == .execution }) { throw ServiceFailure.contractMismatch }
      return try V4ServiceServerSession(registry: self, entries: entries, identity: identity, maximumGeneral: maximumGeneral,
        registrationTail: V4ServiceInputTail(try storage.executionTail()), checkpointPolicy: checkpointPolicy, prepaid: prepaid, check: check)
    }
  }
  public func close() { gate.withLock { closed = true; entries.removeAll(); storage.seal() } }
}

// One admitted inbound operation keeps its diagnostic context through the
// application worker, durable provider, timers and original response publisher.
// Those owners retain this object; observer completion does not end its lifetime.
final class V4ServiceServerDiagnostic: V4ApplicationDiagnosticLifetime, @unchecked Sendable {
  let context: V4DiagnosticContext
  private let gate = NSLock()
  private var failure: TransportDiagnosticCode?
  init(_ context: V4DiagnosticContext) { self.context = context; context.emit(.started) }
  func failed(_ error: any Error) {
    failed(code: v4TransportDiagnosticCode(error))
  }
  func failed(code: TransportDiagnosticCode) { gate.withLock { if failure == nil { failure = code } } }
  deinit {
    if let failure { context.emit(.failed, code: failure, retry: .terminal) } else { context.emit(.succeeded) }
    context.emit(.closed)
  }
}

private final class V4ServiceServerRun: @unchecked Sendable {
  var publication: ResponsePublication?
  var work: V4ApplicationWork?
  var timer: Task<Void, Never>?
  let storage: V4CryptoReservation
  let selector: V4ServerExecutionSelector?
  let position: V4ServiceServerPosition
  let diagnostic: V4ServiceServerDiagnostic?
  var result: Result<V4ServiceServerOutcome, any Error>?
  var continuation: CheckedContinuation<V4ServiceServerOutcome, any Error>?
  var recoveryCommitted = false
  var applicationEntered = false
  var enteredAt: ContinuousClock.Instant?
  init(storage: V4CryptoReservation, selector: V4ServerExecutionSelector?, position: V4ServiceServerPosition,
    diagnostic: V4ServiceServerDiagnostic?) {
    self.storage = storage; self.selector = selector; self.position = position; self.diagnostic = diagnostic
  }
}
private final class V4ServiceServerTarget: @unchecked Sendable {
  let id: UInt64
  let kind: String
  let source: any V4RPCTransport
  let facts: (Data, UInt64, Int, UInt64)?
  let readable: @Sendable () throws -> Bool
  let storage: V4CryptoReservation
  let position: V4ServiceServerPosition
  let created = ContinuousClock.now
  var selected = false
  var deadline: UInt64?
  var inputTask: Task<Void, Never>?
  var inputTimer: Task<Void, Never>?
  init(id: UInt64, kind: String, source: any V4RPCTransport, facts: (Data, UInt64, Int, UInt64)?,
    readable: @escaping @Sendable () throws -> Bool, storage: V4CryptoReservation, position: V4ServiceServerPosition) {
    self.id = id; self.kind = kind; self.source = source; self.facts = facts; self.readable = readable; self.storage = storage; self.position = position
  }
}

final class V4ServiceServerSession: V4ServiceInboundDispatcher, @unchecked Sendable {
  private let registry: ServiceRegistry
  private let registrationTail: V4ServiceInputTail
  private let entries: [UInt32: V4ServiceServerEntry]
  private let identity: ServiceCallerIdentity
  private let maximumGeneral: Int
  private let checkSource: @Sendable () throws -> Void
  private let checkpointPolicy: (@Sendable () throws -> (Int, UInt64))?
  private let environment: V4EnvironmentFoundation
  private let group: V4ApplicationGroup
  private let wire: V4ApplicationWireRegistry
  private let namespace: V4NamespaceRegistry
  private let storage: V4CryptoReservation
  private var managementAssembly: ContinuousClock.Instant?
  private var managementDeadline: UInt64?
  private var runs: [UUID: V4ServiceServerRun] = [:]
  private var targets: [UInt64: V4ServiceServerTarget] = [:]
  private let positionOwner = UUID()
  private var generalPositions = 0
  private var notificationPositions = 0
  var generalPositionCount: Int { gate.withLock { generalPositions } }
  private var pendingTasks = 0
  var drainPending: Int { gate.withLock { runs.count + generalPositions + notificationPositions } }
  var physicalPending: Int { gate.withLock { runs.count + pendingTasks } }
  // Handles are cancellation rights, not completion evidence. Every server
  // task stays with this original admission even after its run or target has
  // been removed, including a canceled timer suspended in source.close().
  @discardableResult
  private func startTask(_ operation: @escaping @Sendable () async -> Void) -> Task<Void, Never> {
    gate.withLock {
      pendingTasks += 1
      return Task { [self] in
        defer { gate.withLock { pendingTasks -= 1 } }
        await operation()
      }
    }
  }
  private var draining = false
  private var drainDeadline: ContinuousClock.Instant?
  func beginDrain(deadline: ContinuousClock.Instant) {
    gate.withLock {
      draining = true
      drainDeadline = deadline
    }
  }
  var streamKinds: Set<String> { Set(entries.values.compactMap { $0.streamKind }) }
  private var closed = false
  private var gate: NSRecursiveLock { environment.gate }
  fileprivate init(registry: ServiceRegistry, entries: [UInt32: V4ServiceServerEntry], identity: ServiceCallerIdentity, maximumGeneral: Int,
    registrationTail: V4ServiceInputTail, checkpointPolicy: (@Sendable () throws -> (Int, UInt64))?,
    prepaid: V4PrepaidSessionResources? = nil, check: @escaping @Sendable () throws -> Void) throws {
    self.registry = registry; self.registrationTail = registrationTail; self.entries = entries; self.identity = identity; self.maximumGeneral = maximumGeneral; self.checkpointPolicy = checkpointPolicy; checkSource = check
    environment = registry.environment; group = try environment.applicationGroup()
    wire = try V4ApplicationWireRegistry(); namespace = try V4NamespaceRegistry()
    storage = try prepaid?.take(.server) ?? environment.serviceServerSessionStorage(maximumGeneral: maximumGeneral)
    runs.reserveCapacity(maximumGeneral + 16)
  }
  private func reserveGeneralPosition() throws -> V4ServiceServerPosition {
    try gate.withLock {
      guard !closed, generalPositions < maximumGeneral else { throw ServiceFailure.resourceExhausted }
      try storage.check(); try checkSource()
      let tail = V4ServiceInputTail(try storage.executionTail())
      generalPositions += 1
      return V4ServiceServerPosition(owner: positionOwner, tail: tail, release: { [weak self] in
        guard let self else { return }; gate.withLock { generalPositions -= 1 }
      })
    }
  }
  func reserveRequest(_ header: V4ApplicationHeader) throws -> V4ServiceServerPosition? {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }; try storage.check(); try checkSource()
      return header.kind == "query_contracts_request" ? nil : try reserveGeneralPosition()
    }
  }
  func reserveNotification(_ header: V4ApplicationHeader, storage: V4CryptoReservation) throws -> V4ServiceServerPosition {
    try gate.withLock {
      guard !closed, notificationPositions < 16, storage.environment === environment else { throw ServiceFailure.resourceExhausted }
      try checkHeader(header); try storage.check()
      let tail = V4ServiceInputTail(try storage.executionTail())
      notificationPositions += 1
      return V4ServiceServerPosition(owner: positionOwner, tail: tail, release: { [weak self] in
        guard let self else { return }; gate.withLock { notificationPositions -= 1 }
      })
    }
  }
  func checkHeader(_ header: V4ApplicationHeader) throws {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }; try storage.check(); try checkSource()
      guard !draining else { throw ServiceFailure.serviceUnavailable }
      guard let now = environment.clock.sample().interval, now.upperMS < (try header.uint(5)) else { throw ServiceFailure.deadlineExceeded }
      if header.kind == "query_contracts_request" {
        let binding = registry.configuration.queryBinding
        guard try header.typeID == binding.typeID, try header.bytes(6) == binding.contractDigest,
          try header.payloadBytes <= 2048, try header.uint(5) - now.lowerMS <= binding.maximumLifetimeMS else { throw ServiceFailure.contractMismatch }
        return
      }
      guard let entry = entries[try header.typeID], try header.bytes(6) == entry.contract.digest,
        try UInt64(header.payloadBytes) <= entry.contract.uint(23) else { throw ServiceFailure.contractMismatch }
      _ = try entry.caller(identity)
      let expected: String
      if entry.role == .resultRead { expected = "read_result_request" }
      else if entry.role == .resume { expected = "resume_request" }
      else if entry.method.shape == .notify { expected = entry.method.semantics == .execution ? "execution_notify" : "observation_notify" }
      else if entry.method.shape == .serverStreaming { expected = entry.method.semantics == .execution ? "execution_stream_request" : "transient_stream_request" }
      else { expected = entry.method.semantics == .execution ? "execution_unary_request" : "transient_unary_request" }
      guard header.kind == expected else { throw ServiceFailure.contractMismatch }
      if entry.method.semantics != .execution {
        guard try header.uint(5) - now.lowerMS <= entry.contract.uint(11) else { throw ServiceFailure.deadlineExceeded }
      }
    }
  }
  private func response(_ request: V4ApplicationHeader, payload: Data, applicationCode: UInt32 = 0, sdk: Bool = false) throws -> V4ApplicationHeader {
    guard let selected = wire.variants.first(where: { $0.value.request == request.kind && $0.value.sdkError == sdk && $0.value.applicationError == (applicationCode > 0) }) else { throw ServiceFailure.protocolFailure }
    var fields: [Int: V4ApplicationHeader.Scalar] = [:]
    for id in selected.value.fields where id != 0 {
      if id == 3 { fields[id] = .uint(UInt64(payload.count)) }
      else if id == 10 { fields[id] = .uint(UInt64(applicationCode)) }
      else if let constant = selected.value.constants[id] { fields[id] = .uint(constant) }
      else if let value = request.fields[id] { fields[id] = value }
      else { throw ServiceFailure.protocolFailure }
    }
    return try V4ApplicationHeader(kind: selected.key, fields: fields, registry: wire)
  }
  private func sdkPayload(_ error: any Error) -> Data { v4ServiceSDKPayload(error) }
  func receive(header: V4ApplicationHeader, payload: Data, serial: UInt64, position: V4ServiceServerPosition?, rejection: ServiceFailure?, channel: V4RPCChannel) async {
    let diagnostic = environment.diagnosticContext(.application).map { V4ServiceServerDiagnostic($0) }
    defer { withExtendedLifetime(diagnostic) {} }
    let queryOwner: V4ApplicationQueryOwner?
    do { queryOwner = header.kind == "query_contracts_request" ? try group.executor.reserveQueryOwner(group: group) : nil }
    catch {
      diagnostic?.failed(error)
      let bytes = sdkPayload(error)
      if let reply = try? response(header, payload: bytes, sdk: true) {
        try? await channel.respond(to: serial, header: reply, payload: bytes, diagnosticLifetime: diagnostic, before: { [self, diagnostic] in
          withExtendedLifetime(diagnostic) {}; try checkSource()
        })
      }
      return
    }
    defer { withExtendedLifetime(position) {}; withExtendedLifetime(queryOwner) {} }
    let before: @Sendable () throws -> Void = { [self, queryOwner, diagnostic] in
      withExtendedLifetime(diagnostic) {}
      try checkSource(); withExtendedLifetime(queryOwner) {}
    }
    do {
      guard header.kind == "query_contracts_request" || position?.owner == positionOwner else { throw ServiceFailure.permissionDenied }
      if let rejection { throw rejection }
      try checkHeader(header)
      let result: V4ServiceServerOutcome
      if header.kind == "query_contracts_request" { result = V4ServiceServerOutcome(payload: try await query(payload, diagnostic: diagnostic), applicationCode: 0) }
      else if header.kind == "read_result_request" { result = try await execute(header: header, payload: payload, position: position, diagnostic: diagnostic) }
      else if header.kind == "resume_request" { try await resume(header: header, payload: payload, serial: serial, channel: channel, diagnostic: diagnostic); return }
      else { result = try await execute(header: header, payload: payload, position: position, diagnostic: diagnostic) }
      let reply = try response(header, payload: result.payload, applicationCode: result.applicationCode)
      try await channel.respond(to: serial, header: reply, payload: result.payload, publication: result.publication, diagnosticLifetime: diagnostic, before: {
        try before()
        guard let now = self.environment.clock.sample().interval, now.upperMS < (try header.uint(5)) else { throw ServiceFailure.deadlineExceeded }
      })
    } catch {
      diagnostic?.failed((error as? V4RPCResponsePublicationFailure)?.underlying ?? error)
      if let publication = error as? V4RPCResponsePublicationFailure,
        publication.committed || publication.cause == .responseAborted || publication.cause == .deadline || publication.cause == .ownerUnavailable { return }
      let bytes = sdkPayload((error as? V4RPCResponsePublicationFailure)?.underlying ?? error)
      if let reply = try? response(header, payload: bytes, sdk: true) {
        try? await channel.respond(to: serial, header: reply, payload: bytes, diagnosticLifetime: diagnostic, before: before)
      }
    }
  }
  func receiveNotification(header: V4ApplicationHeader, payload: Data, position: V4ServiceServerPosition) async {
    let diagnostic = environment.diagnosticContext(.application).map { V4ServiceServerDiagnostic($0) }
    defer { withExtendedLifetime(position) {}; withExtendedLifetime(diagnostic) {} }
    do { try checkHeader(header); _ = try await execute(header: header, payload: payload, position: position, diagnostic: diagnostic) }
    catch { diagnostic?.failed(error) }
  }
  private func selector(entry: V4ServiceServerEntry, header: V4ApplicationHeader, payload: Data) throws -> V4ServerExecutionSelector? {
    guard entry.method.semantics == .execution else { return nil }
    let caller = try entry.caller(identity); let operation = try header.bytes(1); let request = try header.bytes(4)
    guard try entry.contract.executionRequestDigest(header: header, payload: payload) == request,
      let now = environment.clock.sample().interval else { throw ServiceFailure.contractMismatch }
    let cutoff = operation.prefix(8).reduce(0) { $0 << 8 | UInt64($1) }; let deadline = try header.uint(5)
    guard cutoff > now.upperMS, cutoff <= deadline, cutoff - now.lowerMS <= (try entry.contract.uint(16)),
      deadline - cutoff <= (try entry.contract.uint(17)) else { throw ServiceFailure.admissionWindowClosed }
    return V4ServerExecutionSelector(tenant: identity.tenant, audience: identity.audience, namespace: entry.definition.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: operation, request: request, contract: entry.contract.digest)
  }
  private func checkpointReissuer(entry: V4ServiceServerEntry, selector: V4ServerExecutionSelector?) throws -> V4ServiceCheckpointReissuer? {
    guard let selector, let store = registry.configuration.executionStore, let checkpointPolicy,
      entry.method.semantics == .execution, try entry.contract.uint(13) == 1 else { return nil }
    return { [self, store] reference, originalContract, previousToken, lifetimeMS in
      try checkSource(); try originalContract.checkEnvironment(environment)
      guard reference.targetDomain == registry.configuration.authority,
        reference.tenant == identity.tenant, reference.audience == identity.audience, reference.durable,
        reference.serviceNamespace == originalContract.namespace, reference.serviceContractDigest == originalContract.digest,
        originalContract.semantics == .execution, try originalContract.uint(13) == 1,
        let original = entries[originalContract.typeID], original.contract.digest == originalContract.digest,
        original.definition.namespace == reference.serviceNamespace, reference.shape == original.method.shape,
        original.role == .unary || original.role == .streaming,
        try originalContract.checkpointFormat() == previousToken.checkpoint.format else { throw ServiceFailure.permissionDenied }
      let caller = try original.caller(identity)
      guard reference.callerSubject == caller.subject, reference.callerAuthority == caller.executionAuthority else { throw ServiceFailure.permissionDenied }
      let target = V4ServerExecutionSelector(tenant: reference.tenant, audience: reference.audience,
        namespace: reference.serviceNamespace, caller: caller.subject, authority: caller.executionAuthority,
        operation: reference.operationID, request: reference.requestDigest, contract: reference.serviceContractDigest)
      guard target.key != selector.key,
        let record = try await store.lookup(target, includeResult: false), record.deadline == reference.deadlineAtMS else { throw ServiceFailure.operationConflict }
      let (maximumBytes, maximumDuration) = try checkpointPolicy()
      let storage = try environment.resumeStorage(); let tail = V4ServiceInputTail(try storage.executionTail())
      defer { withExtendedLifetime(tail) {} }
      let issued = try await store.reissue(target, issuer: selector, previousToken: previousToken, lifetimeMS: lifetimeMS,
        maximumIssuedDurationMS: maximumDuration, maximumTokenBytes: maximumBytes,
        maximumOriginalRunMS: min(try originalContract.uint(18), originalContract.shape == .serverStreaming ? try originalContract.uint(26) : .max),
        maximumIssuerRunMS: min(try entry.contract.uint(18), entry.method.shape == .serverStreaming ? try entry.contract.uint(26) : .max))
      try checkSource(); return issued
    }
  }
  private func contentSaver(entry: V4ServiceServerEntry, selector: V4ServerExecutionSelector?) throws
    -> (@Sendable (Data, Data) async throws -> StreamContentObservation)? {
    guard let selector, let store = registry.configuration.executionStore,
      let policy = try entry.contract.streamContentPolicy(entry.method.options.content) else { return nil }
    return { [self, store] position, payload in
      try checkSource()
      guard (1...256).contains(position.count), payload.count <= min(policy.maximumBytes, 1_048_576) else { throw ServiceFailure.configurationCapacity }
      let input = try environment.serviceOperationStorage(requestBytes: payload.count, responseBytes: 0)
      let positionOwner = try environment.serviceOperationStorage(requestBytes: position.count, responseBytes: 0)
      let tail = V4ServiceInputTail(try input.executionTail())
      let positionTail = V4ServiceInputTail(try positionOwner.executionTail())
      defer { withExtendedLifetime((tail, positionTail)) {} }
      let result = try await store.saveContent(selector, policy: policy, position: position, payload: payload)
      try checkSource(); return result
    }
  }
  private func contentReader(entry: V4ServiceServerEntry, responseLimit: Int)
    -> (@Sendable (StreamContentTarget, Data, Int) async throws -> RetainedStreamContent)? {
    guard entry.role == .unary, let store = registry.configuration.executionStore,
      entries.values.contains(where: { $0.method.options.content?.readTypeID == entry.method.typeID }) else { return nil }
    return { [self, store, entry] target, position, maximumBytes in
      try checkSource()
      guard target.tenant == identity.tenant, target.audience == identity.audience,
        let original = entries.values.first(where: { $0.role == .streaming && $0.definition.namespace == target.serviceNamespace &&
          $0.contract.digest == target.serviceContractDigest && $0.method.options.content?.readTypeID == entry.method.typeID }),
        original.definition.namespace == entry.definition.namespace,
        let definition = original.method.options.content,
        let declaredReader = original.definition.methods.first(where: { $0.method.typeID == definition.readTypeID }),
        declaredReader.method === entry.method else { throw ServiceFailure.permissionDenied }
      let caller = try original.caller(identity)
      guard target.callerSubject == caller.subject, target.callerAuthority == caller.executionAuthority,
        (1...256).contains(position.count), (0...responseLimit).contains(maximumBytes),
        let policy = try original.contract.streamContentPolicy(definition) else { throw ServiceFailure.permissionDenied }
      let output = try environment.serviceOperationStorage(requestBytes: 4096 + position.count, responseBytes: maximumBytes)
      let tail = V4ServiceInputTail(try output.executionTail()); defer { withExtendedLifetime(tail) {} }
      let result = try await store.readContent(target.selector, policy: policy, position: position, maximumBytes: maximumBytes)
      try checkSource(); return result
    }
  }
  private func execute(header: V4ApplicationHeader, payload: Data, position: V4ServiceServerPosition? = nil, target: V4ServiceServerTarget? = nil,
    diagnostic: V4ServiceServerDiagnostic?) async throws -> V4ServiceServerOutcome {
    guard let entry = entries[try header.typeID] else { throw ServiceFailure.contractMismatch }
    let selector = try selector(entry: entry, header: header, payload: payload)
    let stream = target?.source
    let responseLimit: Int
    if entry.method.shape == .notify { responseLimit = 0 }
    else if entry.role == .resultRead {
      // The fixed result-read header has no caller response-limit field.
      // Its local registered contract owns the body bound before any copy.
      responseLimit = Int(try entry.contract.uint(10))
    } else { responseLimit = Int(try header.uint(8)) }
    guard responseLimit >= (try entry.contract.uint(9)), responseLimit <= (try entry.contract.uint(10)) else { throw ServiceFailure.contractMismatch }
    let token = UUID()
    let run = try gate.withLock { () -> V4ServiceServerRun in
      guard !closed else { throw ServiceFailure.closed }
      if let target {
        guard targets[target.id] === target, target.selected else { throw ServiceFailure.permissionDenied }
      }
      guard let originalPosition = target?.position ?? position, originalPosition.owner == positionOwner else { throw ServiceFailure.permissionDenied }
      try checkSource(); let original = V4ServiceServerRun(storage: try environment.serviceServerOperationStorage(requestBytes: payload.count, responseBytes: max(responseLimit, 256)), selector: selector, position: originalPosition, diagnostic: diagnostic)
      if let deadline = entry.method.options.restartFlushDeadlineMS {
        guard let owner = registry.configuration.maintenanceOwner else { throw ServiceFailure.configurationCapacity }
        original.publication = try owner.reserve(deadlineMS: deadline)
      }
      runs[token] = original; return original
    }
    var selectedPublication = false
    defer {
      gate.withLock { runs.removeValue(forKey: token) }
      if !selectedPublication { run.publication?.abandon(.responseSuperseded) }
    }
    let store = registry.configuration.executionStore
    if let selector, let store {
      let admitted = try await store.admit(selector, deadline: header.uint(5), historyMS: entry.contract.uint(14), responseBytes: entry.method.shape == .unary ? responseLimit : 0,
        contentPolicy: entry.contract.streamContentPolicy(entry.method.options.content),
        originalStreamHeader: entry.method.shape == .serverStreaming ? header.encoded() : nil)
      if !admitted {
        guard let known = try await store.lookup(selector, includeResult: entry.method.shape == .unary, maximumBodyBytes: responseLimit) else { throw ServiceFailure.historyUnknown }
        if entry.method.shape == .notify { return V4ServiceServerOutcome(payload: Data(), applicationCode: 0) }
        guard let bytes = known.result else { throw known.resultDeleted ? ServiceFailure.resultExpired : ServiceFailure.serviceUnavailable }
        return V4ServiceServerOutcome(payload: bytes, applicationCode: UInt32(known.resultCode))
      }
    }
    do {
      let deadline = try header.uint(5)
      let semanticRun: UInt64
      switch entry.method.semantics {
      case .observation:
        // Observation has no contract run field. Its original message deadline
        // and the finite local callback budget both remain in force.
        semanticRun = 30_000
      case .transient: semanticRun = try entry.contract.uint(12)
      case .execution: semanticRun = try entry.contract.uint(18)
      }
      let maximumRun = min(semanticRun,
        entry.method.shape == .serverStreaming ? try entry.contract.uint(26) : UInt64.max)
      let timerTail = V4ServiceInputTail(try run.storage.executionTail())
      let outcome: V4ServiceServerOutcome = try await withCheckedThrowingContinuation { continuation in
        do {
          let original = try gate.withLock { () -> V4ApplicationWork in
            guard !closed else { throw ServiceFailure.closed }; try checkSource(); run.continuation = continuation
            let work = try V4ApplicationWork(group: group, context: nil, operation: { [self, run, entry, store, selector] context in
              context.diagnosticLifetime = run.diagnostic
              gate.withLock { run.applicationEntered = true }
              let result: Result<V4ServiceServerOutcome, any Error>
              do {
                let invocation = ServiceServerInvocation(context: context, check: checkSource, store: store, selector: selector, contract: entry.contract, checkpointPolicy: checkpointPolicy, responsePublication: run.publication ?? .notApplicable,
                  checkpointReissue: try checkpointReissuer(entry: entry, selector: selector), contentSave: try contentSaver(entry: entry, selector: selector),
                  contentRead: contentReader(entry: entry, responseLimit: responseLimit), outputStorage: run.storage, enter: { [self, run] in gate.withLock { if run.enteredAt == nil { run.enteredAt = .now } } }, enteredAt: { [self, run] in gate.withLock { run.enteredAt } }, stream: stream, request: header)
                try invocation.checkCancellation()
                if entry.role == .resultRead {
                  gate.withLock { if run.enteredAt == nil { run.enteredAt = .now } }
                  result = .success(V4ServiceServerOutcome(payload: try await readResult(payload, maximumBytes: responseLimit), applicationCode: 0))
                } else { result = .success(try await entry.invoke(context, invocation, payload, responseLimit)) }
              } catch let failure as ServiceServerApplicationError {
                run.diagnostic?.failed(failure)
                if let declared = entry.method.options.errors.first(where: { $0.code == failure.code }), failure.payload.count <= declared.maxPayloadBytes,
                  failure.payload.count <= responseLimit { result = .success(V4ServiceServerOutcome(payload: failure.payload, applicationCode: failure.code)) }
                else { result = .failure(ServiceFailure.contractMismatch) }
              } catch { run.diagnostic?.failed(error); result = .failure(error) }
              if let selector, let store {
                do {
                  if case .success(let output) = result {
                    let retention = entry.method.shape == .unary ? entry.contract.optionalUInt(15) ?? 0 : 0
                    try await store.complete(selector, payload: output.payload, applicationCode: output.applicationCode,
                      resultRetentionMS: retention, metadataOnly: entry.method.shape != .unary)
                  } else { try await store.complete(selector, payload: nil, resultRetentionMS: 0) }
                } catch { run.diagnostic?.failed(error); gate.withLock { run.result = .failure(ServiceFailure.serviceUnavailable) }; return }
              }
              gate.withLock { run.result = result }
            }, onExit: { [self, run] in
              run.timer?.cancel(); run.work = nil
              if !run.applicationEntered { run.diagnostic?.failed(ServiceFailure.closed) }
              let waiting = run.continuation; run.continuation = nil
              waiting?.resume(with: run.result ?? .failure(ServiceFailure.closed)); run.result = nil
            })
            run.work = work; return work
          }
          gate.withLock {
            run.timer = startTask { [self, run, timerTail] in
              defer { withExtendedLifetime(timerTail) {}; gate.withLock { run.timer = nil } }
              while !Task.isCancelled {
                let expired = gate.withLock { () -> Bool in
                  if closed { return true }
                  guard let now = environment.clock.sample().interval else { return true }
                  if now.upperMS >= deadline { return true }
                  return run.enteredAt.map { ContinuousClock.now >= $0.advanced(by: .milliseconds(Int64(clamping: maximumRun))) } == true
                }
                if expired { run.diagnostic?.failed(ServiceFailure.deadlineExceeded); gate.withLock { run.work?.cancel() }; if let stream { try? await stream.close() }; return }
                do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
              }
            }
          }
          original.start()
        } catch { run.continuation = nil; continuation.resume(throwing: error) }
      }
      selectedPublication = true
      return V4ServiceServerOutcome(payload: outcome.payload, applicationCode: outcome.applicationCode, publication: run.publication)
    } catch {
      run.diagnostic?.failed(error)
      if let selector, let store { try? await store.complete(selector, payload: nil, resultRetentionMS: 0, reason: 2) }
      throw error
    }
  }
  func adoptStream(id: UInt64, kind: String, source: any V4RPCTransport, facts: (Data, UInt64, Int, UInt64)?,
    readable: @escaping @Sendable () throws -> Bool) throws {
    try gate.withLock {
      guard !closed, targets[id] == nil, generalPositions < maximumGeneral, streamKinds.contains(kind) else { throw ServiceFailure.resourceExhausted }
      try checkSource()
      let position = try reserveGeneralPosition()
      targets[id] = V4ServiceServerTarget(id: id, kind: kind, source: source, facts: facts, readable: readable,
        storage: try environment.serviceServerOperationStorage(requestBytes: 0, responseBytes: 0), position: position)
    }
  }
  func pollStreams() {
    gate.withLock {
      for target in targets.values where !target.selected {
        do {
          try checkSource(); try target.storage.check()
          guard ContinuousClock.now < target.created.advanced(by: .seconds(30)) else { throw ServiceFailure.deadlineExceeded }
          guard try target.readable() else { continue }
          guard entries.values.contains(where: { $0.role == .streaming && $0.streamKind == target.kind }) else { throw ServiceFailure.protocolFailure }
          target.selected = true
          let tail = V4ServiceInputTail(try target.storage.executionTail())
          let timerTail = V4ServiceInputTail(try target.storage.executionTail())
          let diagnostic = environment.diagnosticContext(.application).map { V4ServiceServerDiagnostic($0) }
          target.inputTimer = startTask { [self, target, timerTail, diagnostic] in
            defer { withExtendedLifetime(timerTail) {}; withExtendedLifetime(diagnostic) {}; gate.withLock { target.inputTimer = nil } }
            let assemblyDeadline = ContinuousClock.now.advanced(by: .seconds(30))
            while !Task.isCancelled {
              let failure = gate.withLock { () -> ServiceFailure? in
                if closed { return .closed }
                if ContinuousClock.now >= assemblyDeadline { return .deadlineExceeded }
                if let deadline = target.deadline,
                  environment.clock.sample().interval.map({ $0.upperMS >= deadline }) != false {
                  return .deadlineExceeded
                }
                return nil
              }
              if let failure { diagnostic?.failed(failure); try? await target.source.close(); return }
              do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
            }
          }
          target.inputTask = startTask { [self, target, tail, diagnostic] in
            defer {
              withExtendedLifetime(diagnostic) {}
              gate.withLock { target.inputTimer?.cancel(); target.inputTask = nil; targets.removeValue(forKey: target.id) }
              withExtendedLifetime(tail) {}
            }
            do {
              guard let prefix = try await exact(2, from: target.source) else { throw ServiceFailure.protocolFailure }
              let length = prefix.reduce(0) { $0 << 8 | Int($1) }
              guard (1...512).contains(length), let headerBytes = try await exact(length, from: target.source) else { throw ServiceFailure.protocolFailure }
              let header = try V4ApplicationHeader(encoded: headerBytes, registry: wire)
              try checkHeader(header); try gate.withLock { target.deadline = try header.uint(5) }
              guard let entry = entries[try header.typeID], entry.role == .streaming, entry.streamKind == target.kind else { throw ServiceFailure.contractMismatch }
              let bodyStorage = try environment.serviceOperationStorage(requestBytes: header.payloadBytes, responseBytes: 0)
              let bodyTail = V4ServiceInputTail(try bodyStorage.executionTail())
              defer { withExtendedLifetime(bodyTail) {} }
              guard let payload = try await exact(header.payloadBytes, from: target.source) else { throw ServiceFailure.protocolFailure }
              guard try await target.source.read(maxBytes: 1) == nil else { throw ServiceFailure.protocolFailure }
              gate.withLock { target.inputTimer?.cancel() }
              _ = try await execute(header: header, payload: payload, target: target, diagnostic: diagnostic)
            } catch let failure as V4ServiceStreamFailure where failure.terminalAccepted { diagnostic?.failed(failure.underlying) }
            catch { diagnostic?.failed(error); try? await target.source.close() }
          }
        } catch {
          target.selected = true
          let tail = try? target.storage.executionTail()
          startTask { [self, target, tail] in defer { tail?.release(); gate.withLock { targets.removeValue(forKey: target.id) } }; try? await target.source.close() }
        }
      }
    }
  }

  private func resume(header: V4ApplicationHeader, payload: Data, serial: UInt64, channel: V4RPCChannel,
    diagnostic: V4ServiceServerDiagnostic?) async throws {
    guard let entry = entries[try header.typeID], entry.role == .resume, let originalContract = entry.originalContract,
      let callback = entry.resume, let store = registry.configuration.executionStore,
      let originalEntry = entries.values.first(where: { $0.contract.digest == originalContract.digest && ($0.role == .unary || $0.role == .streaming) }),
      let newSelector = try selector(entry: entry, header: header, payload: payload) else { throw ServiceFailure.contractMismatch }
    let caller = try originalEntry.caller(identity)
    let request = try V4NamespaceDocument(payload, schema: "ResumeRequest", bytes: 9345, nodes: 128, registry: namespace).root
    let checkpoint = try ApplicationCheckpoint(request.field("expected_checkpoint"))
    guard checkpoint.format == (try originalContract.checkpointFormat()),
      let protection = CheckpointTokenProtection(rawValue: try request.u("protection")) else { throw ServiceFailure.contractMismatch }
    let oldSelector = try V4ServerExecutionSelector(tenant: identity.tenant, audience: identity.audience, namespace: originalContract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.b("original_operation_id"),
      request: request.b("original_request_digest"), contract: originalContract.digest)
    let limit = Int(try header.uint(8))
    guard limit >= 4248, limit <= (try entry.contract.uint(10)) else { throw ServiceFailure.contractMismatch }
    let admitted = try await store.admit(newSelector, deadline: header.uint(5), historyMS: entry.contract.uint(14), responseBytes: limit)
    if !admitted {
      guard let record = try await store.lookup(newSelector, maximumBodyBytes: limit), let bytes = record.result else { throw ServiceFailure.serviceUnavailable }
      let reply = try response(header, payload: bytes); try await channel.respond(to: serial, header: reply, payload: bytes, diagnosticLifetime: diagnostic, before: checkSource); return
    }
    let token = UUID()
    let target: V4ServiceServerTarget
    let run: V4ServiceServerRun
    do {
      let streamID = try request.u("stream_id"); let context = try request.b("transport_context_digest")
      (target, run) = try gate.withLock {
        guard !closed, let target = targets[streamID], !target.selected,
          let facts = target.facts, facts.0 == context, facts.1 == streamID, target.kind == entry.streamKind,
          ContinuousClock.now < target.created.advanced(by: .seconds(30)), try !target.readable() else { throw ServiceFailure.permissionDenied }
        try checkSource(); try target.storage.check()
        let run = V4ServiceServerRun(storage: try environment.serviceServerOperationStorage(requestBytes: payload.count, responseBytes: 4248), selector: oldSelector, position: target.position, diagnostic: diagnostic)
        target.selected = true; runs[token] = run; return (target, run)
      }
    } catch { try? await store.complete(newSelector, payload: nil, resultRetentionMS: 0, reason: 2); throw error }
    let original: V4ServerExecutionRecord
    let facts: (Data, UInt64, Int, UInt64)
    let originalResultTail: V4ServiceInputTail
    let timerTail: V4ServiceInputTail
    let maximumRun: UInt64
    let originalHeader: V4ApplicationHeader?
    let originalRunDeadline: UInt64
    do {
      guard let record = try await store.lookup(oldSelector, includeResult: false), let observed = target.facts else { throw ServiceFailure.historyUnknown }
      original = record; facts = observed
      if originalContract.shape == .serverStreaming {
        guard let encoded = record.originalStreamHeader else { throw ServiceFailure.historyUnknown }
        let parsed = try V4ApplicationHeader(encoded: encoded, registry: wire)
        guard parsed.kind == "execution_stream_request", try parsed.bytes(1) == oldSelector.operation,
          try parsed.bytes(4) == oldSelector.request, try parsed.bytes(6) == oldSelector.contract,
          try parsed.uint(2) == UInt64(originalContract.typeID), try parsed.uint(5) == record.deadline,
          try parsed.uint(8) >= originalContract.uint(9), try parsed.uint(8) <= originalContract.uint(10) else { throw ServiceFailure.contractMismatch }
        originalHeader = parsed
      } else { originalHeader = nil }
      // Durable disk capacity is distinct from the resumed encoder's actual
      // memory/copy responsibility. Both are owned before token consumption.
      let resultStorage = try environment.serviceServerOperationStorage(requestBytes: 0, responseBytes: max(Int(record.reservedBytes), Int(try originalHeader?.uint(8) ?? 0)))
      originalResultTail = V4ServiceInputTail(try resultStorage.executionTail())
      timerTail = V4ServiceInputTail(try run.storage.executionTail())
      maximumRun = min(try originalContract.uint(18), originalContract.shape == .serverStreaming ? try originalContract.uint(26) : .max)
      originalRunDeadline = try record.originalRunDeadline(maximumRunMS: maximumRun)
      guard let now = environment.clock.sample().interval, now.upperMS < originalRunDeadline else { throw ServiceFailure.deadlineExceeded }
    } catch {
      run.diagnostic?.failed(error)
      try? await target.source.close()
      gate.withLock { targets.removeValue(forKey: target.id); runs.removeValue(forKey: token) }
      try? await store.complete(newSelector, payload: nil, resultRetentionMS: 0, reason: 2); throw error
    }
    let work: V4ApplicationWork
    do {
      work = try V4ApplicationWork(group: group, context: nil, operation: { [self, run, target, store, oldSelector, originalContract, originalResultTail] context in
        defer { withExtendedLifetime(originalResultTail) {} }
        context.diagnosticLifetime = run.diagnostic
        gate.withLock { run.applicationEntered = true }
        do {
          let invocation = ServiceServerInvocation(context: context, check: checkSource, store: store, selector: oldSelector,
            contract: originalContract, checkpointPolicy: checkpointPolicy, contentSave: try contentSaver(entry: originalEntry, selector: oldSelector), outputStorage: run.storage, deadlineAtMS: originalRunDeadline, enter: { [self, run] in gate.withLock { if run.enteredAt == nil { run.enteredAt = .now } } }, enteredAt: { [self, run] in gate.withLock { run.enteredAt } }, resumed: true, stream: target.source, request: originalHeader)
          let output = try await callback(context, invocation, checkpoint, target.source, Int(original.reservedBytes))
          try await store.complete(oldSelector, payload: output.payload, applicationCode: output.applicationCode,
            resultRetentionMS: originalContract.optionalUInt(15) ?? 0, metadataOnly: originalContract.shape == .serverStreaming)
          if originalContract.shape != .serverStreaming {
            try await target.source.closeWrite(); try await target.source.finish()
          }
        } catch let failure as V4ServiceStreamFailure where failure.terminalAccepted {
          run.diagnostic?.failed(failure.underlying)
          // The original streaming owner already accepted its bounded error
          // and FIN. Preserve unknown execution without resetting that tail.
          try? await store.complete(oldSelector, payload: nil, resultRetentionMS: 0)
        } catch {
          run.diagnostic?.failed(error)
          try? await store.complete(oldSelector, payload: nil, resultRetentionMS: 0)
          try? await target.source.close()
        }
      }, onExit: { [self, run, target, store, oldSelector] in
        run.timer?.cancel(); run.work = nil
        runs.removeValue(forKey: token)
        if !run.applicationEntered {
          run.diagnostic?.failed(ServiceFailure.closed)
          let tail = try? run.storage.executionTail()
          startTask { [self, run, target, tail] in
            defer { tail?.release(); gate.withLock { targets.removeValue(forKey: target.id) } }
            if run.recoveryCommitted { try? await store.complete(oldSelector, payload: nil, resultRetentionMS: 0, reason: 2) }
            try? await target.source.close()
          }
        } else { targets.removeValue(forKey: target.id) }
      })
      run.work = work
    } catch {
      run.diagnostic?.failed(error)
      try? await target.source.close()
      gate.withLock { targets.removeValue(forKey: target.id); runs.removeValue(forKey: token) }
      try? await store.complete(newSelector, payload: nil, resultRetentionMS: 0, reason: 2); throw error
    }
    do {
      try checkSource(); try await store.started(newSelector)
      let generation = try await store.consume(oldSelector, encodedToken: request.b("token"), protection: protection,
        generation: request.u("generation"), checkpoint: checkpoint, maximumTokenBytes: facts.2,
        confirmation: newSelector, resultRetentionMS: entry.contract.optionalUInt(15) ?? 0, maximumOriginalRunMS: maximumRun)
      gate.withLock { run.recoveryCommitted = true }
      guard !work.isFinished else { throw ServiceFailure.closed }
      try checkSource()
      let bytes = V4Crypto.map([(0, V4NamespaceValue.head(0, 0)), (1, V4Crypto.map([(0, checkpoint.encoded()), (1, V4NamespaceValue.head(0, generation))]))])
      _ = try V4NamespaceDocument(bytes, schema: "ResumeResult", bytes: 4248, nodes: 32, registry: namespace)
      let reply = try response(header, payload: bytes)
      try await channel.respond(to: serial, header: reply, payload: bytes, diagnosticLifetime: diagnostic, before: checkSource)
      try gate.withLock { guard !closed else { throw ServiceFailure.closed }; try checkSource() }
      gate.withLock {
        run.timer = startTask { [self, run, timerTail, target] in
          defer { withExtendedLifetime(timerTail) {}; gate.withLock { run.timer = nil } }
          while !Task.isCancelled {
            let expired = gate.withLock { () -> Bool in
              if closed || environment.clock.sample().interval.map({ $0.upperMS >= originalRunDeadline }) != false { return true }
              return run.enteredAt.map { ContinuousClock.now >= $0.advanced(by: .milliseconds(Int64(clamping: maximumRun))) } == true
            }
            if expired { run.diagnostic?.failed(ServiceFailure.deadlineExceeded); gate.withLock { run.work?.cancel() }; try? await target.source.close(); return }
            do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
          }
        }
      }
      work.start()
    } catch {
      run.diagnostic?.failed(error)
      work.cancel()
      if run.recoveryCommitted && work.isFinished { try? await store.complete(oldSelector, payload: nil, resultRetentionMS: 0, reason: 2) }
      try? await store.complete(newSelector, payload: nil, resultRetentionMS: 0, reason: 2)
      try? await target.source.close(); throw error
    }
  }

  private func query(_ payload: Data, diagnostic: V4ServiceServerDiagnostic?) async throws -> Data {
    let queryStorage = try environment.serviceQueryStorage(responseBytes: 73728)
    let job = V4ServiceQueryResponseJob(environment: environment, registry: namespace, payload: payload,
      entries: entries, identity: identity, maximumWindowMS: registry.configuration.maximumOfferWindowMS,
      storage: queryStorage, diagnostic: diagnostic, check: checkSource)
    return try await job.result(executor: group.executor.fixedQueries)
  }
  private func managementSelector(_ payload: Data) throws -> (V4ServerExecutionSelector, V4ServiceServerEntry) {
    try checkSource()
    let value = try V4NamespaceDocument(payload, schema: "ExecutionManagementTarget", bytes: 1024, nodes: 32, registry: namespace).root
    let name = try value.t("service_namespace")
    let digest = try value.b("service_contract_digest")
    guard try value.t("tenant_id") == identity.tenant, try value.t("audience") == identity.audience,
      let entry = entries.values.first(where: { $0.definition.namespace == name && $0.contract.digest == digest && $0.method.semantics == .execution }) else { throw ServiceFailure.permissionDenied }
    let caller = try entry.caller(identity)
    guard try value.t("caller_subject") == caller.subject, try value.b("caller_authority") == caller.executionAuthority else { throw ServiceFailure.permissionDenied }
    return try (V4ServerExecutionSelector(tenant: identity.tenant, audience: identity.audience, namespace: name,
      caller: caller.subject, authority: caller.executionAuthority, operation: value.b("operation_id"),
      request: value.b("request_digest"), contract: digest), entry)
  }
  private func readResult(_ payload: Data, maximumBytes: Int) async throws -> Data {
    guard let store = registry.configuration.executionStore else { throw ServiceFailure.serviceUnavailable }
    let (selector, entry) = try managementSelector(payload)
    guard entry.method.shape == .unary, let record = try await store.lookup(selector, maximumBodyBytes: maximumBytes) else { throw ServiceFailure.historyUnknown }
    try checkSource()
    guard let now = environment.clock.sample().interval, now.upperMS < record.resultUntil, let result = record.result else {
      throw record.resultDeleted || record.resultUntil > 0 ? ServiceFailure.resultExpired : ServiceFailure.serviceUnavailable
    }
    guard result.count <= maximumBytes else { throw ServiceFailure.resourceExhausted }
    return result
  }
  func checkManagementSource() throws {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      try storage.check(); try checkSource()
    }
  }
  func handleManagementRequest(_ request: V4ApplicationHeader, payload: Data,
    diagnostic: (any V4ApplicationDiagnosticLifetime)?) async throws -> Data {
    let cancel = request.kind == "request_cancel_request"
    guard cancel || request.kind == "query_operation_request" else { throw ServiceFailure.protocolFailure }
    let document = try JSONSerialization.jsonObject(with: Data(TransportV4Registry.applicationHeaderRegistryJSON.utf8)) as! [String: Any]
    let methods = (document["management"] as! [String: Any])["methods"] as! [String: [String: Any]]
    let binding = methods[cancel ? "cancel" : "query"]!
    guard let type = V4NamespaceRegistry.number(binding["type"]),
      let digestHex = binding["contract_digest_hex"] as? String,
      try request.typeID == type, try request.bytes(6) == V4ExecutionManagementChannel.hex(digestHex) else {
      throw ServiceFailure.protocolFailure
    }
    try gate.withLock {
      guard !closed, payload.count == (try request.payloadBytes),
        try request.payloadBytes <= 1024 else { throw ServiceFailure.protocolFailure }
      guard let interval = environment.clock.sample().interval,
        try request.uint(5) > interval.upperMS,
        try request.uint(5) - interval.lowerMS <= 30_000 else { throw ServiceFailure.deadlineExceeded }
      if let drainDeadline {
        let remaining = max(.zero, ContinuousClock.now.duration(to: drainDeadline)).components
        let ms = UInt64(remaining.seconds) * 1000 + UInt64(remaining.attoseconds) / 1_000_000_000_000_000
        let (end, overflow) = interval.lowerMS.addingReportingOverflow(ms)
        guard !overflow else { throw ServiceFailure.deadlineExceeded }
        managementDeadline = min(try request.uint(5), end)
      } else {
        managementDeadline = try request.uint(5)
      }
      managementAssembly = .now
    }
    defer {
      withExtendedLifetime(diagnostic) {}
      gate.withLock { managementAssembly = nil; managementDeadline = nil }
    }
    do {
      let result = await management(payload, cancel: cancel, diagnostic: diagnostic)
      try checkManagementProgress()
      return result
    } catch {
      diagnostic?.failed(error)
      throw error
    }
  }

  private func checkManagementProgress() throws {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }; try storage.check(); try checkSource()
      if let started = managementAssembly, ContinuousClock.now >= started.advanced(by: .seconds(30)) {
        throw ServiceFailure.deadlineExceeded
      }
      if let drainDeadline { guard ContinuousClock.now < drainDeadline else { throw ServiceFailure.deadlineExceeded } }
      if let deadline = managementDeadline {
        guard let now = environment.clock.sample().interval, now.upperMS < deadline else { throw ServiceFailure.deadlineExceeded }
      }
    }
  }
  private func observation(_ record: V4ServerExecutionRecord?) -> Data {
    guard let record else { return V4Crypto.map([(0, Data([0xf4])), (1, V4NamespaceValue.head(0, 6))]) }
    let available = record.dispatched && record.resultPresent && environment.clock.sample().interval.map { $0.upperMS < record.resultUntil } == true
    // The found=true wire variant requires all fixed facts, including the
    // zero result selector before a body exists. Absence has a separate shape.
    return V4Crypto.map([(0, Data([0xf5])), (1, V4NamespaceValue.head(0, record.reason)),
      (2, V4NamespaceValue.head(0, record.state)), (3, Data([record.cancelled ? 0xf5 : 0xf4])),
      (4, Data([record.dispatched ? 0xf5 : 0xf4])), (5, Data([record.active ? 0xf5 : 0xf4])),
      (6, V4NamespaceValue.head(0, record.historyUntil)), (7, V4NamespaceValue.head(0, record.resultUntil)),
      (8, Data([available ? 0xf5 : 0xf4])), (9, Data([record.resultDeleted ? 0xf5 : 0xf4])),
      (10, V4NamespaceValue.head(0, record.resultBytes)), (11, V4NamespaceValue.head(0, record.resultCode)),
      (12, V4Crypto.bytes(record.resultDigest ?? Data(repeating: 0, count: 32)))])
  }
  private func management(_ payload: Data, cancel: Bool, diagnostic: (any V4ApplicationDiagnosticLifetime)?) async -> Data {
    do {
      guard let store = registry.configuration.executionStore else { throw ServiceFailure.serviceUnavailable }
      let (selector, entry) = try managementSelector(payload)
      if cancel, try entry.contract.uint(19) == 0 {
        diagnostic?.failed(code: .unsupported)
        return V4Crypto.map([(0, V4NamespaceValue.head(0, 4))])
      }
      // The store actor may start later than request admission. Recheck the
      // original request, session and Drain bounds before reading or committing.
      let before: @Sendable () throws -> Void = { [self] in try checkManagementProgress() }
      let record = try await (cancel ? store.cancel(selector, before: before) : store.lookup(selector, includeResult: false, before: before))
      try checkManagementProgress()
      if cancel, record?.active == true {
        gate.withLock { for run in runs.values where run.selector?.key == selector.key { run.work?.cancel() } }
      }
      let status: UInt64 = cancel ? 0 : record == nil ? 8 : record!.resultDeleted ? 6 : 0
      var fields: [(UInt64, Data)] = [(0, V4NamespaceValue.head(0, status)), (1, observation(record))]
      if cancel { fields.append((2, V4NamespaceValue.head(0, record == nil ? 3 : record!.active ? 0 : 1))) }
      return V4Crypto.map(fields)
    } catch {
      diagnostic?.failed(error)
      let status: UInt64 = (error as? ServiceFailure) == .permissionDenied ? 2 : (error as? ServiceFailure) == .operationConflict ? 3 : 1
      return V4Crypto.map([(0, V4NamespaceValue.head(0, status))])
    }
  }
  private func exact(_ count: Int, from source: any V4RPCTransport, allowEOF: Bool = false, management: Bool = false) async throws -> Data? {
    var data = Data(); data.reserveCapacity(count)
    while data.count < count {
      try checkSource(); try storage.check()
      guard let next = try await source.read(maxBytes: count - data.count) else {
        guard allowEOF && data.isEmpty else { throw ServiceFailure.protocolFailure }; return nil
      }
      guard !next.isEmpty, next.count <= count - data.count else { throw ServiceFailure.protocolFailure }
      data += next
    }
    return data
  }
  func close() {
    gate.withLock {
      guard !closed else { return }; closed = true
      for run in runs.values { run.diagnostic?.failed(ServiceFailure.closed); run.work?.cancel() }
      for target in targets.values { target.inputTask?.cancel(); target.inputTimer?.cancel() }
      for target in targets.values {
        if !target.selected {
          target.selected = true
          let tail = try? target.storage.executionTail()
          startTask { [self, target, tail] in
            defer { tail?.release(); gate.withLock { targets.removeValue(forKey: target.id) } }
            try? await target.source.close()
          }
        } else {
          let tail = try? target.storage.executionTail()
          startTask { [target, tail] in defer { tail?.release() }; try? await target.source.close() }
        }
      }
      storage.seal()
    }
  }
}

private final class V4ServiceQueryResponseJob: V4FixedQueryWork, @unchecked Sendable {
  private let gate = NSLock()
  private let environment: V4EnvironmentFoundation
  private let registry: V4NamespaceRegistry
  private let entries: [UInt32: V4ServiceServerEntry]
  private let identity: ServiceCallerIdentity
  private let maximumWindowMS: UInt64
  private var storage: V4CryptoReservation?
  private let diagnostic: V4ServiceServerDiagnostic?
  private let check: @Sendable () throws -> Void
  private var input: Data?
  private var targets: [V4NamespaceValue] = []
  private var index = 0
  private var output = Data()
  private var copying: ServiceContract?
  private var offset = 0
  private var suffix = Data()
  private var canceled = false
  private var continuation: CheckedContinuation<Data, any Error>?
  init(environment: V4EnvironmentFoundation, registry: V4NamespaceRegistry, payload: Data, entries: [UInt32: V4ServiceServerEntry],
    identity: ServiceCallerIdentity, maximumWindowMS: UInt64, storage: V4CryptoReservation,
    diagnostic: V4ServiceServerDiagnostic?, check: @escaping @Sendable () throws -> Void) {
    self.environment = environment; self.registry = registry; self.entries = entries; self.identity = identity
    self.maximumWindowMS = maximumWindowMS; self.storage = storage; self.diagnostic = diagnostic; input = payload; self.check = check
    output.reserveCapacity(73728)
  }
  func result(executor: V4FixedQueryExecutor) async throws -> Data {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        do { try gate.withLock { guard !canceled else { throw ServiceFailure.closed }; try executor.enqueue(self); self.continuation = continuation } }
        catch { diagnostic?.failed(error); continuation.resume(throwing: error) }
      }
    } onCancel: { self.cancel() }
  }
  func step() -> Bool {
    gate.withLock {
      do {
        guard !canceled, let storage else { collect(); return false }; try storage.check(); try check()
        if let input {
          let value = try V4NamespaceDocument(input, schema: "ContractTargets", bytes: 2048, nodes: 80, registry: registry).root
          targets = try Array(value.field("targets").children)
          var distinct: Set<String> = []
          for target in targets {
            let key = try "\(target.t("service_namespace")):\(target.u("method_type_id"))"
            guard distinct.insert(key).inserted else { throw ServiceFailure.protocolFailure }
          }
          guard (1...8).contains(targets.count) else { throw ServiceFailure.protocolFailure }
          self.input = nil; output.append(V4NamespaceValue.head(5, 1)); output.append(V4NamespaceValue.head(0, 0)); output.append(V4NamespaceValue.head(4, UInt64(targets.count)))
          return true
        }
        if let copying {
          if offset < copying.encodedBytes {
            let bytes = try copying.encodedChunk(offset: offset, maximum: 4096); output.append(bytes); offset += bytes.count; return true
          }
          output.append(suffix); suffix = Data(); self.copying = nil; offset = 0; index += 1
        }
        if index == targets.count {
          let waiting = continuation; continuation = nil; waiting?.resume(returning: output); collect(); return false
        }
        let target = targets[index]; let name = try target.t("service_namespace"); let type = try target.u("method_type_id")
        let entry = entries[UInt32(type)]
        let wanted = try target.optional("wanted_contract_digest")?.bytes()
        let known = try target.optional("known_contract_digest")?.bytes()
        var status: UInt64 = 3
        var contract: ServiceContract?
        var offer: Data?
        if let entry, entry.definition.namespace == name {
          if (try? entry.caller(identity)) == nil { status = 2 }
          else if wanted == nil || wanted == entry.contract.digest {
            contract = entry.contract; status = known == entry.contract.digest ? 1 : 0
            if entry.method.semantics == .execution {
              guard let now = environment.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
              let window = min(maximumWindowMS, try entry.contract.uint(16))
              let (after, overflow) = now.lowerMS.addingReportingOverflow(window)
              guard !overflow, now.upperMS < after else { throw ServiceFailure.admissionWindowClosed }
              offer = V4Crypto.map([(0, V4Crypto.bytes(entry.contract.digest)), (1, V4NamespaceValue.head(0, now.lowerMS)), (2, V4NamespaceValue.head(0, after))])
            }
          }
        }
        let fields = status < 2 ? 3 + (offer == nil ? 0 : 1) : 2
        output.append(V4NamespaceValue.head(5, UInt64(fields))); output.append(V4NamespaceValue.head(0, 0)); output.append(V4NamespaceValue.head(0, UInt64(index)))
        output.append(V4NamespaceValue.head(0, 1)); output.append(V4NamespaceValue.head(0, status))
        if let contract {
          if status == 0 {
            output.append(V4NamespaceValue.head(0, 2)); output.append(V4NamespaceValue.head(2, UInt64(contract.encodedBytes)))
            copying = contract
            if let offer { suffix = V4NamespaceValue.head(0, 4) + V4Crypto.bytes(offer) }
          } else {
            output.append(V4NamespaceValue.head(0, 3)); output.append(V4Crypto.bytes(contract.digest))
            if let offer { output.append(V4NamespaceValue.head(0, 4)); output.append(V4Crypto.bytes(offer)) }; index += 1
          }
        } else { index += 1 }
        guard output.count <= targets.count * 9216 else { throw ServiceFailure.protocolFailure }; return true
      } catch {
        diagnostic?.failed(error)
        let waiting = continuation; continuation = nil; waiting?.resume(throwing: error); collect(); return false
      }
    }
  }
  private func collect() { input = nil; targets.removeAll(); copying = nil; output = Data(); suffix = Data(); storage = nil }
  func cancel() {
    gate.withLock {
      if storage != nil { diagnostic?.failed(CancellationError()) }
      canceled = true; let waiting = continuation; continuation = nil; waiting?.resume(throwing: CancellationError())
    }
  }
}
#endif
