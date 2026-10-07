import Foundation

/// Local registration failures have explicit remedies and are never advertised
/// as a second wire error variant or a new execution permission.
public enum ApplicationCallbackEntryError: String, Error, Sendable {
  case asyncDecoderEntryUnavailable = "async_decoder_entry_unavailable"
  case entryNotSignaled = "application_callback_entry_not_signaled"
}

/// The SDK creates one entry for an original admitted callback. An asynchronous
/// codec calls enter() as its first method-body action, after any actor hop.
/// This entry cannot create another permit or classify a codec as SDK parsing.
public final class ApplicationCallbackEntry: @unchecked Sendable {
  private let gate = NSLock()
  private let context: ApplicationInvocationContext
  private let check: @Sendable () throws -> Void
  private let prepare: @Sendable () async throws -> Void
  private let mark: @Sendable () throws -> Void
  private var entered = false
  init(context: ApplicationInvocationContext, check: @escaping @Sendable () throws -> Void,
    prepare: @escaping @Sendable () async throws -> Void, mark: @escaping @Sendable () throws -> Void) {
    self.context = context; self.check = check; self.prepare = prepare; self.mark = mark
  }
  public func enter(isolation: isolated (any Actor)? = #isolation) async throws {
    try context.checkCancellation(); try check()
    try await prepare()
    // This function inherits the cooperating decoder's actual executor. The
    // durable dispatch prelude returns here before the original run is marked.
    try context.checkCancellation(); try check()
    try gate.withLock { if !entered { try mark(); entered = true } }
  }
  func requireEntered() throws {
    guard gate.withLock({ entered }) else { throw ApplicationCallbackEntryError.entryNotSignaled }
  }
}

/// Cooperating asynchronous implementations signal their actual method-body
/// entry. Old async codec operations remain available outside server run gates.
public protocol EntryAwareAsyncMessageCodec<Value>: AsyncMessageCodec {
  func decodeAsync(_ source: Data, context: ApplicationInvocationContext, entry: ApplicationCallbackEntry) async throws -> Value
}

protocol V4ServiceAsyncCodecEntry<Value>: AsyncMessageCodec {
  func decodeEntered(_ source: Data, context: ApplicationInvocationContext, entry: ApplicationCallbackEntry) async throws -> Value
}

/// Holds the callbacks' real isolation instead of erasing it in an async
/// protocol witness. The SDK enters on that executor before the custom body.
public struct AsyncClosureMessageCodec<Value: Sendable>: AsyncMessageCodec, V4ServiceAsyncCodecEntry {
  public let definition: MessageDefinition
  private let encoder: @isolated(any) @Sendable (Value, ApplicationInvocationContext) async throws -> Data
  private let decoder: @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value
  public init(definition: MessageDefinition,
    encode: @escaping @isolated(any) @Sendable (Value, ApplicationInvocationContext) async throws -> Data,
    @_inheritActorContext decode: @escaping @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value) {
    self.definition = definition; encoder = encode; decoder = decode
  }
  /// Adapts only server request decoding and retains the existing encoder,
  /// definition, and every other original async codec behavior.
  public init(adapting codec: any AsyncMessageCodec<Value>,
    @_inheritActorContext decode: @escaping @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value) {
    definition = codec.definition
    encoder = { value, context in try await codec.encodeAsync(value, context: context) }
    decoder = decode
  }
  public var applicationDecodeCallback: (@isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value)? { decoder }
  public func encodeAsync(_ value: Value, context: ApplicationInvocationContext) async throws -> Data {
    try context.checkCancellation(); let bytes = try await encoder(value, context)
    guard bytes.count <= definition.maxMessageBytes else { throw MessageCodecFailure.encodeFailed }; return bytes
  }
  public func decodeAsync(_ source: Data, context: ApplicationInvocationContext) async throws -> Value {
    guard source.count <= definition.maxMessageBytes else { throw MessageCodecFailure.decodeFailed }
    try context.checkCancellation(); return try await decoder(source, context)
  }
  func decodeEntered(_ source: Data, context: ApplicationInvocationContext, entry: ApplicationCallbackEntry) async throws -> Value {
    guard source.count <= definition.maxMessageBytes else { throw MessageCodecFailure.decodeFailed }
    return try await v4DecodeOnExecutor(isolation: decoder.isolation, decoder: decoder, source: source, context: context, entry: entry)
  }
}

func v4DecodeOnExecutor<Value: Sendable>(isolation: isolated (any Actor)?,
  decoder: @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value,
  source: Data, context: ApplicationInvocationContext, entry: ApplicationCallbackEntry) async throws -> Value {
  try await entry.enter()
  return try await decoder(source, context)
}

extension AsyncMessageCodec {
  func encodeAsync(_ value: Value, context: ApplicationInvocationContext, into destination: inout Data) async throws -> Int {
    let bytes = try await encodeAsync(value, context: context)
    guard bytes.count <= definition.maxMessageBytes, bytes.count <= destination.count else { throw MessageCodecFailure.encodeFailed }
    destination.replaceSubrange(0..<bytes.count, with: bytes); return bytes.count
  }
}

extension AsyncMessageCodec {
  /// Create the callback in the actor that owns the decoder so its isolation is
  /// retained. A method reference or a wrapper that hops to another actor does
  /// not establish that actor's callback entry.
  public func serverRequestCodec(
    @_inheritActorContext decode: @escaping @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Value
  ) -> AsyncClosureMessageCodec<Value> {
    AsyncClosureMessageCodec(adapting: self, decode: decode)
  }
}

func v4ServiceCaptureRequestCodec<Value: Sendable>(_ codec: any MessageCodec<Value>) throws -> any MessageCodec<Value> {
  guard let asynchronous = codec as? any AsyncMessageCodec<Value> else { return codec }
  if codec is any V4ServiceAsyncCodecEntry<Value> || codec is any EntryAwareAsyncMessageCodec<Value> { return codec }
  // Capture the application declaration once, during explicit registration.
  // A later request never executes an arbitrary property getter before entry.
  guard let callback = asynchronous.applicationDecodeCallback else { throw ApplicationCallbackEntryError.asyncDecoderEntryUnavailable }
  return AsyncClosureMessageCodec(adapting: asynchronous, decode: callback)
}

// Notification input remains replaceable while an SDK adapter awaits the
// decoder's executor. Its original owner commits entry under its own gate.
func v4DecodeNotification<Value: Sendable>(_ codec: any MessageCodec<Value>, source: Data,
  context: ApplicationInvocationContext, check: @escaping @Sendable () throws -> Void,
  enter: @escaping @Sendable () throws -> Void) async throws -> Value {
  let entry = ApplicationCallbackEntry(context: context, check: check, prepare: {}, mark: enter)
  let value: Value
  if let adapter = codec as? any V4ServiceAsyncCodecEntry<Value> {
    value = try await adapter.decodeEntered(source, context: context, entry: entry)
    try entry.requireEntered()
  } else if let cooperative = codec as? any EntryAwareAsyncMessageCodec<Value> {
    value = try await cooperative.decodeAsync(source, context: context, entry: entry)
    try entry.requireEntered()
  } else {
    guard !(codec is any AsyncMessageCodec<Value>) else { throw ApplicationCallbackEntryError.asyncDecoderEntryUnavailable }
    try enter(); value = try codec.decode(source, context: context)
  }
  try context.checkCancellation(); try check()
  return value
}

#if os(macOS) || os(iOS)
func v4ServiceDispatch<Input: Sendable, Output: Sendable>(isolation: isolated (any Actor)?,
  handler: @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Input) async throws -> Output,
  context: ApplicationInvocationContext, invocation: ServiceServerInvocation, input: Input) async throws -> Output {
  try await invocation.prepareDispatch(); invocation.enterDispatch()
  return try await handler(context, invocation, input)
}

func v4ServiceDispatchStream<Input: Sendable, Item: Sendable>(isolation: isolated (any Actor)?,
  handler: @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Input, ServiceServerStreamWriter<Item>) async throws -> Void,
  context: ApplicationInvocationContext, invocation: ServiceServerInvocation, input: Input,
  writer: ServiceServerStreamWriter<Item>) async throws {
  try await invocation.prepareDispatch(); invocation.enterDispatch()
  try await handler(context, invocation, input, writer)
}

func v4ServiceDispatchResume<Output: Sendable>(isolation: isolated (any Actor)?,
  handler: @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, ApplicationCheckpoint, any ByteStream) async throws -> Output,
  context: ApplicationInvocationContext, invocation: ServiceServerInvocation, checkpoint: ApplicationCheckpoint,
  source: any ByteStream) async throws -> Output {
  try await invocation.prepareDispatch(); invocation.enterDispatch()
  return try await handler(context, invocation, checkpoint, source)
}

func v4ServiceDispatchStreamingResume<Item: Sendable>(isolation: isolated (any Actor)?,
  handler: @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, ApplicationCheckpoint, ServiceServerStreamWriter<Item>) async throws -> Void,
  context: ApplicationInvocationContext, invocation: ServiceServerInvocation, checkpoint: ApplicationCheckpoint,
  writer: ServiceServerStreamWriter<Item>) async throws {
  try await invocation.prepareDispatch(); invocation.enterDispatch()
  try await handler(context, invocation, checkpoint, writer)
}

#endif
