import Foundation

public typealias StreamHandler = @Sendable (IncomingStream) async throws -> Void

public struct StreamHandlerOptions: Sendable {
  public var maxConcurrentStreams: Int
  public var onError: (@Sendable (SessionError) -> Void)?

  public init(
    maxConcurrentStreams: Int = 64,
    onError: (@Sendable (SessionError) -> Void)? = nil
  ) {
    self.maxConcurrentStreams = maxConcurrentStreams
    self.onError = onError
  }
}

public enum HandlerRegistrationError: Error, Equatable, Sendable {
  case invalidHandler
  case alreadyRegistered
  case frozen
}

/// Carrier-neutral application-stream registry and dispatcher for an established session.
public final class StreamHandlers: @unchecked Sendable {
  private struct Snapshot: Sendable {
    let maxConcurrentStreams: Int
    let handlers: [String: StreamHandler]
    let metadataContracts: [String: RawStreamMetadataContract]
    let messageRegistrations: [String: V4MessageStreamRegistration]
    let onError: (@Sendable (SessionError) -> Void)?
  }

  private let lock = NSLock()
  private let registrationLifetime = V4MessageRegistrationLifetime()
  private var closed = false
  private let options: StreamHandlerOptions
  private var handlers: [String: StreamHandler] = [:]
  private var metadataContracts: [String: RawStreamMetadataContract] = [:]
  private var messageRegistrations: [String: V4MessageStreamRegistration] = [:]
  private var snapshot: Snapshot?

  public init(options: StreamHandlerOptions = StreamHandlerOptions()) throws {
    guard (1...128).contains(options.maxConcurrentStreams) else {
      throw HandlerRegistrationError.invalidHandler
    }
    self.options = options
  }

  public func handleStream(
    kind: String,
    metadataContract: RawStreamMetadataContract? = nil,
    handler: @escaping StreamHandler
  ) throws {
    guard V4ApplicationStreamKind.valid(kind) else {
      throw HandlerRegistrationError.invalidHandler
    }
    try lock.withLock {
      guard !closed, snapshot == nil else { throw HandlerRegistrationError.frozen }
      guard handlers[kind] == nil else { throw HandlerRegistrationError.alreadyRegistered }
      guard handlers.count < 256 else { throw HandlerRegistrationError.invalidHandler }
      handlers[kind] = handler
      if let metadataContract { metadataContracts[kind] = metadataContract }
    }
  }

  public func registerMessageStream<InboundCodec: MessageCodec, OutboundCodec: MessageCodec>(
    definition: MessageStreamDefinition,
    inboundCodec: InboundCodec,
    outboundCodec: OutboundCodec,
    options: MessageStreamOptions? = nil,
    authorizeOpen: @escaping @Sendable (StreamMetadata, ApplicationInvocationContext) async throws -> Void,
    handler: @escaping @Sendable (
      TypedMessageStream<InboundCodec.Value, OutboundCodec.Value>, StreamMetadata, ApplicationInvocationContext
    ) async throws -> Void
  ) throws {
    let inbound = inboundCodec.definition, outbound = outboundCodec.definition
    guard inbound == definition.openerToAcceptor, outbound == definition.acceptorToOpener else {
      throw HandlerRegistrationError.invalidHandler
    }
    let fixedOptions = options ?? .standard
    let prepare: @Sendable (V4PreparedMessageStream, StreamMetadata) throws -> V4PreparedMessageHandler = {
      prepared, metadata in
      // Only SDK objects are created here. The original pending OPEN still owns
      // the inactive native token, and no application callback runs in this step.
      let messages = try TypedMessageStream(
        prepared: prepared, definition: definition, opener: false,
        applicationMetadata: metadata, inboundCodec: inboundCodec, outboundCodec: outboundCodec,
        inboundDefinition: inbound, outboundDefinition: outbound, options: fixedOptions)
      return V4PreparedMessageHandler(gate: prepared.storage.environment.gate, check: prepared.check,
        invoke: { context in
        do {
          try await handler(messages, metadata, context)
          try await messages.finish()
        } catch {
          try? await messages.close()
          throw error
        }
      }, close: { try? await messages.close() })
    }
    let wrapped: StreamHandler = { incoming in
      guard let prepared = incoming.preparedMessageHandler, let context = incoming.applicationContext else {
        throw TransportAvailabilityError.runtimeUnavailable
      }
      try await prepared.invoke(context)
    }
    try lock.withLock {
      guard !closed, snapshot == nil else { throw HandlerRegistrationError.frozen }
      guard handlers[definition.kind] == nil else { throw HandlerRegistrationError.alreadyRegistered }
      guard handlers.count < 256 else { throw HandlerRegistrationError.invalidHandler }
      handlers[definition.kind] = wrapped
      messageRegistrations[definition.kind] = V4MessageStreamRegistration(
        definition: definition, authorize: authorizeOpen, options: fixedOptions,
        lifetime: registrationLifetime, maximumConcurrentStreams: self.options.maxConcurrentStreams,
        prepare: prepare)
    }
  }

  /// Seals future kind registration and OPEN acceptance. Existing
  /// accepted handlers keep their original Stream and cleanup ownership.
  public func close() {
    lock.withLock {
      guard !closed else { return }
      closed = true
      registrationLifetime.close()
    }
  }

  private func freeze() throws -> Snapshot {
    try lock.withLock {
      guard !closed else { throw HandlerRegistrationError.frozen }
      if let snapshot { return snapshot }
      let snapshot = Snapshot(
        maxConcurrentStreams: options.maxConcurrentStreams,
        handlers: handlers,
        metadataContracts: metadataContracts,
        messageRegistrations: messageRegistrations,
        onError: options.onError
      )
      self.snapshot = snapshot
      return snapshot
    }
  }

  func prepare(in environment: V4EnvironmentFoundation) throws -> V4PreparedStreamHandlers {
    let frozen = try freeze()
    let count = frozen.handlers.count
    return V4PreparedStreamHandlers(registry: V4StreamHandlerRegistry(
      rawKinds: Set(frozen.handlers.keys).subtracting(frozen.messageRegistrations.keys),
      metadataContracts: frozen.metadataContracts, lifetime: registrationLifetime,
      maximumConcurrentStreams: frozen.maxConcurrentStreams), messages: frozen.messageRegistrations,
      storage: count == 0 ? nil : try environment.messageStreamRegistrationStorage(count: count))
  }

  /// Serves streams until cancellation or session termination, then closes the
  /// session and waits for every active handler task to finish.
  public func serve(session: any Session) async throws {
    let frozen = try freeze()
    let nativeRegistryInstalled: Bool
    if let native = session as? any V4MessageStreamSession {
      try native.installStreamHandlerRegistry(V4StreamHandlerRegistry(
        rawKinds: Set(frozen.handlers.keys).subtracting(frozen.messageRegistrations.keys),
        metadataContracts: frozen.metadataContracts, lifetime: registrationLifetime,
        maximumConcurrentStreams: frozen.maxConcurrentStreams), messages: frozen.messageRegistrations)
      nativeRegistryInstalled = true
    } else {
      guard frozen.messageRegistrations.isEmpty else { throw TransportAvailabilityError.runtimeUnavailable }
      nativeRegistryInstalled = false
    }
    let active = ActiveStreamTasks(limit: frozen.maxConcurrentStreams)
    let closer = SessionCloseBarrier(session: session)

    try await withTaskCancellationHandler {
      let result: Result<Void, Error>
      do {
        while true {
          try Task.checkCancellation()
          var incoming = try await session.acceptStream()
          guard let handler = frozen.handlers[incoming.kind] else {
            await incoming.closeHandlerStream()
            frozen.onError?(.streamRejected)
            continue
          }
          if !nativeRegistryInstalled, let contract = frozen.metadataContracts[incoming.kind] {
            do {
              incoming = IncomingStream(kind: incoming.kind, metadata: try incoming.metadata.applyingRawMetadataContract(contract), stream: incoming.stream, applicationContext: incoming.applicationContext, preparedMessageHandler: incoming.preparedMessageHandler)
            } catch {
              await incoming.closeHandlerStream()
              frozen.onError?(.streamRejected)
              continue
            }
          }
          let acceptedIncoming = incoming
          let typed = frozen.messageRegistrations[incoming.kind] != nil
          let started = await active.start {
            do {
              if let native = session as? any V4ApplicationSession {
                try await native.invokeStreamHandler(acceptedIncoming, handler: handler)
              } else { try await handler(acceptedIncoming) }
              if !typed { try await acceptedIncoming.stream.closeWrite() }
            } catch {
              await acceptedIncoming.closeHandlerStream()
              frozen.onError?(.operationFailed)
            }
          }
          if !started {
            await incoming.closeHandlerStream()
            frozen.onError?(.resourceExhausted)
          }
        }
      } catch {
        result = .failure(Task.isCancelled ? CancellationError() : error)
      }

      await closer.close()
      let tasks = await active.drain()
      for task in tasks { task.cancel() }
      for task in tasks { await task.value }
      try result.get()
    } onCancel: {
      Task { await closer.close() }
    }
  }
}

private actor SessionCloseBarrier {
  private let session: any Session
  private var closing: Task<Void, Never>?

  init(session: any Session) {
    self.session = session
  }

  func close() async {
    if closing == nil {
      closing = Task { [session] in
        try? await session.close()
      }
    }
    await closing?.value
  }
}

private actor ActiveStreamTasks {
  private let limit: Int
  private var tasks: [UUID: Task<Void, Never>] = [:]

  init(limit: Int) {
    self.limit = limit
  }

  func start(_ operation: @escaping @Sendable () async -> Void) -> Bool {
    guard tasks.count < limit else { return false }
    let id = UUID()
    tasks[id] = Task { [weak self] in
      await operation()
      await self?.finished(id)
    }
    return true
  }

  func drain() -> [Task<Void, Never>] {
    let active = Array(tasks.values)
    tasks.removeAll(keepingCapacity: false)
    return active
  }

  private func finished(_ id: UUID) {
    tasks.removeValue(forKey: id)
  }
}

struct V4PreparedStreamHandlers: Sendable {
  let registry: V4StreamHandlerRegistry
  let messages: [String: V4MessageStreamRegistration]
  let storage: V4CryptoReservation?
}
