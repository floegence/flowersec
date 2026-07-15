import Foundation

public enum ArtifactSourceKind: String, Equatable, Sendable {
  case once
  case refreshable
}

public struct ArtifactAcquireContext: Equatable, Sendable {
  public var traceID: String?

  public init(traceID: String? = nil) {
    self.traceID = traceID
  }
}

public enum ArtifactSourceError: LocalizedError, Equatable, Sendable {
  case onceConsumed
  case canceled
  case acquisitionFailed(String)

  public var errorDescription: String? {
    switch self {
    case .onceConsumed:
      return "The one-time artifact source has already been consumed."
    case .canceled:
      return "Artifact acquisition was canceled."
    case .acquisitionFailed(let message):
      return "Artifact acquisition failed: \(message)"
    }
  }
}

public struct ArtifactSource: Sendable {
  public let kind: ArtifactSourceKind
  private let acquireHandler: @Sendable (ArtifactAcquireContext) async throws -> ConnectArtifact

  private init(
    kind: ArtifactSourceKind,
    acquire: @escaping @Sendable (ArtifactAcquireContext) async throws -> ConnectArtifact
  ) {
    self.kind = kind
    self.acquireHandler = acquire
  }

  public static func once(_ artifact: ConnectArtifact) -> ArtifactSource {
    let storage = OnceArtifactStorage(artifact)
    return ArtifactSource(kind: .once) { _ in
      try Task.checkCancellation()
      return try await storage.take()
    }
  }

  public static func refreshable(
    _ acquire: @escaping @Sendable (ArtifactAcquireContext) async throws -> ConnectArtifact
  ) -> ArtifactSource {
    ArtifactSource(kind: .refreshable, acquire: acquire)
  }

  public static func controlplane(_ options: ArtifactRequestOptions) -> ArtifactSource {
    .refreshable { context in
      var request = options
      if let traceID = context.traceID { request.traceID = traceID }
      do {
        return try await Controlplane.requestConnectArtifact(request)
      } catch is CancellationError {
        throw ArtifactSourceError.canceled
      } catch {
        throw ArtifactSourceError.acquisitionFailed(error.localizedDescription)
      }
    }
  }

  public static func entryControlplane(
    _ options: ArtifactRequestOptions,
    entryTicket: String
  ) -> ArtifactSource {
    .refreshable { context in
      var request = options
      if let traceID = context.traceID { request.traceID = traceID }
      do {
        return try await Controlplane.requestEntryConnectArtifact(
          request,
          entryTicket: entryTicket
        )
      } catch is CancellationError {
        throw ArtifactSourceError.canceled
      } catch {
        throw ArtifactSourceError.acquisitionFailed(error.localizedDescription)
      }
    }
  }

  public func acquire(_ context: ArtifactAcquireContext = ArtifactAcquireContext()) async throws
    -> ConnectArtifact
  {
    do {
      try Task.checkCancellation()
      return try await acquireHandler(context)
    } catch is CancellationError {
      throw ArtifactSourceError.canceled
    }
  }
}

private actor OnceArtifactStorage {
  private var artifact: ConnectArtifact?

  init(_ artifact: ConnectArtifact) {
    self.artifact = artifact
  }

  func take() throws -> ConnectArtifact {
    guard let artifact else { throw ArtifactSourceError.onceConsumed }
    self.artifact = nil
    return artifact
  }
}

public struct ReconnectSettings: Equatable, Sendable {
  public var enabled: Bool
  public var maxAttempts: Int
  public var initialDelay: Duration
  public var maxDelay: Duration
  public var factor: Double
  public var jitterRatio: Double

  public init(
    enabled: Bool = false,
    maxAttempts: Int = FlowersecSDKDefaults.Reconnect.maxAttempts,
    initialDelay: Duration = .milliseconds(
      FlowersecSDKDefaults.Reconnect.initialDelayMilliseconds
    ),
    maxDelay: Duration = .milliseconds(FlowersecSDKDefaults.Reconnect.maxDelayMilliseconds),
    factor: Double = FlowersecSDKDefaults.Reconnect.factor,
    jitterRatio: Double = FlowersecSDKDefaults.Reconnect.jitterRatio
  ) {
    self.enabled = enabled
    self.maxAttempts = maxAttempts
    self.initialDelay = initialDelay
    self.maxDelay = maxDelay
    self.factor = factor
    self.jitterRatio = jitterRatio
  }

  public func delay(forFailedAttemptIndex attemptIndex: Int) -> Duration {
    let initial = reconnectDurationMilliseconds(initialDelay)
    let maximum = reconnectDurationMilliseconds(maxDelay)
    let exponent = Double(max(0, attemptIndex))
    let base = min(maximum, initial * pow(factor, exponent))
    let jitter = jitterRatio == 0 ? 0 : Double.random(in: -jitterRatio...jitterRatio)
    let milliseconds = max(0, min(Double(Int64.max), base * (1 + jitter)))
    return .milliseconds(Int64(milliseconds.rounded()))
  }

  func normalized() throws -> ReconnectSettings {
    guard maxAttempts >= 1,
      initialDelay >= .zero,
      maxDelay >= .zero,
      factor.isFinite,
      factor >= 1,
      jitterRatio.isFinite,
      (0...1).contains(jitterRatio)
    else { throw ReconnectError.invalidConfiguration }
    var settings = self
    if !enabled { settings.maxAttempts = 1 }
    return settings
  }
}

public enum ReconnectStatus: String, Equatable, Sendable {
  case disconnected
  case connecting
  case connected
  case error
}

public enum ReconnectError: LocalizedError, Equatable, Sendable {
  case refreshableSourceRequired
  case invalidConfiguration
  case canceled
  case artifact(ArtifactSourceError)
  case connection(FlowersecError)
  case terminated(String)
  case exhausted(attempts: Int, last: String)

  public var errorDescription: String? {
    switch self {
    case .refreshableSourceRequired:
      return "Automatic reconnect requires a refreshable artifact source."
    case .invalidConfiguration:
      return "Reconnect configuration is invalid."
    case .canceled:
      return "Reconnect was canceled."
    case .artifact(let error):
      return error.localizedDescription
    case .connection(let error):
      return error.localizedDescription
    case .terminated(let message):
      return message
    case .exhausted(let attempts, let last):
      return "Reconnect attempts exhausted after \(attempts) attempts: \(last)"
    }
  }

  fileprivate var isTerminal: Bool {
    switch self {
    case .refreshableSourceRequired, .invalidConfiguration, .canceled,
      .artifact(.onceConsumed), .artifact(.canceled):
      return true
    case .connection(let error):
      return [
        .invalidInput, .invalidOption, .transportPolicyDenied, .invalidPSK,
        .invalidSuite, .missingConnectInfo, .missingWSURL, .missingChannelID,
        .missingInitExp,
      ].contains(error.code)
    case .artifact(.acquisitionFailed), .terminated, .exhausted:
      return false
    }
  }
}

public struct ReconnectState: Sendable {
  public var status: ReconnectStatus
  public var error: ReconnectError?
  public var client: FlowersecClient?

  public init(
    status: ReconnectStatus = .disconnected,
    error: ReconnectError? = nil,
    client: FlowersecClient? = nil
  ) {
    self.status = status
    self.error = error
    self.client = client
  }
}

typealias ReconnectConnector = @Sendable (ConnectArtifact, ConnectOptions) async throws
  -> FlowersecClient

public struct ReconnectConfig: Sendable {
  public var source: ArtifactSource
  public var options: ConnectOptions
  public var settings: ReconnectSettings
  fileprivate var connector: ReconnectConnector

  public init(
    source: ArtifactSource,
    options: ConnectOptions = ConnectOptions(),
    settings: ReconnectSettings = ReconnectSettings()
  ) {
    self.source = source
    self.options = options
    self.settings = settings
    self.connector = { artifact, options in
      try await Flowersec.connect(artifact, options: options)
    }
  }

  init(
    source: ArtifactSource,
    options: ConnectOptions = ConnectOptions(),
    settings: ReconnectSettings = ReconnectSettings(),
    connector: @escaping ReconnectConnector
  ) {
    self.source = source
    self.options = options
    self.settings = settings
    self.connector = connector
  }
}

public actor ReconnectManager {
  private var currentState = ReconnectState()
  private var generation: UInt64 = 0
  private var supervisor: Task<Void, Never>?
  private var subscribers: [UUID: AsyncStream<ReconnectState>.Continuation] = [:]

  public init() {}

  public func state() -> ReconnectState {
    currentState
  }

  public func subscribe() -> AsyncStream<ReconnectState> {
    let id = UUID()
    let current = currentState
    return AsyncStream { continuation in
      subscribers[id] = continuation
      continuation.yield(current)
      continuation.onTermination = { [weak self] _ in
        Task { await self?.removeSubscriber(id) }
      }
    }
  }

  public func connect(_ config: ReconnectConfig) async throws {
    await stopSupervisor(setDisconnected: false)
    let settings: ReconnectSettings
    do {
      settings = try config.settings.normalized()
      if settings.enabled, config.source.kind != .refreshable {
        throw ReconnectError.refreshableSourceRequired
      }
    } catch let error as ReconnectError {
      setState(.error, error: error, client: nil)
      throw error
    }
    generation &+= 1
    let runGeneration = generation
    setState(.connecting, error: nil, client: nil)
    try await withCheckedThrowingContinuation {
      (continuation: CheckedContinuation<Void, any Error>) in
      supervisor = Task { [weak self] in
        guard let self else {
          continuation.resume(throwing: ReconnectError.canceled)
          return
        }
        await self.run(
          config: config,
          settings: settings,
          generation: runGeneration,
          firstResult: continuation
        )
      }
    }
  }

  public func connectIfNeeded(_ config: ReconnectConfig) async throws {
    switch currentState.status {
    case .connected:
      return
    case .connecting:
      for await state in subscribe() {
        switch state.status {
        case .connected:
          return
        case .error:
          throw state.error ?? ReconnectError.terminated("Connection failed.")
        case .disconnected:
          throw ReconnectError.canceled
        case .connecting:
          continue
        }
      }
      throw ReconnectError.canceled
    case .disconnected, .error:
      try await connect(config)
    }
  }

  public func disconnect() async {
    await stopSupervisor(setDisconnected: true)
  }

  private func stopSupervisor(setDisconnected: Bool) async {
    generation &+= 1
    let task = supervisor
    supervisor = nil
    task?.cancel()
    if let client = currentState.client { await client.close() }
    if let task { await task.value }
    if setDisconnected { setState(.disconnected, error: nil, client: nil) }
  }

  private func run(
    config: ReconnectConfig,
    settings: ReconnectSettings,
    generation runGeneration: UInt64,
    firstResult initialFirstResult: CheckedContinuation<Void, any Error>
  ) async {
    var firstResult: CheckedContinuation<Void, any Error>? = initialFirstResult
    var attemptSequence = 0
    var traceID: String?

    while isActive(runGeneration) {
      var lastError = ReconnectError.terminated("The Flowersec connection terminated unexpectedly.")
      for attempt in 1...settings.maxAttempts {
        guard isActive(runGeneration) else {
          resumeFirst(&firstResult, with: .failure(ReconnectError.canceled))
          return
        }
        attemptSequence += 1
        let started = ContinuousClock.now
        emit(
          code: attempt == 1 ? "reconnect_attempt" : "reconnect_retry_attempt",
          result: .retry,
          options: config.options,
          attemptSequence: attemptSequence,
          traceID: traceID,
          started: started
        )

        let artifact: ConnectArtifact
        do {
          artifact = try await config.source.acquire(ArtifactAcquireContext(traceID: traceID))
          traceID = artifact.metadata.correlation?.traceID ?? traceID
        } catch {
          lastError = reconnectError(error, artifact: true)
          if await finishOrSchedule(
            error: lastError,
            attempt: attempt,
            settings: settings,
            config: config,
            generation: runGeneration,
            attemptSequence: attemptSequence,
            traceID: traceID,
            started: started,
            firstResult: &firstResult
          ) { return }
          continue
        }

        do {
          let client = try await config.connector(
            artifact,
            correlatedOptions(
              config.options,
              attemptSequence: attemptSequence,
              traceID: traceID
            )
          )
          guard isActive(runGeneration) else {
            await client.close()
            resumeFirst(&firstResult, with: .failure(ReconnectError.canceled))
            return
          }
          setState(.connected, error: nil, client: client)
          emit(
            code: "reconnect_connected",
            result: .ok,
            options: config.options,
            attemptSequence: attemptSequence,
            traceID: traceID,
            started: started
          )
          resumeFirst(&firstResult, with: .success(()))
          let termination = await withTaskCancellationHandler {
            await client.terminated()
          } onCancel: {
            Task { await client.close() }
          }
          guard isActive(runGeneration) else { return }
          lastError = .terminated(
            termination?.localizedDescription
              ?? "The Flowersec connection terminated unexpectedly."
          )
          if !settings.enabled {
            setState(.error, error: lastError, client: nil)
            return
          }
          setState(.connecting, error: lastError, client: nil)
          break
        } catch {
          lastError = reconnectError(error, artifact: false)
          if await finishOrSchedule(
            error: lastError,
            attempt: attempt,
            settings: settings,
            config: config,
            generation: runGeneration,
            attemptSequence: attemptSequence,
            traceID: traceID,
            started: started,
            firstResult: &firstResult
          ) { return }
        }
      }
    }
    resumeFirst(&firstResult, with: .failure(ReconnectError.canceled))
  }

  private func finishOrSchedule(
    error: ReconnectError,
    attempt: Int,
    settings: ReconnectSettings,
    config: ReconnectConfig,
    generation runGeneration: UInt64,
    attemptSequence: Int,
    traceID: String?,
    started: ContinuousClock.Instant,
    firstResult: inout CheckedContinuation<Void, any Error>?
  ) async -> Bool {
    let exhausted = error.isTerminal || !settings.enabled || attempt >= settings.maxAttempts
    if exhausted {
      let finalError = error.isTerminal
        ? error
        : ReconnectError.exhausted(attempts: attempt, last: error.localizedDescription)
      setState(.error, error: finalError, client: nil)
      emit(
        code: "reconnect_exhausted",
        result: .fail,
        options: config.options,
        attemptSequence: attemptSequence,
        traceID: traceID,
        started: started
      )
      resumeFirst(&firstResult, with: .failure(finalError))
      return true
    }
    setState(.connecting, error: error, client: nil)
    emit(
      code: "reconnect_scheduled",
      result: .retry,
      options: config.options,
      attemptSequence: attemptSequence,
      traceID: traceID,
      started: started
    )
    do {
      try await Task.sleep(for: settings.delay(forFailedAttemptIndex: attempt - 1))
    } catch {
      resumeFirst(&firstResult, with: .failure(ReconnectError.canceled))
      return true
    }
    return !isActive(runGeneration)
  }

  private func isActive(_ runGeneration: UInt64) -> Bool {
    generation == runGeneration && !Task.isCancelled
  }

  private func setState(
    _ status: ReconnectStatus,
    error: ReconnectError?,
    client: FlowersecClient?
  ) {
    currentState = ReconnectState(status: status, error: error, client: client)
    for continuation in subscribers.values { continuation.yield(currentState) }
  }

  private func removeSubscriber(_ id: UUID) {
    subscribers.removeValue(forKey: id)
  }

  private func emit(
    code: String,
    result: DiagnosticResult,
    options: ConnectOptions,
    attemptSequence: Int,
    traceID: String?,
    started: ContinuousClock.Instant
  ) {
    options.onDiagnosticEvent?(
      DiagnosticEvent(
        path: .auto,
        stage: .reconnect,
        codeDomain: .event,
        code: code,
        result: result,
        elapsedMS: reconnectDurationMilliseconds(started.duration(to: .now)),
        attemptSeq: attemptSequence,
        traceID: traceID
      )
    )
  }
}

private func reconnectError(_ error: any Error, artifact: Bool) -> ReconnectError {
  if let reconnect = error as? ReconnectError { return reconnect }
  if let source = error as? ArtifactSourceError { return .artifact(source) }
  if let flowersec = error as? FlowersecError { return .connection(flowersec) }
  if error is CancellationError { return .canceled }
  if artifact { return .artifact(.acquisitionFailed(error.localizedDescription)) }
  return .terminated(error.localizedDescription)
}

private func correlatedOptions(
  _ options: ConnectOptions,
  attemptSequence: Int,
  traceID: String?
) -> ConnectOptions {
  var resolved = options
  let observer = options.onDiagnosticEvent
  resolved.onDiagnosticEvent = { event in
    var event = event
    event.attemptSeq = attemptSequence
    if event.traceID == nil { event.traceID = traceID }
    observer?(event)
  }
  return resolved
}

private func resumeFirst(
  _ continuation: inout CheckedContinuation<Void, any Error>?,
  with result: Result<Void, any Error>
) {
  guard let current = continuation else { return }
  continuation = nil
  current.resume(with: result)
}

private func reconnectDurationMilliseconds(_ duration: Duration) -> Double {
  let components = duration.components
  return Double(components.seconds) * 1_000
    + Double(components.attoseconds) / 1_000_000_000_000_000
}
