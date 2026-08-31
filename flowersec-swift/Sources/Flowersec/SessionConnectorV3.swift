import Foundation

enum ConnectorBoundaryErrorV3: Error, Equatable, Sendable {
  case artifactInvalid
  case runtimeUnsupported
  case policyExpired
  case securityFailed
  case runtimeFailed
  case browserPinOpaque
  case admissionFailed
  case admissionRejected
  case admissionRetryable
  case sessionFailed
  case candidateFailures(
    publicError: ConnectError,
    policyTriggerIDs: Set<String>,
    opaquePolicyTriggerIDs: Set<String>,
    failedIDs: Set<String>)
}

enum ControllerConnectFailureV3: Error, Equatable, Sendable {
  case connection(
    ConnectError, RetryDisposition, policyTriggerIDs: Set<String>,
    opaquePolicyTriggerIDs: Set<String>, failedIDs: Set<String>)
}

protocol RuntimeCarrierAdapterV3: Sendable {
  var capabilities: RuntimeCapabilityDescriptorV3 { get }

  func validate(options: ConnectorOptions) throws

  func prepare(
    candidate: CanonicalCandidateV3,
    path: PathKind,
    role: SessionRoleV3,
    options: ConnectorOptions,
    activePinHashes: [Data]?
  ) async throws -> any PreparedCarrierConnectionV3
}

protocol PreparedCarrierConnectionV3: Sendable {
  var carrier: CarrierKind { get }

  func writeAdmission(_ frame: Data) async throws
  func readAdmission() async throws -> Data
  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV3CarrierSession
  func close() async
}

struct SessionConnectorV3: Sendable {
  private let lease: ArtifactLease
  private let options: ConnectorOptions
  private let runtime: any RuntimeCarrierAdapterV3
  private let currentUnixSeconds: @Sendable () -> UInt64

  init(
    lease: ArtifactLease,
    options: ConnectorOptions,
    runtime: any RuntimeCarrierAdapterV3,
    currentUnixSeconds: @escaping @Sendable () -> UInt64 = {
      UInt64(max(0, Date().timeIntervalSince1970))
    }
  ) throws {
    guard options.connectTimeout > .zero else { throw ConnectError.invalidOptions }
    do {
      try runtime.validate(options: options)
    } catch {
      throw ConnectError.invalidOptions
    }
    self.lease = lease
    self.options = options
    self.runtime = runtime
    self.currentUnixSeconds = currentUnixSeconds
  }

  func connect() async throws -> any Session {
    do {
      return try await connectWithDeadline()
    } catch is CancellationError {
      throw ConnectError.canceled
    } catch is ArtifactLeaseError {
      throw ConnectError.artifactInvalid
    } catch ConnectorBoundaryErrorV3.artifactInvalid {
      throw ConnectError.artifactInvalid
    } catch ConnectorBoundaryErrorV3.runtimeUnsupported {
      throw ConnectError.transportSecurityUnsupported
    } catch ConnectorBoundaryErrorV3.policyExpired,
      ConnectorBoundaryErrorV3.securityFailed
    {
      throw ConnectError.transportSecurityFailed
    } catch ConnectorBoundaryErrorV3.candidateFailures(let publicError, _, _, _) {
      throw publicError
    } catch let error as ConnectError {
      throw error
    } catch {
      throw ConnectError.connectionFailed
    }
  }

  func connectForController() async throws -> any Session {
    do {
      return try await connectWithDeadline()
    } catch ConnectorBoundaryErrorV3.artifactInvalid {
      throw ControllerConnectFailureV3.connection(
        .artifactInvalid, .terminal, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    } catch ConnectorBoundaryErrorV3.runtimeUnsupported {
      throw ControllerConnectFailureV3.connection(
        .transportSecurityUnsupported, .terminal, policyTriggerIDs: [],
        opaquePolicyTriggerIDs: [], failedIDs: [])
    } catch ConnectorBoundaryErrorV3.policyExpired,
      ConnectorBoundaryErrorV3.securityFailed
    {
      throw ControllerConnectFailureV3.connection(
        .transportSecurityFailed, .terminal, policyTriggerIDs: [],
        opaquePolicyTriggerIDs: [], failedIDs: [])
    } catch ConnectorBoundaryErrorV3.admissionRejected {
      throw ControllerConnectFailureV3.connection(
        .connectionFailed, .terminal, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    } catch ConnectorBoundaryErrorV3.admissionRetryable {
      throw ControllerConnectFailureV3.connection(
        .connectionFailed, .retryable, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    } catch ConnectorBoundaryErrorV3.candidateFailures(
      let publicError, let policyTriggerIDs, let opaquePolicyTriggerIDs, let failedIDs
    ) {
      throw ControllerConnectFailureV3.connection(
        publicError, publicError.retryDisposition, policyTriggerIDs: policyTriggerIDs,
        opaquePolicyTriggerIDs: opaquePolicyTriggerIDs, failedIDs: failedIDs)
    } catch let error as ConnectError {
      throw ControllerConnectFailureV3.connection(
        error, error.retryDisposition, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    } catch is CancellationError {
      throw ControllerConnectFailureV3.connection(
        .canceled, .terminal, policyTriggerIDs: [], opaquePolicyTriggerIDs: [], failedIDs: [])
    } catch is ArtifactLeaseError {
      throw ControllerConnectFailureV3.connection(
        .artifactInvalid, .terminal, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    } catch {
      throw ControllerConnectFailureV3.connection(
        .connectionFailed, .retryable, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    }
  }

  private func connectWithDeadline() async throws -> any Session {
    let completion = ConnectorCompletionRaceV3<any Session>()
    let connectionBox = PreparedConnectionCloseBoxV3()
    let operation = Task<any Session, Error> {
      try await connectWithoutDeadline(connectionBox: connectionBox)
    }
    let timeout = Task<Void, Never> {
      do {
        try await Task.sleep(for: options.connectTimeout)
        if completion.resolve(.failure(ConnectError.timeout)) {
          operation.cancel()
          connectionBox.requestClose()
        }
      } catch {
        return
      }
    }
    let observer = Task {
      let result: Result<any Session, Error>
      do {
        result = .success(try await operation.value)
      } catch {
        result = .failure(error)
      }
      if completion.resolve(result) {
        timeout.cancel()
      } else if case .success(let session) = result {
        try? await session.close()
      }
    }
    let resolved: Result<any Session, Error>
    do {
      resolved = .success(
        try await withTaskCancellationHandler {
          try await withCheckedThrowingContinuation { continuation in
            completion.install(continuation)
          }
        } onCancel: {
          operation.cancel()
          timeout.cancel()
          connectionBox.requestClose()
          completion.resolve(.failure(CancellationError()))
        })
    } catch {
      resolved = .failure(error)
    }
    timeout.cancel()
    if case .failure = resolved {
      operation.cancel()
      connectionBox.requestClose()
    }
    await observer.value
    await connectionBox.waitForClose()
    return try resolved.get()
  }

  private func connectWithoutDeadline(
    connectionBox: PreparedConnectionCloseBoxV3
  ) async throws -> any Session {
    try Task.checkCancellation()
    let claimed = try await lease.claim()
    do {
      return try await connectClaimed(claimed, connectionBox: connectionBox)
    } catch {
      if !(await claimed.isConsumed) { try? await claimed.retire() }
      throw error
    }
  }

  private func connectClaimed(
    _ claimed: ClaimedArtifactLeaseV3,
    connectionBox: PreparedConnectionCloseBoxV3
  ) async throws -> any Session {
    try Task.checkCancellation()
    let artifact = claimed.artifact
    guard artifact.value.v == 3, artifact.value.profile == TransportV3Contract.sessionProfile else {
      throw ConnectorBoundaryErrorV3.artifactInvalid
    }
    guard artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
      throw ConnectError.expiredArtifact
    }
    let path: PathKind = artifact.value.path.kind == "direct" ? .direct : .tunnel
    let runtimePath: RuntimePathV3 = path == .direct ? .direct : .tunnel
    let role: SessionRoleV3 = artifact.value.path.role == 2 ? .server : .client
    let supported = artifact.canonicalCandidates.filter { candidate in
      runtime.capabilities.tuples.contains {
        $0.carrier.rawValue == candidate.carrier
          && $0.path == runtimePath
          && $0.sessionRole == role
          && $0.networkMode == .dial
          && $0.securityModes.contains(candidate.tls.mode)
      }
    }
    guard !supported.isEmpty else { throw ConnectorBoundaryErrorV3.runtimeUnsupported }

    // Freeze all pin policies once before this candidate race creates an adapter.
    let attemptNow = nowUnixSeconds()
    var sawSecurityFailure = false
    var sawOrdinaryFailure = false
    var policyTriggerIDs = Set<String>()
    var opaquePolicyTriggerIDs = Set<String>()
    // Capability-filtered candidates are skipped attempts for controller F. Keep
    // them in provenance so replacement eligibility cannot treat an unsupported
    // endpoint as a fresh candidate.
    var failedIDs = Set(artifact.canonicalCandidates.map(\.id))
    for candidate in supported { failedIDs.remove(candidate.id) }
    var attempts: [(candidate: CanonicalCandidateV3, activePinHashes: [Data]?)] = []
    for candidate in supported {
      do {
        attempts.append((candidate, try candidate.activePinHashes(at: attemptNow)))
      } catch TransportSecurityFailureV3.tlsPolicyExpired {
        failedIDs.insert(candidate.id)
        sawSecurityFailure = true
        if candidate.tls.mode == "pin" { policyTriggerIDs.insert(candidate.id) }
      } catch {
        throw ConnectorBoundaryErrorV3.artifactInvalid
      }
    }
    let race = CandidatePreparationRaceV3(
      candidateCount: attempts.count, connectionBox: connectionBox)
    for attempt in attempts {
      let task = Task {
        let outcome: CandidatePreparationOutcomeV3
        do {
          let connection = try await runtime.prepare(
            candidate: attempt.candidate, path: path, role: role, options: options,
            activePinHashes: attempt.activePinHashes)
          outcome = .prepared(attempt.candidate, connection)
        } catch ConnectorBoundaryErrorV3.policyExpired {
          outcome = .failed(attempt.candidate, security: true)
        } catch ConnectorBoundaryErrorV3.securityFailed {
          outcome = .failed(attempt.candidate, security: true)
        } catch ConnectorBoundaryErrorV3.browserPinOpaque {
          outcome = .opaque(attempt.candidate)
        } catch ConnectorBoundaryErrorV3.runtimeUnsupported {
          outcome = .unsupported(attempt.candidate)
        } catch {
          outcome = .failed(attempt.candidate, security: false)
        }
        if let lateConnection = race.submit(outcome) {
          await lateConnection.close()
        }
      }
      race.register(task)
    }
    let resolution: CandidatePreparationResolutionV3
    do {
      resolution = try await race.wait()
    } catch {
      await race.join()
      await connectionBox.waitForClose()
      throw error
    }
    await race.join()
    let winner: (CanonicalCandidateV3, any PreparedCarrierConnectionV3)?
    switch resolution {
    case .winner(let candidate, let connection):
      winner = (candidate, connection)
    case .failed(let outcomes):
      winner = nil
      for outcome in outcomes {
        switch outcome {
        case .prepared:
          preconditionFailure("a prepared candidate cannot be reported as a failure")
        case .failed(let candidate, let security):
          failedIDs.insert(candidate.id)
          if security {
            sawSecurityFailure = true
            if candidate.tls.mode == "pin" { policyTriggerIDs.insert(candidate.id) }
          } else {
            sawOrdinaryFailure = true
          }
        case .opaque(let candidate):
          failedIDs.insert(candidate.id)
          if candidate.tls.mode == "pin" { opaquePolicyTriggerIDs.insert(candidate.id) }
        case .unsupported(let candidate):
          failedIDs.insert(candidate.id)
        }
      }
    }
    try Task.checkCancellation()
    guard artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
      if let winner { await winner.1.close() }
      throw ConnectError.expiredArtifact
    }
    guard let (candidate, connection) = winner else {
      if sawSecurityFailure || !opaquePolicyTriggerIDs.isEmpty {
        throw ConnectorBoundaryErrorV3.candidateFailures(
          publicError: sawSecurityFailure ? .transportSecurityFailed : .connectionFailed,
          policyTriggerIDs: policyTriggerIDs,
          opaquePolicyTriggerIDs: opaquePolicyTriggerIDs,
          failedIDs: failedIDs)
      }
      if !sawOrdinaryFailure { throw ConnectorBoundaryErrorV3.runtimeUnsupported }
      throw ConnectorBoundaryErrorV3.runtimeFailed
    }
    do {
      try Task.checkCancellation()
      let admission = try AdmissionCodecV3.encodeFSB3(
        artifact: artifact, chosenCandidateID: candidate.id)
      guard artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
        throw ConnectError.expiredArtifact
      }
      try Task.checkCancellation()
      try await claimed.commitSpend()
      try Task.checkCancellation()
      guard artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
        throw ConnectError.expiredArtifact
      }
      try await connection.writeAdmission(admission.frame)
      let response = try AdmissionCodecV3.decodeFSA3(try await connection.readAdmission())
      switch response.status {
      case .success: break
      case .reject: throw ConnectorBoundaryErrorV3.admissionRejected
      case .retryable: throw ConnectorBoundaryErrorV3.admissionRetryable
      }
      let inboundCapacity = UInt16(artifact.value.session.maxInboundStreams) + 2
      let carrier = try await connection.makeCarrier(inboundCapacity: inboundCapacity)
      guard carrier.chosenCarrier.rawValue == candidate.carrier else {
        throw ConnectorBoundaryErrorV3.admissionFailed
      }
      let session = try await TransportV3Session.establish(
        carrier: carrier,
        config: try sessionConfig(
          artifact: artifact.value,
          path: path,
          role: role,
          admissionBinding: admission.admissionBinding
        )
      )
      try Task.checkCancellation()
      connectionBox.clear()
      return OpaqueSessionV3(session)
    } catch {
      connectionBox.clear()
      await connection.close()
      throw error
    }
  }

  private func sessionConfig(
    artifact: ArtifactWireV3,
    path: PathKind,
    role: SessionRoleV3,
    admissionBinding: Data
  ) throws -> TransportV3SessionConfig {
    guard
      let suite = TransportCipherSuiteV3(rawValue: UInt16(artifact.session.defaultSuite)),
      let maxInbound = UInt16(exactly: artifact.session.maxInboundStreams),
      let idleTimeout = UInt32(exactly: artifact.session.idleTimeoutSeconds)
    else { throw ConnectorBoundaryErrorV3.sessionFailed }
    var config = TransportV3SessionConfig(
      role: role,
      path: path,
      channelID: artifact.session.channelID,
      sessionContractHash: try decode32(artifact.session.contractHashBase64URL),
      suite: suite,
      psk: try decode32(artifact.session.e2eePSKBase64URL),
      maxInboundStreams: maxInbound,
      idleTimeoutSeconds: idleTimeout,
      localAdmissionBinding: admissionBinding,
      peerAdmissionBinding: path == .direct ? admissionBinding : Data(repeating: 0, count: 32),
      localEndpointInstanceID: artifact.path.localEndpointInstanceID ?? "",
      expectedPeerEndpointInstanceID: artifact.path.expectedPeerEndpointInstanceID ?? ""
    )
    config.deadlines.establish = .seconds(Int64(artifact.session.establishTimeoutSeconds))
    config.deadlines.rekeyPrepare = .seconds(Int64(artifact.session.rekeyPrepareTimeoutSeconds))
    config.deadlines.rekeyCompletion = .seconds(
      Int64(artifact.session.rekeyCompletionTimeoutSeconds))
    return config
  }

  private func decode32(_ value: String) throws -> Data {
    var text = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    text += String(repeating: "=", count: (4 - text.count % 4) % 4)
    guard let data = Data(base64Encoded: text), data.count == 32 else {
      throw ConnectorBoundaryErrorV3.sessionFailed
    }
    return data
  }

  private func nowUnixSeconds() -> UInt64 {
    min(currentUnixSeconds(), 9_007_199_254_740_991)
  }
}

private enum CandidatePreparationOutcomeV3: Sendable {
  case prepared(CanonicalCandidateV3, any PreparedCarrierConnectionV3)
  case failed(CanonicalCandidateV3, security: Bool)
  case opaque(CanonicalCandidateV3)
  case unsupported(CanonicalCandidateV3)
}

private enum CandidatePreparationResolutionV3: Sendable {
  case winner(CanonicalCandidateV3, any PreparedCarrierConnectionV3)
  case failed([CandidatePreparationOutcomeV3])
}

private final class CandidatePreparationRaceV3: @unchecked Sendable {
  private let lock = NSLock()
  private let connectionBox: PreparedConnectionCloseBoxV3
  private var remaining: Int
  private var failures: [CandidatePreparationOutcomeV3] = []
  private var tasks: [Task<Void, Never>] = []
  private var continuation: CheckedContinuation<CandidatePreparationResolutionV3, Error>?
  private var result: Result<CandidatePreparationResolutionV3, Error>?

  init(candidateCount: Int, connectionBox: PreparedConnectionCloseBoxV3) {
    precondition(candidateCount >= 0)
    self.remaining = candidateCount
    self.connectionBox = connectionBox
    if candidateCount == 0 { result = .success(.failed([])) }
  }

  func register(_ task: Task<Void, Never>) {
    let cancelImmediately = lock.withLock {
      tasks.append(task)
      return result != nil
    }
    if cancelImmediately { task.cancel() }
  }

  func submit(
    _ outcome: CandidatePreparationOutcomeV3
  ) -> (any PreparedCarrierConnectionV3)? {
    var continuation: CheckedContinuation<CandidatePreparationResolutionV3, Error>?
    var resolved: Result<CandidatePreparationResolutionV3, Error>?
    var tasksToCancel: [Task<Void, Never>] = []
    let connectionToClose = lock.withLock { () -> (any PreparedCarrierConnectionV3)? in
      guard result == nil else {
        if case .prepared(_, let connection) = outcome { return connection }
        return nil
      }
      switch outcome {
      case .prepared(let candidate, let connection):
        guard connectionBox.accept(connection) else {
          resolved = .failure(CancellationError())
          result = resolved
          continuation = self.continuation
          self.continuation = nil
          tasksToCancel = tasks
          return connection
        }
        resolved = .success(.winner(candidate, connection))
      case .failed, .opaque, .unsupported:
        failures.append(outcome)
        remaining -= 1
        guard remaining == 0 else { return nil }
        resolved = .success(.failed(failures))
      }
      result = resolved
      continuation = self.continuation
      self.continuation = nil
      tasksToCancel = tasks
      return nil
    }
    if let resolved { continuation?.resume(with: resolved) }
    for task in tasksToCancel { task.cancel() }
    return connectionToClose
  }

  func wait() async throws -> CandidatePreparationResolutionV3 {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let resolved = lock.withLock { () -> Result<CandidatePreparationResolutionV3, Error>? in
          if let result { return result }
          self.continuation = continuation
          return nil
        }
        if let resolved { continuation.resume(with: resolved) }
      }
    } onCancel: {
      cancel()
    }
  }

  func join() async {
    let pending = lock.withLock { tasks }
    for task in pending { await task.value }
  }

  private func cancel() {
    var continuation: CheckedContinuation<CandidatePreparationResolutionV3, Error>?
    var tasksToCancel: [Task<Void, Never>] = []
    let canceled = lock.withLock {
      guard result == nil else { return false }
      result = .failure(CancellationError())
      continuation = self.continuation
      self.continuation = nil
      tasksToCancel = tasks
      return true
    }
    guard canceled else { return }
    connectionBox.requestClose()
    continuation?.resume(throwing: CancellationError())
    for task in tasksToCancel { task.cancel() }
  }
}

private final class PreparedConnectionCloseBoxV3: @unchecked Sendable {
  private let lock = NSLock()
  private var connection: (any PreparedCarrierConnectionV3)?
  private var closeRequested = false
  private var closeTask: Task<Void, Never>?

  func accept(_ connection: any PreparedCarrierConnectionV3) -> Bool {
    lock.withLock {
      guard !closeRequested, self.connection == nil else { return false }
      self.connection = connection
      return true
    }
  }

  func clear() {
    lock.withLock { connection = nil }
  }

  func requestClose() {
    lock.withLock {
      closeRequested = true
      guard closeTask == nil, let pending = connection else { return }
      connection = nil
      closeTask = Task { await pending.close() }
    }
  }

  func waitForClose() async {
    let pending = lock.withLock { closeTask }
    await pending?.value
  }
}

private final class ConnectorCompletionRaceV3<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Value, Error>?
  private var result: Result<Value, Error>?

  func install(_ continuation: CheckedContinuation<Value, Error>) {
    let resolved = lock.withLock { () -> Result<Value, Error>? in
      if let result { return result }
      self.continuation = continuation
      return nil
    }
    if let resolved { continuation.resume(with: resolved) }
  }

  @discardableResult
  func resolve(_ result: Result<Value, Error>) -> Bool {
    var continuation: CheckedContinuation<Value, Error>?
    let won = lock.withLock { () -> Bool in
      guard self.result == nil else { return false }
      self.result = result
      continuation = self.continuation
      self.continuation = nil
      return true
    }
    continuation?.resume(with: result)
    return won
  }
}
