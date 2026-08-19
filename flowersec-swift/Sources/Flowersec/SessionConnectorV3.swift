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
    ConnectError, RetryDispositionV3, policyTriggerIDs: Set<String>,
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
  private let lease: ArtifactLeaseV3
  private let options: ConnectorOptions
  private let runtime: any RuntimeCarrierAdapterV3
  private let currentUnixSeconds: @Sendable () -> UInt64

  init(
    lease: ArtifactLeaseV3,
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
        publicError, publicError.retryDispositionV3, policyTriggerIDs: policyTriggerIDs,
        opaquePolicyTriggerIDs: opaquePolicyTriggerIDs, failedIDs: failedIDs)
    } catch let error as ConnectError {
      throw ControllerConnectFailureV3.connection(
        error, error.retryDispositionV3, policyTriggerIDs: [], opaquePolicyTriggerIDs: [],
        failedIDs: [])
    } catch is CancellationError {
      throw ControllerConnectFailureV3.connection(
        .canceled, .terminal, policyTriggerIDs: [], opaquePolicyTriggerIDs: [], failedIDs: [])
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
          connectionBox.close()
        }
      } catch {
        return
      }
    }
    Task {
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
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        completion.install(continuation)
      }
    } onCancel: {
      operation.cancel()
      timeout.cancel()
      connectionBox.close()
      completion.resolve(.failure(CancellationError()))
    }
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
    guard artifact.value.v == 3, artifact.value.profile == "flowersec/3" else {
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
    var failedIDs = Set<String>()
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
    var winner: (CanonicalCandidateV3, any PreparedCarrierConnectionV3)?
    await withTaskGroup(of: CandidatePreparationOutcomeV3.self) { group in
      for attempt in attempts {
        group.addTask {
          do {
            let connection = try await runtime.prepare(
              candidate: attempt.candidate, path: path, role: role, options: options,
              activePinHashes: attempt.activePinHashes)
            return .prepared(attempt.candidate, connection)
          } catch ConnectorBoundaryErrorV3.policyExpired {
            return .failed(attempt.candidate, security: true)
          } catch ConnectorBoundaryErrorV3.securityFailed {
            return .failed(attempt.candidate, security: true)
          } catch ConnectorBoundaryErrorV3.browserPinOpaque {
            return .opaque(attempt.candidate)
          } catch ConnectorBoundaryErrorV3.runtimeUnsupported {
            return .unsupported(attempt.candidate)
          } catch {
            return .failed(attempt.candidate, security: false)
          }
        }
      }
      while let outcome = await group.next() {
        switch outcome {
        case .prepared(let candidate, let connection):
          if winner == nil {
            winner = (candidate, connection)
            group.cancelAll()
          } else {
            await connection.close()
          }
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
    connectionBox.set(connection)
    do {
      let admission = try AdmissionCodecV3.encodeFSB3(
        artifact: artifact, chosenCandidateID: candidate.id)
      guard artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
        throw ConnectError.expiredArtifact
      }
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

private final class PreparedConnectionCloseBoxV3: @unchecked Sendable {
  private let lock = NSLock()
  private var connection: (any PreparedCarrierConnectionV3)?
  private var closeRequested = false

  func set(_ connection: any PreparedCarrierConnectionV3) {
    let closeImmediately = lock.withLock {
      if closeRequested { return true }
      self.connection = connection
      return false
    }
    if closeImmediately { Task { await connection.close() } }
  }

  func clear() {
    lock.withLock { connection = nil }
  }

  func close() {
    let pending = lock.withLock {
      closeRequested = true
      let pending = connection
      connection = nil
      return pending
    }
    if let pending { Task { await pending.close() } }
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
