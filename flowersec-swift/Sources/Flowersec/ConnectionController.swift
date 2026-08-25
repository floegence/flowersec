import Dispatch
import Foundation

/// Supplies one fresh, independently spendable v3 artifact lease per attempt.
public protocol ArtifactSource: Sendable {
  func acquireArtifact() async throws -> ArtifactLease
}

public struct ArtifactSourceFailure: Error, Equatable, Sendable {
  public let code: ConnectErrorCode
  public let disposition: RetryDispositionV3

  public init(disposition: RetryDispositionV3) {
    self.code = .connectionFailed
    self.disposition = disposition
  }

  init(code: ConnectErrorCode, disposition: RetryDispositionV3) {
    self.code = code
    self.disposition = disposition
  }
}

public enum ConnectionState: String, Equatable, Sendable {
  case idle
  case connecting
  case connected
  case waiting
  case failed
  case closed
}

public enum ConnectionAttemptFailure: Error, Equatable, Sendable {
  case artifactSource(ArtifactSourceFailure)
  case connection(ConnectError)
  case session(SessionError)

  public var retryDisposition: RetryDispositionV3 {
    switch self {
    case .artifactSource(let failure): failure.disposition
    case .connection(let error): error.retryDispositionV3
    case .session(let error): error.retryDispositionV3
    }
  }
}

public struct ConnectionSnapshot: Sendable {
  public let state: ConnectionState
  public let attempt: UInt64
  public let currentSession: (any Session)?
  public let failure: ConnectionAttemptFailure?
  public let retryDisposition: RetryDispositionV3?
}

public enum ConnectionFailurePhase: String, Equatable, Sendable {
  case artifact
  case connect
  case session
}

public struct ConnectionDiagnosticFailure: Equatable, Sendable {
  public let phase: ConnectionFailurePhase
  public let code: String
}

public struct ConnectionDiagnostic: Equatable, Sendable {
  public let state: ConnectionState
  public let attempt: UInt64
  public let failure: ConnectionDiagnosticFailure?
  public let retryDisposition: RetryDispositionV3?
}

extension ConnectionSnapshot {
  /// Removes the live Session and retains only stable, redacted state.
  public var diagnostic: ConnectionDiagnostic {
    ConnectionDiagnostic(
      state: state,
      attempt: attempt,
      failure: failure.map { value in
        switch value {
        case .artifactSource(let error):
          ConnectionDiagnosticFailure(phase: .artifact, code: error.code.rawValue)
        case .connection(let error):
          ConnectionDiagnosticFailure(phase: .connect, code: error.code.rawValue)
        case .session(let error):
          ConnectionDiagnosticFailure(phase: .session, code: error.rawValue)
        }
      },
      retryDisposition: retryDisposition
    )
  }
}

public enum ConnectionControllerErrorCode: String, Equatable, Sendable {
  case failed
  case closed
  case canceled
}

public struct ConnectionControllerError: Error, Equatable, Sendable {
  public let code: ConnectionControllerErrorCode
  public let diagnostic: ConnectionDiagnostic
}

public enum ConnectionControllerConfigurationError: Error, Equatable, Sendable {
  case invalidMaximumAttempts
}

/// Owns v3 artifact refresh, policy-sensitive replacement, retry, and sessions.
public actor ConnectionController {
  private static let maxSafeInteger: UInt64 = 9_007_199_254_740_991
  public private(set) var state: ConnectionState = .idle
  public private(set) var attempt: UInt64 = 0
  public private(set) var currentSession: (any Session)?
  public private(set) var failure: ConnectionAttemptFailure?
  public private(set) var retryDisposition: RetryDispositionV3?

  private let source: any ArtifactSource
  private let options: ConnectorOptions
  private let maximumAttempts: UInt64?
  private let connectOneShot:
    @Sendable (ArtifactLease, ConnectorOptions) async throws -> any Session
  private let clock: ConnectionControllerClockV3
  private var scheduler: Task<Void, Never>?
  private var inFlightAttempt: Task<AttemptOutcomeV3, Never>?
  private var retryGate: ConnectionRetryGateV3?
  private var retryTimer: Task<Void, Never>?
  private var retryNotBefore: RetryNotBeforeV3?
  private var inFlightAcquisition: SourceAcquisitionRaceV3?
  private var observers: [UUID: AsyncStream<ConnectionSnapshot>.Continuation] = [:]
  private var closeTask: Task<Void, Never>?
  private var active: Bool { state != .closed && !Task.isCancelled }

  public init(
    source: any ArtifactSource,
    options: ConnectorOptions = ConnectorOptions(),
    maximumAttempts: UInt64? = nil
  ) throws {
    let normalizedMaximumAttempts = try Self.validate(maximumAttempts: maximumAttempts)
    self.source = source
    self.options = options
    self.maximumAttempts = normalizedMaximumAttempts
    self.clock = .live
    self.connectOneShot = { lease, options in
      try await connectV3ForController(lease: lease, options: options)
    }
  }

  init(
    source: any ArtifactSource,
    options: ConnectorOptions = ConnectorOptions(),
    maximumAttempts: UInt64? = nil,
    clock: ConnectionControllerClockV3 = .live,
    initialAttempt: UInt64 = 0,
    connectOneShot:
      @escaping @Sendable (ArtifactLease, ConnectorOptions) async throws -> any Session
  ) throws {
    let normalizedMaximumAttempts = try Self.validate(maximumAttempts: maximumAttempts)
    self.source = source
    self.options = options
    self.maximumAttempts = normalizedMaximumAttempts
    self.clock = clock
    self.attempt = min(initialAttempt, Self.maxSafeInteger)
    self.connectOneShot = connectOneShot
  }

  private static func validate(maximumAttempts: UInt64?) throws -> UInt64? {
    guard let maximumAttempts else { return nil }
    guard maximumAttempts <= maxSafeInteger else {
      throw ConnectionControllerConfigurationError.invalidMaximumAttempts
    }
    return maximumAttempts == 0 ? nil : maximumAttempts
  }

  public func start() {
    guard state == .idle, scheduler == nil else { return }
    scheduler = Task { [weak self] in await self?.run() }
  }

  /// Waits for an established Session without starting the controller.
  public func waitForSession() async throws -> any Session {
    let stream = updates()
    for await value in stream {
      if Task.isCancelled {
        throw ConnectionControllerError(code: .canceled, diagnostic: value.diagnostic)
      }
      switch value.state {
      case .connected:
        if let session = value.currentSession { return session }
      case .failed:
        throw ConnectionControllerError(code: .failed, diagnostic: value.diagnostic)
      case .closed:
        throw ConnectionControllerError(code: .closed, diagnostic: value.diagnostic)
      case .idle, .connecting, .waiting:
        break
      }
    }
    let value = snapshot().diagnostic
    throw ConnectionControllerError(
      code: Task.isCancelled ? .canceled : .closed,
      diagnostic: value
    )
  }

  public func updates() -> AsyncStream<ConnectionSnapshot> {
    let id = UUID()
    let pair = AsyncStream.makeStream(
      of: ConnectionSnapshot.self, bufferingPolicy: .bufferingNewest(1))
    observers[id] = pair.continuation
    pair.continuation.yield(snapshot())
    pair.continuation.onTermination = { [weak self] _ in
      Task { await self?.removeObserver(id) }
    }
    return pair.stream
  }

  public func snapshot() -> ConnectionSnapshot {
    ConnectionSnapshot(
      state: state, attempt: attempt, currentSession: currentSession, failure: failure,
      retryDisposition: retryDisposition)
  }

  public func retryNow() async -> Bool {
    guard state == .waiting, let retryGate else { return false }
    if let notBefore = retryNotBefore,
      wallNowMilliseconds(clock.wallNow()) < notBefore.wallDeadlineMilliseconds
    {
      return false
    }
    retryTimer?.cancel()
    return await retryGate.wake(.manual)
  }

  public func close() async {
    if let closeTask {
      await closeTask.value
      return
    }
    let activeScheduler = scheduler
    let activeAttempt = inFlightAttempt
    let activeAcquisition = inFlightAcquisition
    let activeGate = retryGate
    let activeSession = currentSession
    state = .closed
    currentSession = nil
    failure = nil
    scheduler = nil
    inFlightAttempt = nil
    inFlightAcquisition = nil
    retryGate = nil
    retryNotBefore = nil
    retryDisposition = nil
    retryTimer?.cancel()
    retryTimer = nil
    activeAttempt?.cancel()
    activeAcquisition?.cancel()
    activeScheduler?.cancel()
    publish()
    finishObservers()
    let cleanup = Task {
      if let activeGate { await activeGate.wake(.cancellation) }
      await activeAcquisition?.settle()
      try? await activeSession?.close()
      await activeScheduler?.value
    }
    closeTask = cleanup
    await cleanup.value
  }

  private func run() async {
    var consecutiveFailures: UInt64 = 0
    var primaryAttempts: UInt64 = 0
    var replacementUsed = false
    var blockedPinPolicy = BlockedPinPolicyV3()
    while state != .closed, !Task.isCancelled {
      state = .connecting
      failure = nil
      retryDisposition = nil
      attempt = increment(attempt)
      primaryAttempts = increment(primaryAttempts)
      publish()

      let outcome = await runAttempt(blockedPinPolicy: blockedPinPolicy)
      inFlightAttempt = nil
      guard active else {
        switch outcome {
        case .connected(let session): try? await session.close()
        case .failed(_, let lease?, _, _): await retire(lease)
        case .failed: break
        }
        return
      }
      switch outcome {
      case .connected(let session):
        consecutiveFailures = 0
        primaryAttempts = 0
        replacementUsed = false
        blockedPinPolicy = BlockedPinPolicyV3()
        currentSession = session
        state = .connected
        retryDisposition = nil
        publish()
        let termination = await session.waitTermination()
        try? await session.close()
        guard state != .closed, !Task.isCancelled else { return }
        currentSession = nil
        let sessionFailure = ConnectionAttemptFailure.session(termination.error)
        attempt = 0
        guard
          await scheduleRetry(
            after: sessionFailure,
            failures: &consecutiveFailures,
            attempts: primaryAttempts)
        else { return }

      case .failed(
        let attemptFailure, let claimedLease, let dispositionOverride, let provenance):
        if let dispositionOverride, !validRetryDisposition(dispositionOverride) {
          if let claimedLease { await retire(claimedLease) }
          fail(.connection(.artifactInvalid))
          return
        }
        if let claimedLease,
          await shouldRefreshPolicy(
            attemptFailure, lease: claimedLease, provenance: provenance)
        {
          guard active else {
            await retire(claimedLease)
            return
          }
          let trigger = policyIdentity(claimedLease.artifact, provenance: provenance!)
          blockedPinPolicy.formUnion(trigger.pins, opaque: trigger.opaque)
          if replacementUsed {
            await retire(claimedLease)
            let terminalError: ConnectError = blockedPinPolicy.hasNativeTrigger
              ? .transportSecurityFailed : publicError(for: attemptFailure)
            fail(.connection(terminalError))
            return
          }
          consecutiveFailures = increment(consecutiveFailures)
          await retire(claimedLease)
          guard active else { return }
          let replacement = await runReplacement(
            trigger: trigger,
            attempts: &primaryAttempts,
            failures: &consecutiveFailures,
            replacementUsed: &replacementUsed,
            blockedPinPolicy: blockedPinPolicy)
          guard active else {
            if case .connected(let session) = replacement { try? await session.close() }
            return
          }
          switch replacement {
          case .connected(let session):
            consecutiveFailures = 0
            primaryAttempts = 0
            replacementUsed = false
            blockedPinPolicy = BlockedPinPolicyV3()
            currentSession = session
            state = .connected
            retryDisposition = nil
            publish()
            let termination = await session.waitTermination()
            try? await session.close()
            guard state != .closed, !Task.isCancelled else { return }
            currentSession = nil
            let sessionFailure = ConnectionAttemptFailure.session(termination.error)
            attempt = 0
            guard
              await scheduleRetry(
                after: sessionFailure,
                failures: &consecutiveFailures,
                attempts: primaryAttempts)
            else { return }
          case .retryPrimary(let failure, let replacementDisposition):
            guard
              await scheduleRetry(
                after: failure,
                failures: &consecutiveFailures,
                attempts: primaryAttempts,
                dispositionOverride: replacementDisposition)
            else { return }
          case .terminal(let failure):
            fail(failure)
            return
          }
          continue
        }
        if let claimedLease, !(await claimedLease.isConsumed) { await retire(claimedLease) }
        guard
          await scheduleRetry(
            after: attemptFailure,
            failures: &consecutiveFailures,
            attempts: primaryAttempts,
            dispositionOverride: dispositionOverride)
        else { return }
      }
    }
  }

  private func runAttempt(blockedPinPolicy: BlockedPinPolicyV3) async -> AttemptOutcomeV3 {
    let source = self.source
    let options = self.options
    let connectOneShot = self.connectOneShot
    let acquisition = SourceAcquisitionRaceV3(source: source)
    inFlightAcquisition = acquisition
    let task = Task<AttemptOutcomeV3, Never> {
      let lease: ArtifactLease
      do {
        lease = try await acquisition.value()
      } catch let sourceFailure as ArtifactSourceFailure {
        return .failed(.artifactSource(sourceFailure), nil, nil, nil)
      } catch is CancellationError {
        return .failed(.connection(.canceled), nil, nil, nil)
      } catch {
        return .failed(
          .artifactSource(ArtifactSourceFailure(code: .artifactInvalid, disposition: .terminal)),
          nil, nil, nil)
      }
      let claimedLease: ClaimedArtifactLeaseV3
      do {
        claimedLease = try await lease.claimForConnectionController()
      } catch {
        return .failed(
          .artifactSource(
            ArtifactSourceFailure(code: .artifactInvalid, disposition: .terminal)),
          nil, nil, nil)
      }
      guard !Task.isCancelled else {
        return .failed(.connection(.canceled), claimedLease, nil, nil)
      }
      guard claimedLease.artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
        return .failed(.connection(.expiredArtifact), claimedLease, .retryable, nil)
      }
      let candidateIDs = primaryCandidateIDs(
        claimedLease.artifact, blockedPinPolicy: blockedPinPolicy)
      guard !candidateIDs.isEmpty else {
        let code: ConnectError =
          blockedPinPolicy.hasNativeTrigger
          ? .transportSecurityFailed : .connectionFailed
        return .failed(.connection(code), claimedLease, .terminal, nil)
      }
      let connectorArtifact = claimedLease.artifact.filteredForController(
        candidateIDs: candidateIDs)
      do {
        return .connected(
          try await connectOneShot(
            claimedLease.connectorLease(artifact: connectorArtifact), options))
      } catch let error as ConnectError {
        return .failed(.connection(error), claimedLease, nil, nil)
      } catch let error as ControllerConnectFailureV3 {
        switch error {
        case .connection(
          let publicError, let disposition, let policyTriggerIDs, let opaquePolicyTriggerIDs,
          let failedIDs):
          let provenance =
            policyTriggerIDs.isEmpty && opaquePolicyTriggerIDs.isEmpty
            ? nil
            : CandidateFailureProvenanceV3(
              policyTriggerIDs: policyTriggerIDs,
              opaquePolicyTriggerIDs: opaquePolicyTriggerIDs,
              failedIDs: failedIDs)
          return .failed(.connection(publicError), claimedLease, disposition, provenance)
        }
      } catch is CancellationError {
        return .failed(.connection(.canceled), claimedLease, nil, nil)
      } catch {
        return .failed(.connection(.connectionFailed), claimedLease, nil, nil)
      }
    }
    inFlightAttempt = task
    let result = await task.value
    if inFlightAcquisition === acquisition { inFlightAcquisition = nil }
    await acquisition.settle()
    return result
  }

  private func runReplacement(
    trigger: PolicyIdentityV3,
    attempts: inout UInt64,
    failures: inout UInt64,
    replacementUsed: inout Bool,
    blockedPinPolicy: BlockedPinPolicyV3
  ) async -> ReplacementOutcomeV3 {
    guard !Task.isCancelled, state != .closed else {
      return .terminal(.connection(.canceled))
    }
    let claimedLease: ClaimedArtifactLeaseV3
    while true {
      if let maximumAttempts, attempts >= maximumAttempts {
        return .terminal(.connection(trigger.publicError))
      }
      attempt = increment(attempt)
      attempts = increment(attempts)
      state = .connecting
      failure = nil
      retryDisposition = nil
      publish()
      let lease: ArtifactLease
      let acquisition = SourceAcquisitionRaceV3(source: source)
      inFlightAcquisition = acquisition
      do {
        lease = try await acquisition.value()
      } catch let sourceFailure as ArtifactSourceFailure {
        if inFlightAcquisition === acquisition { inFlightAcquisition = nil }
        await acquisition.settle()
        let sourceAttemptFailure = ConnectionAttemptFailure.artifactSource(sourceFailure)
        guard validRetryDisposition(sourceFailure.disposition) else {
          return .terminal(
            .artifactSource(
              ArtifactSourceFailure(code: .artifactInvalid, disposition: .terminal)))
        }
        guard
          await scheduleRetry(
            after: sourceAttemptFailure, failures: &failures, attempts: attempts)
        else { return .terminal(terminalFailure(sourceAttemptFailure)) }
        continue
      } catch is CancellationError {
        if inFlightAcquisition === acquisition { inFlightAcquisition = nil }
        await acquisition.settle()
        return .terminal(.connection(.canceled))
      } catch {
        if inFlightAcquisition === acquisition { inFlightAcquisition = nil }
        await acquisition.settle()
        return .terminal(
          .artifactSource(
            ArtifactSourceFailure(code: .artifactInvalid, disposition: .terminal)))
      }
      if inFlightAcquisition === acquisition { inFlightAcquisition = nil }
      await acquisition.settle()
      do {
        claimedLease = try await lease.claimForConnectionController()
      } catch is CancellationError {
        return .terminal(.connection(.canceled))
      } catch {
        return .terminal(
          .artifactSource(
            ArtifactSourceFailure(code: .artifactInvalid, disposition: .terminal)))
      }
      replacementUsed = true
      break
    }
    guard !Task.isCancelled, state != .closed else {
      await retire(claimedLease)
      return .terminal(.connection(.canceled))
    }
    guard claimedLease.artifact.value.session.initExpireAtUnixSeconds > nowUnixSeconds() else {
      await retire(claimedLease)
      return .retryPrimary(.connection(.expiredArtifact), nil)
    }
    guard
      let candidateIDs = replacementCandidateIDs(
        claimedLease.artifact, after: trigger, blockedPinPolicy: blockedPinPolicy)
    else {
      await retire(claimedLease)
      return .terminal(.connection(trigger.publicError))
    }
    let connectorArtifact = claimedLease.artifact.filteredForController(
      candidateIDs: candidateIDs)
    do {
      return .connected(
        try await connectOneShot(
          claimedLease.connectorLease(artifact: connectorArtifact), options))
    } catch let error as ConnectError {
      if await claimedLease.isConsumed {
        return .retryPrimary(.connection(error), nil)
      }
      await retire(claimedLease)
      if error == .expiredArtifact {
        return .retryPrimary(.connection(error), nil)
      }
      return .terminal(.connection(trigger.publicError))
    } catch let error as ControllerConnectFailureV3 {
      switch error {
      case .connection(let publicError, let disposition, _, _, _):
        guard validRetryDisposition(disposition) else {
          if !(await claimedLease.isConsumed) { await retire(claimedLease) }
          return .terminal(.connection(.artifactInvalid))
        }
        if await claimedLease.isConsumed {
          return .retryPrimary(.connection(publicError), disposition)
        }
        await retire(claimedLease)
        if publicError == .expiredArtifact {
          return .retryPrimary(.connection(publicError), disposition)
        }
        return .terminal(.connection(trigger.publicError))
      }
    } catch {
      if !(await claimedLease.isConsumed) { await retire(claimedLease) }
      return .terminal(.connection(.connectionFailed))
    }
  }

  private func shouldRefreshPolicy(
    _ failure: ConnectionAttemptFailure, lease: ClaimedArtifactLeaseV3,
    provenance: CandidateFailureProvenanceV3?
  ) async -> Bool {
    guard !(await lease.isConsumed), let provenance,
      !policyIdentity(lease.artifact, provenance: provenance).pins.isEmpty
    else { return false }
    switch failure {
    case .connection(let error) where error == .transportSecurityFailed:
      return !provenance.policyTriggerIDs.isEmpty || !provenance.opaquePolicyTriggerIDs.isEmpty
    case .connection(let error) where error.code == .connectionFailed:
      return !provenance.opaquePolicyTriggerIDs.isEmpty
    default: return false
    }
  }

  private func policyIdentity(
    _ artifact: Artifact, provenance: CandidateFailureProvenanceV3
  ) -> PolicyIdentityV3 {
    let sourceEndpoints = Set(
      artifact.canonicalCandidates.map { endpoint(for: $0, artifact: artifact) })
    let failedEndpoints = Set(
      artifact.canonicalCandidates.compactMap { candidate in
        provenance.failedIDs.contains(candidate.id)
          ? endpoint(for: candidate, artifact: artifact) : nil
      })
    let triggerIDs = provenance.policyTriggerIDs.union(provenance.opaquePolicyTriggerIDs)
    let pins = artifact.canonicalCandidates.compactMap { candidate -> PinCandidateIdentityV3? in
      guard triggerIDs.contains(candidate.id),
        candidate.tls.mode == "pin", candidate.tls.pins != nil,
        let digest = try? candidate.tlsPolicyDigest()
      else { return nil }
      return PinCandidateIdentityV3(
        endpoint: endpoint(for: candidate, artifact: artifact),
        digest: digest
      )
    }
    return PolicyIdentityV3(
      pins: pins,
      triggerEndpoints: Set(pins.map(\.endpoint)),
      failedEndpoints: failedEndpoints,
      sourceEndpoints: sourceEndpoints,
      publicError: provenance.policyTriggerIDs.isEmpty
        ? .connectionFailed : .transportSecurityFailed,
      opaque: provenance.policyTriggerIDs.isEmpty && !provenance.opaquePolicyTriggerIDs.isEmpty
    )
  }

  private func replacementCandidateIDs(
    _ artifact: Artifact,
    after trigger: PolicyIdentityV3,
    blockedPinPolicy: BlockedPinPolicyV3
  ) -> Set<String>? {
    guard !trigger.pins.isEmpty else { return nil }
    var changedPin = false
    var eligible = Set<String>()
    for candidate in artifact.canonicalCandidates {
      let candidateEndpoint = endpoint(for: candidate, artifact: artifact)
      if candidate.tls.mode == "ca" {
        if trigger.triggerEndpoints.contains(candidateEndpoint) { continue }
      } else {
        guard candidate.tls.mode == "pin", let digest = try? candidate.tlsPolicyDigest()
        else { continue }
        let identity = PinCandidateIdentityV3(endpoint: candidateEndpoint, digest: digest)
        let changedTrigger: Bool
        if let old = trigger.pins.first(where: { $0.endpoint == identity.endpoint }) {
          if old.digest == digest { continue }
          changedTrigger = true
        } else {
          changedTrigger = false
        }
        if blockedPinPolicy.identities.contains(identity) { continue }
        if changedTrigger {
          changedPin = true
          eligible.insert(candidate.id)
          continue
        }
      }
      if !trigger.sourceEndpoints.contains(candidateEndpoint)
        || !trigger.failedEndpoints.contains(candidateEndpoint)
      {
        eligible.insert(candidate.id)
      }
    }
    return changedPin && !eligible.isEmpty ? eligible : nil
  }

  nonisolated private func primaryCandidateIDs(
    _ artifact: Artifact,
    blockedPinPolicy: BlockedPinPolicyV3
  ) -> Set<String> {
    Set(
      artifact.canonicalCandidates.compactMap { candidate in
        let candidateEndpoint = endpoint(for: candidate, artifact: artifact)
        if candidate.tls.mode == "ca" {
          return blockedPinPolicy.identities.contains { $0.endpoint == candidateEndpoint }
            ? nil : candidate.id
        }
        guard candidate.tls.mode == "pin", let digest = try? candidate.tlsPolicyDigest() else {
          return candidate.id
        }
        let identity = PinCandidateIdentityV3(endpoint: candidateEndpoint, digest: digest)
        return blockedPinPolicy.identities.contains(identity) ? nil : candidate.id
      })
  }

  nonisolated private func endpoint(
    for candidate: CanonicalCandidateV3, artifact: Artifact
  ) -> EndpointKeyV3 {
    EndpointKeyV3(
      carrier: candidate.carrier, path: artifact.value.path.kind, url: candidate.normalizedURL)
  }

  private func retire(_ lease: ClaimedArtifactLeaseV3) async {
    try? await lease.retire()
  }

  private func scheduleRetry(
    after attemptFailure: ConnectionAttemptFailure,
    failures: inout UInt64,
    attempts: UInt64,
    alreadyCounted: Bool = false,
    dispositionOverride: RetryDispositionV3? = nil
  ) async -> Bool {
    guard active else { return false }
    let disposition = dispositionOverride ?? attemptFailure.retryDisposition
    guard validRetryDisposition(disposition) else {
      switch attemptFailure {
      case .artifactSource:
        fail(
          .artifactSource(
            ArtifactSourceFailure(code: .artifactInvalid, disposition: .terminal)))
      case .connection, .session:
        fail(.connection(.artifactInvalid))
      }
      return false
    }
    guard disposition != .terminal else {
      fail(attemptFailure)
      return false
    }
    if let maximumAttempts, attempts >= maximumAttempts {
      fail(terminalFailure(attemptFailure))
      return false
    }
    failure = attemptFailure
    if !alreadyCounted { failures = increment(failures) }
    let monotonicNow = min(clock.monotonicMilliseconds(), Self.maxSafeInteger)
    let backoffDeadline = saturatingAdd(
      monotonicNow, milliseconds(backoff(failure: failures)))
    let mandatory: RetryNotBeforeV3?
    switch disposition {
    case .terminal: return false
    case .retryable: mandatory = nil
    case .retryAfter(let deadline):
      guard validRetryAfter(deadline) else {
        fail(.connection(.artifactInvalid))
        return false
      }
      mandatory = RetryNotBeforeV3(wallDeadlineMilliseconds: deadline)
    }
    return await waitForRetry(backoffDeadline: backoffDeadline, notBefore: mandatory)
  }

  private func waitForRetry(
    backoffDeadline: UInt64, notBefore: RetryNotBeforeV3?
  ) async -> Bool {
    guard active else { return false }
    retryNotBefore = notBefore
    retryDisposition = notBefore.map { .retryAfter($0.wallDeadlineMilliseconds) } ?? .retryable
    state = .waiting
    let clock = self.clock
    publish()
    var manualBackoffBypass = false
    while active {
      let gate = ConnectionRetryGateV3()
      retryGate = gate
      let skipsBackoff = manualBackoffBypass
      retryTimer = Task {
        while !Task.isCancelled {
          let monotonicNow = min(clock.monotonicMilliseconds(), Self.maxSafeInteger)
          let monotonicRemaining =
            skipsBackoff || backoffDeadline <= monotonicNow
            ? 0 : backoffDeadline - monotonicNow
          let wallRemaining: UInt64 =
            notBefore.map {
              let now = wallNowMilliseconds(clock.wallNow())
              return $0.wallDeadlineMilliseconds > now ? $0.wallDeadlineMilliseconds - now : 0
            } ?? 0
          if monotonicRemaining == 0, wallRemaining == 0 {
            await gate.wake(.timer)
            return
          }
          let nextDeadline =
            monotonicRemaining == 0
            ? wallRemaining
            : wallRemaining == 0 ? monotonicRemaining : min(monotonicRemaining, wallRemaining)
          let remaining = min(nextDeadline, 1_000)
          do { try await clock.sleep(.milliseconds(Int64(remaining))) } catch { return }
        }
      }

      let wake = await gate.wait()
      retryTimer?.cancel()
      retryTimer = nil
      guard active else { break }
      if wake == .manual { manualBackoffBypass = true }

      let monotonicReady =
        manualBackoffBypass
        || min(clock.monotonicMilliseconds(), Self.maxSafeInteger) >= backoffDeadline
      let wallReady =
        notBefore.map {
          wallNowMilliseconds(clock.wallNow()) >= $0.wallDeadlineMilliseconds
        } ?? true
      if monotonicReady, wallReady {
        retryGate = nil
        retryNotBefore = nil
        return true
      }
    }
    retryGate = nil
    retryNotBefore = nil
    return false
  }

  private func backoff(failure: UInt64) -> Duration {
    var delay = FlowersecSDKDefaults.ConnectionController.initialDelay
    let maximum = FlowersecSDKDefaults.ConnectionController.maximumDelay
    var remaining = failure > 0 ? failure - 1 : 0
    while remaining > 0, delay < maximum {
      if delay >= maximum / Double(FlowersecSDKDefaults.ConnectionController.multiplier) {
        return maximum
      }
      delay = delay * Double(FlowersecSDKDefaults.ConnectionController.multiplier)
      remaining -= 1
    }
    return delay
  }

  private func fail(_ value: ConnectionAttemptFailure) {
    guard state != .closed else { return }
    currentSession = nil
    failure = value
    retryDisposition = .terminal
    state = .failed
    scheduler = nil
    publish()
  }

  nonisolated private func validRetryAfter(_ deadline: UInt64) -> Bool {
    deadline <= 253_402_300_799_999
  }

  nonisolated private func validRetryDisposition(_ disposition: RetryDispositionV3) -> Bool {
    guard case .retryAfter(let deadline) = disposition else { return true }
    return validRetryAfter(deadline)
  }

  nonisolated private func terminalFailure(
    _ value: ConnectionAttemptFailure
  ) -> ConnectionAttemptFailure {
    switch value {
    case .artifactSource(let failure):
      return .artifactSource(
        ArtifactSourceFailure(code: failure.code, disposition: .terminal))
    case .connection(let error):
      return .connection(error.terminalized())
    case .session:
      // Session termination starts a fresh cycle with an empty attempt budget;
      // a session failure cannot reach this exhaustion branch.
      return value
    }
  }

  private func publicError(for failure: ConnectionAttemptFailure) -> ConnectError {
    switch failure {
    case .artifactSource(let failure):
      switch failure.code {
      case .artifactInvalid: return .artifactInvalid
      case .expiredArtifact: return .expiredArtifact
      case .transportSecurityUnsupported: return .transportSecurityUnsupported
      case .transportSecurityFailed: return .transportSecurityFailed
      case .connectionFailed: return .connectionFailed
      }
    case .connection(let error): return error
    case .session: return .connectionFailed
    }
  }

  private func publish() {
    let value = snapshot()
    for observer in observers.values { observer.yield(value) }
  }

  private func finishObservers() {
    for observer in observers.values { observer.finish() }
    observers.removeAll()
  }

  private func removeObserver(_ id: UUID) { observers.removeValue(forKey: id) }

  private func increment(_ value: UInt64) -> UInt64 {
    value >= Self.maxSafeInteger ? Self.maxSafeInteger : value + 1
  }
  private func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow || sum > Self.maxSafeInteger ? Self.maxSafeInteger : sum
  }

  private func milliseconds(_ duration: Duration) -> UInt64 {
    let components = duration.components
    guard components.seconds >= 0, components.attoseconds >= 0 else { return 0 }
    return saturatingAdd(
      UInt64(components.seconds) * 1_000,
      UInt64(components.attoseconds) / 1_000_000_000_000_000)
  }

  private func nowUnixSeconds() -> UInt64 {
    UInt64(max(0, clock.wallNow().timeIntervalSince1970))
  }

  private nonisolated func wallNowMilliseconds(_ date: Date) -> UInt64 {
    let milliseconds = date.timeIntervalSince1970 * 1_000
    guard milliseconds.isFinite, milliseconds > 0 else { return 0 }
    return min(UInt64(milliseconds.rounded(.down)), Self.maxSafeInteger)
  }
}

struct ConnectionControllerClockV3: Sendable {
  let wallNow: @Sendable () -> Date
  let monotonicMilliseconds: @Sendable () -> UInt64
  let sleep: @Sendable (Duration) async throws -> Void

  static let live = ConnectionControllerClockV3(
    wallNow: { Date() },
    monotonicMilliseconds: {
      DispatchTime.now().uptimeNanoseconds / 1_000_000
    },
    sleep: { duration in try await Task.sleep(for: duration) }
  )
}

/// Serializes source result delivery and cancellation at one shared boundary.
/// A late lease is drained and retired before the race settles so controller
/// close can join all source-side cleanup.
private final class SourceAcquisitionRaceV3: @unchecked Sendable {
  private let lock = NSLock()
  private var result: Result<ArtifactLease, Error>?
  private var continuation: CheckedContinuation<ArtifactLease, Error>?
  private var sourceTask: Task<Void, Never>?

  init(source: any ArtifactSource) {
    sourceTask = nil
    sourceTask = Task { [weak self] in
      do {
        let lease = try await source.acquireArtifact()
        await self?.deliver(lease)
      } catch {
        self?.deliverFailure(error)
      }
    }
  }

  func value() async throws -> ArtifactLease {
    if Task.isCancelled { cancel() }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let resolved = lock.withLock { () -> Result<ArtifactLease, Error>? in
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

  func cancel() {
    var continuation: CheckedContinuation<ArtifactLease, Error>?
    let won = lock.withLock { () -> Bool in
      guard result == nil else { return false }
      result = .failure(CancellationError())
      continuation = self.continuation
      self.continuation = nil
      return true
    }
    guard won else { return }
    sourceTask?.cancel()
    continuation?.resume(throwing: CancellationError())
  }

  func settle() async {
    await sourceTask?.value
  }

  private func deliver(_ lease: ArtifactLease) async {
    var continuation: CheckedContinuation<ArtifactLease, Error>?
    let late = lock.withLock { () -> Bool in
      guard result == nil else { return true }
      result = .success(lease)
      continuation = self.continuation
      self.continuation = nil
      return false
    }
    if late {
      do {
        let claimed = try await lease.claim()
        try await claimed.retire()
      } catch {
        // Cleanup failures are intentionally redacted at the public boundary.
      }
    } else {
      continuation?.resume(returning: lease)
    }
  }

  private func deliverFailure(_ failure: Error) {
    var continuation: CheckedContinuation<ArtifactLease, Error>?
    let won = lock.withLock { () -> Bool in
      guard result == nil else { return false }
      result = .failure(failure)
      continuation = self.continuation
      self.continuation = nil
      return true
    }
    if won { continuation?.resume(throwing: failure) }
  }
}

private enum AttemptOutcomeV3: Sendable {
  case connected(any Session)
  case failed(
    ConnectionAttemptFailure, ClaimedArtifactLeaseV3?, RetryDispositionV3?,
    CandidateFailureProvenanceV3?)
}

private enum ReplacementOutcomeV3: Sendable {
  case connected(any Session)
  case retryPrimary(ConnectionAttemptFailure, RetryDispositionV3?)
  case terminal(ConnectionAttemptFailure)
}

private struct EndpointKeyV3: Hashable, Sendable {
  let carrier: String
  let path: String
  let url: String
}

private struct PinCandidateIdentityV3: Hashable, Sendable {
  let endpoint: EndpointKeyV3
  let digest: Data
}

private struct PolicyIdentityV3: Sendable {
  let pins: [PinCandidateIdentityV3]
  let triggerEndpoints: Set<EndpointKeyV3>
  let failedEndpoints: Set<EndpointKeyV3>
  let sourceEndpoints: Set<EndpointKeyV3>
  let publicError: ConnectError
  let opaque: Bool
}

private struct BlockedPinPolicyV3: Sendable {
  var identities: Set<PinCandidateIdentityV3> = []
  var hasOpaqueTrigger = false
  var hasNativeTrigger = false

  mutating func formUnion(_ values: [PinCandidateIdentityV3], opaque: Bool) {
    identities.formUnion(values)
    if opaque { hasOpaqueTrigger = true } else { hasNativeTrigger = true }
  }
}

private struct CandidateFailureProvenanceV3: Sendable {
  let policyTriggerIDs: Set<String>
  let opaquePolicyTriggerIDs: Set<String>
  let failedIDs: Set<String>
}

private struct RetryNotBeforeV3: Sendable { let wallDeadlineMilliseconds: UInt64 }

private enum ConnectionRetryWakeV3: Sendable { case timer, manual, cancellation }

private actor ConnectionRetryGateV3 {
  private var result: ConnectionRetryWakeV3?
  private var waiter: CheckedContinuation<ConnectionRetryWakeV3, Never>?

  func wait() async -> ConnectionRetryWakeV3 {
    if let result { return result }
    return await withCheckedContinuation { continuation in
      if let result { continuation.resume(returning: result) } else { waiter = continuation }
    }
  }

  @discardableResult
  func wake(_ result: ConnectionRetryWakeV3) -> Bool {
    guard self.result == nil else { return false }
    self.result = result
    waiter?.resume(returning: result)
    waiter = nil
    return true
  }
}
