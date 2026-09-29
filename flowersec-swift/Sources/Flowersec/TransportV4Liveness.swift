import Foundation

public struct TransportV4AutomaticLivenessPolicy: Sendable, Equatable {
  public let intervalMilliseconds: UInt64
  public let submissionMilliseconds: UInt64
  public let responseMilliseconds: UInt64
  public let missThreshold: UInt32
  public init(
    intervalMilliseconds: UInt64, submissionMilliseconds: UInt64,
    responseMilliseconds: UInt64, missThreshold: UInt32
  ) {
    self.intervalMilliseconds = intervalMilliseconds
    self.submissionMilliseconds = submissionMilliseconds
    self.responseMilliseconds = responseMilliseconds
    self.missThreshold = missThreshold
  }
  func validate(_ profile: V4TimeProfile) throws {
    let (total, overflow) = submissionMilliseconds.addingReportingOverflow(responseMilliseconds)
    guard !overflow, missThreshold > 0 else { throw V4TimeFailure.configuration }
    for duration in [intervalMilliseconds, submissionMilliseconds, responseMilliseconds, total] {
      guard duration > (try profile.elapsed(0)).upperMS,
        try profile.deadlineDelta(upper: 0, deadline: duration) > 0
      else { throw V4TimeFailure.configuration }
    }
  }
}

public enum TransportV4LivenessFailure: String, Error, Equatable, Sendable {
  case canceled, closed, timeout
  case rekeyInProgress = "rekey_in_progress"
  case resourceExhausted = "resource_exhausted"
  case timeUnavailable = "time_unavailable"
  case providerFailed = "provider_failed"
  case localStall = "local_stall"
}
public struct TransportV4LivenessProgress: Equatable, Sendable {
  public let submitted: Bool
  public let complete: Bool
  public let elapsedMilliseconds: UInt64?
}
public struct TransportV4LivenessError: Error, Equatable, Sendable {
  public let reason: TransportV4LivenessFailure
  public let progress: TransportV4LivenessProgress
}

// The original record owner marks its irreversible sequence/crypto ticket.
// Completion belongs to the actual provider, including asynchronous failure.
protocol V4RecordPublication: AnyObject, Sendable {
  func ticket(epoch: UInt32)
  func completed(_ success: Bool)
}

final class V4LivenessProbe: V4RecordPublication, @unchecked Sendable {
  fileprivate weak var owner: V4LivenessState?
  fileprivate let clock: V4TrustedClock
  fileprivate var reservation: V4ResourceReference?
  fileprivate var nonce: Data
  fileprivate let start: V4ClockMark
  fileprivate let duration: UInt64
  fileprivate let automatic: Bool
  fileprivate var submitted = false
  fileprivate var complete = false
  fileprivate var publishing = false
  fileprivate var waiterReleased = false
  fileprivate var epoch: UInt32?
  fileprivate var ticketedAt: V4ClockMark?
  fileprivate var completedAt: V4ClockMark?
  fileprivate var respondedAt: V4ClockMark?
  fileprivate var eligible = false
  fileprivate var result: TransportV4LivenessProgress?
  fileprivate var failure: TransportV4LivenessFailure?
  private let cancellationGate = NSLock()
  private var cancellationRequested = false

  fileprivate init(
    owner: V4LivenessState, clock: V4TrustedClock, reservation: V4ResourceReference,
    nonce: Data, start: V4ClockMark, duration: UInt64, automatic: Bool
  ) {
    self.owner = owner
    self.clock = clock
    self.reservation = reservation
    self.nonce = nonce
    self.start = start
    self.duration = duration
    self.automatic = automatic
    waiterReleased = automatic
  }
  // Swift invokes cancellation handlers under its task-status lock. This flag
  // takes no Session gate and resumes no continuation. Every matcher checks it.
  func requestCancellation() { cancellationGate.withLock { cancellationRequested = true } }
  fileprivate var canceled: Bool { cancellationGate.withLock { cancellationRequested } }
  func ticket(epoch: UInt32) {
    clock.gate.withLock {
      submitted = true
      self.epoch = epoch
      do { ticketedAt = try clock.mark() } catch { owner?.finish(self, .timeUnavailable) }
    }
  }
  func completed(_ success: Bool) {
    clock.gate.withLock {
      guard publishing else { return }
      if success {
        complete = true
        do { completedAt = try clock.mark() } catch { owner?.finish(self, .timeUnavailable) }
        owner?.published(self)
      } else {
        owner?.finish(self, .providerFailed)
      }
      publishing = false
      if let owner {
        owner.collect(self)
      } else {
        reservation?.release()
        reservation = nil
      }
    }
  }
  deinit { reservation?.release() }
}

// Fixed probe slots, matcher state and callback allowances are prepaid by the
// original reliable Session admission. A waiter and a real provider tail share
// their original slot until both have stopped using it.
final class V4LivenessState: @unchecked Sendable {
  private let clock: V4TrustedClock
  private let storage: V4CryptoReservation
  private let policy: TransportV4AutomaticLivenessPolicy?
  private var probes: [V4LivenessProbe] = []
  private var counter: UInt128 = 0
  private var closed = false
  private var rekey = false
  private var automatic: V4LivenessProbe?
  private var next: V4ClockMark?
  private var misses: UInt32 = 0
  private(set) var unresponsive = false

  init(
    clock: V4TrustedClock, storage: V4CryptoReservation,
    policy: TransportV4AutomaticLivenessPolicy?
  ) throws {
    try policy?.validate(clock.profile)
    guard 10_000 > (try clock.profile.elapsed(0)).upperMS,
      try clock.profile.deadlineDelta(upper: 0, deadline: 10_000) > 0
    else { throw V4TimeFailure.configuration }
    self.clock = clock
    self.storage = storage
    self.policy = policy
    probes.reserveCapacity(8)
    if policy != nil { next = try clock.mark() }
  }
  private func elapsed(_ start: V4ClockMark, _ now: V4ClockMark) throws -> UInt64 {
    guard now.sameEra(as: start), now.milliseconds >= start.milliseconds else {
      throw V4TimeFailure.continuity
    }
    return now.milliseconds - start.milliseconds
  }
  private func refusal(_ reason: TransportV4LivenessFailure) -> TransportV4LivenessError {
    TransportV4LivenessError(
      reason: reason,
      progress: TransportV4LivenessProgress(
        submitted: false, complete: false, elapsedMilliseconds: nil))
  }
  func begin(automatic: Bool = false) throws -> V4LivenessProbe {
    if closed { throw refusal(.closed) }
    if rekey { throw refusal(.rekeyInProgress) }
    let ordinary = probes.filter { !$0.automatic }.count
    guard probes.count < 8, automatic || ordinary < (policy == nil ? 8 : 7),
      !automatic || self.automatic == nil, counter < UInt128.max
    else { throw refusal(.resourceExhausted) }
    let start: V4ClockMark
    do { start = try clock.mark() } catch { throw refusal(.timeUnavailable) }
    let reference: V4ResourceReference
    do { reference = try storage.executionTail() } catch {
      localStall()
      throw refusal(.resourceExhausted)
    }
    counter += 1
    let nonce =
      V4Crypto.integer(UInt64(counter >> 64), width: 8)
      + V4Crypto.integer(UInt64(truncatingIfNeeded: counter), width: 8)
    let duration =
      automatic ? policy!.submissionMilliseconds + policy!.responseMilliseconds : 10_000
    let probe = V4LivenessProbe(
      owner: self, clock: clock, reservation: reference,
      nonce: nonce, start: start, duration: duration, automatic: automatic)
    probes.append(probe)
    if automatic { self.automatic = probe }
    return probe
  }
  private func check(_ probe: V4LivenessProbe) {
    guard probe.result == nil else { return }
    if probe.canceled {
      finish(probe, .canceled)
      return
    }
    if closed {
      finish(probe, .closed)
      return
    }
    if rekey {
      finish(probe, .rekeyInProgress)
      return
    }
    do {
      let now = try clock.mark()
      if try clock.profile.elapsed(elapsed(probe.start, now)).upperMS >= probe.duration {
        finish(probe, .timeout, at: now)
      }
    } catch { finish(probe, .timeUnavailable) }
  }
  func check() throws {
    for probe in probes { check(probe) }
    if unresponsive { throw SessionError.livenessPathUnresponsive }
  }
  func snapshot(_ probe: V4LivenessProbe) throws -> TransportV4LivenessProgress? {
    if probe.result == nil {
      guard probe.owner === self else { throw refusal(.closed) }
      check(probe)
    }
    if let failure = probe.failure, let result = probe.result {
      throw TransportV4LivenessError(reason: failure, progress: result)
    }
    return probe.result
  }
  func preparePublication(_ probe: V4LivenessProbe) throws -> Data? {
    check(probe)
    guard probe.result == nil else { return nil }
    guard probe.owner === self, !probe.submitted, !probe.publishing else {
      throw V4CryptoFailure.phase
    }
    if !probe.automatic { localStall() }
    probe.publishing = true
    return probe.nonce
  }
  func match(nonce: Data, epoch: UInt32) {
    for probe in probes where probe.result == nil && probe.submitted && probe.epoch == epoch {
      if probe.nonce == nonce {
        check(probe)
        if probe.result == nil { finish(probe) }
        return
      }
    }
  }
  fileprivate func published(_ probe: V4LivenessProbe) {
    check(probe)
    if probe.automatic, probe.result == nil, let completed = probe.completedAt {
      do {
        probe.eligible =
          try clock.profile.elapsed(elapsed(probe.start, completed)).upperMS
          <= policy!.submissionMilliseconds
      } catch { finish(probe, .timeUnavailable) }
    }
  }
  fileprivate func finish(
    _ probe: V4LivenessProbe, _ cause: TransportV4LivenessFailure? = nil,
    at supplied: V4ClockMark? = nil
  ) {
    guard probe.result == nil else { return }
    let now = supplied ?? (try? clock.mark())
    let duration = now.flatMap { try? elapsed(probe.start, $0) }
    let cause =
      duration == nil && cause != .closed && cause != .providerFailed ? .timeUnavailable : cause
    probe.failure = cause
    probe.result = TransportV4LivenessProgress(
      submitted: probe.submitted,
      complete: probe.complete, elapsedMilliseconds: duration)
    if cause == nil { probe.respondedAt = now }
    if probe.automatic, !closed {
      if cause == nil {
        misses = 0
      } else if cause == .timeout, probe.eligible, !rekey, let now, let handoff = probe.completedAt,
        let response = try? clock.profile.elapsed(elapsed(handoff, now)),
        response.lowerMS >= policy!.responseMilliseconds
      {
        misses += 1
        unresponsive = misses >= policy!.missThreshold
      }
    }
    V4Crypto.wipe(&probe.nonce)
    collect(probe)
  }
  func end(_ probe: V4LivenessProbe, reason: TransportV4LivenessFailure) { finish(probe, reason) }
  func release(_ probe: V4LivenessProbe) {
    if probe.result == nil { finish(probe, .canceled) }
    probe.waiterReleased = true
    collect(probe)
  }
  fileprivate func collect(_ probe: V4LivenessProbe) {
    guard probe.result != nil, !probe.publishing, probe.waiterReleased else { return }
    probes.removeAll { $0 === probe }
    if automatic === probe {
      automatic = nil
      next = try? clock.mark()
    }
    probe.owner = nil
    probe.reservation?.release()
    probe.reservation = nil
  }
  func beginRekey() {
    rekey = true
    next = nil
    for probe in probes { finish(probe, .rekeyInProgress) }
  }
  func completeRekey() {
    rekey = false
    misses = 0
    next = try? clock.mark()
  }
  func clockUnavailable() { for probe in probes { finish(probe, .timeUnavailable) } }
  func localStall() { if let automatic { finish(automatic, .localStall) } }
  func providerBlocked() {
    // The sample's own physical publication consumes its submission budget;
    // another blocked write cannot be turned into a remote miss.
    if automatic?.publishing != true { localStall() }
  }
  func nextAutomatic() throws -> V4LivenessProbe? {
    try check()
    guard !closed, !rekey, let policy else { return nil }
    if let automatic {
      return automatic.result == nil && !automatic.submitted && !automatic.publishing
        ? automatic : nil
    }
    guard let next else { return nil }
    let now = try clock.mark()
    guard try clock.profile.elapsed(elapsed(next, now)).lowerMS >= policy.intervalMilliseconds
    else {
      return nil
    }
    do { return try begin(automatic: true) } catch let error as TransportV4LivenessError
      where error.reason == .resourceExhausted
    {
      self.next = now
      return nil
    }
  }
  func close() {
    guard !closed else { return }
    closed = true
    next = nil
    for probe in probes { finish(probe, .closed) }
  }
}
