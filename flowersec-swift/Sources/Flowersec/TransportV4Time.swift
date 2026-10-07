import Foundation

enum V4TimeFailure: Error, Sendable, Equatable {
  case configuration, unavailable, pending, expired, continuity, contradiction, canceled, owner
}

struct V4TimeInterval: Sendable, Equatable {
  let lowerMS: UInt64
  let upperMS: UInt64
}

struct V4TimeProfile: Sendable {
  let rateNumerator: UInt64
  let rateDenominator: UInt64
  let quantizationMS: UInt64
  let maximumWidthMS: UInt64
  let maximumAnchorAgeMS: UInt64

  func validate() throws {
    guard rateDenominator > 0, rateNumerator < rateDenominator,
      maximumWidthMS > 0, maximumAnchorAgeMS > 0
    else { throw V4TimeFailure.configuration }
    _ = try elapsed(proveDelta(lower: 0, bound: maximumWidthMS))
  }

  private func narrow(_ value: UInt128) throws -> UInt64 {
    guard value <= UInt128(UInt64.max) else { throw V4TimeFailure.unavailable }
    return UInt64(value)
  }

  private func ceiling(_ numerator: UInt128, _ denominator: UInt128) -> UInt128 {
    numerator / denominator + (numerator % denominator == 0 ? 0 : 1)
  }

  func elapsed(_ delta: UInt64) throws -> V4TimeInterval {
    let d = UInt128(rateDenominator)
    let n = UInt128(rateNumerator)
    guard d > n else { throw V4TimeFailure.configuration }
    let lower = UInt128(delta > quantizationMS ? delta - quantizationMS : 0) * d / (d + n)
    let (upperInput, overflow) = delta.addingReportingOverflow(quantizationMS)
    guard !overflow else { throw V4TimeFailure.unavailable }
    return try V4TimeInterval(
      lowerMS: narrow(lower), upperMS: narrow(ceiling(UInt128(upperInput) * d, d - n)))
  }

  func deadlineDelta(upper: UInt64, deadline: UInt64) throws -> UInt64 {
    guard upper < deadline else { throw V4TimeFailure.expired }
    let d = UInt128(rateDenominator)
    let n = UInt128(rateNumerator)
    guard d > n else { throw V4TimeFailure.configuration }
    let budget = UInt128(deadline - upper) * (d - n) / d
    guard budget > UInt128(quantizationMS) else { throw V4TimeFailure.expired }
    return try narrow(budget - UInt128(quantizationMS))
  }

  func proveDelta(lower: UInt64, bound: UInt64) throws -> UInt64 {
    guard bound > lower else { return 0 }
    let d = UInt128(rateDenominator)
    let n = UInt128(rateNumerator)
    guard d > n else { throw V4TimeFailure.configuration }
    let (product, overflow) = UInt128(bound - lower).multipliedReportingOverflow(by: d + n)
    guard !overflow else { throw V4TimeFailure.unavailable }
    return try narrow(ceiling(product, d) + UInt128(quantizationMS))
  }

  func advance(_ interval: V4TimeInterval, delta: UInt64) throws -> V4TimeInterval {
    guard interval.lowerMS <= interval.upperMS else { throw V4TimeFailure.unavailable }
    let elapsed = try elapsed(delta)
    let (lower, lowerOverflow) = interval.lowerMS.addingReportingOverflow(elapsed.lowerMS)
    let (upper, upperOverflow) = interval.upperMS.addingReportingOverflow(elapsed.upperMS)
    guard !lowerOverflow, !upperOverflow, upper - lower <= maximumWidthMS else {
      throw V4TimeFailure.unavailable
    }
    return V4TimeInterval(lowerMS: lower, upperMS: upper)
  }
}

struct V4MonotonicTick: Sendable {
  let milliseconds: UInt64
  let incarnation: UInt64
}

// The admitted host adapter supplies bounded local reads only. It must report
// lost suspension/migration/rate guarantees even if its OS tick increases.
// No system wall clock or peer timestamp is an authorization fallback.
protocol V4MonotonicSource: Sendable {
  func read() throws -> V4MonotonicTick
}

final class V4ContinuousTimeSource: V4MonotonicSource, @unchecked Sendable {
  private let lock = NSLock()
  private let start = ContinuousClock.now
  private var incarnation: UInt64 = 1
  private var usable = true

  func invalidateContinuity() {
    lock.withLock {
      if incarnation == .max { usable = false } else { incarnation += 1 }
    }
  }
  func setUnavailable() { lock.withLock { usable = false } }

  func read() throws -> V4MonotonicTick {
    try lock.withLock {
      guard usable else { throw V4TimeFailure.unavailable }
      let components = start.duration(to: .now).components
      guard components.seconds >= 0, components.attoseconds >= 0 else {
        throw V4TimeFailure.continuity
      }
      let value =
        UInt128(UInt64(components.seconds)) * 1000 + UInt128(UInt64(components.attoseconds))
        / 1_000_000_000_000_000
      guard value <= UInt128(UInt64.max) else { throw V4TimeFailure.unavailable }
      return V4MonotonicTick(milliseconds: UInt64(value), incarnation: incarnation)
    }
  }
}

struct V4ClockMark: Sendable {
  fileprivate let owner: V4TrustedClock
  let milliseconds: UInt64
  let incarnation: UInt64
  fileprivate let era: UInt64

  func sameEra(as other: Self) -> Bool {
    owner === other.owner && era == other.era && incarnation == other.incarnation
  }
}

struct V4ClockSample: Sendable {
  let mark: V4ClockMark?
  let interval: V4TimeInterval?
  let failure: V4TimeFailure?
}

final class V4TrustedClock: @unchecked Sendable {
  private struct Anchor {
    let at: V4ClockMark
    let origin: V4ClockMark
    let interval: V4TimeInterval
  }
  let gate: NSRecursiveLock
  let profile: V4TimeProfile
  private let source: any V4MonotonicSource
  private var last: V4MonotonicTick?
  private var era: UInt64 = 1
  private var sourceFailed = false
  private var closed = false
  private var anchor: Anchor?

  init(profile: V4TimeProfile, source: any V4MonotonicSource, gate: NSRecursiveLock) throws {
    try profile.validate()
    self.profile = profile
    self.source = source
    self.gate = gate
  }

  private func breakContinuityLocked() {
    anchor = nil
    if era == .max { closed = true } else { era += 1 }
  }

  private func markLocked() throws -> V4ClockMark {
    guard !closed else { throw V4TimeFailure.unavailable }
    let tick: V4MonotonicTick
    do {
      tick = try source.read()
      guard tick.incarnation != 0 else { throw V4TimeFailure.unavailable }
    } catch {
      if !sourceFailed { breakContinuityLocked() }
      sourceFailed = true
      throw V4TimeFailure.unavailable
    }
    sourceFailed = false
    if let last {
      if tick.incarnation != last.incarnation {
        breakContinuityLocked()
      } else if tick.milliseconds < last.milliseconds {
        breakContinuityLocked()
        self.last = tick
        throw V4TimeFailure.continuity
      }
    }
    last = tick
    guard !closed else { throw V4TimeFailure.unavailable }
    return V4ClockMark(
      owner: self, milliseconds: tick.milliseconds, incarnation: tick.incarnation, era: era)
  }

  func mark() throws -> V4ClockMark { try gate.withLock { try markLocked() } }

  private func intervalLocked(at now: V4ClockMark) throws -> V4TimeInterval {
    guard let anchor, now.sameEra(as: anchor.origin), now.milliseconds >= anchor.at.milliseconds
    else {
      throw V4TimeFailure.unavailable
    }
    let age = try profile.elapsed(now.milliseconds - anchor.origin.milliseconds)
    guard age.upperMS <= profile.maximumAnchorAgeMS else { throw V4TimeFailure.unavailable }
    return try profile.advance(anchor.interval, delta: now.milliseconds - anchor.at.milliseconds)
  }

  func sample() -> V4ClockSample {
    gate.withLock {
      let now: V4ClockMark
      do { now = try markLocked() } catch {
        return V4ClockSample(
          mark: nil, interval: nil, failure: (error as? V4TimeFailure) ?? .unavailable)
      }
      do {
        return V4ClockSample(mark: now, interval: try intervalLocked(at: now), failure: nil)
      } catch {
        return V4ClockSample(
          mark: now, interval: nil, failure: (error as? V4TimeFailure) ?? .unavailable)
      }
    }
  }

  // This narrow internal entry consumes already independently authenticated
  // host/control evidence at its actual captured mark. It performs no I/O and
  // grants no credential or namespace validity by itself.
  func installTrusted(at original: V4ClockMark, interval: V4TimeInterval) throws {
    try gate.withLock {
      let now = try markLocked()
      guard original.owner === self, now.sameEra(as: original),
        original.milliseconds <= now.milliseconds
      else {
        throw V4TimeFailure.continuity
      }
      let age = try profile.elapsed(now.milliseconds - original.milliseconds)
      guard age.upperMS <= profile.maximumAnchorAgeMS else { throw V4TimeFailure.unavailable }
      var current = try profile.advance(interval, delta: now.milliseconds - original.milliseconds)
      if let old = try? intervalLocked(at: now) {
        guard old.lowerMS <= current.upperMS, current.lowerMS <= old.upperMS else {
          anchor = nil
          throw V4TimeFailure.contradiction
        }
        current = V4TimeInterval(
          lowerMS: max(current.lowerMS, old.lowerMS), upperMS: min(current.upperMS, old.upperMS))
      }
      anchor = Anchor(at: now, origin: original, interval: current)
    }
  }

  func close() {
    gate.withLock {
      closed = true
      anchor = nil
    }
  }
}

// A deadline retains an absolute cap and the earliest projection in its clock
// era. This foundation conservatively ends an owner on lost continuity; no
// Session/key restoration exists until a real verification-continuity owner
// can prove that the original protocol state has not rolled back.
final class V4SecurityDeadline: @unchecked Sendable {
  let clock: V4TrustedClock
  private var cap: UInt64
  var capMS: UInt64 { clock.gate.withLock { cap } }
  private var projection: V4ClockMark?
  private var monotonicEnd: UInt64 = 0
  private var terminal: V4TimeFailure?

  init(clock: V4TrustedClock, capMS: UInt64) throws {
    self.clock = clock
    self.cap = capMS
    try clock.gate.withLock { _ = try sampleLocked() }
  }

  private func sampleLocked() throws -> V4ClockSample {
    if let terminal { throw terminal }
    let sample = clock.sample()
    if let projection {
      guard let mark = sample.mark, mark.sameEra(as: projection) else {
        terminal = .continuity
        throw V4TimeFailure.continuity
      }
      if mark.milliseconds >= monotonicEnd {
        terminal = .expired
        throw V4TimeFailure.expired
      }
    }
    if let failure = sample.failure { throw failure }
    guard let mark = sample.mark, let interval = sample.interval else {
      throw V4TimeFailure.unavailable
    }
    guard interval.upperMS < capMS else {
      terminal = .expired
      throw V4TimeFailure.expired
    }
    do {
      let delta = try clock.profile.deadlineDelta(upper: interval.upperMS, deadline: capMS)
      let (end, overflow) = mark.milliseconds.addingReportingOverflow(delta)
      guard !overflow else { throw V4TimeFailure.unavailable }
      monotonicEnd = projection == nil ? end : min(monotonicEnd, end)
      projection = mark
      guard mark.milliseconds < monotonicEnd else { throw V4TimeFailure.expired }
      return sample
    } catch {
      terminal = (error as? V4TimeFailure) ?? .unavailable
      throw terminal!
    }
  }

  func sample() throws -> V4ClockSample { try clock.gate.withLock { try sampleLocked() } }
  func check() throws { _ = try sample() }
  func tighten(to capMS: UInt64) throws {
    try clock.gate.withLock {
      cap = min(cap, capMS)
      _ = try sampleLocked()
    }
  }
  func cancel() { clock.gate.withLock { if terminal == nil { terminal = .canceled } } }

  func remainingTicks() throws -> UInt64 {
    try clock.gate.withLock {
      let sample = try sampleLocked()
      return monotonicEnd - sample.mark!.milliseconds
    }
  }
}

final class V4LocalWorkWindow: @unchecked Sendable {
  private let clock: V4TrustedClock
  private let start: V4ClockMark
  private let durationMS: UInt64
  private var terminal: V4TimeFailure?

  init(clock: V4TrustedClock, durationMS: UInt64) throws {
    self.clock = clock
    self.start = try clock.mark()
    self.durationMS = durationMS
    guard durationMS > (try clock.profile.elapsed(0)).upperMS else { throw V4TimeFailure.expired }
  }

  func check() throws {
    try clock.gate.withLock {
      if let terminal { throw terminal }
      do {
        let now = try clock.mark()
        guard now.sameEra(as: start), now.milliseconds >= start.milliseconds else {
          throw V4TimeFailure.continuity
        }
        guard try clock.profile.elapsed(now.milliseconds - start.milliseconds).upperMS < durationMS
        else {
          throw V4TimeFailure.expired
        }
      } catch {
        terminal = (error as? V4TimeFailure) ?? .unavailable
        throw terminal!
      }
    }
  }

  func cancel() { clock.gate.withLock { if terminal == nil { terminal = .canceled } } }
}

// One prepaid Session anchor; no host-duration narrowing, new timer, or clock
// repair can extend an already expired idle window. The caller owns scheduling.
final class V4SessionIdleWatchdog: @unchecked Sendable {
  private let clock: V4TrustedClock
  private let durationMS: UInt64
  private var anchor: V4ClockMark
  private var terminal: SessionError?

  init(clock: V4TrustedClock, durationMS: UInt64) throws {
    self.clock = clock
    self.durationMS = durationMS
    anchor = try clock.mark()
    if durationMS > 0 {
      guard durationMS > (try clock.profile.elapsed(0)).upperMS,
        try clock.profile.deadlineDelta(upper: 0, deadline: durationMS) > 0
      else { throw V4TimeFailure.configuration }
    }
  }
  private func check(_ now: V4ClockMark) throws {
    if let terminal { throw terminal }
    guard durationMS > 0 else { return }
    do {
      guard now.sameEra(as: anchor), now.milliseconds >= anchor.milliseconds else {
        throw SessionError.timeUnavailable
      }
      guard try clock.profile.elapsed(now.milliseconds - anchor.milliseconds).upperMS < durationMS
      else { throw SessionError.idleTimeout }
    } catch {
      terminal = (error as? SessionError) ?? .timeUnavailable
      throw terminal!
    }
  }
  func check() throws {
    try clock.gate.withLock {
      if let terminal { throw terminal }
      guard durationMS > 0 else { return }
      do { try check(clock.mark()) } catch {
        terminal = (error as? SessionError) ?? .timeUnavailable
        throw terminal!
      }
    }
  }
  func activity() throws {
    try clock.gate.withLock {
      if let terminal { throw terminal }
      guard durationMS > 0 else { return }
      do {
        let now = try clock.mark()
        try check(now)
        anchor = now
      } catch {
        terminal = (error as? SessionError) ?? .timeUnavailable
        throw terminal!
      }
    }
  }
  func close() { clock.gate.withLock { if terminal == nil { terminal = .closed } } }
}
