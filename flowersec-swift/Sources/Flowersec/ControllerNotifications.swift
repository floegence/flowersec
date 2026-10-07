import Foundation

public enum ControllerNotificationObservation: String, Sendable { case currentOnly = "current_only", drainAware = "drain_aware" }
public enum ControllerNotificationSourcePhase: String, Sendable { case current, retained, draining }
public enum ControllerNotificationGapReason: String, Sendable, CaseIterable {
  case handoff, unattached, lateAttachment = "late_attachment", sourceClosed = "source_closed"
  case sourceUnauthorized = "source_unauthorized", droppedBudget = "dropped_budget", coalesced
  case expired, decodeError = "decode_error", handlerError = "handler_error"
}
public struct ControllerNotificationGap: Sendable {
  public let fromGeneration: UInt64
  public let toGeneration: UInt64
  public let reasons: [ControllerNotificationGapReason]
  public let knownDropped: UInt64
  public let possibleGap: Bool
}
public enum ControllerNotificationEvent<Value: Sendable>: Sendable {
  case notification(value: Value, sourceGeneration: UInt64, sourcePhase: ControllerNotificationSourcePhase)
  case observationGap(ControllerNotificationGap)
}
public struct ControllerNotificationObservationStatus: Sendable {
  public let delivered: UInt64
  public let pending: Int
  public let callbackActive: Bool
  public let observedSources: Int
  public let attachedToCurrent: Bool
  public let gap: ControllerNotificationGap?
  public let closed: Bool
}

protocol V4ControllerNotificationRoot: AnyObject, Sendable {
  var token: UUID { get }
  var isClosed: Bool { get }
  var businessPending: Int { get }
  func attach(id: UUID, environment: V4EnvironmentFoundation, identity: ServiceCallerIdentity,
    check: @escaping @Sendable () throws -> Void, candidate: Bool, receiver: V4NotificationReceiver,
    draining: @escaping @Sendable () -> Bool, handoff: (any V4ControllerHandoffReservation)?,
    slotAvailable: (@Sendable () async -> Void)?) async
  func attached(id: UUID) -> Bool
  func noteLateAttachment()
  func publish(id: UUID)
  func retire(id: UUID)
  func close()
}

// The initial attempt snapshot is installed before irreversible own READY.
// Late roots join this same bounded retirement owner after publication.
final class V4ControllerNotificationPlan: @unchecked Sendable {
  let id = UUID()
  private struct Slot { weak var root: (any V4ControllerNotificationRoot)? }
  private let gate = NSLock()
  private var roots: [Slot]
  private var retired = false
  private let handoff: (any V4ControllerHandoffReservation)?
  init(_ roots: [any V4ControllerNotificationRoot], handoff: (any V4ControllerHandoffReservation)? = nil) {
    self.roots = roots.map { Slot(root: $0) }; self.handoff = handoff
  }
  func install(environment: V4EnvironmentFoundation, identity: ServiceCallerIdentity,
    receiver: V4NotificationReceiver, check: @escaping @Sendable () throws -> Void, draining: @escaping @Sendable () -> Bool) async {
    let snapshot = gate.withLock { roots.compactMap { $0.root } }
    for root in snapshot {
      guard !isRetired else { return }
      await root.attach(id: id, environment: environment, identity: identity,
        check: { [weak self] in
          guard let self, !self.isRetired else { throw ServiceFailure.closed }
          try check()
        }, candidate: true, receiver: receiver, draining: draining, handoff: handoff, slotAvailable: nil)
      if isRetired { root.retire(id: id) }
    }
  }
  var isRetired: Bool { gate.withLock { retired } }
  func includeLate(_ root: any V4ControllerNotificationRoot) -> Bool {
    // Never hold the plan lock while entering a root's Environment gate.
    let snapshot = gate.withLock { roots.compactMap { $0.root } }
    let closed = Set(snapshot.filter { $0.isClosed }.map { $0.token })
    return gate.withLock {
      guard !retired else { return false }
      roots.removeAll { slot in slot.root.map { closed.contains($0.token) } ?? true }
      if roots.contains(where: { $0.root?.token == root.token }) { return true }
      guard roots.count < 32 else { return false }
      roots.append(Slot(root: root)); return true
    }
  }
  func publish() {
    let snapshot = gate.withLock { retired ? [] : roots.compactMap { $0.root } }
    for root in snapshot {
      guard !isRetired else { return }
      root.publish(id: id)
      if isRetired { root.retire(id: id) }
    }
  }
  func retire() {
    let snapshot = gate.withLock { retired = true; return roots.compactMap { $0.root } }
    for root in snapshot { root.retire(id: id) }
  }
}

private final class V4ControllerNotificationSource: @unchecked Sendable {
  let id: UUID
  let generation: UInt64
  let storage: V4CryptoReservation
  let check: @Sendable () throws -> Void
  let draining: @Sendable () -> Bool
  var published = false
  var phase: ControllerNotificationSourcePhase = .current
  var closed = false
  var detaching = false
  var installing = true
  var physicalCallbacks = 0
  var timerTasks = 0
  weak var receiver: V4NotificationReceiver?
  weak var registration: V4ControllerNotificationRegistration?
  init(id: UUID, generation: UInt64, storage: V4CryptoReservation, check: @escaping @Sendable () throws -> Void, draining: @escaping @Sendable () -> Bool) {
    self.id = id; self.generation = generation; self.storage = storage; self.check = check; self.draining = draining
  }
}
private final class V4ControllerNotificationRegistration: V4NotificationRegistration, @unchecked Sendable {
  let token = UUID()
  let typeID: UInt32
  private let source: V4ControllerNotificationSource
  private let matchesInput: @Sendable (V4ApplicationHeader, V4ControllerNotificationSource) -> Bool
  private let deliverInput: @Sendable (V4NotificationInput, V4ControllerNotificationSource) -> Void
  private let gapInput: @Sendable (NotificationGap, V4ControllerNotificationSource) -> Void
  private let closeSource: @Sendable (V4ControllerNotificationSource) -> Void
  private let businessPendingInput: @Sendable () -> Int
  init(typeID: UInt32, source: V4ControllerNotificationSource,
    matches: @escaping @Sendable (V4ApplicationHeader, V4ControllerNotificationSource) -> Bool,
    deliver: @escaping @Sendable (V4NotificationInput, V4ControllerNotificationSource) -> Void,
    gap: @escaping @Sendable (NotificationGap, V4ControllerNotificationSource) -> Void,
    close: @escaping @Sendable (V4ControllerNotificationSource) -> Void,
    businessPending: @escaping @Sendable () -> Int) {
    self.typeID = typeID; self.source = source; matchesInput = matches; deliverInput = deliver; gapInput = gap; closeSource = close
    businessPendingInput = businessPending
  }
  var businessPending: Int { source.storage.environment.gate.withLock { businessPendingInput() } }
  var physicalPending: Int { source.storage.environment.gate.withLock { source.physicalCallbacks + source.timerTasks + (source.detaching ? 1 : 0) + (source.installing ? 1 : 0) } }
  func matches(_ header: V4ApplicationHeader) -> Bool { matchesInput(header, source) }
  func deliver(_ input: V4NotificationInput) { deliverInput(input, source) }
  func recordGap(_ reason: NotificationGap) { gapInput(reason, source) }
  func close() { closeSource(source) }
}
private struct V4ControllerNotificationDelivery: Sendable {
  let input: V4NotificationInput
  let source: V4ControllerNotificationSource
  let storage: V4CryptoReservation
}

private struct V4ControllerNotificationSlotWake: Sendable {
  let id: UUID
  let callback: @Sendable () async -> Void
}

/// One bounded queue and one serial callback across candidate, current and
/// draining sources. Generation is local observation metadata, never identity.
public final class ControllerNotificationSubscription<Value: Sendable>: V4ControllerNotificationRoot, @unchecked Sendable {
  let token = UUID()
  private let gate: NSRecursiveLock
  private let environment: V4EnvironmentFoundation
  private var group: V4ApplicationGroup?
  private var storage: V4CryptoReservation?
  private var contract: ServiceContract?
  private var codec: (any MessageCodec<Value>)?
  private let method: MethodDefinition
  private let target: ServiceBindingTarget
  private let observation: ControllerNotificationObservation
  private let options: NotificationSubscriptionOptions
  private let invocationContext: ApplicationInvocationContext?
  private var handler: (@Sendable (ApplicationInvocationContext, ControllerNotificationEvent<Value>) async throws -> Void)?
  private var sources: [V4ControllerNotificationSource] = []
  // One coalesced descriptor and one original charged wake task per root.
  private var sourceSlotWake: V4ControllerNotificationSlotWake?
  private var sourceSlotTask: Task<Void, Never>?
  private var sourceSlotTaskID: UUID?
  private var pending: [V4ControllerNotificationDelivery] = []
  private var current: V4ControllerNotificationDelivery?
  private var currentEntered = false
  private var currentRevoked = false
  private var currentID: UUID?
  private var generation: UInt64 = 0
  private var delivered: UInt64 = 0
  private var work: V4ApplicationWork?
  private var timers: [UUID: Task<Void, Never>] = [:]
  private var gapReasons: Set<ControllerNotificationGapReason> = []
  private var gapFrom: UInt64 = 0
  private var gapTo: UInt64 = 0
  private var knownDropped: UInt64 = 0
  private var possibleGap = false
  private var gapPending = false
  private var lastWasGap = false
  private var currentExpired = false
  private var closed = false
  private var closeDeadline: ContinuousClock.Instant?

  init(environment: V4EnvironmentFoundation, definition: ServiceDefinition, method: MethodDefinition,
    target: ServiceBindingTarget, snapshot: ServiceContractSnapshot, codec: any MessageCodec<Value>,
    observation: ControllerNotificationObservation, options: NotificationSubscriptionOptions, context: ApplicationInvocationContext? = nil,
    handler: @escaping @Sendable (ApplicationInvocationContext, ControllerNotificationEvent<Value>) async throws -> Void) throws {
    guard definition.contains(method), method.shape == .notify, method.semantics == .observation,
      codec.definition == method.options.request, snapshot.offer == nil else { throw ServiceFailure.contractMismatch }
    try snapshot.contract.checkEnvironment(environment); try snapshot.contract.checkMethod(method, in: definition)
    self.environment = environment; gate = environment.gate; self.method = method; self.target = target
    contract = snapshot.contract; self.codec = try v4ServiceCaptureRequestCodec(codec); self.observation = observation; self.options = options; invocationContext = context; self.handler = handler
    group = try environment.applicationGroup(); storage = try environment.controllerNotificationStorage(applicationBytes: options.applicationBytes)
    pending.reserveCapacity(16); sources.reserveCapacity(2); gapReasons.reserveCapacity(ControllerNotificationGapReason.allCases.count)
  }
  func attach(id: UUID, environment: V4EnvironmentFoundation, identity: ServiceCallerIdentity,
    check: @escaping @Sendable () throws -> Void, candidate: Bool, receiver: V4NotificationReceiver,
    draining: @escaping @Sendable () -> Bool, handoff: (any V4ControllerHandoffReservation)? = nil,
    slotAvailable: (@Sendable () async -> Void)? = nil) async {
    let source: V4ControllerNotificationSource
    do {
      guard let admitted = try gate.withLock({ () throws -> V4ControllerNotificationSource? in
        guard !closed, !Task.isCancelled else { return nil }
        guard self.environment === environment else { throw ServiceFailure.serviceUnavailable }
        if sources.contains(where: { $0.id == id && !$0.closed }) { return nil }
        if !candidate { try check() }
        guard sources.count < 2, !sources.contains(where: { $0.id == id }) else {
          // Pre-READY installation makes one attempt and never waits for an
          // observation slot. The current publication pass installs this wake.
          if let slotAvailable { sourceSlotWake = V4ControllerNotificationSlotWake(id: id, callback: slotAvailable) }
          report(.unattached, generation: generation, dropped: 0, possible: true); beginNext()
          return nil
        }
        guard generation < .max, let storage, let contract else { throw ServiceFailure.resourceExhausted }
        try storage.check(); try contract.checkEnvironment(environment); try target.check(identity)
        generation += 1
        let original = V4ControllerNotificationSource(id: id, generation: generation,
          storage: try handoff?.takeNotification(token: token, in: environment) ?? environment.controllerNotificationSourceStorage(), check: check, draining: draining)
        if sourceSlotWake?.id == id { sourceSlotWake = nil }
        sources.append(original); return original
      }) else { return }
      source = admitted
    } catch {
      gate.withLock { if !closed { report(.unattached, generation: generation, dropped: 0, possible: true); beginNext() } }
      return
    }
    let registration = V4ControllerNotificationRegistration(typeID: method.typeID, source: source,
      matches: { [weak self] header, source in self?.matches(header, source: source) ?? false },
      deliver: { [weak self] input, source in self?.deliver(input, source: source) },
      gap: { [weak self] reason, source in self?.record(reason, source: source) },
      close: { [weak self] source in self?.sourceClosed(source) },
      businessPending: { [weak self, source] in self?.businessPending(for: source) ?? 0 })
    gate.withLock { source.registration = registration; source.receiver = receiver }
    do { try await receiver.install(registration) }
    catch { sourceClosed(source, reason: .unattached) }
    let remove = gate.withLock {
      if !source.closed {
        do {
          guard !closed, !Task.isCancelled else { throw ServiceFailure.closed }
          if !candidate { try source.check() }
        } catch { sourceClosed(source, reason: .sourceClosed) }
      }
      if !source.closed { source.installing = false }
      return source.closed
    }
    if remove {
      // An in-flight installation retains its source slot through the original
      // install and uninstall, even if the root or plan was already retired.
      await receiver.uninstall(registration.token)
      gate.withLock { source.installing = false; source.receiver = nil; collectSources(); collect() }
    }
  }
  private func wakeReleasedSourceSlot() {
    guard !closed, sourceSlotTask == nil, sources.count < 2,
      let wake = sourceSlotWake, !sources.contains(where: { $0.id == wake.id }),
      let tail = try? storage?.executionTail() else { return }
    sourceSlotWake = nil; sourceSlotTaskID = wake.id
    sourceSlotTask = Task { [self, tail] in
      let current = gate.withLock { !closed && sourceSlotTaskID == wake.id && !Task.isCancelled }
      if current { await wake.callback() }
      gate.withLock {
        tail.release(); sourceSlotTask = nil; sourceSlotTaskID = nil
        wakeReleasedSourceSlot(); collect()
      }
    }
  }
  func attached(id: UUID) -> Bool { gate.withLock { sources.contains { $0.id == id && !$0.closed && !$0.installing } } }
  var isClosed: Bool { gate.withLock { closed } }
  private func businessPending(for source: V4ControllerNotificationSource) -> Int {
    pending.reduce(0) { $0 + ($1.source === source ? 1 : 0) }
      + (current?.source === source ? 1 : 0)
  }
  var businessPending: Int { gate.withLock { pending.count + (current == nil ? 0 : 1) } }
  func publish(id: UUID) {
    gate.withLock {
      guard !closed else { return }
      let previous = currentID; currentID = id
      if sourceSlotWake?.id != id { sourceSlotWake = nil }
      if sourceSlotTaskID != id { sourceSlotTask?.cancel() }
      if previous != nil, previous != id { report(.handoff, generation: generation, dropped: 0, possible: true) }
      for source in sources where source.id != id && !source.closed && source.published {
        if observation == .currentOnly { sourceClosed(source, reason: .handoff) }
        else { source.phase = .retained }
      }
      if let source = sources.first(where: { $0.id == id && !$0.closed }) {
        source.published = true; source.phase = .current
      } else { report(.unattached, generation: generation, dropped: 0, possible: true) }
      beginNext()
    }
  }
  func retire(id: UUID) {
    gate.withLock {
      if sourceSlotWake?.id == id { sourceSlotWake = nil }
      if sourceSlotTaskID == id { sourceSlotTask?.cancel() }
      for source in sources where source.id == id { sourceClosed(source) }
    }
  }
  func noteLateAttachment() { gate.withLock { report(.lateAttachment, generation: generation, dropped: 0, possible: true) } }
  private func matches(_ header: V4ApplicationHeader, source: V4ControllerNotificationSource) -> Bool {
    gate.withLock {
      guard !closed, !source.closed, let contract, let codec, header.kind == "observation_notify",
        (try? header.typeID) == method.typeID, (try? header.bytes(6)) == contract.digest else { return false }
      do {
        try storage?.check(); try source.storage.check(); try source.check()
        let count = try header.payloadBytes
        guard count <= codec.definition.maxMessageBytes, UInt64(count) <= (try contract.uint(23)),
          let interval = environment.clock.sample().interval else { return false }
        let deadline = try header.uint(5)
        return try interval.upperMS < deadline && deadline - interval.lowerMS <= contract.uint(11)
      } catch { return false }
    }
  }
  private func eligible(_ source: V4ControllerNotificationSource) -> Bool {
    !closed && !source.closed && source.published && (observation == .drainAware || currentID == source.id)
  }
  private func record(_ reason: NotificationGap, source: V4ControllerNotificationSource) {
    gate.withLock {
      let mapped: ControllerNotificationGapReason
      switch reason {
      case .droppedBudget: mapped = .droppedBudget
      case .coalesced: mapped = .coalesced
      case .expired: mapped = .expired
      case .decodeError: mapped = .decodeError
      case .handlerError: mapped = .handlerError
      case .closed: mapped = .sourceClosed
      }
      report(mapped, generation: source.generation, dropped: 1, possible: false); beginNext()
    }
  }
  private func report(_ reason: ControllerNotificationGapReason, generation: UInt64, dropped: UInt64, possible: Bool) {
    guard !closed else { return }
    if reason == .droppedBudget || reason == .coalesced || reason == .expired {
      environment.root.diagnosticCounters.increment(.slowConsumers, by: dropped)
    }
    gapReasons.insert(reason); gapFrom = gapFrom == 0 ? generation : min(gapFrom, generation); gapTo = max(gapTo, generation)
    let (sum, overflow) = knownDropped.addingReportingOverflow(dropped); knownDropped = overflow ? .max : sum
    possibleGap = possibleGap || possible; gapPending = true
  }
  private func gapSnapshot() -> ControllerNotificationGap? {
    guard !gapReasons.isEmpty else { return nil }
    return ControllerNotificationGap(fromGeneration: gapFrom, toGeneration: gapTo,
      reasons: ControllerNotificationGapReason.allCases.filter(gapReasons.contains), knownDropped: knownDropped, possibleGap: possibleGap)
  }
  private var pendingCount: Int {
    pending.count + (current != nil && !currentEntered && !currentRevoked ? 1 : 0)
  }
  private func deliver(_ input: V4NotificationInput, source: V4ControllerNotificationSource) {
    gate.withLock {
      guard matches(input.header, source: source), !closed, !source.closed else { return }
      let replacing = options.pendingPolicy == .latestPending
      guard replacing || pendingCount < options.pendingLimit else {
        report(.droppedBudget, generation: source.generation, dropped: 1, possible: false); beginNext(); return
      }
      // Reserve the new item's overlap before relinquishing the old input.
      guard let copy = try? environment.serviceOperationStorage(requestBytes: input.bytes.count, responseBytes: 0) else {
        report(.droppedBudget, generation: source.generation, dropped: 1, possible: false); beginNext(); return
      }
      guard matches(input.header, source: source), !closed, !source.closed,
        (try? input.storage.check()) != nil else { return }
      guard replacing || pendingCount < options.pendingLimit else {
        report(.droppedBudget, generation: source.generation, dropped: 1, possible: false); beginNext(); return
      }
      let replacesCurrent = replacing && current != nil && !currentEntered && !currentRevoked
      if replacing {
        // Recheck publication eligibility after admission. An unpublished
        // candidate cannot evict eligible input, including queued work.
        let currentEligible = replacesCurrent && (current.map { eligible($0.source) } ?? false)
        guard eligible(source) || (!currentEligible && !pending.contains(where: { eligible($0.source) })) else {
          report(.droppedBudget, generation: source.generation, dropped: 1, possible: false); beginNext(); return
        }
      }
      let delivery = V4ControllerNotificationDelivery(input: input, source: source, storage: copy)
      if replacing {
        let replaced = pending
        pending.removeAll(keepingCapacity: true)
        pending.append(delivery)
        for old in replaced { report(.coalesced, generation: old.source.generation, dropped: 1, possible: false) }
        if replacesCurrent, let old = current {
          // The original task retains its source and input until onExit, even
          // when it has a running permit but has not entered the decoder.
          currentRevoked = true
          report(.coalesced, generation: old.source.generation, dropped: 1, possible: false)
          work?.cancel()
        }
        withExtendedLifetime(replaced) {}
      } else { pending.append(delivery) }
      beginNext()
    }
  }
  private func sourceClosed(_ source: V4ControllerNotificationSource, reason: ControllerNotificationGapReason = .sourceClosed) {
    gate.withLock {
      guard !source.closed else { return }; source.closed = true
      let revokeCurrent = current?.source === source && !currentEntered && !currentRevoked
      let count = pending.filter { $0.source === source }.count + (revokeCurrent ? 1 : 0)
      pending.removeAll { $0.source === source }
      if revokeCurrent { currentRevoked = true }
      report(reason, generation: source.generation, dropped: UInt64(count), possible: true)
      if !source.installing, let receiver = source.receiver, let registration = source.registration,
        let tail = try? source.storage.executionTail() {
        source.detaching = true
        let cleanupGate = gate
        Task { [weak self, source, receiver, tail, cleanupGate] in
          await receiver.uninstall(registration.token)
          cleanupGate.withLock { tail.release(); source.detaching = false; source.receiver = nil; self?.collectSources(); self?.collect() }
        }
      }
      if revokeCurrent { work?.cancel() }
      collectSources(); beginNext()
    }
  }
  private func collectSources() {
    sources.removeAll { source in source.closed && !source.installing && !source.detaching && source.timerTasks == 0 && current?.source !== source }
    wakeReleasedSourceSlot()
  }
  private func beginNext() {
    // The single prepaid timer position remains occupied until its task exits.
    guard !closed, work == nil, timers.isEmpty, let storage, let group else { return }
    // Drop expired or unauthorized input without holding a callback position.
    pending.removeAll { delivery in
      guard !delivery.source.closed else { return true }
      do {
        try delivery.source.check(); try delivery.storage.check()
        guard let interval = environment.clock.sample().interval,
          interval.upperMS < (try delivery.input.header.uint(5)) else { throw ServiceFailure.deadlineExceeded }
        return false
      } catch {
        report((error as? ServiceFailure) == .deadlineExceeded ? .expired : .sourceUnauthorized,
          generation: delivery.source.generation, dropped: 1, possible: true); return true
      }
    }
    let index = pending.firstIndex { eligible($0.source) }
    let chooseGap = gapPending && (index == nil || !lastWasGap)
    guard chooseGap || index != nil else { return }
    let delivery: V4ControllerNotificationDelivery?
    let gap: ControllerNotificationGap?
    if chooseGap { delivery = nil; gap = gapSnapshot(); gapPending = false }
    else { delivery = pending.remove(at: index!); gap = nil }
    current = delivery; currentEntered = false; currentRevoked = false; currentExpired = false
    delivery?.source.physicalCallbacks += 1
    let timerSource = delivery?.source
    let workTimerID = UUID()
    do {
      try storage.check()
      let tail = V4ServiceInputTail(try storage.executionTail())
      let timeoutTail = V4ServiceInputTail(try storage.executionTail())
      let original = try V4ApplicationWork(group: group, context: invocationContext, resident: options.resident,
        operation: { [self, delivery, gap, tail, timeoutTail, timerSource, workTimerID] context in
          defer { withExtendedLifetime(tail) {}; withExtendedLifetime(delivery) {} }
          var decoding = delivery != nil
          do {
            let privateInput = delivery.map { $0.input.bytes.withUnsafeBytes { Data($0) } }
            let captured = try gate.withLock { () -> ((@Sendable (ApplicationInvocationContext, ControllerNotificationEvent<Value>) async throws -> Void), (any MessageCodec<Value>)?) in
              guard !closed, !currentRevoked, let handler else { throw ServiceFailure.closed }
              return (handler, codec)
            }
            let enter: @Sendable () throws -> Void = { [self] in try gate.withLock {
              guard !closed, !currentRevoked else { throw ServiceFailure.closed }
              try context.checkCancellation(); try storage.check()
              if let delivery { try checkDelivery(delivery) }
              guard !currentEntered else { return }
              let timeout = options.applicationTimeoutMS
              timerSource?.timerTasks += 1
              let timer = Task { [self, timeoutTail, timerSource, workTimerID] in
                defer {
                  withExtendedLifetime(timeoutTail) {}
                  gate.withLock {
                    timerSource?.timerTasks -= 1
                    timers.removeValue(forKey: workTimerID)
                    collectSources()
                    if closed { collect() } else { beginNext() }
                  }
                }
                do { try await ContinuousClock().sleep(for: .milliseconds(Int64(timeout))) } catch { return }
                gate.withLock {
                  guard !closed, work != nil else { return }
                  currentExpired = true
                  report(.expired, generation: delivery?.source.generation ?? generation, dropped: 0, possible: false)
                  work?.cancel()
                }
              }
              timers[workTimerID] = timer
              currentEntered = true; lastWasGap = delivery == nil
            } }
            let event: ControllerNotificationEvent<Value>
            if let delivery {
              guard let codec = captured.1, let privateInput else { throw ServiceFailure.closed }
              let value = try await v4DecodeNotification(codec, source: privateInput, context: context, check: { [self] in
                try gate.withLock {
                  guard !currentRevoked else { throw ServiceFailure.closed }
                  try checkDelivery(delivery)
                }
              }, enter: enter)
              decoding = false
              let phase = try gate.withLock { () -> ControllerNotificationSourcePhase in
                try checkDelivery(delivery); try context.checkCancellation()
                return delivery.source.draining() ? .draining : delivery.source.phase
              }
              event = .notification(value: value, sourceGeneration: delivery.source.generation, sourcePhase: phase)
            } else if let gap { try enter(); event = .observationGap(gap) }
            else { throw ServiceFailure.closed }
            try gate.withLock {
              guard !closed else { throw ServiceFailure.closed }; try context.checkCancellation()
              if let delivery { try checkDelivery(delivery) }
              if delivered < .max { delivered += 1 }
            }
            try await captured.0(context, event)
          } catch {
            gate.withLock {
              if !closed, !currentExpired, !currentRevoked {
                report((error as? ServiceFailure) == .deadlineExceeded ? .expired : decoding ? .decodeError : .handlerError,
                  generation: delivery?.source.generation ?? generation, dropped: decoding ? 1 : 0, possible: false)
                // An entered gap callback is never retried because it threw.
                if delivery == nil { gapPending = false }
              }
            }
          }
        }, onExit: { [self, delivery, workTimerID] in
          delivery?.source.physicalCallbacks -= 1
          timers[workTimerID]?.cancel(); work = nil; current = nil
          currentEntered = false; currentRevoked = false; currentExpired = false; collectSources()
          if closed { collect() } else { beginNext() }
        })
      work = original; original.start()
    } catch {
      delivery?.source.physicalCallbacks -= 1
      current = nil
      if chooseGap { gapPending = true }
      else if let delivery { report(.droppedBudget, generation: delivery.source.generation, dropped: 1, possible: false) }
    }
  }
  private func checkDelivery(_ delivery: V4ControllerNotificationDelivery) throws {
    guard eligible(delivery.source), let storage else { throw ServiceFailure.closed }
    try delivery.source.check(); try storage.check(); try delivery.source.storage.check()
    try delivery.storage.check(); try delivery.input.storage.check()
    guard let interval = environment.clock.sample().interval,
      interval.upperMS < (try delivery.input.header.uint(5)) else { throw ServiceFailure.deadlineExceeded }
  }
  public func observationStatus() -> ControllerNotificationObservationStatus {
    gate.withLock { ControllerNotificationObservationStatus(delivered: delivered, pending: pendingCount,
      callbackActive: currentEntered, observedSources: sources.count,
      attachedToCurrent: sources.contains { $0.id == currentID && !$0.closed && !$0.installing && $0.published }, gap: gapSnapshot(), closed: closed) }
  }
  public func cleanupStatus() -> CleanupStatus {
    gate.withLock { CleanupStatus(complete: closed && work == nil && sources.isEmpty && sourceSlotTask == nil && timers.isEmpty, cleanupIncomplete: !closed || work != nil || !sources.isEmpty || sourceSlotTask != nil || !timers.isEmpty, pendingCallbacks: UInt64((work == nil ? 0 : 1) + timers.count + (sourceSlotTask == nil ? 0 : 1) + sources.filter { $0.detaching || $0.installing }.count)) }
  }
  public func waitClosed(_ options: NotificationWaitOptions = NotificationWaitOptions()) async throws -> CleanupStatus {
    guard options.timeout > .zero, options.timeout <= .seconds(5) else { throw ServiceFailure.configurationCapacity }
    let callDeadline = ContinuousClock.now.advanced(by: options.timeout)
    while true {
      try Task.checkCancellation()
      let value = cleanupStatus()
      if value.complete { return value }
      let dependency = gate.withLock { () -> Bool in
        guard let work = self.work, let context = options.context else { return false }
        return (try? work.hasDependency(context)) == true
      }
      if dependency { return CleanupStatus(complete: false, cleanupIncomplete: true, pendingCallbacks: value.pendingCallbacks) }
      let deadline = gate.withLock { closeDeadline.map { min($0, callDeadline) } ?? callDeadline }
      let now = ContinuousClock.now
      guard now < deadline else { return CleanupStatus(complete: false, cleanupIncomplete: true, pendingCallbacks: value.pendingCallbacks) }
      try await ContinuousClock().sleep(for: min(.milliseconds(20), deadline - now))
    }
  }
  public func close() {
    gate.withLock {
      guard !closed else { return }; closeDeadline = closeDeadline ?? ContinuousClock.now.advanced(by: .seconds(5)); closed = true; handler = nil; pending.removeAll(); gapPending = false
      sourceSlotWake = nil; sourceSlotTask?.cancel()
      for source in sources { sourceClosed(source) }
      timers.values.forEach { $0.cancel() }; work?.cancel(); collectSources(); collect()
    }
  }
  private func collect() { if closed, work == nil, sources.isEmpty, sourceSlotTask == nil, timers.isEmpty { storage = nil; codec = nil; contract = nil; group = nil } }
  deinit { close() }
}
