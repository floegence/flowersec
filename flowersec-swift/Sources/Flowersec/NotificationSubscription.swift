import Foundation

public enum NotificationPendingPolicy: String, Sendable { case dropNewest = "drop_newest", latestPending = "latest_pending" }
public enum NotificationGap: String, Sendable { case droppedBudget = "dropped_budget", coalesced, decodeError = "decode_error", handlerError = "handler_error", expired, closed }
public struct NotificationObservationStatus: Sendable {
  public let delivered: UInt64
  public let dropped: UInt64
  public let lastGap: NotificationGap?
  public let pending: Int
  public let callbackActive: Bool
  public let closed: Bool
}
public struct NotificationWaitOptions: Sendable {
  public let timeout: Duration
  public let context: ApplicationInvocationContext?
  public init(timeout: Duration = .seconds(5), context: ApplicationInvocationContext? = nil) {
    self.timeout = timeout; self.context = context
  }
}

public struct NotificationSubscriptionOptions: Sendable {
  public let pendingPolicy: NotificationPendingPolicy
  public let pendingLimit: Int
  public let applicationBytes: UInt64
  public let applicationTimeoutMS: UInt64
  public let resident: Bool
  public init(pendingPolicy: NotificationPendingPolicy = .dropNewest, pendingLimit: Int = 16,
    applicationBytes: UInt64 = 65_536, applicationTimeoutMS: UInt64 = 30_000, resident: Bool = false) throws {
    guard (1...16).contains(pendingLimit), applicationBytes > 0, applicationBytes < 1 << 63,
      (1...120_000).contains(applicationTimeoutMS) else { throw ServiceFailure.configurationCapacity }
    self.pendingPolicy = pendingPolicy; self.pendingLimit = pendingLimit; self.applicationBytes = applicationBytes
    self.applicationTimeoutMS = applicationTimeoutMS; self.resident = resident
  }
}

final class V4NotificationInput: @unchecked Sendable {
  let header: V4ApplicationHeader
  let bytes: Data
  let storage: V4CryptoReservation
  init(header: V4ApplicationHeader, bytes: Data, storage: V4CryptoReservation) {
    self.header = header; self.bytes = bytes; self.storage = storage
  }
}
private struct V4NotificationDelivery: Sendable {
  let input: V4NotificationInput
  let storage: V4CryptoReservation
}
protocol V4NotificationRegistration: AnyObject, Sendable {
  var token: UUID { get }
  var typeID: UInt32 { get }
  var physicalPending: Int { get }
  var businessPending: Int { get }
  func matches(_ header: V4ApplicationHeader) -> Bool
  func deliver(_ input: V4NotificationInput)
  func recordGap(_ reason: NotificationGap)
  func close()
}

/// A serial observation registration. Its counters remain readable after
/// close, and a canceled callback retains its input until its real return.
public final class ServiceNotificationSubscription<Value: Sendable>: V4NotificationRegistration, @unchecked Sendable {
  let token = UUID()
  let typeID: UInt32
  private let gate: NSRecursiveLock
  private var contract: ServiceContract?
  private var codec: (any MessageCodec<Value>)?
  private let options: NotificationSubscriptionOptions
  private let invocationContext: ApplicationInvocationContext?
  private var group: V4ApplicationGroup?
  private var storage: V4CryptoReservation?
  private var checkSource: (@Sendable () throws -> Void)?
  private var handler: (@Sendable (ApplicationInvocationContext, Value) async throws -> Void)?
  private var released: (@Sendable () -> Void)?
  private var pending: [V4NotificationDelivery] = []
  private var current: V4NotificationDelivery?
  private var currentEntered = false
  private var currentRevoked = false
  private var work: V4ApplicationWork?
  private var timers: [UUID: Task<Void, Never>] = [:]
  private var closed = false
  private var closeDeadline: ContinuousClock.Instant?
  private var currentExpired = false
  private var delivered: UInt64 = 0
  private var dropped: UInt64 = 0
  private var gap: NotificationGap?
  init(client: ServiceClient, method: MethodDefinition, contract: ServiceContract, codec: any MessageCodec<Value>,
    options: NotificationSubscriptionOptions, context: ApplicationInvocationContext?, released: @escaping @Sendable () -> Void,
    handler: @escaping @Sendable (ApplicationInvocationContext, Value) async throws -> Void) throws {
    typeID = method.typeID; self.contract = contract; self.codec = try v4ServiceCaptureRequestCodec(codec); self.options = options; invocationContext = context
    gate = client.environment.gate; group = client.group; self.handler = handler; self.released = released
    checkSource = { [weak client] in guard let client else { throw ServiceFailure.closed }; try client.check() }
    storage = try client.environment.notificationSubscriptionStorage(applicationBytes: options.applicationBytes)
    pending.reserveCapacity(options.pendingLimit)
  }
  func matches(_ header: V4ApplicationHeader) -> Bool {
    gate.withLock {
      guard !closed, let contract, let codec, header.kind == "observation_notify",
        (try? header.typeID) == typeID, (try? header.bytes(6)) == contract.digest else { return false }
      do {
        try checkSource?()
        let bytes = try header.payloadBytes
        guard bytes <= codec.definition.maxMessageBytes, UInt64(bytes) <= (try contract.uint(23)),
          let interval = storage?.environment.clock.sample().interval else { return false }
        let deadline = try header.uint(5)
        return try interval.upperMS < deadline && deadline - interval.lowerMS <= contract.uint(11)
      } catch { return false }
    }
  }
  func recordGap(_ reason: NotificationGap) { gate.withLock { if !closed { report(reason) } } }
  private func report(_ reason: NotificationGap) {
    if dropped < .max { dropped += 1 }; gap = reason
    if reason == .droppedBudget || reason == .coalesced || reason == .expired {
      storage?.environment.root.diagnosticCounters.increment(.slowConsumers)
    }
  }
  private var pendingCount: Int {
    pending.count + (current != nil && !currentEntered && !currentRevoked ? 1 : 0)
  }
  func deliver(_ input: V4NotificationInput) {
    gate.withLock {
      guard matches(input.header), !closed, let storage,
        input.storage.environment === storage.environment else { return }
      let replacing = options.pendingPolicy == .latestPending
      guard replacing || pendingCount < options.pendingLimit else { report(.droppedBudget); return }
      // Acquire the overlap charge while the original pending item is still
      // retained. A failed admission must leave its dispatch right intact.
      guard let copyStorage = try? input.storage.environment.serviceOperationStorage(requestBytes: input.bytes.count, responseBytes: 0) else {
        report(.droppedBudget); return
      }
      guard matches(input.header), !closed,
        (try? storage.check()) != nil, (try? input.storage.check()) != nil else { return }
      guard replacing || pendingCount < options.pendingLimit else { report(.droppedBudget); return }
      let delivery = V4NotificationDelivery(input: input, storage: copyStorage)
      if replacing {
        let replaced = pending
        pending.removeAll(keepingCapacity: true)
        pending.append(delivery)
        for _ in replaced { report(.coalesced) }
        if current != nil, !currentEntered, !currentRevoked {
          // Selection by the executor is not application input delivery.
          // Keep any selected task's old input charged until its real exit.
          currentRevoked = true; report(.coalesced); work?.cancel()
        }
        withExtendedLifetime(replaced) {}
      } else { pending.append(delivery) }
      beginNext()
    }
  }
  private func beginNext() {
    // Reuse the prepaid timer position only after the canceled task exits.
    guard !closed, work == nil, current == nil, timers.isEmpty, !pending.isEmpty, let storage, let group, let codec else { return }
    let delivery = pending.removeFirst(); let input = delivery.input
    do {
      try storage.check()
      let tail = V4ServiceInputTail(try storage.executionTail())
      current = delivery; currentEntered = false; currentRevoked = false; currentExpired = false
      let timeoutTail = V4ServiceInputTail(try storage.executionTail())
      let workTimerID = UUID()
      let original = try V4ApplicationWork(group: group, context: invocationContext, resident: options.resident, operation: { [self, input, delivery, tail, timeoutTail, workTimerID] context in
        defer { withExtendedLifetime(input) {}; withExtendedLifetime(delivery) {}; withExtendedLifetime(tail) {} }
        var decoding = true
        do {
          // Each decoder owns a private mutable copy. The immutable channel
          // body may be shared, but cannot become another observer's scratch.
          let privateInput = input.bytes.withUnsafeBytes { Data($0) }
          let enter: @Sendable () throws -> Void = { [self] in try gate.withLock {
            guard !currentRevoked, handler != nil, let original = work else { throw ServiceFailure.closed }
            try checkDelivery(delivery); try context.checkCancellation()
            guard !currentEntered else { return }
            let timeoutMS = options.applicationTimeoutMS
            let timer = Task { [self, original, timeoutTail, workTimerID] in
              defer {
                withExtendedLifetime(timeoutTail) {}
                gate.withLock {
                  timers.removeValue(forKey: workTimerID)
                  if closed { collect() } else { beginNext() }
                }
              }
              do { try await ContinuousClock().sleep(for: .milliseconds(Int64(timeoutMS))) } catch { return }
              gate.withLock {
                guard !closed, current != nil else { return }
                currentExpired = true; report(.expired); original.cancel()
              }
            }
            timers[workTimerID] = timer
            currentEntered = true
            if delivered < .max { delivered += 1 }
          } }
          let value = try await v4DecodeNotification(codec, source: privateInput, context: context, check: { [self] in
            try gate.withLock {
              guard !currentRevoked else { throw ServiceFailure.closed }
              try checkDelivery(delivery)
            }
          }, enter: enter)
          decoding = false
          let callback = try gate.withLock { () -> (@Sendable (ApplicationInvocationContext, Value) async throws -> Void) in
            try checkDelivery(delivery); try context.checkCancellation()
            guard let handler else { throw ServiceFailure.closed }; return handler
          }
          try await callback(context, value)
        } catch {
          gate.withLock {
            if !closed, !currentExpired, !currentRevoked {
              report((error as? ServiceFailure) == .deadlineExceeded ? .expired : decoding ? .decodeError : .handlerError)
            }
          }
        }
      }, onExit: { [self, workTimerID] in
        timers[workTimerID]?.cancel(); work = nil; current = nil
        currentEntered = false; currentRevoked = false; currentExpired = false
        if closed { collect() } else { beginNext() }
      })
      work = original
      original.start()
    } catch {
      current = nil; report(.droppedBudget)
      if !pending.isEmpty { beginNext() }
    }
  }
  private func checkDelivery(_ delivery: V4NotificationDelivery) throws {
    guard !closed, let storage, let checkSource else { throw ServiceFailure.closed }
    try checkSource(); try storage.check(); try delivery.storage.check(); try delivery.input.storage.check()
    guard let interval = delivery.input.storage.environment.clock.sample().interval,
      interval.upperMS < (try delivery.input.header.uint(5)) else { throw ServiceFailure.deadlineExceeded }
  }
  public func observationStatus() -> NotificationObservationStatus {
    gate.withLock { NotificationObservationStatus(delivered: delivered, dropped: dropped, lastGap: gap,
      pending: pendingCount, callbackActive: currentEntered, closed: closed) }
  }
  var physicalPending: Int { gate.withLock { (current == nil ? 0 : 1) + timers.count } }
  var businessPending: Int { gate.withLock { pending.count + (current == nil ? 0 : 1) } }
  public func cleanupStatus() -> CleanupStatus {
    gate.withLock { CleanupStatus(complete: closed && current == nil && timers.isEmpty, cleanupIncomplete: !closed || current != nil || !timers.isEmpty,
      pendingCallbacks: UInt64((current == nil ? 0 : 1) + timers.count)) }
  }
  public func waitClosed(_ options: NotificationWaitOptions = NotificationWaitOptions()) async throws -> CleanupStatus {
    guard options.timeout > .zero, options.timeout <= .seconds(5) else { throw ServiceFailure.configurationCapacity }
    let callDeadline = ContinuousClock.now.advanced(by: options.timeout)
    while true {
      try Task.checkCancellation()
      let status = cleanupStatus()
      if status.complete { return status }
      let dependency = gate.withLock { () -> Bool in
        guard let work = self.work, let context = options.context else { return false }
        return (try? work.hasDependency(context)) == true
      }
      if dependency { return CleanupStatus(complete: false, cleanupIncomplete: true, pendingCallbacks: status.pendingCallbacks) }
      let deadline = gate.withLock { closeDeadline.map { min($0, callDeadline) } ?? callDeadline }
      let now = ContinuousClock.now
      guard now < deadline else { return CleanupStatus(complete: false, cleanupIncomplete: true, pendingCallbacks: status.pendingCallbacks) }
      try await ContinuousClock().sleep(for: min(.milliseconds(20), deadline - now))
    }
  }
  public func close() {
    gate.withLock {
      guard !closed else { return }; closeDeadline = closeDeadline ?? ContinuousClock.now.advanced(by: .seconds(5)); closed = true
      pending.removeAll(); checkSource = nil; handler = nil
      timers.values.forEach { $0.cancel() }; work?.cancel(); collect()
    }
  }
  private func collect() {
    guard closed, current == nil, timers.isEmpty else { return }
    storage = nil; contract = nil; codec = nil; group = nil; let original = released; released = nil; original?()
  }
  deinit { close() }
}

/// A prepaid receiver owns each original frame and full-input fanout. It never
/// waits for an observer, and no notification produces an ACK or response.
actor V4NotificationReceiver {
  private let environment: V4EnvironmentFoundation
  private let registry: V4ApplicationWireRegistry
  private let gate: NSRecursiveLock
  private var storage: V4CryptoReservation?
  private var registrations: [UUID: any V4NotificationRegistration] = [:]
  private var retiredRegistrations: [any V4NotificationRegistration] = []
  private var cleanupStorage: V4CryptoReservation?
  private var physicalWorkers = 0
  var businessPending: Int {
    collectRetiredSource()
    let callbacks = retiredRegistrations.reduce(0) { $0 + $1.businessPending }
      + registrations.values.reduce(0) { $0 + $1.businessPending }
    return serverPending + callbacks + (assembly == nil ? 0 : 1)
  }
  var physicalPending: Int {
    collectRetiredSource()
    retiredRegistrations.removeAll { $0.physicalPending == 0 }
    let callbacks = retiredRegistrations.reduce(0) { $0 + $1.physicalPending }
      + registrations.values.reduce(0) { $0 + $1.physicalPending }
    let pending = physicalWorkers + serverPending + callbacks + (retiredSource == nil ? 0 : 1)
    if closed && pending == 0 { cleanupStorage = nil }
    return pending
  }
  private var server: (any V4ServiceInboundDispatcher)?
  private var serverPending = 0
  private var source: (any V4RPCTransport)?
  private var retiredSource: (any V4RPCTransport)?
  private var reader: Task<Void, Never>?
  private var timer: Task<Void, Never>?
  private var assembly: ContinuousClock.Instant?
  private var closed = false
  private func collectRetiredSource() {
    guard physicalWorkers == 0 else { return }
    #if os(macOS) || os(iOS)
    if let original = retiredSource as? V4NativeByteStream, !original.rpcCleanupComplete { return }
    #endif
    retiredSource = nil
  }
  var acceptsChannel: Bool {
    collectRetiredSource()
    return !closed && source == nil && physicalWorkers == 0 && retiredSource == nil
  }
  init(environment: V4EnvironmentFoundation, storage: V4CryptoReservation) throws {
    self.environment = environment; self.storage = storage; gate = environment.gate
    registry = try V4ApplicationWireRegistry(); registrations.reserveCapacity(128)
  }
  func subscribe<Value: Sendable>(client: ServiceClient, method: MethodDefinition, codec: any MessageCodec<Value>,
    options: NotificationSubscriptionOptions, context: ApplicationInvocationContext?,
    handler: @escaping @Sendable (ApplicationInvocationContext, Value) async throws -> Void) throws -> ServiceNotificationSubscription<Value> {
    guard !closed, registrations.count + retainedRegistrationCount() < 128,
      registrationCount(typeID: method.typeID) < 32 else { throw ServiceFailure.resourceExhausted }
    let snapshot = try client.contract(method)
    guard method.shape == .notify, method.semantics == .observation,
      codec.definition == method.options.request else { throw ServiceFailure.contractMismatch }
    let token = UUID()
    let subscription = try ServiceNotificationSubscription(client: client, method: method, contract: snapshot.contract,
      codec: codec, options: options, context: context, released: { [weak self, weak client] in
        client?.release(token)
        Task { await self?.remove(token) }
      }, handler: handler)
    registrations[token] = subscription
    do { try client.ownNotification(token: token, close: { [weak subscription] in subscription?.close() }) }
    catch { registrations.removeValue(forKey: token); subscription.close(); throw error }
    return subscription
  }
  func bindServer(_ server: any V4ServiceInboundDispatcher) { if !closed { self.server = server } }
  func install(_ registration: any V4NotificationRegistration) throws {
    guard !closed, registrations[registration.token] == nil, registrations.count + retainedRegistrationCount() < 128,
      registrationCount(typeID: registration.typeID) < 32 else { throw ServiceFailure.resourceExhausted }
    try storage?.check(); registrations[registration.token] = registration
  }
  private func retainedRegistrationCount() -> Int {
    retiredRegistrations.removeAll { $0.physicalPending == 0 }
    return retiredRegistrations.count
  }
  private func registrationCount(typeID: UInt32) -> Int {
    _ = retainedRegistrationCount()
    return registrations.values.filter { $0.typeID == typeID }.count
      + retiredRegistrations.filter { $0.typeID == typeID }.count
  }
  private func retainPhysicalTail(_ registration: any V4NotificationRegistration) {
    _ = retainedRegistrationCount()
    if registration.physicalPending > 0,
      !retiredRegistrations.contains(where: { $0.token == registration.token }) {
      retiredRegistrations.append(registration)
    }
  }
  func uninstall(_ token: UUID) {
    guard let registration = registrations.removeValue(forKey: token) else { return }
    registration.close()
    retainPhysicalTail(registration)
  }
  private func remove(_ token: UUID) {
    guard let registration = registrations.removeValue(forKey: token) else { return }
    retainPhysicalTail(registration)
  }
  func accept(_ stream: any V4RPCTransport) async {
    guard acceptsChannel, let storage else { try? await stream.close(); return }
    source = stream
    let tail: V4ResourceReference
    let timerTail: V4ResourceReference
    do {
      tail = try storage.executionTail()
      do { timerTail = try storage.executionTail() }
      catch { tail.release(); throw error }
    }
    catch { await close(); return }
    physicalWorkers += 2
    timer = Task { [self] in
      defer { timerTail.release(); physicalWorkers -= 1; collectRetiredSource() }
      while !closed, !Task.isCancelled {
        if let assembly, ContinuousClock.now >= assembly.advanced(by: .seconds(30)) { await close(); return }
        do { try await ContinuousClock().sleep(for: .milliseconds(20)) } catch { return }
      }
    }
    reader = Task { [self] in
      defer { tail.release(); physicalWorkers -= 1; collectRetiredSource() }
      do { try await receive(stream) } catch { }
      await closeInput()
    }
  }
  private func exact(_ count: Int, stream: any V4RPCTransport, firstPrefix: Bool = false) async throws -> Data? {
    var result = Data(); result.reserveCapacity(count)
    while result.count < count {
      guard !closed else { throw ServiceFailure.closed }
      try storage?.check()
      guard let bytes = try await stream.read(maxBytes: count - result.count) else {
        guard result.isEmpty, firstPrefix else { throw ServiceFailure.protocolFailure }; return nil
      }
      guard !closed else { throw ServiceFailure.closed }
      guard !bytes.isEmpty, bytes.count <= count - result.count else { throw ServiceFailure.protocolFailure }
      if firstPrefix, result.isEmpty { assembly = .now }
      result += bytes
    }
    return result
  }
  private func receive(_ stream: any V4RPCTransport) async throws {
    while !closed {
      guard let prefix = try await exact(2, stream: stream, firstPrefix: true) else { return }
      let length = prefix.reduce(0) { $0 << 8 | Int($1) }
      guard (1...512).contains(length), let encoded = try await exact(length, stream: stream) else { throw ServiceFailure.protocolFailure }
      let header = try V4ApplicationHeader(encoded: encoded, registry: registry)
      guard ["observation_notify", "execution_notify"].contains(header.kind) else { throw ServiceFailure.protocolFailure }
      let count = try header.payloadBytes
      let recipients = registrations.values.filter { $0.matches(header) }
      let inputStorage: V4CryptoReservation?
      // Execution notifications have no observation fanout, but their
      // original server dispatch still owns the complete request body.
      let serverPosition: V4ServiceServerPosition?
      if let server, let storage, serverPending < 16 {
        do { serverPosition = try server.reserveNotification(header, storage: storage) }
        catch { serverPosition = nil }
      }
      else { serverPosition = nil }
      let serverNeedsInput = serverPosition != nil
      if recipients.isEmpty && !serverNeedsInput { inputStorage = nil }
      else { inputStorage = try? environment.serviceOperationStorage(requestBytes: count, responseBytes: 0) }
      var payload = Data()
      if inputStorage != nil { payload.reserveCapacity(count) }
      var offset = 0
      while offset < count {
        guard let chunk = try await exact(min(count - offset, 16_384), stream: stream) else { throw ServiceFailure.protocolFailure }
        offset += chunk.count; if inputStorage != nil { payload += chunk }
      }
      assembly = nil
      if let server, let serverPosition, inputStorage != nil, serverPending < 16,
        header.kind == "observation_notify" || header.kind == "execution_notify" {
        do {
          try server.checkHeader(header)
          if let inputStorage {
            let tail = try inputStorage.executionTail(); serverPending += 1
            Task { [self, server, header, payload, inputStorage, serverPosition, tail] in
              defer { tail.release(); withExtendedLifetime(inputStorage) {}; withExtendedLifetime(serverPosition) {} }
              await server.receiveNotification(header: header, payload: payload, position: serverPosition); serverPending -= 1
            }
          }
        } catch { }
      }
      guard header.kind == "observation_notify" else { continue }
      let completeRecipients = registrations.values.filter { $0.matches(header) }
      guard let interval = environment.clock.sample().interval,
        interval.upperMS < (try header.uint(5)) else {
        for recipient in recipients { recipient.recordGap(.expired) }
        continue
      }
      guard let inputStorage else {
        for recipient in completeRecipients { recipient.recordGap(.droppedBudget) }
        continue
      }
      try inputStorage.check()
      let input = V4NotificationInput(header: header, bytes: payload, storage: inputStorage)
      // Snapshot only at the complete-input boundary; later subscriptions
      // cannot receive this original event through a replay path.
      for registration in completeRecipients { registration.deliver(input) }
    }
  }
  private func closeInput() async {
    reader = nil; timer?.cancel(); timer = nil; assembly = nil
    let original = source; source = nil
    if let original { retiredSource = original; try? await original.close() }
  }
  func close() async {
    guard !closed else { return }; closed = true
    reader?.cancel(); timer?.cancel()
    for registration in registrations.values {
      registration.close()
      retainPhysicalTail(registration)
    }
    registrations.removeAll(); server = nil; await closeInput(); storage?.seal(); cleanupStorage = storage; storage = nil
    collectRetiredSource()
  }
}

extension ServiceClient {
  func ownNotification(token: UUID, close: @escaping @Sendable () -> Void) throws {
    try gate.withLock {
      try check(); guard operations.count < 1024 else { throw ServiceFailure.resourceExhausted }; operations[token] = close
    }
  }
  public func subscribe<Value: Sendable>(_ method: MethodDefinition, codec: any MessageCodec<Value>,
    options: NotificationSubscriptionOptions, context: ApplicationInvocationContext? = nil,
    handler: @escaping @Sendable (ApplicationInvocationContext, Value) async throws -> Void) async throws -> ServiceNotificationSubscription<Value> {
    try check()
    guard let receiver = session.serviceNotificationReceiver else { throw ServiceFailure.serviceUnavailable }
    return try await receiver.subscribe(client: self, method: method, codec: codec, options: options, context: context, handler: handler)
  }
}
