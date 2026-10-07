import Foundation

/// A physical fetching position. RPC publication, input, decoding and custom
/// sources borrow this same object; cancellation never returns its position.
final class V4ContractFetchPosition: @unchecked Sendable {
  let coordinator: V4ServiceContractCoordinator
  let session: any V4ServiceSession
  let protected: Bool
  var storage: V4CryptoReservation?
  var rpcStorage: V4CryptoReservation?
  var queryOwner: V4ApplicationQueryOwner?
  var bindingRegistration: V4ServiceContractRegistration?
  var bindingStorage: V4CryptoReservation?

  init(coordinator: V4ServiceContractCoordinator, session: any V4ServiceSession,
    protected: Bool, storage: V4CryptoReservation? = nil,
    rpcStorage: V4CryptoReservation? = nil, queryOwner: V4ApplicationQueryOwner? = nil) {
    self.coordinator = coordinator; self.session = session; self.protected = protected
    self.storage = storage; self.rpcStorage = rpcStorage; self.queryOwner = queryOwner
  }
  deinit { coordinator.returnPosition(session: session, protected: protected) }
}

/// All public service roots, including fixed old Sessions, own independent
/// method positions until their original binding and descendants disappear.
final class V4ServiceContractRegistration: @unchecked Sendable {
  let coordinator: V4ServiceContractCoordinator
  let token: UUID
  init(coordinator: V4ServiceContractCoordinator, token: UUID) {
    self.coordinator = coordinator; self.token = token
  }
  func stopRenewal() { coordinator.stopRenewal(token) }
  func attach(_ client: ServiceClient) throws { try coordinator.attach(token, client: client) }
  deinit { coordinator.remove(token) }
}

/// One original Environment scheduler owns the finite method table, one timer
/// and bounded physical workers. Future renewal protection does not launch a query.
final class V4ServiceContractCoordinator: @unchecked Sendable {
  private final class Method: @unchecked Sendable {
    weak var client: ServiceClient?
    let token: UUID
    let definition: MethodDefinition
    let order: UInt64
    var renewing = false
    var requested = false
    var selected = false
    var deadline: UInt64?
    var retryAt: UInt64 = 0
    var context: ApplicationInvocationContext?
    var waiters: [UUID: Waiter] = [:]
    init(token: UUID, definition: MethodDefinition, order: UInt64) {
      self.token = token; self.definition = definition; self.order = order
    }
  }
  private struct Waiter {
    let deadline: UInt64
    let deliver: @Sendable (Result<ServiceContractSnapshot, any Error>) -> Void
  }
  private struct Root {
    let token: UUID
    let count: Int
    var methods: [Method]
  }
  private struct Fetch: Sendable {
    let item: Method
    let client: ServiceClient
    let source: any ServiceContractSource
    let captured: ServiceContractSnapshot?
    let exact: Bool
    let wantedDigest: Data?
  }
  private struct Protection {
    let storage: V4CryptoReservation
    let rpcStorage: V4CryptoReservation
    let owner: V4ApplicationQueryOwner
  }
  private weak var environment: V4EnvironmentFoundation?
  private let gate: NSRecursiveLock
  private let maximumMethods: Int
  private let maximumFetches: Int
  private var storage: V4CryptoReservation?
  private var roots: [Root] = []
  private var running: [ObjectIdentifier: Int] = [:]
  private var ordinary = 0
  private var protectedRunning = false
  private var protection: Protection?
  private var timer: Task<Void, Never>?
  private var workers: [UUID: Task<Void, Never>] = [:]
  private var workerCount = 0
  private var protectedWorkerActive = false
  private var closed = false
  private var order: UInt64 = 0
  private var rotation: UInt64 = 0

  init(environment: V4EnvironmentFoundation, storage: V4CryptoReservation) {
    self.environment = environment; self.storage = storage; gate = environment.gate
    maximumMethods = environment.applicationResources == .constrained ? 16 : 256
    maximumFetches = environment.applicationResources == .constrained ? 2 : 4
    roots.reserveCapacity(64); running.reserveCapacity(64)
  }
  func reserve(_ definition: ServiceDefinition) throws -> V4ServiceContractRegistration {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      try storage?.check()
      guard roots.count < 64,
        roots.reduce(0, { $0 + $1.count }) + definition.methods.count <= maximumMethods else {
        throw ServiceFailure.resourceExhausted
      }
      let token = UUID()
      var methods: [Method] = []
      for entry in definition.methods {
        guard order < UInt64.max else { throw ServiceFailure.resourceExhausted }
        order += 1
        methods.append(Method(token: token, definition: entry.method, order: order))
      }
      roots.append(Root(token: token, count: methods.count, methods: methods))
      return V4ServiceContractRegistration(coordinator: self, token: token)
    }
  }
  fileprivate func attach(_ token: UUID, client: ServiceClient) throws {
    try gate.withLock {
      guard !closed, let root = roots.first(where: { $0.token == token }),
        root.methods.count == client.definition.methods.count,
        root.methods.allSatisfy({ $0.client == nil }) else { throw ServiceFailure.serviceUnavailable }
      for (item, entry) in zip(root.methods, client.definition.methods) {
        guard item.definition === entry.method else { throw ServiceFailure.contractMismatch }
        item.client = client
      }
    }
  }
  private var methods: [Method] { roots.flatMap(\.methods) }
  private var renewing: [Method] { methods.filter { $0.renewing && $0.client != nil } }
  private func protects(_ session: any V4ServiceSession) -> Bool {
    renewing.contains { $0.client?.session === session }
  }
  func acquire(session: any V4ServiceSession, protected: Bool = false) throws -> V4ContractFetchPosition {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      try storage?.check(); try session.checkServiceAdmission()
      let key = ObjectIdentifier(session)
      let count = running[key, default: 0]
      if protected {
        guard !protectedRunning, ordinary < maximumFetches, count < 2, let protection else {
          throw ServiceFailure.resourceExhausted
        }
        try protection.storage.check(); try protection.rpcStorage.check()
        protectedRunning = true; running[key] = count + 1
        return V4ContractFetchPosition(coordinator: self, session: session, protected: true,
          storage: protection.storage, rpcStorage: protection.rpcStorage, queryOwner: protection.owner)
      }
      let total = ordinary + (protectedRunning ? 1 : 0)
      let ordinaryLimit = maximumFetches - (renewing.isEmpty ? 0 : 1)
      guard ordinary < ordinaryLimit, total < maximumFetches,
        count < (protects(session) ? 1 : 2) else { throw ServiceFailure.resourceExhausted }
      ordinary += 1; running[key] = count + 1
      return V4ContractFetchPosition(coordinator: self, session: session, protected: false)
    }
  }
  fileprivate func returnPosition(session: any V4ServiceSession, protected: Bool) {
    gate.withLock {
      let key = ObjectIdentifier(session)
      if let count = running[key] {
        if count == 1 { running.removeValue(forKey: key) } else { running[key] = count - 1 }
      }
      if protected { protectedRunning = false } else { ordinary -= 1 }
      collectProtection()
    }
  }
  private func peer(_ source: any ServiceContractSource) -> PeerServiceContractSource? {
    source as? PeerServiceContractSource
  }
  private func sameGroup(_ a: ServiceClient, _ b: ServiceClient) -> Bool {
    guard a.session === b.session, a.target == b.target,
      let first = a.contractSource, let second = b.contractSource,
      let x = peer(first), let y = peer(second) else { return false }
    return x.binding.typeID == y.binding.typeID && x.binding.contractDigest == y.binding.contractDigest &&
      x.binding.maximumLifetimeMS == y.binding.maximumLifetimeMS && x.maximumOfferWindowMS == y.maximumOfferWindowMS
  }
  /// Count actual legal batches, including distinct bindings and duplicate
  /// selectors that cannot coexist in a single wire request.
  private func batches(_ items: [Method]) -> Int {
    var groups: [[Method]] = []
    for item in items {
      guard let client = item.client else { continue }
      if let index = groups.firstIndex(where: { group in
        guard group.count < 8, let first = group.first?.client, sameGroup(first, client) else { return false }
        return !group.contains { $0.client?.definition.namespace == client.definition.namespace &&
          $0.definition.typeID == item.definition.typeID }
      }) { groups[index].append(item) }
      else { groups.append([item]) }
    }
    return groups.count
  }
  private func qualification(_ items: [Method]) -> (advance: UInt64, deadline: UInt64, remaining: UInt64) {
    let required = UInt64(74_000 + batches(items) * 2_000)
    let advance = required + 30_000
    return (advance, required + 20_000, max(300_000, 2 * advance))
  }
  func activate(_ client: ServiceClient, deadlineAtMS: UInt64, first: (MethodDefinition, ServiceContractSnapshot)? = nil) throws {
    try gate.withLock {
      try client.checkPreparation()
      guard client.offerRefresh == .managed, client.contractSource != nil else { return }
      guard let root = roots.first(where: { $0.methods.first?.client === client }) else {
        throw ServiceFailure.serviceUnavailable
      }
      let added = root.methods.filter { $0.definition.semantics == .execution && !$0.renewing && (client.snapshots[$0.definition.typeID] != nil || first?.0 === $0.definition) }
      guard !added.isEmpty else { return }
      guard let environment, let time = environment.clock.sample().interval,
        time.upperMS < deadlineAtMS, client.session.serviceChannel != nil else {
        throw ServiceFailure.deadlineExceeded
      }
      let responsibilities = renewing + added
      let plan = qualification(responsibilities)
      for method in responsibilities {
        guard let binding = method.client,
          let snapshot = (binding === client && first?.0 === method.definition) ? first?.1 : binding.snapshots[method.definition.typeID],
          let offer = snapshot.offer, offer.notBeforeMS <= time.lowerMS, offer.notAfterMS > time.upperMS,
          offer.notAfterMS - time.upperMS >= plan.remaining else { throw ServiceFailure.admissionWindowClosed }
      }
      // This ordering never withdraws an admitted ordinary query. A full pool
      // refuses publication in the original Bind deadline instead.
      guard ordinary <= maximumFetches - 1,
        running[ObjectIdentifier(client.session), default: 0] <= 1 else { throw ServiceFailure.resourceExhausted }
      if protection == nil {
        let group = try environment.applicationGroup()
        let queryStorage = try environment.serviceQueryStorage(responseBytes: 8 * 9216)
        let rpcStorage = try environment.serviceOperationStorage(requestBytes: 2048, responseBytes: 8 * 9216)
        let owner = try group.executor.reserveQueryOwner(group: group)
        protection = Protection(storage: queryStorage, rpcStorage: rpcStorage, owner: owner)
      }
      for item in added { item.renewing = true }
      startTimer()
    }
  }
  func snapshotChanged(_ client: ServiceClient, method: MethodDefinition,
    candidate: ServiceContractSnapshot) throws {
    try gate.withLock {
      guard let item = methods.first(where: { $0.client === client && $0.definition === method }), item.renewing else { return }
      guard let environment, let interval = environment.clock.sample().interval,
        let offer = candidate.offer, offer.notAfterMS > interval.upperMS,
        offer.notAfterMS - interval.upperMS >= qualification(renewing).remaining,
        offer.notBeforeMS <= interval.lowerMS else { throw ServiceFailure.admissionWindowClosed }
      if let previous = client.snapshots[method.typeID]?.offer {
        guard offer.notBeforeMS <= previous.notAfterMS else { throw ServiceFailure.admissionWindowClosed }
      }
    }
  }
  func refresh(_ client: ServiceClient, method: MethodDefinition, deadlineAtMS: UInt64,
    context: ApplicationInvocationContext?) async throws -> ServiceContractSnapshot {
    let results = try await refresh(client, methods: [method], deadlineAtMS: deadlineAtMS, context: context)
    guard let first = results.first else { throw ServiceFailure.protocolFailure }
    return try first.get()
  }
  func refresh(_ client: ServiceClient, methods requested: [MethodDefinition], deadlineAtMS: UInt64,
    context: ApplicationInvocationContext?) async throws -> [Result<ServiceContractSnapshot, any Error>] {
    guard (1...8).contains(requested.count), Set(requested.map(\.typeID)).count == requested.count else {
      throw ServiceFailure.configurationCapacity
    }
    let token = UUID(), batch = V4ContractRefreshWaiter(count: requested.count, gate: gate)
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        gate.withLock {
          do {
            try client.checkPreparation(); try Task.checkCancellation(); try context?.checkCancellation()
            guard let environment, let interval = environment.clock.sample().interval,
              interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
            let items = try requested.map { method -> Method in
              guard let item = methods.first(where: { $0.client === client && $0.definition === method }),
                item.waiters.count < 16 else { throw ServiceFailure.resourceExhausted }
              if item.selected && context != nil { throw ApplicationInvocationFailure.dependencyUnavailable }
              return item
            }
            guard methods.reduce(0, { $0 + $1.waiters.count }) + items.count <= 64 else {
              throw ServiceFailure.resourceExhausted
            }
            // Resolve every throwing lookup before installing any waiter.
            let immediate = try items.map { item -> ServiceContractSnapshot? in
              if try item.definition.semantics != .execution && client.contractPolicy(item.definition).isExact {
                return client.snapshots[item.definition.typeID]
              }
              return nil
            }
            guard batch.attach(continuation) else { return }
            for (index, item) in items.enumerated() {
              if let snapshot = immediate[index] {
                batch.deliver(index: index, result: .success(snapshot)); continue
              }
              if !item.requested && !item.selected {
                item.requested = true; item.deadline = deadlineAtMS
                item.context = item.renewing ? nil : context
              }
              item.waiters[token] = Waiter(deadline: deadlineAtMS, deliver: { result in batch.deliver(index: index, result: result) })
            }
            startTimer()
          } catch { batch.fail(error, continuation: continuation) }
        }
      }
    } onCancel: {
      self.gate.withLock {
        for item in self.methods where item.waiters[token] != nil {
          item.waiters.removeValue(forKey: token)
          if item.waiters.isEmpty && !item.selected { item.requested = false; item.deadline = nil; item.context = nil }
        }
        batch.cancel()
      }
    }
  }
  private func startTimer() {
    guard timer == nil, !closed, let storage else { return }
    let tail: V4ResourceReference
    do { tail = try storage.executionTail() } catch { return }
    timer = Task { [self] in
      defer { tail.release() }
      while !Task.isCancelled {
        let keep = gate.withLock { tick() }
        guard keep else { break }
        do { try await Task.sleep(for: .milliseconds(100)) } catch { break }
      }
      gate.withLock {
        timer = nil; collectProtection()
        if !closed && (!renewing.isEmpty || methods.contains(where: { $0.requested })) { startTimer() }
      }
    }
  }
  private func tick() -> Bool {
    guard !closed, let environment else { return false }
    let interval = environment.clock.sample().interval
    for method in methods {
      for (token, waiter) in Array(method.waiters) {
        if interval == nil || interval!.upperMS >= waiter.deadline {
          method.waiters.removeValue(forKey: token)?.deliver(.failure(ServiceFailure.deadlineExceeded))
        }
      }
      if !method.selected && method.waiters.isEmpty && method.requested {
        method.requested = false; method.deadline = nil; method.context = nil
      }
    }
    guard workerCount < maximumFetches, let interval else {
      return workerCount > 0 || !renewing.isEmpty || methods.contains { $0.requested }
    }
    let plan = qualification(renewing)
    let eligible = methods.filter { item in
      guard !item.selected, let client = item.client else { return false }
      if item.renewing && (protectedWorkerActive || protectedRunning) { return false }
      if !item.renewing && workerCount - (protectedWorkerActive ? 1 : 0) >= maximumFetches - (renewing.isEmpty ? 0 : 1) { return false }
      if item.requested { return true }
      guard item.renewing, interval.upperMS >= item.retryAt,
        let offer = client.snapshots[item.definition.typeID]?.offer else { return false }
      return offer.notAfterMS <= interval.upperMS || offer.notAfterMS - interval.upperMS <= plan.advance
    }.sorted { a, b in
      if a.renewing != b.renewing { return a.renewing }
      let x = a.client?.snapshots[a.definition.typeID]?.offer?.notAfterMS ?? UInt64.max
      let y = b.client?.snapshots[b.definition.typeID]?.offer?.notAfterMS ?? UInt64.max
      if x != y { return x < y }
      let ar = a.order > rotation, br = b.order > rotation
      return ar != br ? ar : a.order < b.order
    }
    guard let first = eligible.first, let client = first.client else {
      return workerCount > 0 || !renewing.isEmpty || methods.contains { $0.requested }
    }
    var selected = [first]
    if let source = client.contractSource, peer(source) != nil {
      for item in eligible.dropFirst() where selected.count < 8 {
        guard let next = item.client, sameGroup(client, next), item.renewing == first.renewing,
          !selected.contains(where: { $0.client?.definition.namespace == next.definition.namespace &&
            $0.definition.typeID == item.definition.typeID }) else { continue }
        selected.append(item)
      }
    }
    var fetches: [Fetch] = []
    for item in selected {
      guard let client = item.client, let source = client.contractSource else { continue }
      let captured = client.snapshots[item.definition.typeID]
      item.selected = true
      if item.deadline == nil {
        let (deadline, overflow) = interval.upperMS.addingReportingOverflow(plan.deadline)
        item.deadline = overflow ? UInt64.max : deadline
      }
      let exact = item.definition.semantics == .execution || (try? client.contractPolicy(item.definition).isExact) == true
      fetches.append(Fetch(item: item, client: client, source: source, captured: captured, exact: exact, wantedDigest: exact ? client.firstSnapshotDigest(item.definition) : nil))
    }
    guard !fetches.isEmpty, let storage else { return !renewing.isEmpty }
    do {
      let tail = try storage.executionTail()
      workerCount += 1
      let protected = first.renewing
      if protected { protectedWorkerActive = true }
      let original = fetches, token = UUID()
      workers[token] = Task { [self] in
        defer { tail.release() }
        await run(original)
        gate.withLock {
          workerCount -= 1; workers.removeValue(forKey: token)
          if protected { protectedWorkerActive = false }
          collectProtection()
        }
      }
    } catch {
      for fetch in fetches { finish(fetch, result: .failure(error)) }
    }
    return true
  }
  private func run(_ fetches: [Fetch]) async {
    guard let first = fetches.first else { return }
    do {
      let deadline = gate.withLock { fetches.compactMap { $0.item.deadline }.min() ?? 0 }
      let position = try acquire(session: first.client.session, protected: first.item.renewing)
      defer { withExtendedLifetime(position) {} }
      let candidates: [Result<ServiceContractSnapshot, any Error>]
      if let source = peer(first.source) {
        let selectors = try fetches.map { fetch in
          try ServiceContractQueryTarget(namespace: fetch.client.definition.namespace,
            typeID: fetch.item.definition.typeID, wantedDigest: fetch.wantedDigest,
            known: fetch.captured, maximumOfferWindowMS: source.maximumOfferWindowMS)
        }
        guard let environment, let interval = environment.clock.sample().interval else {
          throw ServiceFailure.serviceUnavailable
        }
        let (batchEnd, overflow) = interval.upperMS.addingReportingOverflow(min(2_000, source.binding.maximumLifetimeMS))
        guard !overflow else { throw ServiceFailure.deadlineExceeded }
        let results = try await first.client.session.v4QueryContracts(selectors, target: first.client.target,
          binding: source.binding, deadlineAtMS: min(deadline, batchEnd), before: {
            // Each original method retains its own publication eligibility.
            // A closed member does not invalidate unrelated members of a batch.
            guard fetches.contains(where: { fetch in
              do {
                if fetch.item.renewing { try fetch.client.checkAdmission() }
                else { try fetch.client.checkPreparation() }
                return true
              } catch { return false }
            }) else {
              throw ServiceFailure.closed
            }
          }, position: position)
        candidates = results.map { item in
          if let snapshot = item.snapshot { return .success(snapshot) }
          return .failure(item.status == .denied ? ServiceFailure.permissionDenied : ServiceFailure.serviceUnavailable)
        }
      } else {
        guard let interval = environment?.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
        let (batchEnd, overflow) = interval.upperMS.addingReportingOverflow(2_000)
        guard !overflow else { throw ServiceFailure.deadlineExceeded }
        let request = ServiceContractSourceRequest(namespace: first.client.definition.namespace,
          method: first.item.definition, target: first.client.target, known: first.captured,
          wantedDigest: first.wantedDigest, deadlineAtMS: min(deadline, batchEnd))
        candidates = [.success(try await v4AcquireContract(source: first.source, request: request,
          session: first.client.session, context: first.item.context,
          before: {
            if first.item.renewing { try first.client.checkAdmission() }
            else { try first.client.checkPreparation() }
          }, position: position))]
      }
      gate.withLock {
        for (index, fetch) in fetches.enumerated() {
          do {
            if fetch.item.renewing { try fetch.client.checkAdmission() }
            else { try fetch.client.checkPreparation() }
            try fetch.item.context?.checkCancellation()
            guard fetch.item.renewing || !fetch.item.waiters.isEmpty else { throw CancellationError() }
            guard let environment, let interval = environment.clock.sample().interval,
              interval.upperMS < (fetch.item.deadline ?? 0), index < candidates.count else {
              throw ServiceFailure.deadlineExceeded
            }
            let candidate = try candidates[index].get()
            let current = fetch.client.snapshots[fetch.item.definition.typeID]
            if current == nil && fetch.captured == nil {
              try fetch.client.installFirstSnapshot(fetch.item.definition, snapshot: candidate, deadlineAtMS: fetch.item.deadline ?? 0)
            } else if current?.contract === fetch.captured?.contract &&
              current?.offer?.notBeforeMS == fetch.captured?.offer?.notBeforeMS &&
              current?.offer?.notAfterMS == fetch.captured?.offer?.notAfterMS {
              if fetch.exact && candidate.contract.digest != fetch.captured?.contract.digest { throw ServiceFailure.contractMismatch }
              if fetch.item.renewing { try fetch.client.installRenewedOffer(fetch.item.definition, snapshot: candidate) }
              else { try fetch.client.updateContract(fetch.item.definition, snapshot: candidate, explicitUpdate: false) }
            }
            finish(fetch, result: .success(try fetch.client.contract(fetch.item.definition)))
          } catch { finish(fetch, result: .failure(error)) }
        }
      }
    } catch { gate.withLock { for fetch in fetches { finish(fetch, result: .failure(error)) } } }
  }
  private func finish(_ fetch: Fetch, result: Result<ServiceContractSnapshot, any Error>) {
    let item = fetch.item
    item.selected = false; item.requested = false; item.deadline = nil; item.context = nil
    rotation = item.order
    if let now = environment?.clock.sample().interval?.upperMS {
      let (next, overflow) = now.addingReportingOverflow(5_000)
      item.retryAt = overflow ? UInt64.max : next
    }
    let waiting = item.waiters; item.waiters.removeAll()
    for waiter in waiting.values { waiter.deliver(result) }
  }
  fileprivate func stopRenewal(_ token: UUID) {
    gate.withLock {
      guard let root = roots.first(where: { $0.token == token }) else { return }
      for item in root.methods {
        item.renewing = false
        let waiting = item.waiters; item.waiters.removeAll()
        for waiter in waiting.values { waiter.deliver(.failure(ServiceFailure.closed)) }
        if !item.selected { item.requested = false; item.context = nil; item.deadline = nil }
      }
      collectProtection()
    }
  }
  fileprivate func remove(_ token: UUID) {
    gate.withLock { stopRenewal(token); roots.removeAll { $0.token == token }; collectProtection() }
  }
  private func collectProtection() {
    guard renewing.isEmpty, !protectedRunning, !protectedWorkerActive else { return }
    protection = nil
  }
  func close() {
    gate.withLock {
      guard !closed else { return }; closed = true
      for root in roots { stopRenewal(root.token) }
      timer?.cancel(); for worker in workers.values { worker.cancel() }
      collectProtection(); storage = nil
    }
  }
}

private final class V4ContractRefreshWaiter: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private var results: [Result<ServiceContractSnapshot, any Error>?]
  private var continuation: CheckedContinuation<[Result<ServiceContractSnapshot, any Error>], any Error>?
  private var canceled = false
  private var completed = false
  init(count: Int, gate: NSRecursiveLock) {
    results = Array(repeating: nil, count: count); self.gate = gate
  }
  func attach(_ continuation: CheckedContinuation<[Result<ServiceContractSnapshot, any Error>], any Error>) -> Bool {
    guard !canceled else { completed = true; continuation.resume(throwing: CancellationError()); return false }
    self.continuation = continuation; return true
  }
  func deliver(index: Int, result: Result<ServiceContractSnapshot, any Error>) {
    gate.withLock {
      guard !completed, !canceled, results.indices.contains(index), results[index] == nil else { return }
      results[index] = result
      if results.allSatisfy({ $0 != nil }) {
        completed = true; let waiting = continuation; continuation = nil
        waiting?.resume(returning: results.compactMap { $0 })
      }
    }
  }
  func fail(_ error: any Error,
    continuation: CheckedContinuation<[Result<ServiceContractSnapshot, any Error>], any Error>) {
    guard !completed else { return }; completed = true; self.continuation = nil
    continuation.resume(throwing: error)
  }
  func cancel() {
    guard !completed else { return }; canceled = true
    if let continuation { completed = true; self.continuation = nil; continuation.resume(throwing: CancellationError()) }
  }
}

public struct ServiceContractRefreshResult: Sendable {
  public let method: MethodDefinition
  public let result: Result<ServiceContractSnapshot, any Error>
}

extension ServiceClient {
  /// All batches share one original deadline; per-method success is retained
  /// when another source selector is refused or unavailable.
  public func refresh(_ methods: [MethodDefinition], deadlineAtMS: UInt64,
    context: ApplicationInvocationContext? = nil) async throws -> [ServiceContractRefreshResult] {
    try gate.withLock {
      try checkPreparation()
      guard !methods.isEmpty, methods.count <= definition.methods.count,
        methods.allSatisfy(definition.contains), Set(methods.map(\.typeID)).count == methods.count else {
        throw ServiceFailure.configurationCapacity
      }
    }
    var results: [ServiceContractRefreshResult] = []; results.reserveCapacity(methods.count)
    var index = 0
    while index < methods.count {
      try Task.checkCancellation(); try context?.checkCancellation()
      let batch = Array(methods[index..<min(index + 8, methods.count)])
      do {
        let snapshots = try await environment.serviceContracts().refresh(self, methods: batch,
          deadlineAtMS: deadlineAtMS, context: context)
        for (method, snapshot) in zip(batch, snapshots) { results.append(ServiceContractRefreshResult(method: method, result: snapshot)) }
      } catch {
        if error is CancellationError { throw error }
        for method in batch { results.append(ServiceContractRefreshResult(method: method, result: .failure(error))) }
      }
      index += batch.count
    }
    return results
  }
}
