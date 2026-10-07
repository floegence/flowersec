import Foundation

public enum ServiceOfferRefresh: String, Sendable { case explicit, managed }
public struct ServiceContractSourceRequest: Sendable {
  public let namespace: String
  public let method: MethodDefinition
  public let target: ServiceBindingTarget
  public let known: ServiceContractSnapshot?
  public let wantedDigest: Data?
  public let deadlineAtMS: UInt64
}
/// Application sources run through the original ordinary invocation lane.
/// A returned advertisement never installs a route or authorizes a Start.
public protocol ServiceContractSource: Sendable {
  func snapshot(_ request: ServiceContractSourceRequest, session: any Session,
    context: ApplicationInvocationContext) async throws -> ServiceContractSnapshot
}
protocol V4FixedContractSource: ServiceContractSource {
  func sdkSnapshot(_ request: ServiceContractSourceRequest, session: any Session) async throws -> ServiceContractSnapshot
  func sdkSnapshot(_ request: ServiceContractSourceRequest, session: any Session,
    before: (@Sendable () throws -> Void)?) async throws -> ServiceContractSnapshot
}
extension V4FixedContractSource {
  func sdkSnapshot(_ request: ServiceContractSourceRequest, session: any Session,
    before: (@Sendable () throws -> Void)?) async throws -> ServiceContractSnapshot {
    try before?(); return try await sdkSnapshot(request, session: session)
  }
}
public struct PeerServiceContractSource: V4FixedContractSource {
  public let binding: ServiceContractQueryBinding
  public let maximumOfferWindowMS: UInt64
  public init(binding: ServiceContractQueryBinding, maximumOfferWindowMS: UInt64) throws {
    guard maximumOfferWindowMS > 0 else { throw ServiceFailure.configurationCapacity }
    self.binding = binding; self.maximumOfferWindowMS = maximumOfferWindowMS
  }
  func sdkSnapshot(_ request: ServiceContractSourceRequest, session: any Session) async throws -> ServiceContractSnapshot {
    try await sdkSnapshot(request, session: session, before: nil)
  }
  func sdkSnapshot(_ request: ServiceContractSourceRequest, session: any Session,
    before: (@Sendable () throws -> Void)?) async throws -> ServiceContractSnapshot {
    let selector = try ServiceContractQueryTarget(namespace: request.namespace, typeID: request.method.typeID,
      wantedDigest: request.wantedDigest, known: request.known, maximumOfferWindowMS: maximumOfferWindowMS)
    let result = try await session.v4QueryContracts([selector], target: request.target, binding: binding,
      deadlineAtMS: request.deadlineAtMS, before: before)
    guard let item = result.first, let snapshot = item.snapshot else {
      if result.first?.status == .denied { throw ServiceFailure.permissionDenied }
      throw ServiceFailure.serviceUnavailable
    }
    return snapshot
  }
  public func snapshot(_ request: ServiceContractSourceRequest, session: any Session,
    context: ApplicationInvocationContext) async throws -> ServiceContractSnapshot {
    try context.checkCancellation(); return try await sdkSnapshot(request, session: session)
  }
}
func v4AcquireContract(source: any ServiceContractSource, request: ServiceContractSourceRequest,
  session: any V4ServiceSession, context: ApplicationInvocationContext?,
  before: (@Sendable () throws -> Void)? = nil,
  position: V4ContractFetchPosition? = nil) async throws -> ServiceContractSnapshot {
  func check() throws {
    try session.serviceEnvironment.gate.withLock {
      try before?()
      try session.checkServiceAdmission(); try request.target.check(session.serviceIdentity)
      try Task.checkCancellation(); try context?.checkCancellation()
      guard let interval = session.serviceEnvironment.clock.sample().interval,
        interval.upperMS < request.deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
    }
  }
  try check()
  let snapshot: ServiceContractSnapshot
  if let fixed = source as? any V4FixedContractSource {
    if let peer = source as? PeerServiceContractSource {
      let selector = try ServiceContractQueryTarget(namespace: request.namespace, typeID: request.method.typeID,
        wantedDigest: request.wantedDigest, known: request.known, maximumOfferWindowMS: peer.maximumOfferWindowMS)
      let results = try await session.v4QueryContracts([selector], target: request.target, binding: peer.binding,
        deadlineAtMS: request.deadlineAtMS, before: before, position: position)
      guard let value = results.first?.snapshot else {
        throw results.first?.status == .denied ? ServiceFailure.permissionDenied : ServiceFailure.serviceUnavailable
      }
      snapshot = value
    } else {
      let originalPosition = try position ?? session.serviceEnvironment.serviceContracts().acquire(session: session)
      defer { withExtendedLifetime(originalPosition) {} }
      snapshot = try await fixed.sdkSnapshot(request, session: session, before: before)
    }
  }
  else {
    let environment = session.serviceEnvironment
    let originalPosition = try position ?? environment.serviceContracts().acquire(session: session)
    let storage = try environment.operationReferenceStorage()
    let tail = V4ServiceInputTail(try storage.executionTail())
    snapshot = try await environment.applicationGroup().invoke(context: context) { context in
      defer { withExtendedLifetime(tail) {}; withExtendedLifetime(originalPosition) {} }
      try environment.gate.withLock { try before?(); try session.checkServiceAdmission(); try request.target.check(session.serviceIdentity) }
      try context.checkCancellation()
      return try await source.snapshot(request, session: session, context: context)
    }
  }
  try check()
  return snapshot
}
extension Session {
  public func bindService(_ definition: ServiceDefinition, target: ServiceBindingTarget,
    contractSource: any ServiceContractSource, deadlineAtMS: UInt64, initialMethods: [MethodDefinition]? = nil, channelClass: ServiceRPCChannelClass = .interactive,
    acceptance: ContractAcceptance = .exact, offerRefresh: ServiceOfferRefresh = .explicit,
    streamBindings: [ServiceStreamBinding] = [], context: ApplicationInvocationContext? = nil) async throws -> ServiceClient {
    guard let session = self as? any V4ServiceSession else { throw ServiceFailure.serviceUnavailable }
    return try await v4BindService(session: session, definition: definition, target: target,
      source: contractSource, deadlineAtMS: deadlineAtMS, acceptance: acceptance,
      offerRefresh: offerRefresh, streamBindings: streamBindings, context: context, initialMethods: initialMethods, channelClass: channelClass)
  }
}

enum V4ControllerBindingFailure: Error { case superseded }

func v4BindService(session: any V4ServiceSession, definition: ServiceDefinition,
  target: ServiceBindingTarget, source: any ServiceContractSource, deadlineAtMS: UInt64,
  acceptance: ContractAcceptance, offerRefresh: ServiceOfferRefresh,
  streamBindings: [ServiceStreamBinding], context: ApplicationInvocationContext?,
  generation: V4ControllerServiceGeneration? = nil,
  previous: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)] = [], initialMethods: [MethodDefinition]? = nil,
  channelClass: ServiceRPCChannelClass = .interactive,
  prepaidStorage: V4CryptoReservation? = nil, registration prepaidRegistration: V4ServiceContractRegistration? = nil
) async throws -> ServiceClient {
  func check() throws {
    try session.serviceEnvironment.gate.withLock {
      if let generation, !generation.matches(session, generation: generation.generation) { throw V4ControllerBindingFailure.superseded }
      try session.checkServiceAdmission(); try target.check(session.serviceIdentity)
      try generation?.check(session); try Task.checkCancellation(); try context?.checkCancellation()
      guard let interval = session.serviceEnvironment.clock.sample().interval,
        interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
    }
  }
  try check()
  let storage = try prepaidStorage ?? session.serviceEnvironment.serviceBindingStorage(methods: definition.methods.count)
  let registration = try prepaidRegistration ?? session.serviceEnvironment.serviceContracts().reserve(definition)
  let selected = initialMethods ?? definition.methods.map(\.method)
  guard selected.allSatisfy(definition.contains), Set(selected.map(\.typeID)).count == selected.count else {
    throw ServiceFailure.configurationCapacity
  }
  let selectedEntries = definition.methods.filter { entry in selected.contains { $0 === entry.method } }
  var contracts: [ServiceContractSnapshot] = []; contracts.reserveCapacity(selectedEntries.count)
  var index = 0
  while index < selectedEntries.count {
    try check()
    let count = source is PeerServiceContractSource ? min(8, selectedEntries.count - index) : 1
    let entries = Array(selectedEntries[index..<(index + count)])
    let requests = entries.map { entry in
      let installed = previous.first { $0.0 === entry.method }
      let exact = installed?.2 ?? acceptance
      return ServiceContractSourceRequest(namespace: definition.namespace, method: entry.method, target: target,
        known: installed?.1, wantedDigest: exact.isExact ? installed?.1.contract.digest : nil, deadlineAtMS: deadlineAtMS)
    }
    let candidates: [ServiceContractSnapshot]
    if let peer = source as? PeerServiceContractSource {
      guard let interval = session.serviceEnvironment.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
      let (batchEnd, overflow) = interval.upperMS.addingReportingOverflow(min(2_000, peer.binding.maximumLifetimeMS))
      guard !overflow else { throw ServiceFailure.deadlineExceeded }
      let selectors = try requests.map { request in
        try ServiceContractQueryTarget(namespace: request.namespace, typeID: request.method.typeID,
          wantedDigest: request.wantedDigest, known: request.known, maximumOfferWindowMS: peer.maximumOfferWindowMS)
      }
      let position = try session.serviceEnvironment.serviceContracts().acquire(session: session)
      position.bindingRegistration = registration; position.bindingStorage = storage
      let results = try await session.v4QueryContracts(selectors, target: target, binding: peer.binding,
        deadlineAtMS: min(deadlineAtMS, batchEnd), before: {
          if let generation, !generation.matches(session, generation: generation.generation) {
            throw V4ControllerBindingFailure.superseded
          }
          try generation?.check(session)
        }, position: position)
      candidates = try results.map { item in
        guard let snapshot = item.snapshot else {
          throw item.status == .denied ? ServiceFailure.permissionDenied : ServiceFailure.serviceUnavailable
        }
        return snapshot
      }
    } else {
      let position = try session.serviceEnvironment.serviceContracts().acquire(session: session)
      position.bindingRegistration = registration; position.bindingStorage = storage
      let snapshot = try await v4AcquireContract(source: source, request: requests[0], session: session, context: context,
        before: {
          if let generation, !generation.matches(session, generation: generation.generation) {
            throw V4ControllerBindingFailure.superseded
          }
          try generation?.check(session)
        }, position: position)
      candidates = [snapshot]
    }
    try check()
    guard candidates.count == entries.count else { throw ServiceFailure.protocolFailure }
    for (entry, snapshot) in zip(entries, candidates) {
      let installed = previous.first { $0.0 === entry.method }
      try snapshot.contract.checkMethod(entry.method, in: definition)
      try snapshot.contract.checkPolicy(installed?.2 ?? acceptance, current: installed?.1.contract)
      contracts.append(snapshot)
    }
    index += count
  }
  let selectedChannel = try await session.openServiceChannel(channelClass, deadlineAtMS: deadlineAtMS)
  return try session.serviceEnvironment.gate.withLock {
    try check()
    let candidate = try ServiceClient(session: session, definition: definition, target: target, contracts: contracts,
      acceptance: acceptance, allowsPartialContracts: true, streamBindings: streamBindings, channel: selectedChannel, channelClass: channelClass, contractSource: source, offerRefresh: offerRefresh,
      prepaidStorage: storage, registration: registration)
    do {
      try candidate.inheritContractState(previous)
      if let generation { try candidate.attachControllerGeneration(generation) }
      try session.serviceEnvironment.serviceContracts().activate(candidate, deadlineAtMS: deadlineAtMS)
      return candidate
    } catch { candidate.close(); throw error }
  }
}

extension ServiceClient {
  public func refresh(_ method: MethodDefinition, deadlineAtMS: UInt64,
    context: ApplicationInvocationContext? = nil) async throws -> ServiceContractSnapshot {
    let captured = try gate.withLock { () -> ServiceContractSnapshot? in
      try checkPreparation()
      guard definition.contains(method), contractSource != nil else { throw ServiceFailure.serviceUnavailable }
      return snapshots[method.typeID]
    }
    let policy = try contractStateForReplacement().first { $0.0 === method }?.2
    if let captured, method.semantics != .execution && policy?.isExact == true { return captured }
    return try await environment.serviceContracts().refresh(self, method: method,
      deadlineAtMS: deadlineAtMS, context: context)
  }
  func operationSnapshot(_ method: MethodDefinition, options: ServiceCallOptions) async throws -> ServiceContractSnapshot {
    // Preparation only captures the locally verified snapshot. Renewal is an
    // original scheduler responsibility and never a hidden query on a Call.
    try gate.withLock { try checkPreparation(); return try contract(method) }
  }
}

/// A Controller binding selects the current Session before each preparation.
/// An existing prepared handle remains owned by the Session that created it.
public actor ControllerServiceClient {
  private var controller: ConnectionController?
  public let definition: ServiceDefinition
  public let target: ServiceBindingTarget
  private let source: any ServiceContractSource
  private let acceptance: ContractAcceptance
  private let offerRefresh: ServiceOfferRefresh
  private let streamBindings: [ServiceStreamBinding]
  private let requiredForDispatch: [MethodDefinition]
  private let workloads: [ServiceMethodWorkload]
  private let initialMethods: [MethodDefinition]?
  private let channelClass: ServiceRPCChannelClass
  private var serviceDeclaration: V4ControllerServiceDeclaration?
  private var bindingSlot: V4ControllerServiceBindingSlot?
  private var binding: ServiceClient? { serviceDeclaration?.binding ?? bindingSlot?.client }
  private var bindingGeneration: V4ControllerServiceGeneration?
  private var contractState: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)] = []
  private var acquiring = false
  private var acquisitionWaiters: [UUID: CheckedContinuation<Void, any Error>] = [:]
  init(controller: ConnectionController, definition: ServiceDefinition, target: ServiceBindingTarget,
    source: any ServiceContractSource, acceptance: ContractAcceptance, offerRefresh: ServiceOfferRefresh,
    streamBindings: [ServiceStreamBinding], requiredForDispatch: [MethodDefinition] = [],
    workloads: [ServiceMethodWorkload] = [], initialMethods: [MethodDefinition]? = nil, channelClass: ServiceRPCChannelClass = .interactive) {
    self.controller = controller; self.definition = definition; self.target = target; self.source = source
    self.acceptance = acceptance; self.offerRefresh = offerRefresh; self.streamBindings = streamBindings
    self.requiredForDispatch = requiredForDispatch; self.workloads = workloads
    self.initialMethods = initialMethods; self.channelClass = channelClass
  }
  private func waitForAcquisition() async throws {
    let token = UUID()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
        guard controller != nil else { continuation.resume(throwing: ServiceFailure.closed); return }
        guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
        guard acquiring else { continuation.resume(); return }
        guard acquisitionWaiters.count < 16 else { continuation.resume(throwing: ServiceFailure.resourceExhausted); return }
        acquisitionWaiters[token] = continuation
      }
    } onCancel: {
      Task { await self.cancelAcquisitionWaiter(token) }
    }
  }
  private func cancelAcquisitionWaiter(_ token: UUID) {
    acquisitionWaiters.removeValue(forKey: token)?.resume(throwing: CancellationError())
  }
  private func finishAcquisition() {
    acquiring = false
    let waiting = acquisitionWaiters; acquisitionWaiters.removeAll()
    for continuation in waiting.values { continuation.resume() }
  }
  func current(deadlineAtMS: UInt64, context: ApplicationInvocationContext?) async throws -> ServiceClient {
    var reselections = 0
    while true {
      try Task.checkCancellation(); try context?.checkCancellation()
      guard let controller else { throw ServiceFailure.closed }
      let selected = try await controller.captureServiceSelection()
      guard self.controller != nil else { throw ServiceFailure.closed }
      let session = selected.session
      try selected.generation.check(session)
      guard let interval = session.serviceEnvironment.clock.sample().interval,
        interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
      if let declaration = serviceDeclaration, declaration.generation === selected.generation,
        let current = declaration.binding { try current.checkPreparation(); return current }
      if let binding, bindingGeneration === selected.generation {
        try binding.checkPreparation(); return binding
      }
      if acquiring {
        // A source callback cannot recursively wait behind its own binding
        // acquisition while holding the parent's ordinary invocation permit.
        guard context == nil else { throw ApplicationInvocationFailure.dependencyUnavailable }
        try await waitForAcquisition(); continue
      }
      guard requiredForDispatch.allSatisfy(definition.contains), workloads.allSatisfy({ definition.contains($0.method) }),
        Set(requiredForDispatch.map(\.typeID)).count == requiredForDispatch.count,
        Set(workloads.map { $0.method.typeID }).count == workloads.count else { throw ServiceFailure.configurationCapacity }
      var recipes = workloads
      for method in requiredForDispatch where method.shape == .unary && !recipes.contains(where: { $0.method === method }) {
        recipes.append(try ServiceMethodWorkload(method: method))
      }
      let previous = try serviceDeclaration?.state().1 ?? contractState
      acquiring = true
      defer { finishAcquisition() }
      do {
        let candidate = try await v4BindService(session: session, definition: definition, target: target,
          source: source, deadlineAtMS: deadlineAtMS, acceptance: acceptance, offerRefresh: offerRefresh,
          streamBindings: streamBindings, context: context, generation: selected.generation, previous: previous,
          initialMethods: {
            let selected = definition.methods.map(\.method).filter { method in
              initialMethods?.contains { $0 === method } == true
                || requiredForDispatch.contains { $0 === method }
                || workloads.contains { $0.method === method }
            }
            return selected.isEmpty && initialMethods == nil && requiredForDispatch.isEmpty && workloads.isEmpty ? nil : selected
          }(), channelClass: channelClass)
        guard self.controller != nil else { candidate.close(); throw ServiceFailure.closed }
        do {
            var targets: [V4ServiceUnaryTarget] = []
            for recipe in recipes {
              for _ in 0..<recipe.calls {
                let target = try V4ServiceUnaryTarget(environment: candidate.environment, recipe: recipe)
                try await target.attach(candidate); targets.append(target)
              }
            }
            candidate.unaryTargets = targets
            try await candidate.prepareRequiredDependencies(requiredForDispatch, deadlineAtMS: deadlineAtMS)
            if serviceDeclaration == nil {
              let declaration = try V4ControllerServiceDeclaration(client: candidate, source: source,
                acceptance: acceptance, offerRefresh: offerRefresh, streamBindings: streamBindings,
                required: requiredForDispatch, workloads: recipes)
              try await controller.registerServiceDeclaration(declaration, generation: selected.generation)
              serviceDeclaration = declaration
            }
          } catch { candidate.close(); throw error }
        if Task.isCancelled || context?.isCancelled == true { candidate.close(); throw CancellationError() }
        do {
          try session.serviceEnvironment.gate.withLock {
            guard selected.generation.matches(session, generation: selected.generation.generation) else {
              throw V4ControllerBindingFailure.superseded
            }
            try candidate.checkPreparation()
            let installed = try candidate.contractStateForReplacement()
            // Every prepared operation keeps its original binding/Session.
            // Replacing this facade's alias must not Close that old binding.
            if let declaration = serviceDeclaration {
              try declaration.install(candidate, generation: selected.generation)
            } else { bindingSlot = try selected.generation.attach(candidate) }
            bindingGeneration = selected.generation; contractState = installed
          }
          return candidate
        } catch { candidate.close(); throw error }
      } catch {
        // Only a superseded local generation permits a fresh selection. A
        // source, target, contract or timeout failure is never hidden/replayed.
        if error is V4ControllerBindingFailure, self.controller != nil, reselections < 2 {
          reselections += 1; continue
        }
        if error is V4ControllerBindingFailure { throw ServiceFailure.serviceUnavailable }
        throw error
      }
    }
  }
  public func contract(_ method: MethodDefinition, deadlineAtMS: UInt64,
    context: ApplicationInvocationContext? = nil) async throws -> ServiceContractSnapshot {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: context)
    return try client.gate.withLock { try client.checkPreparation(); return try client.contract(method) }
  }
  public func refresh(_ method: MethodDefinition, deadlineAtMS: UInt64,
    context: ApplicationInvocationContext? = nil) async throws -> ServiceContractSnapshot {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: context)
    let result = try await client.refresh(method, deadlineAtMS: deadlineAtMS, context: context)
    if binding === client { contractState = try client.contractStateForReplacement() }
    return result
  }
  public func refresh(_ methods: [MethodDefinition], deadlineAtMS: UInt64,
    context: ApplicationInvocationContext? = nil) async throws -> [ServiceContractRefreshResult] {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: context)
    let results = try await client.refresh(methods, deadlineAtMS: deadlineAtMS, context: context)
    if binding === client { contractState = try client.contractStateForReplacement() }
    return results
  }
  public func updateContract(_ method: MethodDefinition, snapshot: ServiceContractSnapshot,
    acceptance: ContractAcceptance? = nil, deadlineAtMS: UInt64,
    context: ApplicationInvocationContext? = nil) async throws {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: context)
    try client.gate.withLock {
      try client.checkPreparation(); try Task.checkCancellation(); try context?.checkCancellation()
      try client.updateContract(method, snapshot: snapshot, acceptance: acceptance, explicitUpdate: true)
      if binding === client { contractState = try client.contractStateForReplacement() }
    }
  }
  public func prepareOperation<Request: Sendable, Response: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, responseCodec: any MessageCodec<Response>, options: ServiceCallOptions) async throws -> ServiceOperation<Response> {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    let operation = try await client.prepareOperation(method, request: request, requestCodec: requestCodec, responseCodec: responseCodec, options: options)
    do { if let serviceDeclaration { try operation.attachControllerRoute(serviceDeclaration) }; return operation }
    catch { operation.close(); throw error }
  }
  public func call<Request: Sendable, Response: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, responseCodec: any MessageCodec<Response>, options: ServiceCallOptions) async throws -> MessageReceived<Response> {
    let operation = try await prepareOperation(method, request: request, requestCodec: requestCodec,
      responseCodec: responseCodec, options: options)
    defer { operation.close() }
    try await operation.start(); return try await operation.takeResult(context: options.context)
  }
  public func stream<Request: Sendable, Item: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>, options: ServiceCallOptions) async throws -> ServiceStreamingOperation<Item> {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.stream(method, request: request, requestCodec: requestCodec, itemCodec: itemCodec, options: options)
  }
  public func notify<Request: Sendable>(_ method: MethodDefinition, request: Request,
    codec: any MessageCodec<Request>, options: ServiceCallOptions) async throws -> NotificationSendResult {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.notify(method, request: request, codec: codec, options: options)
  }
  public func prepareNotify<Request: Sendable>(_ method: MethodDefinition, request: Request,
    codec: any MessageCodec<Request>, options: ServiceCallOptions) async throws -> ServiceNotificationOperation {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareNotify(method, request: request, codec: codec, options: options)
  }
  public func prepareStream<Request: Sendable, Item: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>, options: ServiceCallOptions) async throws -> ServiceStreamingOperation<Item> {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareStream(method, request: request, requestCodec: requestCodec, itemCodec: itemCodec, options: options)
  }
  public func prepareAndSave<Request: Sendable, Response: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, responseCodec: any MessageCodec<Response>, store: any OperationReferenceStore,
    options: ServiceCallOptions) async throws -> PreparedAndSavedOperation<Response> {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareAndSave(method, request: request, requestCodec: requestCodec,
      responseCodec: responseCodec, store: store, options: options)
  }
  public func prepareNotifyAndSave<Request: Sendable>(_ method: MethodDefinition, request: Request,
    codec: any MessageCodec<Request>, store: any OperationReferenceStore,
    options: ServiceCallOptions) async throws -> PreparedAndSavedNotification {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareNotifyAndSave(method, request: request, codec: codec, store: store, options: options)
  }
  public func prepareStreamAndSave<Request: Sendable, Item: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>, store: any OperationReferenceStore,
    options: ServiceCallOptions) async throws -> PreparedAndSavedStream<Item> {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareStreamAndSave(method, request: request, requestCodec: requestCodec,
      itemCodec: itemCodec, store: store, options: options)
  }
  public func prepareContentRead<Request: Sendable, Response: Sendable>(_ method: MethodDefinition,
    reference: OperationReference, request: Request, requestCodec: any MessageCodec<Request>,
    responseCodec: any MessageCodec<Response>, options: ServiceCallOptions) async throws -> ServiceOperation<Response> {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareContentRead(method, reference: reference, request: request,
      requestCodec: requestCodec, responseCodec: responseCodec, options: options)
  }
  public func prepareResume(_ method: MethodDefinition, token: ApplicationCheckpointToken, target: ServiceResumeTarget,
    options: ServiceCallOptions) async throws -> ServiceResumeOperation {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try client.prepareResume(method, token: token, target: target, options: options)
  }
  public func prepareResumeAndSave(_ method: MethodDefinition, token: ApplicationCheckpointToken,
    target: ServiceResumeTarget, store: any OperationReferenceStore,
    options: ServiceCallOptions) async throws -> PreparedAndSavedResume {
    let client = try await current(deadlineAtMS: options.deadlineAtMS, context: options.context)
    return try await client.prepareResumeAndSave(method, token: token, target: target, store: store, options: options)
  }
  public func readOperationResult(_ reference: OperationReference, binding: OperationResultReadBinding,
    deadlineAtMS: UInt64) async throws -> OperationResultRead {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: nil)
    return try await client.readOperationResult(reference, binding: binding, deadlineAtMS: deadlineAtMS)
  }
  public func queryOperation(_ reference: OperationReference, deadlineAtMS: UInt64) async throws -> ExecutionManagementResult {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: nil)
    return try await client.queryOperation(reference, deadlineAtMS: deadlineAtMS)
  }
  public func requestCancel(_ reference: OperationReference, deadlineAtMS: UInt64) async throws -> ExecutionManagementResult {
    let client = try await current(deadlineAtMS: deadlineAtMS, context: nil)
    return try await client.requestCancel(reference, deadlineAtMS: deadlineAtMS)
  }
  public func close() {
    controller = nil
    bindingGeneration = nil; contractState.removeAll()
    binding?.close(); serviceDeclaration?.close(); serviceDeclaration = nil
    bindingSlot?.release(); bindingSlot = nil
    let waiting = acquisitionWaiters; acquisitionWaiters.removeAll()
    for continuation in waiting.values { continuation.resume(throwing: ServiceFailure.closed) }
  }
}
extension ConnectionController {
  /// Completes the initial contracts against the already published current
  /// generation within one caller deadline. This never starts the Controller.
  public func bindService(_ definition: ServiceDefinition, target: ServiceBindingTarget,
    contractSource: any ServiceContractSource, deadlineAtMS: UInt64,
    acceptance: ContractAcceptance = .exact, offerRefresh: ServiceOfferRefresh = .managed,
    streamBindings: [ServiceStreamBinding] = [], requiredForDispatch: [MethodDefinition] = [],
    workloads: [ServiceMethodWorkload] = [], initialMethods: [MethodDefinition]? = nil,
    channelClass: ServiceRPCChannelClass = .interactive, context: ApplicationInvocationContext? = nil) async throws -> ControllerServiceClient {
    let client = ControllerServiceClient(controller: self, definition: definition, target: target, source: contractSource,
      acceptance: acceptance, offerRefresh: offerRefresh, streamBindings: streamBindings,
      requiredForDispatch: requiredForDispatch, workloads: workloads, initialMethods: initialMethods, channelClass: channelClass)
    do { _ = try await client.current(deadlineAtMS: deadlineAtMS, context: context); return client }
    catch { await client.close(); throw error }
  }
  public func bindService(_ definition: ServiceDefinition, target: ServiceBindingTarget,
    contractSource: any ServiceContractSource, acceptance: ContractAcceptance = .exact,
    offerRefresh: ServiceOfferRefresh = .managed, streamBindings: [ServiceStreamBinding] = [],
    requiredForDispatch: [MethodDefinition] = [], workloads: [ServiceMethodWorkload] = [],
    initialMethods: [MethodDefinition]? = nil, channelClass: ServiceRPCChannelClass = .interactive) -> ControllerServiceClient {
    ControllerServiceClient(controller: self, definition: definition, target: target, source: contractSource,
      acceptance: acceptance, offerRefresh: offerRefresh, streamBindings: streamBindings,
      requiredForDispatch: requiredForDispatch, workloads: workloads, initialMethods: initialMethods, channelClass: channelClass)
  }
}
