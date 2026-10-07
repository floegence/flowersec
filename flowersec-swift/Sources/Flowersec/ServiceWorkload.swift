import Foundation

/// A finite local promise for simultaneous unary preparations. Each call owns
/// its request, response, RPC position, completion descriptor and physical tails.
public struct ServiceMethodWorkload: Sendable {
  public let method: MethodDefinition
  public let calls: Int
  public let requestBytes: Int
  public let responseBytes: Int
  public init(method: MethodDefinition, calls: Int = 1, requestBytes: Int? = nil,
    responseBytes: Int? = nil) throws {
    let request = requestBytes ?? method.options.requestMaxBytes
    let response = responseBytes ?? method.options.maxResponseBytes
    guard method.shape == .unary, (1...64).contains(calls),
      (0...method.options.requestMaxBytes).contains(request),
      (method.options.minResponseLimitBytes...method.options.maxResponseBytes).contains(response) else {
      throw ServiceFailure.configurationCapacity
    }
    self.method = method; self.calls = calls; self.requestBytes = request; self.responseBytes = response
  }
}

/// A single exclusive target is prepaid before candidate connection acquisition.
/// It becomes reusable only when every borrowed preparation/RPC/decoder exits.
final class V4ServiceUnaryTarget: @unchecked Sendable {
  let recipe: ServiceMethodWorkload
  let storage: V4CryptoReservation
  let rpcStorage: V4CryptoReservation
  let descriptor: V4ResourceReference
  let completion: V4CompletionReservation
  let encoder: V4OrdinaryReservation
  private let physicalStorage: V4ResourceReference
  private let physicalRPC: V4ResourceReference
  let gate: NSRecursiveLock
  private weak var client: ServiceClient?
  private var channel: V4RPCChannel?
  private var position: UInt64?
  private var sessionPosition: V4RPCSessionPosition?
  private var occupied = false
  private var sealed = false
  init(environment: V4EnvironmentFoundation, recipe: ServiceMethodWorkload) throws {
    self.recipe = recipe; gate = environment.gate
    storage = try environment.serviceOperationStorage(requestBytes: recipe.requestBytes, responseBytes: recipe.responseBytes)
    rpcStorage = try environment.serviceOperationStorage(requestBytes: recipe.requestBytes, responseBytes: recipe.responseBytes)
    let group = try environment.applicationGroup()
    encoder = try group.executor.reserveOrdinaryPosition(group: group)
    descriptor = try group.reserveCompletion(bytes: recipe.responseBytes)
    do {
      completion = try group.executor.reserveCompletionPosition(group: group)
      let bodyTail = try storage.executionTail()
      do { physicalRPC = try rpcStorage.executionTail() }
      catch { bodyTail.release(); throw error }
      physicalStorage = bodyTail
    } catch { descriptor.release(); throw error }
  }
  func attach(_ client: ServiceClient) async throws {
    let reserved = try await client.channel.reserveDedicatedRequest()
    do {
      let original = try await client.channel.dedicatedRequestOwner(reserved)
      try gate.withLock {
        guard !sealed, self.client == nil, storage.environment === client.environment else { throw ServiceFailure.closed }
        try client.checkAdmission(); try storage.check(); try rpcStorage.check()
        self.client = client; channel = client.channel; position = reserved; sessionPosition = original
      }
    } catch { await client.channel.releaseDedicatedRequest(reserved); throw error }
  }
  func claim(_ client: ServiceClient, method: MethodDefinition, requestBytes: Int,
    responseBytes: Int) throws -> V4ServiceUnaryClaim {
    try claim(client, method: method, requestBytes: requestBytes, responseBytes: responseBytes, allowUnbound: false)
  }
  private func claim(_ client: ServiceClient, method: MethodDefinition, requestBytes: Int,
    responseBytes: Int, allowUnbound: Bool) throws -> V4ServiceUnaryClaim {
    try gate.withLock {
      guard !sealed, !occupied, self.client === client, recipe.method === method,
        requestBytes <= recipe.requestBytes, responseBytes <= recipe.responseBytes,
        let channel, sessionPosition != nil, allowUnbound || position != nil else { throw ServiceFailure.resourceExhausted }
      try client.checkAdmission(); try storage.check(); try rpcStorage.check(); try descriptor.check(); try encoder.check()
      let binding = try client.bindingTail()
      occupied = true
      return V4ServiceUnaryClaim(target: self, binding: binding, channel: channel, position: position)
    }
  }
  func claim(_ client: ServiceClient, method: MethodDefinition, requestBytes: Int,
    responseBytes: Int, on selected: V4RPCChannel) async throws -> V4ServiceUnaryClaim {
    let claim = try claim(client, method: method, requestBytes: requestBytes,
      responseBytes: responseBytes, allowUnbound: true)
    if claim.channel === selected, claim.rpcPosition != nil { return claim }
    let original = try gate.withLock { () -> V4RPCSessionPosition in
      guard let original = sessionPosition, original.engine === selected.sessionEngine else {
        throw ServiceFailure.serviceUnavailable
      }
      return original
    }
    // This exclusive claim proves every earlier user of the prepaid workload
    // has physically exited. Keep its same Session K owner across the move.
    let oldPosition = gate.withLock { () -> UInt64? in defer { position = nil }; return position }
    if let oldPosition { await claim.channel.releaseDedicatedRequest(oldPosition) }
    try Task.checkCancellation(); try client.checkPreparation()
    let replacement = try await selected.reserveDedicatedRequest(using: original)
    do {
      try Task.checkCancellation()
      try gate.withLock {
        guard !sealed, self.client === client else { throw ServiceFailure.closed }
        try client.checkPreparation()
        channel = selected; position = replacement
        claim.bind(channel: selected, position: replacement)
      }
      return claim
    } catch { await selected.releaseDedicatedRequest(replacement); throw error }
  }
  func check(_ client: ServiceClient) throws {
    try gate.withLock {
      guard !sealed, self.client === client, position != nil else { throw ServiceFailure.serviceUnavailable }
      try storage.check(); try rpcStorage.check(); try descriptor.check(); try encoder.check(); try client.checkPreparation()
    }
  }
  var rpcPosition: UInt64? { gate.withLock { position } }
  fileprivate func returnClaim() { gate.withLock { occupied = false } }
  func seal() {
    gate.withLock { sealed = true }
  }
  deinit {
    descriptor.release(); physicalStorage.release(); physicalRPC.release()
    if let channel, let position { Task { await channel.releaseDedicatedRequest(position) } }
  }
}

final class V4ServiceUnaryClaim: @unchecked Sendable {
  let target: V4ServiceUnaryTarget
  let binding: V4ServiceBindingTail
  private var selectedChannel: V4RPCChannel
  private var selectedPosition: UInt64?
  var channel: V4RPCChannel { target.gate.withLock { selectedChannel } }
  var rpcPosition: UInt64? { target.gate.withLock { selectedPosition } }
  init(target: V4ServiceUnaryTarget, binding: V4ServiceBindingTail, channel: V4RPCChannel, position: UInt64?) {
    self.target = target; self.binding = binding; selectedChannel = channel; selectedPosition = position
  }
  fileprivate func bind(channel: V4RPCChannel, position: UInt64) {
    target.gate.withLock { selectedChannel = channel; selectedPosition = position }
  }
  deinit { target.returnClaim() }
}

/// A facade's exact lineage is an original gate capability, never a digest or
/// namespace match. Only its atomically published target can supply reselection.
final class V4ControllerServiceDeclaration: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  let definition: ServiceDefinition
  let target: ServiceBindingTarget
  let source: any ServiceContractSource
  let acceptance: ContractAcceptance
  let offerRefresh: ServiceOfferRefresh
  let streamBindings: [ServiceStreamBinding]
  let required: [MethodDefinition]
  let workloads: [ServiceMethodWorkload]
  private(set) var revision: UInt64 = 0
  private(set) var active = true
  private var slot: V4ControllerServiceBindingSlot?
  private var currentGeneration: V4ControllerServiceGeneration?
  private var installed: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)] = []
  init(client: ServiceClient, source: any ServiceContractSource, acceptance: ContractAcceptance,
    offerRefresh: ServiceOfferRefresh, streamBindings: [ServiceStreamBinding],
    required: [MethodDefinition], workloads: [ServiceMethodWorkload]) throws {
    environment = client.environment; definition = client.definition; target = client.target
    self.source = source; self.acceptance = acceptance; self.offerRefresh = offerRefresh
    self.streamBindings = streamBindings; self.required = required; self.workloads = workloads
    guard required.allSatisfy(definition.contains), workloads.allSatisfy({ definition.contains($0.method) }),
      Set(required.map(\.typeID)).count == required.count,
      Set(workloads.map { $0.method.typeID }).count == workloads.count else { throw ServiceFailure.configurationCapacity }
    installed = try client.contractStateForReplacement()
  }
  var needsCandidate: Bool { environment.gate.withLock { active && (!required.isEmpty || !workloads.isEmpty) } }
  var binding: ServiceClient? { environment.gate.withLock { slot?.client } }
  func isInstalled(_ client: ServiceClient) -> Bool { environment.gate.withLock { active && slot?.client === client } }
  var generation: V4ControllerServiceGeneration? { environment.gate.withLock { currentGeneration } }
  func state() throws -> (UInt64, [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)]) {
    try environment.gate.withLock {
      guard active else { throw ServiceFailure.closed }; return (revision, installed)
    }
  }
  func checkRevision(_ expected: UInt64) throws {
    try environment.gate.withLock {
      guard active, revision < UInt64.max, revision == expected else { throw ServiceFailure.serviceUnavailable }
    }
  }
  func checkInstallation(_ client: ServiceClient) throws {
    try environment.gate.withLock {
      guard active, revision < UInt64.max, slot?.client === client else { throw ServiceFailure.serviceUnavailable }
    }
  }
  func prepareUpdate(_ client: ServiceClient, method: MethodDefinition,
    snapshot: ServiceContractSnapshot, policy: ContractAcceptance) throws ->
    [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)] {
    try environment.gate.withLock {
      try checkInstallation(client)
      let previous = try client.contractStateForReplacement()
      guard definition.contains(method) else { throw ServiceFailure.contractMismatch }
      var next = previous.map { entry in entry.0 === method ? (method, snapshot, policy) : entry }
      if !previous.contains(where: { $0.0 === method }) { next.append((method, snapshot, policy)) }
      return next
    }
  }
  func publishUpdate(_ state: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)]) {
    installed = state; revision += 1
  }
  func recordUpdate(_ client: ServiceClient, method: MethodDefinition,
    snapshot: ServiceContractSnapshot, policy: ContractAcceptance) throws {
    try environment.gate.withLock { publishUpdate(try prepareUpdate(client, method: method, snapshot: snapshot, policy: policy)) }
  }
  func preparedPublication(_ client: ServiceClient, generation: V4ControllerServiceGeneration) throws ->
    (V4ControllerServiceBindingSlot, [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)]) {
    try environment.gate.withLock {
      guard active, revision < UInt64.max, client.environment === environment else { throw ServiceFailure.closed }
      return (try generation.attach(client), try client.contractStateForReplacement())
    }
  }
  func publish(_ client: ServiceClient, alias: V4ControllerServiceBindingSlot,
    generation: V4ControllerServiceGeneration,
    state: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)]) {
    slot = alias; currentGeneration = generation; installed = state; revision += 1
    client.controllerDeclaration = self
  }
  func install(_ client: ServiceClient, generation: V4ControllerServiceGeneration) throws {
    try environment.gate.withLock {
      guard active, client.environment === environment, revision < UInt64.max else { throw ServiceFailure.closed }
      let prepared = try preparedPublication(client, generation: generation)
      publish(client, alias: prepared.0, generation: generation, state: prepared.1)
    }
  }
  func selected(_ method: MethodDefinition, captured: ServiceContractSnapshot,
    payloadBytes: Int, responseBytes: Int, cutoff: UInt64?) throws -> (ServiceClient, V4ServiceUnaryClaim) {
    try environment.gate.withLock {
      guard active, let client = slot?.client, let generation = currentGeneration else { throw ServiceFailure.serviceUnavailable }
      try generation.check(client.session); try client.checkPreparation()
      let snapshot = try client.contract(method)
      guard snapshot.contract.digest == captured.contract.digest else { throw ServiceFailure.contractMismatch }
      if let cutoff, let offer = snapshot.offer { try offer.check(contract: snapshot.contract, cutoff: cutoff, environment: environment) }
      let claim = try client.claimUnaryTarget(method, requestBytes: payloadBytes, responseBytes: responseBytes)
      return (client, claim)
    }
  }
  func close() {
    environment.gate.withLock {
      guard active else { return }; active = false
      slot?.client?.close(); slot?.release(); slot = nil; currentGeneration = nil; installed.removeAll()
    }
  }
}

/// A frozen candidate plan reserves full binding roots and actual call targets
/// before Acquire. Publication checks every declaration revision in one gate.
final class V4ControllerServicePlan: @unchecked Sendable {
  private struct Entry: Sendable {
    let declaration: V4ControllerServiceDeclaration
    let revision: UInt64
    let previous: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)]
    let storage: V4CryptoReservation
    let registration: V4ServiceContractRegistration
    let targets: [V4ServiceUnaryTarget]
    let streams: [UInt32: V4RequiredServiceStreamStorage]
    var candidate: ServiceClient?
  }
  private let environment: V4EnvironmentFoundation?
  private var entries: [Entry] = []
  private var deadlineAtMS: UInt64 = 0
  private var transferred = false
  init(_ declarations: [V4ControllerServiceDeclaration]) throws {
    environment = declarations.first?.environment
    guard declarations.allSatisfy({ declaration in environment.map { $0 === declaration.environment } ?? false }) else { throw ServiceFailure.configurationCapacity }
    guard declarations.count <= 64 else { throw ServiceFailure.configurationCapacity }
    if let environment {
      guard let interval = environment.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
      let (deadline, overflow) = interval.upperMS.addingReportingOverflow(30_000)
      guard !overflow else { throw ServiceFailure.deadlineExceeded }; deadlineAtMS = deadline
    }
    var streams = 0
    for declaration in declarations {
      let state = try declaration.state()
      let requiredStreams = declaration.required.filter { $0.shape == .serverStreaming }
      streams += requiredStreams.count
      guard requiredStreams.count <= 2, streams <= 8 else { throw ServiceFailure.configurationCapacity }
      let storage = try declaration.environment.serviceBindingStorage(methods: declaration.definition.methods.count)
      let registration = try declaration.environment.serviceContracts().reserve(declaration.definition)
      var targets: [V4ServiceUnaryTarget] = []
      for recipe in declaration.workloads {
        for _ in 0..<recipe.calls { targets.append(try V4ServiceUnaryTarget(environment: declaration.environment, recipe: recipe)) }
      }
      var streamStorage: [UInt32: V4RequiredServiceStreamStorage] = [:]
      for method in requiredStreams {
        streamStorage[method.typeID] = try V4RequiredServiceStreamStorage(environment: declaration.environment, method: method)
      }
      entries.append(Entry(declaration: declaration, revision: state.0, previous: state.1,
        storage: storage, registration: registration, targets: targets, streams: streamStorage))
    }
  }
  func prepare(_ session: any Session) async throws {
    guard let environment else { return }
    guard let native = session as? any V4ServiceSession, native.serviceEnvironment === environment,
      let interval = environment.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
    guard interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
    for index in entries.indices {
      let entry = entries[index], declaration = entry.declaration
      try declaration.checkRevision(entry.revision)
      let client = try await v4BindService(session: native, definition: declaration.definition, target: declaration.target,
        source: declaration.source, deadlineAtMS: deadlineAtMS, acceptance: declaration.acceptance,
        offerRefresh: declaration.offerRefresh, streamBindings: declaration.streamBindings, context: nil,
        previous: entry.previous.map { ($0.0, $0.1, .exact) },
        initialMethods: declaration.definition.methods.compactMap { item in
          declaration.required.contains(where: { $0 === item.method }) || declaration.workloads.contains(where: { $0.method === item.method }) ? item.method : nil
        }, prepaidStorage: entry.storage, registration: entry.registration)
      try client.inheritContractState(entry.previous)
      entries[index].candidate = client
      for target in entry.targets { try await target.attach(client) }
      client.unaryTargets = entry.targets
      try await client.prepareRequiredDependencies(declaration.required, deadlineAtMS: deadlineAtMS, prepaidStreams: entry.streams)
      try declaration.checkRevision(entry.revision)
    }
  }
  func check() throws {
    guard let environment else { return }
    try environment.gate.withLock {
      guard !transferred, let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS else {
        throw ServiceFailure.deadlineExceeded
      }
      for entry in entries {
        try entry.declaration.checkRevision(entry.revision)
        guard let candidate = entry.candidate else { throw ServiceFailure.serviceUnavailable }
        try candidate.checkRequiredDependencies(entry.declaration.required, deadlineAtMS: deadlineAtMS)
        for target in entry.targets { try target.check(candidate) }
      }
    }
  }
  func publish(generation: V4ControllerServiceGeneration, switchCurrent: () throws -> Void) throws {
    guard let environment else { try switchCurrent(); transferred = true; return }
    try environment.gate.withLock {
      try check()
      var publications: [(V4ControllerServiceDeclaration, ServiceClient, V4ControllerServiceBindingSlot,
        [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)])] = []
      for entry in entries {
        guard let candidate = entry.candidate else { throw ServiceFailure.serviceUnavailable }
        try candidate.attachControllerGeneration(generation)
        let prepared = try entry.declaration.preparedPublication(candidate, generation: generation)
        publications.append((entry.declaration, candidate, prepared.0, prepared.1))
      }
      try switchCurrent()
      for publication in publications {
        publication.0.publish(publication.1, alias: publication.2, generation: generation, state: publication.3)
      }
      transferred = true
    }
  }
  deinit {
    if !transferred { for entry in entries { entry.candidate?.close(); for target in entry.targets { target.seal() } } }
  }
}

/// A stream required for dispatch owns an accepted native stream and a K
/// position. Selection transfers those originals once; it never opens again.
/// Candidate stream storage is paid in the frozen plan before connection Acquire.
/// The same owners are consumed by the accepted source and its prepared operation.
final class V4RequiredServiceStreamStorage: @unchecked Sendable {
  let storage: V4CryptoReservation
  let messageStorage: V4CryptoReservation
  let operationStorage: V4CryptoReservation
  let itemStorage: V4CryptoReservation
  let completionReservation: V4CompletionReservation
  init(environment: V4EnvironmentFoundation, method: MethodDefinition) throws {
    guard method.shape == .serverStreaming else { throw ServiceFailure.configurationCapacity }
    storage = try environment.serviceOperationStorage(requestBytes: method.options.requestMaxBytes,
      responseBytes: method.options.maxResponseBytes)
    messageStorage = try environment.messageStreamStorage()
    operationStorage = try environment.serviceOperationStorage(requestBytes: method.options.requestMaxBytes,
      responseBytes: method.options.maxResponseBytes)
    itemStorage = try environment.messageStreamPayloadStorage(bytes: method.options.maxResponseBytes, encoding: false)
    let group = try environment.applicationGroup()
    completionReservation = try group.executor.reserveCompletionPosition(group: group)
  }
}

final class V4RequiredServiceStream: @unchecked Sendable {
  let environment: V4EnvironmentFoundation
  let storage: V4CryptoReservation
  let messageStorage: V4CryptoReservation
  let operationStorage: V4CryptoReservation
  let itemStorage: V4CryptoReservation
  let completionReservation: V4CompletionReservation
  private let channel: V4RPCChannel
  private let position: UInt64
  private var source: (any V4RPCTransport)?
  private let checkSource: @Sendable () throws -> Void
  init(client: ServiceClient, source: any V4RPCTransport, position: UInt64,
    storage: V4CryptoReservation, messageStorage: V4CryptoReservation,
    operationStorage: V4CryptoReservation, itemStorage: V4CryptoReservation,
    completionReservation: V4CompletionReservation) throws {
    environment = client.environment; channel = client.channel; self.source = source; self.position = position
    self.storage = storage; self.messageStorage = messageStorage; self.operationStorage = operationStorage; self.itemStorage = itemStorage; self.completionReservation = completionReservation
    #if os(macOS) || os(iOS)
    guard let native = source as? V4NativeByteStream else { throw ServiceFailure.serviceUnavailable }
    checkSource = { try native.checkServiceDependency() }
    #else
    throw ServiceFailure.serviceUnavailable
    #endif
  }
  func check() throws {
    try environment.gate.withLock {
      guard source != nil else { throw ServiceFailure.serviceUnavailable }
      try storage.check(); try messageStorage.check(); try operationStorage.check(); try itemStorage.check(); try checkSource()
    }
  }
  func take() throws -> (any V4RPCTransport, UInt64) {
    try environment.gate.withLock {
      try check(); let original = source!; source = nil; return (original, position)
    }
  }
  func close() {
    let original = environment.gate.withLock { () -> (any V4RPCTransport)? in
      defer { source = nil }; return source
    }
    if let original {
      Task { try? await original.close(); await channel.releaseDedicatedRequest(position) }
    }
  }
  deinit { close() }
}
