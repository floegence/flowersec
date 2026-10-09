import Foundation
import Crypto

struct ServiceCallerIdentity: Sendable {
  let tenant: String
  let audience: String
  let subject: String
  let identityDigest: Data
  let peerSubject: String
  let peerIdentityDigest: Data
}
public enum ServiceRPCChannelClass: Sendable, Hashable { case interactive, bulk }
typealias V4RPCChannelClass = ServiceRPCChannelClass

protocol V4ServiceSession: AnyObject, Session {
  var serviceEnvironment: V4EnvironmentFoundation { get }
  var serviceChannel: V4RPCChannel? { get }
  var serviceManagement: (any V4ExecutionManagementOwner)? { get }
  var serviceNotifications: V4NotificationPublisher? { get }
  var serviceNotificationReceiver: V4NotificationReceiver? { get }
  var serviceIdentity: ServiceCallerIdentity { get throws }
  func checkServiceSession() throws
  var serviceObservationDraining: Bool { get }
  func captureServiceResumeTarget(_ stream: any ByteStream, kind: String) throws -> ServiceResumeTarget
  func openServiceTransport(kind: String) async throws -> any V4RPCTransport
  func openServiceChannel(_ channelClass: V4RPCChannelClass) async throws -> V4RPCChannel
  func openServiceChannel(_ channelClass: V4RPCChannelClass, deadlineAtMS: UInt64?) async throws -> V4RPCChannel
}

extension V4ServiceSession {
  var serviceObservationDraining: Bool { false }
  func checkServiceAdmission() throws {
    try checkServiceSession()
    guard !serviceObservationDraining else { throw ServiceFailure.serviceUnavailable }
  }
  func checkServiceOpeningDeadline(_ deadlineAtMS: UInt64?) throws {
    try Task.checkCancellation()
    if let deadlineAtMS {
      guard let now = serviceEnvironment.clock.sample().interval, now.upperMS < deadlineAtMS else {
        throw ServiceFailure.deadlineExceeded
      }
    }
  }
  func openServiceChannel(_ channelClass: V4RPCChannelClass) async throws -> V4RPCChannel {
    guard let serviceChannel else { throw ServiceFailure.serviceUnavailable }
    try await serviceChannel.waitReady(); return serviceChannel
  }
  func openServiceChannel(_ channelClass: V4RPCChannelClass, deadlineAtMS: UInt64? = nil) async throws -> V4RPCChannel {
    let channel = try await openServiceChannel(channelClass)
    try await channel.waitReady(deadlineAtMS: deadlineAtMS); return channel
  }
}

public struct ServiceBindingTarget: Sendable, Equatable {
  public struct Peer: Sendable, Equatable {
    public let subject: String
    public let identityDigest: Data
    public init(subject: String, identityDigest: Data) throws {
      guard V4NamespaceRegistry.securityID(subject.utf8), identityDigest.count == 32,
        identityDigest.contains(where: { $0 != 0 }) else { throw ServiceFailure.configurationCapacity }
      self.subject = subject; self.identityDigest = Data(identityDigest)
    }
  }
  public let authority: String
  public let tenant: String
  public let audience: String
  public let localSubject: String
  public let peers: [Peer]
  public let executionCallerIdentity: String?
  public let executionCallerAuthority: Data?
  public init(authority: String, tenant: String, audience: String, localSubject: String, peers: [Peer], executionCallerAuthority: Data? = nil, executionCallerIdentity: String? = nil) throws {
    guard [authority, tenant, audience, localSubject].allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
      (1...16).contains(peers.count), executionCallerAuthority == nil || (executionCallerAuthority!.count == 32 && executionCallerAuthority!.contains(where: { $0 != 0 })) else { throw ServiceFailure.configurationCapacity }
    self.authority = authority; self.tenant = tenant; self.audience = audience; self.localSubject = localSubject
    guard executionCallerIdentity == nil || V4NamespaceRegistry.securityID(executionCallerIdentity!.utf8) else { throw ServiceFailure.configurationCapacity }
    self.executionCallerIdentity = executionCallerIdentity
    self.peers = peers; self.executionCallerAuthority = executionCallerAuthority.map { Data($0) }
  }
  func check(_ identity: ServiceCallerIdentity) throws {
    guard tenant == identity.tenant, audience == identity.audience, localSubject == identity.subject,
      peers.contains(where: { $0.subject == identity.peerSubject && $0.identityDigest == identity.peerIdentityDigest }) else {
      throw ServiceFailure.permissionDenied
    }
  }
}

public struct ServiceContractSnapshot: Sendable {
  public let contract: ServiceContract
  public let offer: AdmissionOffer?
  public init(contract: ServiceContract, offer: AdmissionOffer? = nil) { self.contract = contract; self.offer = offer }
}

public struct ServiceCallOptions: Sendable {
  public let deadlineAtMS: UInt64
  public let admissionNotAfterMS: UInt64?
  public let responseLimitBytes: Int?
  public let admissionMode: MessageSendAdmission
  public let context: ApplicationInvocationContext?
  public init(deadlineAtMS: UInt64, admissionNotAfterMS: UInt64? = nil, responseLimitBytes: Int? = nil,
    admissionMode: MessageSendAdmission = .queued, context: ApplicationInvocationContext? = nil) {
    self.deadlineAtMS = deadlineAtMS; self.admissionNotAfterMS = admissionNotAfterMS
    self.responseLimitBytes = responseLimitBytes; self.admissionMode = admissionMode; self.context = context
  }
}

public struct ServiceApplicationError: Error, Sendable {
  public let code: UInt32
  public let payload: Data
  public let definition: MessageCodecIdentity
}

/// One immutable application declaration bound to an authenticated Session and
/// trusted local destination. Advertisement changes never retarget old work.
public final class ServiceClient: @unchecked Sendable {
  let session: any V4ServiceSession
  let environment: V4EnvironmentFoundation
  let channel: V4RPCChannel
  private let channelClass: ServiceRPCChannelClass
  let group: V4ApplicationGroup
  public let definition: ServiceDefinition
  public let target: ServiceBindingTarget
  let gate: NSRecursiveLock
  var snapshots: [UInt32: ServiceContractSnapshot]
  private var policies: [UInt32: ContractAcceptance]
  private var inheritedSnapshots: [UInt32: ServiceContractSnapshot] = [:]
  let streamBindings: [UInt32: ServiceStreamBinding]
  var contractSource: (any ServiceContractSource)?
  let offerRefresh: ServiceOfferRefresh
  var closed = false
  private var controllerGeneration: V4ControllerServiceGeneration?
  private var storage: V4CryptoReservation?
  var contractRegistration: V4ServiceContractRegistration?
  weak var controllerDeclaration: V4ControllerServiceDeclaration?
  var unaryTargets: [V4ServiceUnaryTarget] = []
  var requiredStreams: [UInt32: V4RequiredServiceStream] = [:]
  var requiredNotifications: [UInt32: V4NotificationDependency] = [:]
  var operations: [UUID: @Sendable () -> Void] = [:]
  init(session: any V4ServiceSession, definition: ServiceDefinition, target: ServiceBindingTarget,
    contracts: [ServiceContractSnapshot], acceptance: ContractAcceptance, allowsPartialContracts: Bool = false, streamBindings: [ServiceStreamBinding] = [], channel: V4RPCChannel? = nil,
    channelClass: ServiceRPCChannelClass = .interactive,
    contractSource: (any ServiceContractSource)? = nil, offerRefresh: ServiceOfferRefresh = .explicit,
    prepaidStorage: V4CryptoReservation? = nil, registration: V4ServiceContractRegistration? = nil) throws {
    self.contractSource = contractSource; self.offerRefresh = offerRefresh
    self.session = session; environment = session.serviceEnvironment
    guard let channel = channel ?? session.serviceChannel else { throw ServiceFailure.serviceUnavailable }
    self.channel = channel; self.channelClass = channelClass; self.definition = definition; self.target = target
    gate = environment.gate
    try session.checkServiceAdmission(); try target.check(session.serviceIdentity)
    guard contracts.count <= definition.methods.count,
      allowsPartialContracts || contracts.count == definition.methods.count,
      contracts.allSatisfy({ snapshot in definition.methods.contains { $0.method.typeID == snapshot.contract.typeID } }),
      Set(contracts.map { $0.contract.typeID }).count == contracts.count else { throw ServiceFailure.contractMismatch }
    var captured: [UInt32: ServiceContractSnapshot] = [:]
    for entry in definition.methods {
      guard let snapshot = contracts.first(where: { $0.contract.typeID == entry.method.typeID }) else { continue }
      guard captured[entry.method.typeID] == nil else { throw ServiceFailure.contractMismatch }
      try snapshot.contract.checkEnvironment(environment)
      try snapshot.contract.checkMethod(entry.method, in: definition)
      try snapshot.contract.checkPolicy(acceptance)
      guard snapshot.contract.semantics != .execution || snapshot.offer != nil else { throw ServiceFailure.admissionWindowClosed }
      captured[entry.method.typeID] = snapshot
    }
    var streams: [UInt32: ServiceStreamBinding] = [:]
    for binding in streamBindings {
      guard definition.contains(binding.method), streams[binding.method.typeID] == nil else { throw ServiceFailure.configurationCapacity }
      streams[binding.method.typeID] = binding
    }
    self.streamBindings = streams
    snapshots = captured; policies = Dictionary(uniqueKeysWithValues: definition.methods.map { ($0.method.typeID, acceptance) })
    group = try environment.applicationGroup()
    storage = try prepaidStorage ?? environment.serviceBindingStorage(methods: definition.methods.count)
    contractRegistration = try registration ?? environment.serviceContracts().reserve(definition)
    try contractRegistration?.attach(self)
  }
  func bindingTail() throws -> V4ServiceBindingTail {
    try gate.withLock {
      try check()
      guard let storage, let contractRegistration else { throw ServiceFailure.closed }
      return V4ServiceBindingTail(client: self, storage: storage, registration: contractRegistration,
        snapshots: Array(snapshots.values))
    }
  }
  func check() throws {
    try gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      try storage?.check(); try session.checkServiceSession(); try target.check(session.serviceIdentity)
    }
  }
  func checkAdmission() throws { try gate.withLock { try check(); try session.checkServiceAdmission() } }
  func attachControllerGeneration(_ generation: V4ControllerServiceGeneration) throws {
    try gate.withLock {
      try check()
      guard generation.environment === environment, controllerGeneration == nil else { throw ServiceFailure.serviceUnavailable }
      try generation.check(session)
      controllerGeneration = generation
    }
  }
  func checkPreparation() throws {
    try gate.withLock { try checkAdmission(); try controllerGeneration?.check(session) }
  }
  func checkControllerCurrent() throws {
    try gate.withLock { try check(); try controllerGeneration?.check(session) }
  }
  func contractStateForReplacement() throws -> [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)] {
    try gate.withLock {
      try check()
      return try definition.methods.compactMap { entry in
        guard let snapshot = snapshots[entry.method.typeID] ?? inheritedSnapshots[entry.method.typeID] else { return nil }
        guard let policy = policies[entry.method.typeID] else { throw ServiceFailure.contractMismatch }
        return (entry.method, snapshot, policy)
      }
    }
  }
  func inheritContractState(_ previous: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)]) throws {
    try gate.withLock {
      try check()
      for (method, old, policy) in previous {
        guard let current = snapshots[method.typeID] else {
          policies[method.typeID] = policy; inheritedSnapshots[method.typeID] = old; continue
        }
        try current.contract.checkPolicy(policy, current: old.contract)
        policies[method.typeID] = policy
      }
    }
  }

  func claimUnaryTarget(_ method: MethodDefinition, requestBytes: Int, responseBytes: Int) throws -> V4ServiceUnaryClaim {
    for target in unaryTargets where target.recipe.method === method {
      do { return try target.claim(self, method: method, requestBytes: requestBytes, responseBytes: responseBytes) }
      catch let failure as ServiceFailure where failure == .resourceExhausted { continue }
    }
    throw ServiceFailure.resourceExhausted
  }
  private func channelForNewCall(deadlineAtMS: UInt64) async throws -> V4RPCChannel {
    try Task.checkCancellation(); try checkPreparation()
    // Only a new preparation selects a carrier. Existing operations keep the
    // channel captured with their original bytes, admission and publication.
    if await channel.acceptsOpeningWaiter {
      do { try await channel.waitReady(deadlineAtMS: deadlineAtMS); try checkPreparation(); return channel }
      catch {
        if error is CancellationError || error as? ServiceFailure == .deadlineExceeded || error as? ServiceFailure == .resourceExhausted { throw error }
        if await channel.acceptsOpeningWaiter { throw error }
      }
    }
    try Task.checkCancellation(); try checkPreparation()
    try session.checkServiceOpeningDeadline(deadlineAtMS)
    let selected = try await session.openServiceChannel(channelClass, deadlineAtMS: deadlineAtMS)
    try Task.checkCancellation(); try checkPreparation()
    guard selected.sessionEngine === channel.sessionEngine else { throw ServiceFailure.serviceUnavailable }
    return selected
  }
  private func claimUnaryTarget(_ method: MethodDefinition, responseBytes: Int,
    on channel: V4RPCChannel) async throws -> V4ServiceUnaryClaim? {
    let candidates = try gate.withLock { () -> [V4ServiceUnaryTarget] in
      try checkPreparation(); return unaryTargets.filter { $0.recipe.method === method }
    }
    guard !candidates.isEmpty else { return nil }
    for target in candidates {
      do { return try await target.claim(self, method: method, requestBytes: 0, responseBytes: responseBytes, on: channel) }
      catch let failure as ServiceFailure where failure == .resourceExhausted { continue }
    }
    throw ServiceFailure.resourceExhausted
  }
  func prepareRequiredDependencies(_ methods: [MethodDefinition], deadlineAtMS: UInt64,
    prepaidStreams: [UInt32: V4RequiredServiceStreamStorage] = [:]) async throws {
    try await channel.checkContractChannel()
    for method in methods {
      try checkPreparation()
      guard definition.contains(method), let snapshot = snapshots[method.typeID] else { throw ServiceFailure.serviceUnavailable }
      if method.semantics == .execution {
        guard session.serviceManagement != nil else { throw ServiceFailure.serviceUnavailable }
      }
      if method.shape == .notify {
        guard let publisher = session.serviceNotifications else { throw ServiceFailure.serviceUnavailable }
        let dependency = try await publisher.prepareDependency()
        try gate.withLock { try checkPreparation(); requiredNotifications[method.typeID] = dependency }
      } else if method.shape == .serverStreaming {
        guard let binding = streamBindings[method.typeID] else { throw ServiceFailure.configurationCapacity }
        let paid = try prepaidStreams[method.typeID] ?? V4RequiredServiceStreamStorage(environment: environment, method: method)
        let position = try await channel.reserveDedicatedRequest()
        var opened: (any ByteStream)?
        do {
          let stream = try await session.openStream(kind: binding.kind, metadata: binding.metadata); opened = stream
          guard let native = stream as? any V4RPCTransport else { throw ServiceFailure.serviceUnavailable }
          let dependency = try V4RequiredServiceStream(client: self, source: native, position: position,
            storage: paid.storage, messageStorage: paid.messageStorage, operationStorage: paid.operationStorage,
                itemStorage: paid.itemStorage, completionReservation: paid.completionReservation)
          try gate.withLock {
            try checkPreparation()
            guard let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS,
              requiredStreams[method.typeID] == nil else { throw ServiceFailure.deadlineExceeded }
            requiredStreams[method.typeID] = dependency
          }
        } catch { try? await opened?.close(); await channel.releaseDedicatedRequest(position); throw error }
      }
      if method.semantics == .execution {
        guard let offer = snapshot.offer, let interval = environment.clock.sample().interval,
          interval.upperMS < deadlineAtMS else { throw ServiceFailure.admissionWindowClosed }
        try offer.check(contract: snapshot.contract, cutoff: min(deadlineAtMS, offer.notAfterMS), environment: environment)
      }
    }
  }
  func checkRequiredDependencies(_ methods: [MethodDefinition], deadlineAtMS: UInt64) throws {
    try checkPreparation()
    guard let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS else {
      throw ServiceFailure.deadlineExceeded
    }
    for method in methods {
      guard definition.contains(method), let snapshot = snapshots[method.typeID] else { throw ServiceFailure.serviceUnavailable }
      if method.shape == .serverStreaming { try requiredStreams[method.typeID]?.check()
        guard requiredStreams[method.typeID] != nil else { throw ServiceFailure.serviceUnavailable }
      }
      if method.shape == .notify {
        guard session.serviceNotifications != nil, let dependency = requiredNotifications[method.typeID] else {
          throw ServiceFailure.serviceUnavailable
        }
        try dependency.check()
      }
      if method.semantics == .execution {
        guard let offer = snapshot.offer, session.serviceManagement != nil else { throw ServiceFailure.admissionWindowClosed }
        try offer.check(contract: snapshot.contract, cutoff: min(deadlineAtMS, offer.notAfterMS), environment: environment)
      }
    }
  }

  func contractPolicy(_ method: MethodDefinition) throws -> ContractAcceptance {
    try gate.withLock {
      try check(); guard definition.contains(method), let policy = policies[method.typeID] else { throw ServiceFailure.contractMismatch }
      return policy
    }
  }
  func firstSnapshotDigest(_ method: MethodDefinition) -> Data? {
    gate.withLock { (snapshots[method.typeID] ?? inheritedSnapshots[method.typeID])?.contract.digest }
  }
  public func contract(_ method: MethodDefinition) throws -> ServiceContractSnapshot {
    try gate.withLock {
      try check(); guard definition.contains(method) else { throw ServiceFailure.contractMismatch }
      guard let result = snapshots[method.typeID] else { throw ServiceFailure.serviceUnavailable }
      return result
    }
  }
  func installFirstSnapshot(_ method: MethodDefinition, snapshot: ServiceContractSnapshot, deadlineAtMS: UInt64) throws {
    try gate.withLock {
      try checkPreparation(); try controllerDeclaration?.checkInstallation(self)
      guard definition.contains(method), snapshots[method.typeID] == nil, let policy = policies[method.typeID] else {
        throw ServiceFailure.contractMismatch
      }
      try snapshot.contract.checkEnvironment(environment); try snapshot.contract.checkMethod(method, in: definition)
      try snapshot.contract.checkPolicy(policy, current: inheritedSnapshots[method.typeID]?.contract)
      if method.semantics == .execution {
        guard let offer = snapshot.offer else { throw ServiceFailure.admissionWindowClosed }
        try offer.check(contract: snapshot.contract, cutoff: min(deadlineAtMS, offer.notAfterMS), environment: environment)
      }
      let publication = try controllerDeclaration?.prepareUpdate(self, method: method, snapshot: snapshot, policy: policy)
      try environment.serviceContracts().activate(self, deadlineAtMS: deadlineAtMS, first: (method, snapshot))
      snapshots[method.typeID] = snapshot; inheritedSnapshots.removeValue(forKey: method.typeID)
      if let publication { controllerDeclaration?.publishUpdate(publication) }
    }
  }
  public func updateContract(_ method: MethodDefinition, snapshot: ServiceContractSnapshot,
    acceptance: ContractAcceptance? = nil, explicitUpdate: Bool = true) throws {
    try gate.withLock {
      try checkPreparation(); try controllerDeclaration?.checkInstallation(self)
      guard definition.contains(method), let old = snapshots[method.typeID], let policy = acceptance ?? policies[method.typeID] else {
        throw ServiceFailure.contractMismatch
      }
      try snapshot.contract.checkEnvironment(environment); try snapshot.contract.checkMethod(method, in: definition)
      try snapshot.contract.checkPolicy(policy, current: old.contract, explicitUpdate: explicitUpdate)
      guard snapshot.contract.semantics != .execution || snapshot.offer != nil else { throw ServiceFailure.admissionWindowClosed }
      try environment.serviceContracts().snapshotChanged(self, method: method, candidate: snapshot)
      try controllerDeclaration?.recordUpdate(self, method: method, snapshot: snapshot, policy: policy)
      snapshots[method.typeID] = snapshot; policies[method.typeID] = policy
    }
  }
  /// Exact Offer renewal belongs to this fixed binding even after the
  /// Controller retires its publication alias. It cannot retarget or change
  /// the old method's semantics, policy or source.
  func installRenewedOffer(_ method: MethodDefinition, snapshot: ServiceContractSnapshot) throws {
    try gate.withLock {
      try checkAdmission()
      guard definition.contains(method), method.semantics == .execution,
        let old = snapshots[method.typeID], snapshot.contract.digest == old.contract.digest else {
        throw ServiceFailure.contractMismatch
      }
      try snapshot.contract.checkEnvironment(environment); try snapshot.contract.checkMethod(method, in: definition)
      try snapshot.contract.checkPolicy(.exact, current: old.contract)
      try environment.serviceContracts().snapshotChanged(self, method: method, candidate: snapshot)
      if let declaration = controllerDeclaration, declaration.isInstalled(self) {
        guard let policy = policies[method.typeID] else { throw ServiceFailure.contractMismatch }
        try declaration.recordUpdate(self, method: method, snapshot: snapshot, policy: policy)
      }
      snapshots[method.typeID] = snapshot
    }
  }
  public func prepareOperation<Request: Sendable, Response: Sendable>(
    _ method: MethodDefinition, request: Request, requestCodec: any MessageCodec<Request>,
    responseCodec: any MessageCodec<Response>, options: ServiceCallOptions
  ) async throws -> ServiceOperation<Response> {
    let snapshot = try await operationSnapshot(method, options: options)
    guard method.shape == .unary, requestCodec.definition == method.options.request,
      responseCodec.definition == method.options.response else { throw ServiceFailure.contractMismatch }
    let selectedChannel = try await channelForNewCall(deadlineAtMS: options.deadlineAtMS)
    let owner = try await claimUnaryTarget(method,
      responseBytes: options.responseLimitBytes ?? method.options.maxResponseBytes, on: selectedChannel)
    let (payload, preparedStorage) = try await encodeRequest(method: method, snapshot: snapshot, value: request,
      codec: requestCodec, options: options, prepaid: owner)
    if owner == nil { try preparedStorage.prepareExecutionTail() }
    let token = UUID()
    let value = try ServiceOperation(client: self, token: token, method: method, snapshot: snapshot,
      payload: Data(payload), codec: responseCodec, options: options, storage: preparedStorage, prepaid: owner, channel: selectedChannel)
    do {
      try gate.withLock {
        try checkPreparation()
        guard operations.count < 1024 else { throw ServiceFailure.resourceExhausted }
        operations[token] = { [weak value] in value?.close() }
      }
      return value
    } catch { value.close(); throw error }
  }
  func encodeRequest<Request: Sendable>(method: MethodDefinition, snapshot: ServiceContractSnapshot,
    value: Request, codec: any MessageCodec<Request>, options: ServiceCallOptions,
    prepaid: V4ServiceUnaryClaim? = nil, prepaidStorage: V4CryptoReservation? = nil
  ) async throws -> (Data, V4CryptoReservation) {
    try checkPreparation()
    let preparedStorage = try prepaid?.target.storage ?? prepaidStorage ?? environment.serviceOperationStorage(requestBytes: method.options.requestMaxBytes,
      responseBytes: method.options.maxResponseBytes)
    if prepaid == nil { try preparedStorage.prepareExecutionTail() }
    let payload: Data
    let inputTail: V4ServiceInputTail
    if let prepaid { inputTail = V4ServiceInputTail(owner: prepaid) }
    else { inputTail = V4ServiceInputTail(try preparedStorage.executionTail(), binding: try bindingTail()) }
    if let asynchronous = codec as? any AsyncMessageCodec<Request> {
      payload = try await group.invoke(context: options.context, preparedPosition: prepaid?.target.encoder) { ctx in try await withExtendedLifetimeAsync(inputTail) { try await asynchronous.encodeAsync(value, context: ctx) } }
    } else if let context = options.context,
      let stage = try group.executor.synchronousStage(group: group, context: context) {
      defer { stage.finish() }
      var destination = Data()
      do {
        let count = try codec.encode(value, context: stage.context, into: &destination)
        guard count == destination.count else { throw MessageCodecFailure.encodeFailed }
        payload = destination
      } catch { throw MessageCodecFailure.encodeFailed }
    } else {
      payload = try await group.invoke(context: options.context, preparedPosition: prepaid?.target.encoder) { ctx in
        var destination = Data()
        defer { withExtendedLifetime(inputTail) {} }
        do {
          let count = try codec.encode(value, context: ctx, into: &destination)
          guard count == destination.count else { throw MessageCodecFailure.encodeFailed }
          return destination
        } catch { throw MessageCodecFailure.encodeFailed }
      }
    }
    guard payload.count <= (prepaid?.target.recipe.requestBytes ?? method.options.requestMaxBytes),
      payload.count <= method.options.requestMaxBytes, payload.count <= (try snapshot.contract.uint(23)) else {
      throw MessageCodecFailure.encodeFailed
    }
    return (payload, preparedStorage)
  }
  func retainOperation(_ token: UUID, close: @escaping @Sendable () -> Void) throws {
    try gate.withLock {
      try checkPreparation()
      guard operations.count < 1024 else { throw ServiceFailure.resourceExhausted }
      operations[token] = close
    }
  }
  public func prepareNotify<Request: Sendable>(_ method: MethodDefinition, request: Request,
    codec: any MessageCodec<Request>, options: ServiceCallOptions) async throws -> ServiceNotificationOperation {
    let snapshot = try await operationSnapshot(method, options: options)
    guard method.shape == .notify, codec.definition == method.options.request,
      session.serviceNotifications != nil else { throw ServiceFailure.contractMismatch }
    let (payload, storage) = try await encodeRequest(method: method, snapshot: snapshot, value: request, codec: codec, options: options)
    try storage.prepareExecutionTail()
    let token = UUID()
    let operation = try ServiceNotificationOperation(client: self, token: token, method: method, snapshot: snapshot,
      payload: payload, options: options, storage: storage)
    do { try retainOperation(token) { [weak operation] in operation?.close() }; return operation }
    catch { operation.close(); throw error }
  }
  public func prepareStream<Request: Sendable, Item: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>, options: ServiceCallOptions
  ) async throws -> ServiceStreamingOperation<Item> {
    let snapshot = try await operationSnapshot(method, options: options)
    guard method.shape == .serverStreaming, requestCodec.definition == method.options.request,
      itemCodec.definition == method.options.response, let binding = streamBindings[method.typeID] else { throw ServiceFailure.contractMismatch }
    let dependency = gate.withLock { requiredStreams.removeValue(forKey: method.typeID) }
    let (payload, storage): (Data, V4CryptoReservation)
    do {
      (payload, storage) = try await encodeRequest(method: method, snapshot: snapshot, value: request,
        codec: requestCodec, options: options, prepaidStorage: dependency?.operationStorage)
    } catch { dependency?.close(); throw error }
    try storage.prepareExecutionTail()
    let token = UUID()
    let operation: ServiceStreamingOperation<Item>
    do {
      operation = try ServiceStreamingOperation(client: self, token: token, method: method, snapshot: snapshot,
        binding: binding, payload: payload, codec: itemCodec, options: options, storage: storage, dependency: dependency)
    } catch { dependency?.close(); throw error }
    do { try retainOperation(token) { [weak operation] in operation?.close() }; return operation }
    catch { operation.close(); throw error }
  }
  public func stream<Request: Sendable, Item: Sendable>(_ method: MethodDefinition, request: Request,
    requestCodec: any MessageCodec<Request>, itemCodec: any MessageCodec<Item>, options: ServiceCallOptions
  ) async throws -> ServiceStreamingOperation<Item> {
    let operation = try await prepareStream(method, request: request, requestCodec: requestCodec, itemCodec: itemCodec, options: options)
    do { try await operation.start(); return operation } catch { operation.close(); throw error }
  }
  public func notify<Request: Sendable>(_ method: MethodDefinition, request: Request,
    codec: any MessageCodec<Request>, options: ServiceCallOptions) async throws -> NotificationSendResult {
    let operation = try await prepareNotify(method, request: request, codec: codec, options: options)
    defer { operation.close() }
    try await operation.start()
    return try await operation.waitPublished()
  }
  public func call<Request: Sendable, Response: Sendable>(
    _ method: MethodDefinition, request: Request, requestCodec: any MessageCodec<Request>,
    responseCodec: any MessageCodec<Response>, options: ServiceCallOptions
  ) async throws -> MessageReceived<Response> {
    let operation = try await prepareOperation(method, request: request, requestCodec: requestCodec,
      responseCodec: responseCodec, options: options)
    defer { operation.close() }
    try await operation.start()
    return try await operation.takeResult(context: options.context)
  }
  func release(_ token: UUID) { gate.withLock { _ = operations.removeValue(forKey: token) } }
  func checkReference(_ reference: OperationReference) throws {
    try check()
    guard reference.targetDomain == target.authority, reference.tenant == target.tenant,
      reference.audience == target.audience, reference.callerSubject == target.localSubject,
      reference.serviceNamespace == definition.namespace,
      target.executionCallerAuthority == reference.callerAuthority else { throw ServiceFailure.permissionDenied }
  }
  public func queryOperation(_ reference: OperationReference, deadlineAtMS: UInt64) async throws -> ExecutionManagementResult {
    try checkControllerCurrent(); try checkReference(reference)
    guard let management = session.serviceManagement else { throw ServiceFailure.serviceUnavailable }
    return try await management.call(reference: reference, cancel: false, deadlineAtMS: deadlineAtMS, before: { [self] in
      try checkControllerCurrent(); try checkReference(reference)
    })
  }
  public func requestCancel(_ reference: OperationReference, deadlineAtMS: UInt64) async throws -> ExecutionManagementResult {
    try checkControllerCurrent(); try checkReference(reference)
    guard let management = session.serviceManagement else { throw ServiceFailure.serviceUnavailable }
    return try await management.call(reference: reference, cancel: true, deadlineAtMS: deadlineAtMS, before: { [self] in
      try checkControllerCurrent(); try checkReference(reference)
    })
  }
  public func close() {
    let owned = gate.withLock { () -> [@Sendable () -> Void] in
      guard !closed else { return [] }
      closed = true; contractRegistration?.stopRenewal(); storage = nil; controllerGeneration = nil
      for target in unaryTargets { target.seal() }; unaryTargets.removeAll()
      for stream in requiredStreams.values { stream.close() }; requiredStreams.removeAll(); requiredNotifications.removeAll()
      let owned = Array(operations.values); operations.removeAll(); snapshots.removeAll(); policies.removeAll(); contractSource = nil
      return owned
    }
    for close in owned { close() }
  }
  deinit { close() }
}

extension Session {
  public func bindService(_ definition: ServiceDefinition, target: ServiceBindingTarget,
    contracts: [ServiceContractSnapshot], acceptance: ContractAcceptance = .exact, streamBindings: [ServiceStreamBinding] = []) throws -> ServiceClient {
    guard let session = self as? any V4ServiceSession else { throw ServiceFailure.serviceUnavailable }
    return try ServiceClient(session: session, definition: definition, target: target, contracts: contracts, acceptance: acceptance, streamBindings: streamBindings)
  }
}

private func withExtendedLifetimeAsync<T: Sendable>(_ value: V4ServiceInputTail,
  operation: () async throws -> T) async rethrows -> T {
  defer { withExtendedLifetime(value) {} }
  return try await operation()
}

final class V4ServiceInputTail: @unchecked Sendable {
  private let reference: V4ResourceReference?
  private let owner: V4ServiceUnaryClaim?
  private let binding: V4ServiceBindingTail?
  init(_ reference: V4ResourceReference, binding: V4ServiceBindingTail? = nil) {
    self.reference = reference; owner = nil; self.binding = binding
  }
  init(owner: V4ServiceUnaryClaim) { reference = nil; self.owner = owner; binding = nil }
  deinit { reference?.release(); withExtendedLifetime(owner) {} }
}

/// Retains original metadata and accounting through actual callback and wire exit,
/// even when logical Close clears the binding's public state.
final class V4ServiceBindingTail: @unchecked Sendable {
  let client: ServiceClient
  let storage: V4CryptoReservation
  let registration: V4ServiceContractRegistration
  let snapshots: [ServiceContractSnapshot]
  init(client: ServiceClient, storage: V4CryptoReservation, registration: V4ServiceContractRegistration,
    snapshots: [ServiceContractSnapshot]) {
    self.client = client; self.storage = storage; self.registration = registration; self.snapshots = snapshots
  }
}
