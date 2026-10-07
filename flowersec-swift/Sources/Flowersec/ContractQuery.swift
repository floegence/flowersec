import Foundation
import Crypto

public struct ServiceContractQueryBinding: Sendable {
  public let typeID: UInt32
  public let contractDigest: Data
  public let maximumLifetimeMS: UInt64
  public init(typeID: UInt32, contractDigest: Data, maximumLifetimeMS: UInt64 = 30_000) throws {
    guard typeID > 0, contractDigest.count == 32, (1...30_000).contains(maximumLifetimeMS) else { throw ServiceFailure.configurationCapacity }
    self.typeID = typeID; self.contractDigest = Data(contractDigest); self.maximumLifetimeMS = maximumLifetimeMS
  }
}
public struct ServiceContractQueryTarget: Sendable {
  public let namespace: String
  public let typeID: UInt32
  public let wantedDigest: Data?
  public let known: ServiceContractSnapshot?
  public let maximumOfferWindowMS: UInt64
  public init(namespace: String, typeID: UInt32, wantedDigest: Data? = nil, known: ServiceContractSnapshot? = nil,
    maximumOfferWindowMS: UInt64) throws {
    guard V4NamespaceRegistry.securityID(namespace.utf8), typeID > 0, maximumOfferWindowMS > 0,
      wantedDigest == nil || wantedDigest!.count == 32, known == nil || known!.contract.namespace == namespace && known!.contract.typeID == typeID,
      wantedDigest == nil || known == nil || wantedDigest! == known!.contract.digest else { throw ServiceFailure.configurationCapacity }
    self.namespace = namespace; self.typeID = typeID; self.wantedDigest = wantedDigest.map { Data($0) }
    self.known = known; self.maximumOfferWindowMS = maximumOfferWindowMS
  }
  func encoded() -> Data {
    var fields: [(UInt64, Data)] = [(0, V4Crypto.text(namespace)), (1, V4NamespaceValue.head(0, UInt64(typeID)))]
    if let wantedDigest { fields.append((2, V4Crypto.bytes(wantedDigest))) }
    if let known { fields.append((3, V4Crypto.bytes(known.contract.digest))) }
    return V4Crypto.map(fields)
  }
}
public struct ServiceContractQueryResult: Sendable {
  public enum Status: String, Sendable { case availableFull = "available_full", availableUnchanged = "available_unchanged", denied, unavailable }
  public let status: Status
  public let snapshot: ServiceContractSnapshot?
}

// This sealed lane accepts only finite SDK jobs, never an application closure.
// Its original root service pays one actual worker shared by all Environments.
protocol V4FixedQueryWork: AnyObject, Sendable {
  func step() -> Bool
  func cancel()
}
final class V4FixedQueryExecutor: @unchecked Sendable {
  private let gate: NSRecursiveLock
  private let service: V4ResourceService
  private let maximum: Int
  private var queue: [any V4FixedQueryWork] = []
  private var active = false
  init(root: V4ResourceRoot, maximum: Int) throws {
    gate = root.gate; self.maximum = maximum
    service = try root.reserveService(V4ResourceVector(sdkBytes: 256 * 1024, items: UInt64(maximum + 5), work: 1, tasks: 1))
    queue.reserveCapacity(maximum)
  }
  func attach(account: V4ResourceAccount, owner: V4ResourceOwnerKey) throws -> V4ResourceReference {
    try service.attach(account: account, owner: owner)
  }
  func enqueue(_ work: any V4FixedQueryWork) throws {
    try gate.withLock {
      try service.check(); guard queue.count + (active ? 1 : 0) < maximum else { throw V4ResourceFailure.capacity }; queue.append(work)
    }
    schedule()
  }
  private func schedule() {
    let start = gate.withLock { () -> Bool in
      guard !active, !queue.isEmpty else { return false }; active = true; return true
    }
    guard start else { return }
    Task.detached { [self] in
      while true {
        let next = gate.withLock { () -> (any V4FixedQueryWork)? in
          guard !queue.isEmpty else { active = false; return nil }
          return queue.removeFirst()
        }
        guard let next else { return }
        if next.step() { gate.withLock { queue.append(next) } }
        await Task.yield()
      }
    }
  }
}
private final class V4ContractSnapshotDecode: V4FixedQueryWork, @unchecked Sendable {
  private let gate: NSRecursiveLock
  private let environment: V4EnvironmentFoundation
  private let targets: [ServiceContractQueryTarget]
  private let registry: V4NamespaceRegistry
  private var storage: V4CryptoReservation?
  private var queryOwner: V4ApplicationQueryOwner?
  private var position: V4ContractFetchPosition?
  private var payload: Data?
  private var envelope: V4NamespaceValue?
  private var envelopeDocument: V4NamespaceDocument?
  private var contractDocument: V4NamespaceDocument?
  private var contractBytes = Data()
  private var contractCopyOffset = 0
  private var contractHash: SHA256?
  private var contractHashOffset = 0
  private var contract: ServiceContract?
  private var results: [ServiceContractQueryResult] = []
  private var index = 0
  private var canceled = false
  private var continuation: CheckedContinuation<[ServiceContractQueryResult], any Error>?
  init(environment: V4EnvironmentFoundation, targets: [ServiceContractQueryTarget], payload: Data, storage: V4CryptoReservation, queryOwner: V4ApplicationQueryOwner, position: V4ContractFetchPosition, registry: V4NamespaceRegistry) {
    gate = environment.gate
    self.queryOwner = queryOwner; self.position = position; self.registry = registry
    self.environment = environment; self.targets = targets; self.payload = payload; self.storage = storage
    results.reserveCapacity(targets.count)
  }
  func result(executor: V4FixedQueryExecutor) async throws -> [ServiceContractQueryResult] {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        let error = gate.withLock { () -> (any Error)? in
          guard !canceled, !Task.isCancelled else { return CancellationError() }
          self.continuation = continuation
          do { try executor.enqueue(self); return nil } catch { self.continuation = nil; return error }
        }
        if let error { continuation.resume(throwing: error) }
      }
    } onCancel: { self.cancel() }
  }
  func step() -> Bool {
    gate.withLock {
      guard !canceled, let storage else { collect(); return false }
      do {
        try storage.check()
        if envelope == nil {
          if envelopeDocument == nil {
            guard let payload = self.payload else { throw ServiceFailure.closed }
            envelopeDocument = try V4NamespaceDocument(payload, schema: "ContractSnapshots", bytes: targets.count * 9216,
              nodes: 1024, registry: registry, cooperative: true)
            self.payload = nil
          }
          guard let document = envelopeDocument else { throw ServiceFailure.protocolFailure }
          guard try document.advanceQueryParsing() else { return true }
          let value = document.root
          guard try value.field("items").count == targets.count else { throw ServiceFailure.protocolFailure }
          envelope = value; return true
        }
        guard let envelope,
          let item = try envelope.field("items").children.enumerated().first(where: { $0.offset == index })?.element
        else { throw ServiceFailure.protocolFailure }
        guard try item.u("target_index") == UInt64(index) else { throw ServiceFailure.protocolFailure }
        let statusCode = try item.u("status")
        let statuses: [ServiceContractQueryResult.Status] = [.availableFull, .availableUnchanged, .denied, .unavailable]
        guard statusCode < UInt64(statuses.count) else { throw ServiceFailure.protocolFailure }
        let target = targets[index]; let status = statuses[Int(statusCode)]
        var snapshot: ServiceContractSnapshot?
        if status == .availableFull || status == .availableUnchanged {
          let contract: ServiceContract
          if status == .availableFull {
            guard try item.optional("contract_digest") == nil else { throw ServiceFailure.protocolFailure }
            if self.contract == nil {
              let original = try item.field("contract").payload
              if contractCopyOffset < original.count {
                let end = min(original.count, contractCopyOffset + 4096)
                let startIndex = original.startIndex + contractCopyOffset
                contractBytes.append(contentsOf: original[startIndex..<original.startIndex + end])
                contractCopyOffset = end; return true
              }
              if contractDocument == nil {
                contractDocument = try V4NamespaceDocument(contractBytes, schema: "ServiceContract", bytes: 8192,
                  nodes: 1024, registry: registry, cooperative: true)
              }
              guard let document = contractDocument else { throw ServiceFailure.protocolFailure }
              guard try document.advanceQueryParsing() else { return true }
              if contractHash == nil {
                let (label, projection) = try registry.domain("service_contract_digest", schema: "ServiceContract", operation: "sha256")
                guard projection == "full" else { throw ServiceFailure.protocolFailure }
                var hash = SHA256(); hash.update(data: label)
                hash.update(data: V4Crypto.integer(UInt64(contractBytes.count), width: 4)); contractHash = hash
                return true
              }
              if contractHashOffset < contractBytes.count {
                let end = min(contractBytes.count, contractHashOffset + 4096)
                contractHash?.update(data: contractBytes[contractHashOffset..<end]); contractHashOffset = end; return true
              }
              guard let hash = contractHash else { throw ServiceFailure.protocolFailure }
              let reservation = try environment.serviceContractStorage(bytes: contractBytes.count)
              self.contract = try ServiceContract(canonical: contractBytes, document: document,
                digest: Data(hash.finalize()), reservation: reservation)
              return true
            }
            guard let decoded = self.contract else { throw ServiceFailure.protocolFailure }
            contract = decoded
          } else {
            guard try item.optional("contract") == nil, let known = target.known,
              try item.b("contract_digest") == known.contract.digest else { throw ServiceFailure.protocolFailure }
            contract = known.contract
          }
          try contract.checkEnvironment(environment)
          guard contract.namespace == target.namespace, contract.typeID == target.typeID,
            target.wantedDigest == nil || target.wantedDigest == contract.digest else { throw ServiceFailure.protocolFailure }
          let offered = try item.optional("offer")
          guard (offered != nil) == (contract.semantics == .execution) else { throw ServiceFailure.protocolFailure }
          let offer = try offered.map { try AdmissionOffer(canonical: $0.bytes(), contract: contract, maximumWindowMS: target.maximumOfferWindowMS) }
          snapshot = ServiceContractSnapshot(contract: contract, offer: offer)
        } else {
          guard item.count == 2 else { throw ServiceFailure.protocolFailure }
        }
        results.append(ServiceContractQueryResult(status: status, snapshot: snapshot)); index += 1
        contract = nil; contractDocument = nil; contractBytes = Data(); contractCopyOffset = 0
        contractHash = nil; contractHashOffset = 0
        if index < targets.count { return true }
        let waiting = continuation; continuation = nil; waiting?.resume(returning: results); collect(); return false
      } catch {
        let waiting = continuation; continuation = nil; waiting?.resume(throwing: error); collect(); return false
      }
    }
  }
  private func collect() {
    payload = nil; envelope = nil; envelopeDocument = nil; contractDocument = nil; contract = nil
    contractBytes = Data(); contractHash = nil; storage = nil; queryOwner = nil; position = nil; results.removeAll()
  }
  func cancel() {
    gate.withLock {
      guard !canceled else { return }; canceled = true
      let waiting = continuation; continuation = nil; waiting?.resume(throwing: CancellationError())
    }
  }
}

extension Session {
  public func queryContracts(_ targets: [ServiceContractQueryTarget], target: ServiceBindingTarget,
    binding: ServiceContractQueryBinding, deadlineAtMS: UInt64) async throws -> [ServiceContractQueryResult] {
    try await v4QueryContracts(targets, target: target, binding: binding, deadlineAtMS: deadlineAtMS, before: nil)
  }
  func v4QueryContracts(_ targets: [ServiceContractQueryTarget], target: ServiceBindingTarget,
    binding: ServiceContractQueryBinding, deadlineAtMS: UInt64,
    before: (@Sendable () throws -> Void)?,
    position: V4ContractFetchPosition? = nil) async throws -> [ServiceContractQueryResult] {
    guard let session = self as? any V4ServiceSession else { throw ServiceFailure.serviceUnavailable }
    let channel = try await session.openServiceChannel(.interactive, deadlineAtMS: deadlineAtMS)
    try session.serviceEnvironment.gate.withLock {
      try before?(); try session.checkServiceAdmission(); try target.check(session.serviceIdentity)
    }
    let environment = session.serviceEnvironment
    guard (1...8).contains(targets.count), Set(targets.map { "\($0.namespace):\($0.typeID)" }).count == targets.count,
      let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS,
      deadlineAtMS - interval.lowerMS <= binding.maximumLifetimeMS else { throw ServiceFailure.configurationCapacity }
    for target in targets { try target.known?.contract.checkEnvironment(environment) }
    let originalPosition = try position ?? environment.serviceContracts().acquire(session: session)
    let storage = try originalPosition.storage ?? environment.serviceQueryStorage(responseBytes: targets.count * 9216)
    let registry = try V4NamespaceRegistry()
    let group = try environment.applicationGroup()
    let queryOwner = try originalPosition.queryOwner ?? group.executor.reserveQueryOwner(group: group)
    originalPosition.queryOwner = queryOwner; originalPosition.storage = storage
    let payload = V4Crypto.map([(0, V4NamespaceValue.head(4, UInt64(targets.count)) + targets.reduce(Data()) { $0 + $1.encoded() })])
    guard payload.count <= 2048 else { throw ServiceFailure.configurationCapacity }
    _ = try V4NamespaceDocument(payload, schema: "ContractTargets", bytes: 2048, nodes: 80, registry: registry)
    let header = try V4ApplicationHeader(kind: "query_contracts_request", fields: [2: .uint(UInt64(binding.typeID)),
      3: .uint(UInt64(payload.count)), 5: .uint(deadlineAtMS), 6: .bytes(binding.contractDigest)], registry: channel.registry)
    let (serial, response) = try await channel.enqueue(header: header, payload: payload, responseCapacity: targets.count * 9216,
      expectsResponse: true, query: true, queryOwner: queryOwner, queryPosition: originalPosition, guardHeader: {
        try before?(); try session.checkServiceAdmission(); try target.check(session.serviceIdentity)
        guard let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
      })
    do {
      let result = try await response.take()
      guard result.header.kind == "query_contracts_response" else { throw ServiceFailure.serviceUnavailable }
      let decoder = V4ContractSnapshotDecode(environment: environment, targets: targets, payload: result.payload, storage: storage, queryOwner: queryOwner, position: originalPosition, registry: registry)
      let results = try await decoder.result(executor: group.executor.fixedQueries)
      try await response.waitPhysicalExit()
      try session.serviceEnvironment.gate.withLock {
        try before?(); try session.checkServiceSession(); try target.check(session.serviceIdentity)
      }
      guard let interval = environment.clock.sample().interval, interval.upperMS < deadlineAtMS else { throw ServiceFailure.deadlineExceeded }
      return results
    } catch { try? await channel.abandon(serial); throw error }
  }
}
