import Foundation
import XCTest
@testable import Flowersec

private func v4ServiceSemaphoreSignaled(_ semaphore: DispatchSemaphore) -> Bool {
  semaphore.wait(timeout: .now()) == .success
}
private let v4ServiceTestDirectory = packageRoot().appendingPathComponent(".flowersec")

private final class V4ServiceTestTimeSource: V4MonotonicSource, @unchecked Sendable {
  private let gate = NSLock()
  private var milliseconds: UInt64 = 0
  func read() throws -> V4MonotonicTick { gate.withLock { V4MonotonicTick(milliseconds: milliseconds, incarnation: 1) } }
  func advance(to value: UInt64) { gate.withLock { precondition(value >= milliseconds); milliseconds = value } }
}

final class ServiceApplicationWireV4Tests: XCTestCase {
  func testRPCFragmentUsesIndependentFixedOffsetsAndBoundary() throws {
    let header = Data([0xa1, 0x00, 0x0a])
    let begin = try V4RPCFragment(kind: .begin, serial: 0x0102030405060708, replyTo: 9, payload: header).encoded()
    XCTAssertEqual(begin, Data([
      0, 0, 0, 22, 0, 1, 2, 3, 4, 5, 6, 7, 8,
      0, 0, 0, 0, 0, 0, 0, 9, 0, 3, 0xa1, 0, 0x0a,
    ]))
    let data = try V4RPCFragment(kind: .data, serial: 9, offset: 0x01020304, payload: Data([0x80, 0xff])).encoded()
    XCTAssertEqual(data, Data([0, 0, 0, 15, 1, 0, 0, 0, 0, 0, 0, 0, 9, 1, 2, 3, 4, 0x80, 0xff]))
    let abort = try V4RPCFragment(kind: .abort, serial: 9, offset: 2).encoded()
    XCTAssertEqual(abort, Data([0, 0, 0, 13, 2, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 2]))
    let stop = try V4RPCFragment(kind: .stopOutput, serial: 9).encoded()
    XCTAssertEqual(stop, Data([0, 0, 0, 9, 3, 0, 0, 0, 0, 0, 0, 0, 9]))
    XCTAssertEqual(try V4RPCFragment(encoded: begin).replyTo, 9)
    XCTAssertEqual(try V4RPCFragment(encoded: data).offset, 0x01020304)
    XCTAssertEqual(try V4RPCFragment(kind: .data, serial: 1, payload: Data(count: 16_367)).encoded().count, 16_384)
    XCTAssertThrowsError(try V4RPCFragment(kind: .data, serial: 1, payload: Data(count: 16_368)))
    XCTAssertThrowsError(try V4RPCFragment(encoded: stop + Data([0])))
    XCTAssertThrowsError(try V4RPCFragment(encoded: Data(stop.dropLast())))
  }
  func testRegistryHeadersRejectExtraFieldsAndResponseIdentitySubstitution() throws {
    let registry = try V4ApplicationWireRegistry()
    let digest = Data(repeating: 7, count: 32)
    let request = try V4ApplicationHeader(kind: "execution_unary_request", fields: [
      1: .bytes(Data(repeating: 1, count: 32)), 2: .uint(3), 3: .uint(0),
      4: .bytes(Data(repeating: 2, count: 32)), 5: .uint(1000), 6: .bytes(digest), 7: .uint(0), 8: .uint(8),
    ], registry: registry)
    let reply = try V4ApplicationHeader(kind: "execution_unary_response", fields: [
      1: request.fields[1]!, 2: .uint(3), 3: .uint(8), 4: request.fields[4]!, 6: .bytes(digest),
    ], registry: registry)
    try reply.checkResponse(to: request, registry: registry)
    var substitution = reply.fields; substitution[1] = .bytes(Data(repeating: 9, count: 32))
    let substituted = try V4ApplicationHeader(kind: reply.kind, fields: substitution, registry: registry)
    XCTAssertThrowsError(try substituted.checkResponse(to: request, registry: registry))
    var extra = reply.fields; extra[5] = .uint(1)
    XCTAssertThrowsError(try V4ApplicationHeader(kind: reply.kind, fields: extra, registry: registry))
    XCTAssertEqual(try V4ApplicationHeader(encoded: request.encoded(), registry: registry), request)
    let noncanonical = Data([0xa2, 0x18, 0, 0x18, 10, 2, 1])
    XCTAssertThrowsError(try V4ApplicationHeader(encoded: noncanonical, registry: registry))
  }
  func testFixedQueryParserAdvancesOriginalLargeByteLeavesInBoundedSteps() throws {
    let registry = try V4NamespaceRegistry()
    let items = (0..<8).map { index in
      V4Crypto.map([(0, V4NamespaceValue.head(0, UInt64(index))), (1, V4NamespaceValue.head(0, 0)),
        (2, V4Crypto.bytes(Data(repeating: UInt8(index + 1), count: 8192)))])
    }
    let encoded = V4Crypto.map([(0, V4NamespaceValue.head(4, 8) + items.reduce(Data(), +))])
    let original = try V4NamespaceDocument(encoded, schema: "ContractSnapshots", bytes: 73728, nodes: 1024,
      registry: registry, cooperative: true)
    var turns = 0
    while !original.parsingComplete {
      let copied = original.bytes.count; let scanned = original.queryParsingOffset
      _ = try original.advanceQueryParsing(); turns += 1
      XCTAssertLessThanOrEqual(original.bytes.count - copied, 4096)
      XCTAssertLessThanOrEqual(original.queryParsingOffset - scanned, 4096)
      XCTAssertLessThan(turns, 512)
    }
    XCTAssertGreaterThan(turns, 16)
    let eager = try V4NamespaceDocument(encoded, schema: "ContractSnapshots", bytes: 73728, nodes: 1024, registry: registry)
    XCTAssertEqual(Data(original.root.raw), Data(eager.root.raw))
    XCTAssertEqual(try original.root.field("items").children.map { try $0.u("target_index") }, Array(0..<8).map(UInt64.init))
    XCTAssertTrue(try original.root.field("items").children.allSatisfy { try $0.b("contract").count == 8192 })
    XCTAssertThrowsError(try V4NamespaceDocument(encoded + Data([0]), schema: "ContractSnapshots", bytes: 73728,
      nodes: 1024, registry: registry).root)
  }

  func testLocalProfilesKeepIndependentRunningAndReadyBounds() throws {
    XCTAssertEqual(ApplicationResourceProfile.client.ordinaryRunning, 26)
    XCTAssertEqual(ApplicationResourceProfile.server.ordinaryRunning, 26)
    XCTAssertEqual(ApplicationResourceProfile.client.ordinaryReady, 52)
    XCTAssertEqual(ApplicationResourceProfile.server.residentRunning, 18)
    XCTAssertEqual(ApplicationResourceProfile.server.residentReady, 36)
    XCTAssertEqual(ApplicationResourceProfile.constrained.ordinaryRunning, 8)
    XCTAssertEqual(ApplicationResourceProfile.constrained.ordinaryReady, 16)
    XCTAssertEqual(ApplicationResourceProfile.constrained.queryOwnerLimit, 6)
    XCTAssertThrowsError(try ApplicationResourceProfile.custom(ordinaryRunning: 0, ordinaryReady: 1,
      residentRunning: 0, residentReady: 0, ordinaryBackingBytes: 8192, queryOwners: 1))
  }
}

@MainActor
final class ServiceApplicationOwnershipV4Tests: XCTestCase {
  private var timeSources: [ObjectIdentifier: V4ServiceTestTimeSource] = [:]
  private func environment(profile: ApplicationResourceProfile = .client,
    initialTime: V4TimeInterval = V4TimeInterval(lowerMS: 1000, upperMS: 1000)) throws -> V4EnvironmentFoundation {
    let limit = V4ResourceVector(sdkBytes: 4 << 30, providerBytes: 1 << 30, diskBytes: 1 << 30,
      items: 65_536, work: 256, tasks: 256, timers: 256, connections: 256, handshakes: 256, sessions: 256, handles: 4096)
    let root = try V4ResourceRoot(V4ResourceRootConfiguration(limit: limit, accounts: 32, reservations: 8192,
      references: 16_384, cleanupWaiters: 16, runtimeOverheadBytes: 1024))
    let tenant = try root.account(kind: .tenant, identity: V4ResourceIdentity(high: 19, low: 1), limit: limit)
    let source = V4ServiceTestTimeSource()
    let environment = try V4EnvironmentFoundation(root: root, tenant: tenant, configuration: V4EnvironmentConfiguration(
      identity: V4ResourceIdentity(high: 19, low: 2), limit: limit, maximumReadBudgets: 8, maximumWork: 8,
      runtimeOverheadBytes: 1024, cleanupTimeout: .seconds(1), verificationContinuity: .onlineBootstrap,
      applicationResources: profile), timeProfile: V4TimeProfile(rateNumerator: 0, rateDenominator: 1,
        quantizationMS: 0, maximumWidthMS: 100, maximumAnchorAgeMS: 100_000), monotonicSource: source)
    try environment.clock.installTrusted(at: environment.clock.mark(), interval: initialTime)
    timeSources[ObjectIdentifier(environment)] = source
    return environment
  }
  private func advanceTime(_ environment: V4EnvironmentFoundation, to milliseconds: UInt64) throws {
    try XCTUnwrap(timeSources[ObjectIdentifier(environment)]).advance(to: milliseconds - 1000)
  }
  private func request(registry: V4ApplicationWireRegistry) throws -> V4ApplicationHeader {
    try V4ApplicationHeader(kind: "transient_unary_request", fields: [2: .uint(7), 3: .uint(0), 5: .uint(30_000),
      6: .bytes(Data(repeating: 8, count: 32)), 7: .uint(0), 8: .uint(32)], registry: registry)
  }
  func testCanceledResponseWaiterLeavesOriginalResultForRejoiningWaiter() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let registry = try V4ApplicationWireRegistry(); let header = try request(registry: registry)
    let owner = V4RPCOperation(request: header, responseCapacity: 32, expectsResponse: true, query: false,
      storage: try environment.serviceOperationStorage(requestBytes: 0, responseBytes: 32))
    owner.acceptHeaderBytes(1)
    let interrupted = Task { try await owner.take() }
    await Task.yield(); interrupted.cancel()
    do { _ = try await interrupted.value; XCTFail("Canceled wait must not receive an outcome") } catch is CancellationError { }
    let response = try V4ApplicationHeader(kind: "transient_unary_response", fields: [2: .uint(7), 3: .uint(2),
      6: .bytes(Data(repeating: 8, count: 32))], registry: registry)
    owner.complete(.success(V4RPCResponse(header: response, payload: Data([1, 2]))))
    XCTAssertTrue(owner.headerSubmitted)
    let result = try await owner.take()
    XCTAssertEqual(result.payload, Data([1, 2]))
    do { _ = try await owner.take(); XCTFail("Original encoding must be consumed once") } catch { XCTAssertEqual(error as? ServiceFailure, .closed) }
  }
  func testDedicatedStreamingPositionSharesKButDoesNotConsumeQ2() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let position = try await channel.reserveDedicatedRequest()
    do { _ = try await channel.reserveDedicatedRequest(); XCTFail("K must include dedicated streams") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    let header = try request(registry: channel.registry)
    do { _ = try await channel.enqueue(header: header, payload: Data(), responseCapacity: 32, expectsResponse: true, guardHeader: {})
      XCTFail("Unary and streaming must share K") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    let query = try V4ApplicationHeader(kind: "query_contracts_request", fields: [2: .uint(9), 3: .uint(0),
      5: .uint(30_000), 6: .bytes(Data(repeating: 4, count: 32))], registry: channel.registry)
    _ = try await channel.enqueue(header: query, payload: Data(), responseCapacity: 9216, expectsResponse: true, query: true, guardHeader: {})
    _ = try await channel.enqueue(header: query, payload: Data(), responseCapacity: 9216, expectsResponse: true, query: true, guardHeader: {})
    do { _ = try await channel.enqueue(header: query, payload: Data(), responseCapacity: 9216, expectsResponse: true, query: true, guardHeader: {})
      XCTFail("Q2 must remain finite") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    await channel.releaseDedicatedRequest(position); await channel.close()
  }
  func testSharedQueryOwnerCapReturnsOnlyOriginalReleasedPosition() throws {
    let environment = try environment(profile: .constrained); defer { environment.beginClose() }
    let group = try environment.applicationGroup()
    var owners: [V4ApplicationQueryOwner] = []
    for _ in 0..<6 { owners.append(try group.executor.reserveQueryOwner(group: group)) }
    XCTAssertThrowsError(try group.executor.reserveQueryOwner(group: group))
    owners[0].release(); let replacement = try group.executor.reserveQueryOwner(group: group)
    owners[0].release()
    XCTAssertThrowsError(try group.executor.reserveQueryOwner(group: group))
    replacement.release(); for owner in owners { owner.release() }
  }
  func testProtectedManagementOwnersRemainAvailableWhenQueriesAreFull() throws {
    let environment = try environment(profile: .constrained); defer { environment.beginClose() }
    let group = try environment.applicationGroup(); try group.executor.protectManagement()
    let queries = try (0..<6).map { _ in try group.executor.reserveQueryOwner(group: group) }
    defer { queries.forEach { $0.release() } }
    let first = try group.executor.reserveManagementOwner(group: group)
    let second = try group.executor.reserveManagementOwner(group: group)
    XCTAssertThrowsError(try group.executor.reserveManagementOwner(group: group))
    first.release(); let replacement = try group.executor.reserveManagementOwner(group: group)
    first.release()
    XCTAssertThrowsError(try group.executor.reserveManagementOwner(group: group))
    XCTAssertThrowsError(try group.executor.reserveQueryOwner(group: group))
    second.release(); replacement.release()
  }
  func testAbandonedQueryRetainsOwnerUntilNetworkAndPublisherExit() throws {
    let environment = try environment(profile: .constrained); defer { environment.beginClose() }
    let group = try environment.applicationGroup()
    var otherOwners: [V4ApplicationQueryOwner] = []
    for _ in 0..<5 { otherOwners.append(try group.executor.reserveQueryOwner(group: group)) }
    defer { for owner in otherOwners { owner.release() } }
    var originalOwner: V4ApplicationQueryOwner? = try group.executor.reserveQueryOwner(group: group)
    let registry = try V4ApplicationWireRegistry()
    let header = try V4ApplicationHeader(kind: "query_contracts_request", fields: [
      2: .uint(1), 3: .uint(0), 5: .uint(20_000), 6: .bytes(Data(repeating: 3, count: 32)),
    ], registry: registry)
    let pending = V4RPCOperation(request: header, responseCapacity: 32, expectsResponse: true, query: true,
      storage: try environment.serviceOperationStorage(requestBytes: 0, responseBytes: 32), queryOwner: originalOwner)
    originalOwner = nil
    pending.abandon()
    pending.complete(.failure(.serviceUnavailable))
    XCTAssertThrowsError(try group.executor.reserveQueryOwner(group: group))
    pending.finishPublication()
    let replacement = try group.executor.reserveQueryOwner(group: group)
    replacement.release()

    var nextOwner: V4ApplicationQueryOwner? = try group.executor.reserveQueryOwner(group: group)
    let next = V4RPCOperation(request: header, responseCapacity: 32, expectsResponse: true, query: true,
      storage: try environment.serviceOperationStorage(requestBytes: 0, responseBytes: 32), queryOwner: nextOwner)
    nextOwner = nil
    next.abandon(); next.finishPublication()
    XCTAssertThrowsError(try group.executor.reserveQueryOwner(group: group))
    next.complete(.failure(.serviceUnavailable))
    let afterInputExit = try group.executor.reserveQueryOwner(group: group)
    afterInputExit.release()
  }
  func testImportedReferenceContainsOnlySelectorAndRejectsOtherTrustedTarget() throws {
    let environment = try environment(); defer { environment.beginClose() }
    let peer = try ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 1, count: 32))
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client", peers: [peer])
    let reference = try OperationReference(target: target, authority: Data(repeating: 2, count: 32), namespace: "example.files",
      operation: V4Crypto.integer(10_000, width: 8) + Data(repeating: 3, count: 24), request: Data(repeating: 4, count: 32),
      contract: Data(repeating: 5, count: 32), shape: .unary, durable: true, deadline: 20_000, cancellation: true, limit: 32)
    let codec = try OperationReferenceCodec(environment: environment)
    var encoded = Data(count: 2048); let length = try codec.export(reference, into: &encoded)
    let imported = try codec.importReference(Data(encoded.prefix(length)), target: target)
    XCTAssertEqual(imported.operationID, reference.operationID)
    XCTAssertEqual(imported.requestDigest, reference.requestDigest)
    XCTAssertEqual(imported.serviceContractDigest, reference.serviceContractDigest)
    XCTAssertEqual(imported.resultLimit, 1_048_576)
    let other = try ServiceBindingTarget(authority: "other", tenant: "tenant", audience: "service", localSubject: "client", peers: [peer])
    XCTAssertThrowsError(try codec.importReference(Data(encoded.prefix(length)), target: other))
    codec.close()
  }
}

#if os(macOS) || os(iOS)
extension ServiceApplicationOwnershipV4Tests {
  private func executionStoreConfiguration(directory: URL, create: Bool, rows: Int = 2,
    resultBytes: Int = 2048, active: Int = 1, secretByte: UInt8 = 13, contentItems: Int = 0, contentBytes: Int = 0) throws -> SQLiteServiceExecutionConfiguration {
    SQLiteServiceExecutionConfiguration(directory: directory, authority: "example", storeID: Data(repeating: 11, count: 16),
      generation: 1, create: create, maximumHistoryRows: rows, maximumActive: active, maximumResultBytes: resultBytes,
      maximumDatabaseBytes: 2 << 20, checkpointKey: try ServiceCheckpointSigningKey(protection: .hmacSHA256,
        keyID: Data(repeating: 12, count: 16), secret: Data(repeating: secretByte, count: 32)), maximumContentItems: contentItems, maximumContentBytes: contentBytes, checkContinuity: {})
  }
  private func executionSelector(operation: UInt8 = 1, request: UInt8 = 2) -> V4ServerExecutionSelector {
    V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: "example.files", caller: "client",
      authority: Data(repeating: 3, count: 32), operation: Data(repeating: operation, count: 32),
      request: Data(repeating: request, count: 32), contract: Data(repeating: 4, count: 32))
  }
  func testExecutionStoreRestartPreservesCheckpointResultCapacityAndConsumesOnce() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-execution-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let selector = executionSelector()
    let original = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let admitted = try await original.admit(selector, deadline: 30_000, historyMS: 1000, responseBytes: 256)
    XCTAssertTrue(admitted); try await original.started(selector)
    let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1, 2, 3]))
    let issued = try await original.issue(selector, checkpoint: checkpoint, lifetimeMS: 10_000)
    await original.close()
    let reopened = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: false))
    let before = try await reopened.lookup(selector)
    XCTAssertEqual(before?.state, 5); XCTAssertEqual(before?.reservedBytes, 256)
    XCTAssertEqual(before?.generation, issued.generation); XCTAssertEqual(before?.checkpoint, checkpoint.encoded())
    let consumed = try await reopened.consume(selector, encodedToken: issued.encodedToken, protection: issued.protection,
      generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 4096)
    XCTAssertEqual(consumed, issued.generation + 1)
    try await reopened.complete(selector, payload: Data(), resultRetentionMS: 1000)
    let complete = try await reopened.lookup(selector)
    XCTAssertEqual(complete?.result, Data()); XCTAssertTrue(complete?.resultPresent == true)
    let metadata = try await reopened.lookup(selector, includeResult: false)
    XCTAssertNil(metadata?.result); XCTAssertTrue(metadata?.resultPresent == true)
    do {
      _ = try await reopened.consume(selector, encodedToken: issued.encodedToken, protection: issued.protection,
        generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 4096)
      XCTFail("A consumed durable checkpoint generation cannot be replayed")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    await reopened.close()
  }
  func testCheckpointIssuanceUsesTrustedLowerBoundAndKeepsOldExpiryAtConsumption() async throws {
    let environment = try environment(initialTime: V4TimeInterval(lowerMS: 1000, upperMS: 1100)); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-issuance-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let selector = executionSelector(); _ = try await store.admit(selector, deadline: 30_000, historyMS: 1000, responseBytes: 256)
    try await store.started(selector); let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1]))
    do { _ = try await store.issue(selector, checkpoint: checkpoint, lifetimeMS: 500, maximumIssuedDurationMS: 100)
      XCTFail("Current issuance policy cannot authorize a longer token") }
    catch { XCTAssertEqual(error as? ServiceFailure, .admissionWindowClosed) }
    let token = try await store.issue(selector, checkpoint: checkpoint, lifetimeMS: 500, maximumIssuedDurationMS: 500)
    XCTAssertEqual(token.expiresAtMS, 1500)
    do { _ = try await store.issue(selector, checkpoint: checkpoint, lifetimeMS: 500, maximumIssuedDurationMS: 500)
      XCTFail("The same durable scope cannot reset its issuance rate") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    try await store.complete(selector, payload: nil, resultRetentionMS: 0)
    // Consumption has only the new input byte bound. A new Session's smaller
    // issuance duration is not a rule for changing this original signed expiry.
    let generation = try await store.consume(selector, encodedToken: token.encodedToken, protection: token.protection,
      generation: token.generation, checkpoint: checkpoint, maximumTokenBytes: 4096)
    XCTAssertEqual(generation, token.generation + 1)
    await store.close()
  }
  func testRetainedResultBodyChecksOriginalReadBoundBeforeCopyAndExpiresViaMetadata() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-result-bound-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let selector = executionSelector(); let payload = Data([1, 2, 3, 4])
    _ = try await store.admit(selector, deadline: 30_000, historyMS: 1000, responseBytes: 256)
    try await store.started(selector)
    try await store.complete(selector, payload: payload, applicationCode: 17, resultRetentionMS: 50)
    do { _ = try await store.lookup(selector, maximumBodyBytes: 3); XCTFail("Read admission cannot allocate a larger original result body") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    let complete = try await store.lookup(selector, maximumBodyBytes: 4); XCTAssertEqual(complete?.result, payload)
    let metadata = try await store.lookup(selector, includeResult: false, maximumBodyBytes: 0)
    XCTAssertNil(metadata?.result); XCTAssertEqual(metadata?.resultBytes, 4)
    XCTAssertEqual(metadata?.state, 4); XCTAssertEqual(metadata?.resultCode, 17)
    try advanceTime(environment, to: 1100)
    let expired = try await store.lookup(selector, maximumBodyBytes: 0)
    XCTAssertNil(expired?.result); XCTAssertEqual(expired?.resultDeleted, true); XCTAssertEqual(expired?.reservedBytes, 0)
    await store.close()
  }
  func testExecutionWithoutRetentionStoresResultFactsWithoutBody() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-no-retention-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let selector = executionSelector(); let payload = Data([4, 5, 6])
    _ = try await store.admit(selector, deadline: 30_000, historyMS: 1000, responseBytes: 256)
    try await store.started(selector)
    try await store.complete(selector, payload: payload, applicationCode: 17, resultRetentionMS: 0)
    let observed = try await store.lookup(selector, maximumBodyBytes: 0)
    let record = try XCTUnwrap(observed)
    XCTAssertEqual(record.state, 4); XCTAssertEqual(record.resultCode, 17)
    XCTAssertEqual(record.resultBytes, UInt64(payload.count)); XCTAssertEqual(record.resultDigest?.count, 32)
    XCTAssertNil(record.result); XCTAssertFalse(record.resultPresent); XCTAssertFalse(record.resultDeleted)
    XCTAssertEqual(record.resultUntil, 0); XCTAssertEqual(record.reservedBytes, 0)
    await store.close()
  }
  func testExecutionStoreRejectsReplacedLockAndChangedCheckpointKey() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-lock-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let selector = executionSelector()
    _ = try await store.admit(selector, deadline: 30_000, historyMS: 1000, responseBytes: 256)
    let lock = directory.appendingPathComponent("execution.lock")
    let originalLock = directory.appendingPathComponent("original-lock")
    try FileManager.default.moveItem(at: lock, to: originalLock)
    XCTAssertTrue(FileManager.default.createFile(atPath: lock.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
    do { _ = try await store.lookup(selector); XCTFail("A different inode cannot inherit the original exclusive lock") }
    catch { XCTAssertEqual(error as? ServiceFailure, .permissionDenied) }
    await store.close()
    try FileManager.default.removeItem(at: lock); try FileManager.default.moveItem(at: originalLock, to: lock)
    do {
      _ = try SQLiteServiceExecutionStore(environment: environment,
        configuration: executionStoreConfiguration(directory: directory, create: false, secretByte: 14))
      XCTFail("The same key ID cannot silently replace the durable checkpoint signing key")
    } catch {
      let projection = try XCTUnwrap(error as? StorageFormatError).projection
      XCTAssertEqual(projection.reason, .identityMismatch); XCTAssertFalse(projection.observedRevision.known)
    }
    let reopened = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: false))
    let record = try await reopened.lookup(selector)
    XCTAssertEqual(record?.request, selector.request)
    await reopened.close()
  }
  func testOperationReferenceStoreRejectsReplacedExclusiveLock() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-reference-lock-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let peer = try ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 1, count: 32))
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client", peers: [peer])
    let configuration = SQLiteOperationReferenceConfiguration(directory: directory, target: target,
      storeID: Data(repeating: 2, count: 16), generation: 1, create: true, maximumRows: 2, maximumBytes: 1 << 20, checkContinuity: {})
    let store = try SQLiteOperationReferenceStore(environment: environment, configuration: configuration)
    let operation = Data(repeating: 3, count: 32)
    let missing = try await store.load(operationID: operation); XCTAssertNil(missing)
    let lock = directory.appendingPathComponent("operation-references.sqlite3.lock")
    try FileManager.default.moveItem(at: lock, to: directory.appendingPathComponent("original-lock"))
    XCTAssertTrue(FileManager.default.createFile(atPath: lock.path, contents: Data(), attributes: [.posixPermissions: 0o600]))
    do { _ = try await store.load(operationID: operation); XCTFail("Reference reads require the original locked inode") }
    catch { XCTAssertEqual(error as? ServiceFailure, .permissionDenied) }
    await store.close()
  }
  func testExecutionHistoryRetainsFiniteTombstonesAndFullWidthTimestamps() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-history-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 1))
    let selector = executionSelector(); let deadline = UInt64.max - 1000
    let admitted = try await store.admit(selector, deadline: deadline, historyMS: 500, responseBytes: 256)
    XCTAssertTrue(admitted)
    try await store.complete(selector, payload: nil, resultRetentionMS: 0)
    let record = try await store.lookup(selector)
    XCTAssertEqual(record?.deadline, deadline); XCTAssertEqual(record?.historyUntil, deadline + 500)
    let duplicate = try await store.admit(selector, deadline: deadline, historyMS: 500, responseBytes: 256)
    XCTAssertFalse(duplicate)
    do { _ = try await store.admit(executionSelector(request: 5), deadline: deadline, historyMS: 500, responseBytes: 256)
      XCTFail("The original operation cannot accept a different request") }
    catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    do { _ = try await store.admit(executionSelector(operation: 6), deadline: deadline, historyMS: 500, responseBytes: 256)
      XCTFail("Bounded completed history cannot grant a fresh execution slot") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    await store.close()
    do { _ = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: false, rows: 1, resultBytes: 4096))
      XCTFail("Reopening must preserve the declared durable quotas") }
    catch {
      let projection = try XCTUnwrap(error as? StorageFormatError).projection
      XCTAssertEqual(projection.reason, .identityMismatch); XCTAssertFalse(projection.observedRevision.known)
    }
  }
}
#endif

actor V4ApplicationInputTransport: V4RPCTransport {
  nonisolated let kind: String
  private var inbound = Data()
  private var waiting: CheckedContinuation<Void, Never>?
  private var closed = false
  private var closes = 0
  private var firstCloseHeld = false
  private var closeWaiting: CheckedContinuation<Void, Never>?
  private var inputEnded = false
  private var outbound = Data()
  private var writeClosed = false
  private var finished = false
  private var writesHeld = false
  private var writeWaiting: CheckedContinuation<Void, Never>?
  private var handoffsHeld = false
  private var handoffs: [(Int, @Sendable (Int, Bool) -> Void)] = []
  init(kind: String = "flowersec/notify-observation") { self.kind = kind }
  func push(_ bytes: Data) { inbound += bytes; waiting?.resume(); waiting = nil }
  func endInput() { inputEnded = true; waiting?.resume(); waiting = nil }
  func output() -> Data { outbound }
  func outputFinished() -> Bool { writeClosed && finished }
  func closeCount() -> Int { closes }
  func holdFirstClose() { firstCloseHeld = true }
  func closeIsWaiting() -> Bool { closeWaiting != nil }
  func inputIsWaiting() -> Bool { waiting != nil }
  func releaseClose() { firstCloseHeld = false; closeWaiting?.resume(); closeWaiting = nil }
  func holdWrites() { writesHeld = true }
  func releaseWrites() { writesHeld = false; writeWaiting?.resume(); writeWaiting = nil }
  func publicationWaiting() -> Bool { writeWaiting != nil }
  func holdHandoffs() { handoffsHeld = true }
  func handoffPending() -> Bool { !handoffs.isEmpty }
  func handoffCount() -> Int { handoffs.count }
  func releaseHandoffs(success: Bool = true) {
    handoffsHeld = false; let original = handoffs; handoffs.removeAll()
    for (bytes, completed) in original { completed(bytes, success) }
  }
  private func prepareWrite() async throws {
    while writesHeld && !closed { await withCheckedContinuation { writeWaiting = $0 } }
    guard !closed, !writeClosed else { throw ServiceFailure.closed }
  }
  func read(maxBytes: Int) async throws -> Data? {
    while inbound.isEmpty && !inputEnded && !closed {
      await withCheckedContinuation { waiting = $0 }
    }
    if inbound.isEmpty { return nil }
    let bytes = Data(inbound.prefix(maxBytes)); inbound.removeFirst(bytes.count); return bytes
  }
  func write(_ bytes: Data) async throws -> Int { try await prepareWrite(); outbound += bytes; return bytes.count }
  func writeRPCChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int {
    try await prepareWrite(); try beforeAccept(); outbound += bytes; accepted(bytes.count); return bytes.count
  }
  func writeRPCPublicationChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void, completed: @escaping @Sendable (Int, Bool) -> Void) async throws -> Int {
    do {
      try await prepareWrite(); try beforeAccept(); outbound += bytes; accepted(bytes.count)
      if handoffsHeld { handoffs.append((bytes.count, completed)) } else { completed(bytes.count, true) }
      return bytes.count
    } catch { completed(0, false); throw error }
  }
  func closeWrite() async throws { writeClosed = true }
  func finish() async throws { finished = true }
  func reset() async throws { try await close() }
  func close() async throws {
    closes += 1; closed = true; waiting?.resume(); waiting = nil; writeWaiting?.resume(); writeWaiting = nil
    releaseHandoffs(success: false)
    if firstCloseHeld && closes == 1 { await withCheckedContinuation { closeWaiting = $0 } }
  }
  func terminalError() async -> SessionError? { nil }
}
private final class V4ServiceDiagnosticEntropy: @unchecked Sendable {
  private let gate = NSLock()
  private var identifier: UInt64 = 0
  func bytes(_ count: Int) -> Data {
    gate.withLock {
      guard count == 16 else { return Data(repeating: 0, count: count) }
      identifier += 1
      return Data(count: 8) + V4Crypto.integer(identifier, width: 8)
    }
  }
}
private final class V4ServiceDiagnosticLog: @unchecked Sendable {
  private let gate = NSLock()
  private var events: [TransportDiagnosticEvent] = []
  var snapshot: [TransportDiagnosticEvent] { gate.withLock { events } }
  func append(_ event: TransportDiagnosticEvent) { gate.withLock { events.append(event) } }
}

private actor V4ControllerObservationLog {
  var notifications: [(Data, UInt64, ControllerNotificationSourcePhase)] = []
  var gaps = 0
  func record(_ event: ControllerNotificationEvent<Data>) {
    switch event {
    case .notification(let value, let generation, let phase): notifications.append((value, generation, phase))
    case .observationGap: gaps += 1
    }
  }
}
private actor V4ControllerCallbackHold {
  private var waiting: CheckedContinuation<Void, Never>?
  private var released = false
  func hold() async { if !released { await withCheckedContinuation { waiting = $0 } } }
  func release() { released = true; waiting?.resume(); waiting = nil }
}
private final class V4ControllerSourceFlags: @unchecked Sendable {
  private let gate = NSLock()
  private var drain = false
  func setDraining() { gate.withLock { drain = true } }
  func draining() -> Bool { gate.withLock { drain } }
}
extension ServiceApplicationOwnershipV4Tests {
  private func waitForObservation(_ predicate: @escaping @Sendable () async -> Bool) async throws {
    for _ in 0..<2000 {
      if await predicate() { return }
      try await ContinuousClock().sleep(for: .milliseconds(1))
    }
    XCTFail("The original observation state did not advance within its finite test window")
    throw ServiceFailure.deadlineExceeded
  }
  private func observationFixture(_ environment: V4EnvironmentFoundation) throws
    -> (ServiceDefinition, MethodDefinition, ServiceContract, ServiceBindingTarget, ServiceCallerIdentity) {
    let corpus = try JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
    let vector = try XCTUnwrap(corpus["vectors"].array?.first { $0["id"].text == "service_notify_observation" })
    let contract = try ServiceContract(environment: environment, canonical: v4RuleHex(XCTUnwrap(vector["hex"].text)))
    let message = try MessageDefinition(schemaDigest: Data(repeating: 7, count: 32), revision: "1", maxMessageBytes: 1_048_576)
    let method = try MethodDefinition(MethodDefinitionOptions(typeID: contract.typeID, shape: .notify, semantics: .observation,
      request: message, responseRevision: "1", requestMaxBytes: 1_048_576))
    let definition = try ServiceDefinition(namespace: contract.namespace, methods: [ServiceMethod(name: "changed", method: method)])
    let peer = try ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 8, count: 32))
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client", peers: [peer])
    let identity = ServiceCallerIdentity(tenant: "tenant", audience: "service", subject: "client", identityDigest: Data(repeating: 9, count: 32),
      peerSubject: peer.subject, peerIdentityDigest: peer.identityDigest)
    return (definition, method, contract, target, identity)
  }
  private func observationFrame(_ payload: Data, method: MethodDefinition, contract: ServiceContract) throws -> Data {
    let header = try V4ApplicationHeader(kind: "observation_notify", fields: [2: .uint(UInt64(method.typeID)),
      3: .uint(UInt64(payload.count)), 5: .uint(20_000), 6: .bytes(contract.digest)], registry: V4ApplicationWireRegistry()).encoded()
    return V4Crypto.integer(UInt64(header.count), width: 2) + header + payload
  }
  func testControllerCandidateQueuesLatestInputWithoutCallingHandlerBeforePublication() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract, target, identity) = try observationFixture(environment)
    let log = V4ControllerObservationLog()
    let root = try ControllerNotificationSubscription(environment: environment, definition: definition, method: method, target: target,
      snapshot: ServiceContractSnapshot(contract: contract), codec: BytesMessageCodec(definition: method.options.request),
      observation: .currentOnly, options: NotificationSubscriptionOptions(pendingPolicy: .latestPending),
      handler: { _, event in await log.record(event) })
    let receiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let source = V4ApplicationInputTransport(); let id = UUID()
    await root.attach(id: id, environment: environment, identity: identity, check: {}, candidate: false, receiver: receiver, draining: { false })
    await receiver.accept(source)
    await source.push(try observationFrame(Data([1]), method: method, contract: contract))
    await source.push(try observationFrame(Data([2]), method: method, contract: contract))
    try await waitForObservation { root.observationStatus().gap?.knownDropped == 1 }
    XCTAssertEqual(root.observationStatus().pending, 1)
    let before = await log.notifications; XCTAssertTrue(before.isEmpty)
    root.publish(id: id)
    try await waitForObservation { await log.notifications.count == 1 }
    let delivered = await log.notifications
    XCTAssertEqual(delivered.first?.0, Data([2])); XCTAssertEqual(delivered.first?.1, 1)
    root.close(); await receiver.close()
    try await waitForObservation { root.cleanupStatus().complete }
  }
  func testControllerLatestPendingReplacesInputsWaitingForActualDecoderActor() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract, target, identity) = try observationFixture(environment)
    let actor = V4ServiceEntryActor(); let decoder = await actor.decoderCallback
    let blocked = Task.detached { await actor.block() }
    try await waitForObservation { v4ServiceSemaphoreSignaled(actor.entered) }
    defer { actor.release.signal() }
    let log = V4ControllerObservationLog()
    let codec = AsyncClosureMessageCodec(definition: method.options.request, encode: { bytes, _ in bytes }, decode: decoder)
    let root = try ControllerNotificationSubscription(environment: environment, definition: definition, method: method, target: target,
      snapshot: ServiceContractSnapshot(contract: contract), codec: codec, observation: .currentOnly,
      options: NotificationSubscriptionOptions(pendingPolicy: .latestPending), handler: { _, event in await log.record(event) })
    defer { root.close() }
    let receiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let source = V4ApplicationInputTransport(); let id = UUID()
    await root.attach(id: id, environment: environment, identity: identity, check: {}, candidate: false, receiver: receiver, draining: { false })
    await receiver.accept(source); root.publish(id: id)
    await source.push(try observationFrame(Data([1]), method: method, contract: contract))
    try await waitForObservation { root.observationStatus().pending == 1 || root.observationStatus().callbackActive }
    // Selecting SDK work cannot deliver input while the decoder actor is blocked.
    for value: UInt8 in [2, 3] {
      await source.push(try observationFrame(Data([value]), method: method, contract: contract))
      try await waitForObservation { (root.observationStatus().gap?.knownDropped ?? 0) >= UInt64(value - 1) }
    }
    actor.release.signal(); await blocked.value
    try await waitForObservation { await log.notifications.count >= 1 && root.observationStatus().pending == 0 && !root.observationStatus().callbackActive }
    root.close(); await receiver.close()
    try await waitForObservation { root.cleanupStatus().complete }
    let values = await log.notifications
    XCTAssertEqual(values.map { $0.0 }, [Data([3])])
  }
  func testControllerDrainAwareLabelsRetainedSourceAndKeepsSingleRootQueue() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract, target, identity) = try observationFixture(environment)
    let log = V4ControllerObservationLog(); let flags = V4ControllerSourceFlags()
    let root = try ControllerNotificationSubscription(environment: environment, definition: definition, method: method, target: target,
      snapshot: ServiceContractSnapshot(contract: contract), codec: BytesMessageCodec(definition: method.options.request),
      observation: .drainAware, options: NotificationSubscriptionOptions(), handler: { _, event in await log.record(event) })
    let oldReceiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let newReceiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let old = V4ApplicationInputTransport(); let new = V4ApplicationInputTransport(); let a = UUID(); let b = UUID()
    await root.attach(id: a, environment: environment, identity: identity, check: {}, candidate: false, receiver: oldReceiver, draining: { flags.draining() })
    await oldReceiver.accept(old); root.publish(id: a)
    await root.attach(id: b, environment: environment, identity: identity, check: {}, candidate: false, receiver: newReceiver, draining: { false })
    await newReceiver.accept(new); root.publish(id: b)
    await old.push(try observationFrame(Data([3]), method: method, contract: contract))
    try await waitForObservation { await log.notifications.count == 1 }
    let retained = await log.notifications; XCTAssertEqual(retained.first?.2, .retained)
    flags.setDraining()
    await old.push(try observationFrame(Data([4]), method: method, contract: contract))
    await new.push(try observationFrame(Data([5]), method: method, contract: contract))
    try await waitForObservation { await log.notifications.count == 3 }
    let values = await log.notifications
    XCTAssertTrue(values.contains { $0.0 == Data([4]) && $0.1 == 1 && $0.2 == .draining })
    XCTAssertTrue(values.contains { $0.0 == Data([5]) && $0.1 == 2 && $0.2 == .current })
    XCTAssertEqual(root.observationStatus().observedSources, 2)
    root.close(); await oldReceiver.close(); await newReceiver.close()
    try await waitForObservation { root.cleanupStatus().complete }
  }
  func testControllerCurrentOnlyCountsOriginalActiveCallbackUntilItsActualExit() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract, target, identity) = try observationFixture(environment)
    let log = V4ControllerObservationLog(); let hold = V4ControllerCallbackHold()
    let root = try ControllerNotificationSubscription(environment: environment, definition: definition, method: method, target: target,
      snapshot: ServiceContractSnapshot(contract: contract), codec: BytesMessageCodec(definition: method.options.request),
      observation: .currentOnly, options: NotificationSubscriptionOptions(), handler: { _, event in
        await log.record(event); if case .notification = event { await hold.hold() }
      })
    let oldReceiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let newReceiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let thirdReceiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    let source = V4ApplicationInputTransport(); let a = UUID(); let b = UUID(); let c = UUID()
    await root.attach(id: a, environment: environment, identity: identity, check: {}, candidate: false, receiver: oldReceiver, draining: { false })
    await oldReceiver.accept(source); root.publish(id: a)
    await source.push(try observationFrame(Data([6]), method: method, contract: contract))
    try await waitForObservation { await log.notifications.count == 1 }
    await root.attach(id: b, environment: environment, identity: identity, check: {}, candidate: false, receiver: newReceiver, draining: { false })
    root.publish(id: b)
    await root.attach(id: c, environment: environment, identity: identity, check: {}, candidate: false, receiver: thirdReceiver, draining: { false })
    XCTAssertFalse(root.attached(id: c)); XCTAssertEqual(root.observationStatus().observedSources, 2)
    root.close(); XCTAssertFalse(root.cleanupStatus().complete)
    await source.push(try observationFrame(Data([7]), method: method, contract: contract))
    await hold.release(); await oldReceiver.close(); await newReceiver.close(); await thirdReceiver.close()
    try await waitForObservation { root.cleanupStatus().complete }
    let values = await log.notifications; XCTAssertEqual(values.count, 1)
  }
  func testControllerGapCallbackErrorDoesNotReenterTheSameGapForever() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract, target, _) = try observationFixture(environment)
    let log = V4ControllerObservationLog()
    let root = try ControllerNotificationSubscription(environment: environment, definition: definition, method: method, target: target,
      snapshot: ServiceContractSnapshot(contract: contract), codec: BytesMessageCodec(definition: method.options.request),
      observation: .currentOnly, options: NotificationSubscriptionOptions(), handler: { _, event in
        await log.record(event); throw ServiceFailure.serviceFailed
      })
    root.noteLateAttachment(); root.publish(id: UUID())
    try await waitForObservation { await log.gaps == 1 && !root.observationStatus().callbackActive }
    for _ in 0..<20 { await Task.yield() }
    let attempts = await log.gaps; XCTAssertEqual(attempts, 1)
    XCTAssertTrue(root.observationStatus().gap?.reasons.contains(.handlerError) == true)
    root.close()
  }
}

#if os(macOS) || os(iOS)
private actor V4ServiceServerInvocationLog {
  var values: [Data] = []
  func record(_ value: Data) { values.append(value) }
}
private actor V4ServiceServerResumeLog {
  var issued: IssuedServiceCheckpoint?
  var checkpoints: [ApplicationCheckpoint] = []
  func recordIssued(_ value: IssuedServiceCheckpoint) { issued = value }
  func recordResume(_ value: ApplicationCheckpoint) { checkpoints.append(value) }
}
private func v4ServiceTestRPCFrames(_ encoded: Data) throws -> [V4RPCFragment] {
  var offset = 0
  var frames: [V4RPCFragment] = []
  while offset < encoded.count {
    guard encoded.count - offset >= 4 else { throw ServiceFailure.protocolFailure }
    let length = encoded[offset..<offset + 4].reduce(0) { $0 << 8 | Int($1) }
    guard length <= 16_380, encoded.count - offset - 4 >= length else { throw ServiceFailure.protocolFailure }
    frames.append(try V4RPCFragment(encoded: Data(encoded[offset..<offset + length + 4])))
    offset += length + 4
  }
  return frames
}
private func v4ServiceTestMessage(_ encoded: Data) throws -> (V4ApplicationHeader, Data) {
  guard encoded.count >= 2 else { throw ServiceFailure.protocolFailure }
  let length = encoded.prefix(2).reduce(0) { $0 << 8 | Int($1) }
  guard (1...512).contains(length), encoded.count >= 2 + length else { throw ServiceFailure.protocolFailure }
  let header = try V4ApplicationHeader(encoded: Data(encoded[2..<2 + length]), registry: V4ApplicationWireRegistry())
  guard encoded.count == 2 + length + (try header.payloadBytes) else { throw ServiceFailure.protocolFailure }
  return (header, Data(encoded.dropFirst(2 + length)))
}
extension ServiceApplicationOwnershipV4Tests {
  private func serverFixture(_ environment: V4EnvironmentFoundation, vectorID: String,
    replacing: [Int: Data] = [:], omitting: Set<Int> = [],
    content: StreamContentDefinition? = nil, additionalMethods: [ServiceMethod] = []) throws
    -> (ServiceDefinition, MethodDefinition, ServiceContract) {
    let corpus = try JSONDecoder().decode(V4JSON.self,
      from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
    let vector = try XCTUnwrap(corpus["vectors"].array?.first { $0["id"].text == vectorID })
    let source = try v4RuleHex(XCTUnwrap(vector["hex"].text))
    let original = try V4NamespaceDocument(source, schema: "ServiceContract", bytes: 8192, nodes: 1024,
      registry: V4NamespaceRegistry()).root
    let canonical = V4Crypto.map((0..<29).compactMap { id -> (UInt64, Data)? in
      guard !omitting.contains(id) else { return nil }
      if let replacement = replacing[id] { return (UInt64(id), replacement) }
      guard let field = original.optionalID(id) else { return nil }
      return (UInt64(id), Data(field.raw))
    })
    let contract = try ServiceContract(environment: environment, canonical: canonical)
    let value = try V4NamespaceDocument(canonical, schema: "ServiceContract", bytes: 8192, nodes: 1024,
      registry: V4NamespaceRegistry()).root
    let request = try MessageDefinition(schemaDigest: Data(repeating: 7, count: 32),
      revision: value.t("request_schema_revision"), maxMessageBytes: 1_048_576)
    let responseRevision = try value.t("response_schema_revision")
    let response = contract.shape == .notify ? nil : try MessageDefinition(schemaDigest: Data(repeating: 8, count: 32),
      revision: responseRevision, maxMessageBytes: 1_048_576)
    let errors = try value.field("application_error_catalog").children.map { entry in
      try ApplicationErrorDefinition(code: UInt32(entry.u("code")),
        message: MessageDefinition(schemaDigest: entry.b("schema_digest"), revision: entry.t("schema_revision"),
          maxMessageBytes: max(1, Int(entry.u("max_payload_bytes")))), maxPayloadBytes: Int(entry.u("max_payload_bytes")))
    }
    let streaming = contract.shape == .serverStreaming ? try StreamingLimits(maxItemCount: UInt32(contract.uint(24)),
      maxPayloadBytes: contract.uint(25), maxDurationMS: contract.uint(26)) : nil
    let method = try MethodDefinition(MethodDefinitionOptions(typeID: contract.typeID, shape: contract.shape,
      semantics: contract.semantics, request: request, response: response, responseRevision: responseRevision,
      requestMaxBytes: 1_048_576, minResponseLimitBytes: Int(contract.uint(9)), maxResponseBytes: Int(contract.uint(10)),
      requireDurable: contract.optionalUInt(13) == 1, checkpointFormat: value.optional("checkpoint_format")?.text(),
      restartFlushDeadlineMS: contract.optionalUInt(22), streaming: streaming, content: content, errors: errors))
    let definition = try ServiceDefinition(namespace: contract.namespace, methods: [ServiceMethod(name: "operation", method: method)] + additionalMethods)
    return (definition, method, contract)
  }
  private func serverCaller() throws -> ServiceServerCaller {
    try ServiceServerCaller(subject: "client", identityDigest: Data(repeating: 9, count: 32),
      executionAuthority: Data(repeating: 3, count: 32))
  }
  private func serverIdentity() -> ServiceCallerIdentity {
    ServiceCallerIdentity(tenant: "tenant", audience: "service", subject: "server", identityDigest: Data(repeating: 8, count: 32),
      peerSubject: "client", peerIdentityDigest: Data(repeating: 9, count: 32))
  }
  private func serverQueryBinding() throws -> ServiceContractQueryBinding {
    try ServiceContractQueryBinding(typeID: 12345, contractDigest: Data(repeating: 6, count: 32))
  }
  private func serverRequest(_ method: MethodDefinition, contract: ServiceContract, payload: Data,
    kindOverride: String? = nil, responseLimitBytes: UInt64? = nil, operationByte: UInt8 = 4, clockMS: UInt64 = 1000) throws -> V4ApplicationHeader {
    let registry = try V4ApplicationWireRegistry()
    let execution = method.semantics == .execution
    let kind: String
    if let kindOverride { kind = kindOverride }
    else if method.shape == .notify { kind = execution ? "execution_notify" : "observation_notify" }
    else if method.shape == .serverStreaming { kind = execution ? "execution_stream_request" : "transient_stream_request" }
    else { kind = execution ? "execution_unary_request" : "transient_unary_request" }
    let cutoff = execution ? clockMS + min(try contract.uint(16), 1000) : 0
    let deadline = execution ? cutoff + min(try contract.uint(17), 10_000) : clockMS + min(try contract.uint(11), 10_000)
    var fields: [Int: V4ApplicationHeader.Scalar] = [2: .uint(UInt64(method.typeID)), 3: .uint(UInt64(payload.count)),
      5: .uint(deadline), 6: .bytes(contract.digest)]
    if method.shape != .notify || execution { fields[7] = .uint(0); fields[8] = .uint(try responseLimitBytes ?? contract.uint(10)) }
    if execution {
      fields[1] = .bytes(V4Crypto.integer(cutoff, width: 8) + Data(repeating: operationByte, count: 24))
      fields[4] = .bytes(Data(repeating: 0, count: 32))
      let unsigned = try V4ApplicationHeader(kind: kind, fields: fields, registry: registry)
      fields[4] = .bytes(try contract.executionRequestDigest(header: unsigned, payload: payload))
    }
    return try V4ApplicationHeader(kind: kind, fields: fields, registry: registry)
  }
  func testServerUnaryKeepsOriginalKPositionThroughBlockedPublication() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_transient")
    let binding = try serverQueryBinding()
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: binding))
    let log = V4ServiceServerInvocationLog(); let hold = V4ControllerCallbackHold()
    let responseCodec = BytesMessageCodec(definition: try XCTUnwrap(method.options.response))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request), responseCodec: responseCodec) { _, _, value in
        await log.record(value); await hold.hold(); return value
      }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    await source.holdWrites(); try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([1, 2, 3]); let header = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: header.encoded()).encoded())
    try await waitForObservation { server.generalPositionCount == 1 }
    XCTAssertThrowsError(try server.reserveRequest(header))
    let query = try V4ApplicationHeader(kind: "query_contracts_request", fields: [2: .uint(UInt64(binding.typeID)),
      3: .uint(0), 5: .uint(20_000), 6: .bytes(binding.contractDigest)], registry: channel.registry)
    XCTAssertNil(try server.reserveRequest(query))
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { await log.values.count == 1 }
    await hold.release()
    try await waitForObservation { await source.publicationWaiting() }
    XCTAssertThrowsError(try server.reserveRequest(header))
    await source.releaseWrites()
    try await waitForObservation {
      guard let frames = try? v4ServiceTestRPCFrames(await source.output()) else { return false }
      return frames.last?.kind == .data && frames.last?.payload == payload
    }
    let frames = try v4ServiceTestRPCFrames(await source.output())
    XCTAssertEqual(frames.count, 2); XCTAssertEqual(frames.first?.replyTo, 1)
    let response = try V4ApplicationHeader(encoded: XCTUnwrap(frames.first).payload, registry: channel.registry)
    try response.checkResponse(to: header, registry: channel.registry)
    try await waitForObservation { server.generalPositionCount == 0 }
    await channel.close(); registry.close()
  }
  func testServerUnknownTypeDrainsOriginalInputAndKeepsRPCChannelAvailable() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_transient")
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding()))
    let log = V4ServiceServerInvocationLog()
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value in
        await log.record(value); return value
      }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([1, 2, 3]); let request = try serverRequest(method, contract: contract, payload: payload)
    var fields = request.fields; fields.removeValue(forKey: 0)
    fields[2] = .uint(method.typeID == 1 ? 2 : 1)
    let unknown = try V4ApplicationHeader(kind: request.kind, fields: fields, registry: channel.registry)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: unknown.encoded()).encoded())
    try await waitForObservation { server.generalPositionCount == 1 }
    let beforeBody = await source.output(); XCTAssertTrue(beforeBody.isEmpty)
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation {
      guard let frames = try? v4ServiceTestRPCFrames(await source.output()) else { return false }
      return frames.count == 2 && frames.last?.kind == .data
    }
    let rejected = try v4ServiceTestRPCFrames(await source.output())
    let refusal = try V4ApplicationHeader(encoded: XCTUnwrap(rejected.first).payload, registry: channel.registry)
    try refusal.checkResponse(to: unknown, registry: channel.registry)
    XCTAssertEqual(refusal.kind, "transient_unary_sdk_error")
    XCTAssertEqual(try contract.decodeServiceFailure(XCTUnwrap(rejected.last).payload), .contractMismatch)
    let deniedCalls = await log.values; XCTAssertTrue(deniedCalls.isEmpty)
    try await waitForObservation { server.generalPositionCount == 0 }
    await source.push(try V4RPCFragment(kind: .begin, serial: 2, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 2, payload: payload).encoded())
    try await waitForObservation {
      guard let frames = try? v4ServiceTestRPCFrames(await source.output()) else { return false }
      return frames.count == 4 && frames.last?.payload == payload
    }
    let accepted = try v4ServiceTestRPCFrames(await source.output())
    XCTAssertEqual(accepted[2].replyTo, 2)
    let values = await log.values; XCTAssertEqual(values, [payload])
    await channel.close(); registry.close()
  }
  func testServerFixedContractQueryKeepsOwnerThroughBlockedResponsePublication() async throws {
    let environment = try environment(profile: .constrained); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_transient")
    let binding = try serverQueryBinding()
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: binding))
    let log = V4ServiceServerInvocationLog()
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value in
        await log.record(value); return value
      }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    await source.holdWrites(); try await channel.bindInbound(server); try await channel.start { source }
    let target = try ServiceContractQueryTarget(namespace: contract.namespace, typeID: contract.typeID,
      maximumOfferWindowMS: 30_000)
    let payload = V4Crypto.map([(0, V4NamespaceValue.head(4, 1) + target.encoded())])
    let request = try V4ApplicationHeader(kind: "query_contracts_request", fields: [2: .uint(UInt64(binding.typeID)),
      3: .uint(UInt64(payload.count)), 5: .uint(20_000), 6: .bytes(binding.contractDigest)], registry: channel.registry)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { await source.publicationWaiting() }
    XCTAssertEqual(server.generalPositionCount, 0)
    let group = try environment.applicationGroup()
    var remaining: [V4ApplicationQueryOwner] = []
    for _ in 1..<ApplicationResourceProfile.constrained.queryOwnerLimit {
      remaining.append(try group.executor.reserveQueryOwner(group: group))
    }
    XCTAssertThrowsError(try group.executor.reserveQueryOwner(group: group))
    await source.releaseWrites()
    try await waitForObservation {
      guard let frames = try? v4ServiceTestRPCFrames(await source.output()) else { return false }
      return frames.count == 2 && frames.last?.kind == .data
    }
    let frames = try v4ServiceTestRPCFrames(await source.output())
    let reply = try V4ApplicationHeader(encoded: XCTUnwrap(frames.first).payload, registry: channel.registry)
    try reply.checkResponse(to: request, registry: channel.registry)
    let result = try V4NamespaceDocument(XCTUnwrap(frames.last).payload, schema: "ContractSnapshots", bytes: 9216,
      nodes: 128, registry: V4NamespaceRegistry()).root
    let entry = try XCTUnwrap(result.field("items").children.first(where: { _ in true }))
    XCTAssertEqual(try entry.u("status"), 0)
    var original = Data(count: contract.encodedBytes); _ = try contract.copyEncoded(into: &original)
    XCTAssertEqual(try entry.b("contract"), original)
    let values = await log.values; XCTAssertTrue(values.isEmpty)
    for owner in remaining { owner.release() }; remaining.removeAll()
    await channel.close(); registry.close()
  }
  func testServerExecutionNotificationDispatchesWithoutObservationSubscribers() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-notify-server-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_notify_execution")
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    let caller = try serverCaller(); let log = V4ServiceServerInvocationLog(); let hold = V4ControllerCallbackHold()
    try registry.registerNotify(method, in: definition, contract: contract, callers: [caller],
      codec: BytesMessageCodec(definition: method.options.request)) { _, _, value in
        await log.record(value); await hold.hold()
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let receiver = try V4NotificationReceiver(environment: environment, storage: environment.notificationReceiverStorage())
    await receiver.bindServer(server)
    let source = V4ApplicationInputTransport(kind: "flowersec.notify.v4"); await receiver.accept(source)
    let payload = Data([4, 5, 6]); let request = try serverRequest(method, contract: contract, payload: payload)
    var rpcPosition = try server.reserveRequest(request)
    let encoded = request.encoded()
    await source.push(V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded + payload)
    try await waitForObservation { await log.values == [payload] }
    XCTAssertEqual(server.generalPositionCount, 1)
    rpcPosition = nil
    XCTAssertEqual(server.generalPositionCount, 0)
    await hold.release()
    let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
    try await waitForObservation { (try? await store.lookup(selector))?.state == 3 }
    let output = await source.output(); XCTAssertTrue(output.isEmpty)
    let group = try environment.applicationGroup()
    var queryOwners: [V4ApplicationQueryOwner] = []
    for _ in 0..<ApplicationResourceProfile.client.queryOwnerLimit {
      queryOwners.append(try group.executor.reserveQueryOwner(group: group))
    }
    let metadata = V4Crypto.map([(0, V4Crypto.text(selector.tenant)), (1, V4Crypto.text(selector.audience)),
      (2, V4Crypto.text(selector.namespace)), (3, V4Crypto.text(selector.caller)), (4, V4Crypto.bytes(selector.authority)),
      (5, V4Crypto.bytes(selector.operation)), (6, V4Crypto.bytes(selector.request)), (7, V4Crypto.bytes(selector.contract))])
    let encodedRegistry = try XCTUnwrap(JSONSerialization.jsonObject(with:
      Data(TransportV4Registry.applicationHeaderRegistryJSON.utf8)) as? [String: Any])
    let managementConfig = try XCTUnwrap(encodedRegistry["management"] as? [String: Any])
    let methods = try XCTUnwrap(managementConfig["methods"] as? [String: [String: Any]])
    let query = try XCTUnwrap(methods["query"])
    let type = try XCTUnwrap(V4NamespaceRegistry.number(query["type"]))
    let digest = try V4ExecutionManagementChannel.hex(XCTUnwrap(query["contract_digest_hex"] as? String))
    let managementRequest = try V4ApplicationHeader(kind: "query_operation_request", fields: [2: .uint(type),
      3: .uint(UInt64(metadata.count)), 5: .uint(20_000), 6: .bytes(digest), 9: .uint(1)], registry: V4ApplicationWireRegistry())
    let diagnosticLog = V4ServiceDiagnosticLog()
    let diagnosticEntropy = V4ServiceDiagnosticEntropy()
    try environment.installDiagnosticSink(TransportDiagnosticSinkConfiguration(samplingPartsPerMillion: 10_000) { event in
      diagnosticLog.append(event)
    }, random: { diagnosticEntropy.bytes($0) })
    let managementSource = V4ApplicationInputTransport(kind: "flowersec.execution-management.v4")
    let management = try V4ExecutionManagementChannel(environment: environment,
      storage: environment.executionManagementStorage(), initiates: false,
      factory: { throw ServiceFailure.serviceUnavailable })
    let managementHandler: V4ExecutionManagementHandler = { request, payload, diagnostic in
      try await server.handleManagementRequest(request, payload: payload, diagnostic: diagnostic)
    }
    await management.installHandler(managementHandler, checkSource: { try server.checkManagementSource() })
    await managementSource.holdHandoffs(); await management.acceptPeer(managementSource)
    let managementHeader = managementRequest.encoded()
    await managementSource.push(V4Crypto.integer(UInt64(managementHeader.count), width: 2) + managementHeader + metadata)
    try await waitForObservation {
      let pending = await managementSource.handoffCount()
      let output = await managementSource.output()
      return pending == 1 && (try? v4ServiceTestMessage(output)) != nil && diagnosticLog.snapshot.count == 1
    }
    let firstOutput = await managementSource.output()
    XCTAssertEqual(diagnosticLog.snapshot.map { $0.state }, [.started])
    var nextFields = managementRequest.fields; nextFields[9] = .uint(2)
    let nextRequest = try V4ApplicationHeader(kind: managementRequest.kind, fields: nextFields, registry: V4ApplicationWireRegistry())
    await managementSource.push(V4Crypto.integer(UInt64(nextRequest.encoded().count), width: 2) + nextRequest.encoded() + metadata)
    try await waitForObservation {
      let pending = await managementSource.handoffCount()
      return pending == 2 && diagnosticLog.snapshot.count == 2
    }
    let started = diagnosticLog.snapshot
    XCTAssertEqual(started.map { $0.state }, [.started, .started])
    XCTAssertNotEqual(started[0].correlationID, started[1].correlationID)
    await managementSource.releaseHandoffs(success: false)
    try await waitForObservation { diagnosticLog.snapshot.count == 6 }
    let groupedDiagnostics = Dictionary(grouping: diagnosticLog.snapshot, by: { $0.correlationID })
    XCTAssertEqual(groupedDiagnostics.count, 2)
    for events in groupedDiagnostics.values { XCTAssertEqual(events.map { $0.state }, [.started, .failed, .closed]) }
    let (managementReply, body) = try v4ServiceTestMessage(firstOutput)
    try managementReply.checkResponse(to: managementRequest, registry: V4ApplicationWireRegistry())
    let managementOutput = await managementSource.output()
    let (nextReply, nextBody) = try v4ServiceTestMessage(Data(managementOutput.dropFirst(firstOutput.count)))
    try nextReply.checkResponse(to: nextRequest, registry: V4ApplicationWireRegistry())
    XCTAssertEqual(nextBody, body)
    let observed = try V4NamespaceDocument(body, schema: "QueryOperationResponse", bytes: 512, nodes: 64,
      registry: V4NamespaceRegistry()).root
    XCTAssertEqual(try observed.u("status"), 0)
    let facts = try observed.field("observation")
    XCTAssertEqual(facts.count, 13); XCTAssertEqual(try facts.u("state"), 3)
    XCTAssertTrue(try facts.field("dispatched").equals(true)); XCTAssertEqual(try facts.u("result_bytes"), 0)
    XCTAssertEqual(try facts.b("result_digest"), Data(repeating: 0, count: 32))
    for owner in queryOwners { owner.release() }; queryOwners.removeAll()
    await receiver.close(); await management.close(); server.close(); registry.close(); await store.close()
  }
  func testServerExecutionWithoutRetentionReturnsItsOriginalResponse() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-no-retention-server-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256)], omitting: [15])
    let caller = try serverCaller(); let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value in value }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([1, 2, 3]); let request = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation {
      let frames = try? v4ServiceTestRPCFrames(await source.output())
      return server.generalPositionCount == 0 && frames?.count == 2
    }
    let frames = try v4ServiceTestRPCFrames(await source.output())
    let response = try V4ApplicationHeader(encoded: frames[0].payload, registry: channel.registry)
    XCTAssertEqual(response.kind, "execution_unary_response"); XCTAssertEqual(frames[1].payload, payload)
    try response.checkResponse(to: request, registry: channel.registry)
    let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
    let record = try await store.lookup(selector, maximumBodyBytes: 0)
    XCTAssertEqual(record?.state, 3); XCTAssertEqual(record?.resultBytes, UInt64(payload.count))
    XCTAssertNil(record?.result); XCTAssertEqual(record?.resultPresent, false); XCTAssertEqual(record?.resultDeleted, false)
    await channel.close(); server.close(); registry.close(); await store.close()
  }

  func testServerResultReadUsesFixedContractCapacityAndOriginalRetainedBody() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-result-server-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256)])
    let (readDefinition, readMethod, readContract) = try serverFixture(environment, vectorID: "service_unary_transient",
      replacing: [1: V4NamespaceValue.head(0, 2), 10: V4NamespaceValue.head(0, 256)])
    let caller = try serverCaller(); let log = V4ServiceServerInvocationLog()
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value in
        await log.record(value); return value
      }
    try registry.registerResultRead(readMethod, in: readDefinition,
      binding: OperationResultReadBinding(contract: readContract), callers: [caller])
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([1, 2, 3]); let request = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation {
      let frames = try? v4ServiceTestRPCFrames(await source.output())
      return server.generalPositionCount == 0 && frames?.count == 2
    }
    let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
    let metadata = V4Crypto.map([(0, V4Crypto.text(selector.tenant)), (1, V4Crypto.text(selector.audience)),
      (2, V4Crypto.text(selector.namespace)), (3, V4Crypto.text(selector.caller)), (4, V4Crypto.bytes(selector.authority)),
      (5, V4Crypto.bytes(selector.operation)), (6, V4Crypto.bytes(selector.request)), (7, V4Crypto.bytes(selector.contract))])
    let readRequest = try V4ApplicationHeader(kind: "read_result_request", fields: [2: .uint(UInt64(readMethod.typeID)),
      3: .uint(UInt64(metadata.count)), 5: .uint(20_000), 6: .bytes(readContract.digest)], registry: channel.registry)
    await source.holdWrites()
    await source.push(try V4RPCFragment(kind: .begin, serial: 2, payload: readRequest.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 2, payload: metadata).encoded())
    try await waitForObservation { await source.publicationWaiting() }
    XCTAssertEqual(server.generalPositionCount, 1)
    await source.releaseWrites()
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()))?.count == 4 }
    let frames = try v4ServiceTestRPCFrames(await source.output())
    let response = try V4ApplicationHeader(encoded: frames[2].payload, registry: channel.registry)
    XCTAssertEqual(response.kind, "read_result_response"); XCTAssertEqual(frames[2].replyTo, 2)
    XCTAssertEqual(frames[3].payload, payload); try response.checkResponse(to: readRequest, registry: channel.registry)
    let values = await log.values; XCTAssertEqual(values, [payload])
    try await waitForObservation { server.generalPositionCount == 0 }
    await channel.close(); server.close(); registry.close(); await store.close()
  }

  func testServerResumeConfirmsAcceptedTargetBeforeCallbackAndSettlesOriginalResult() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-resume-server-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 4, resultBytes: 16_384, active: 2))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256), 20: V4Crypto.text("cursor")])
    let (resumeDefinition, resumeMethod, resumeContract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [1: V4NamespaceValue.head(0, 2), 9: V4NamespaceValue.head(0, 4248),
        10: V4NamespaceValue.head(0, 4248), 20: V4Crypto.text("cursor")])
    let caller = try serverCaller(); let log = V4ServiceServerResumeLog(); let hold = V4ControllerCallbackHold()
    let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([7, 8]))
    let result = Data([4, 5, 6]); let originalCodec = BytesMessageCodec(definition: try XCTUnwrap(method.options.response))
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: method.options.request), responseCodec: originalCodec) { _, invocation, _ in
        let issued = try await invocation.issueCheckpoint(checkpoint, lifetimeMS: 5000)
        await log.recordIssued(issued); throw ServiceFailure.serviceUnavailable
      }
    try registry.registerResume(resumeMethod, in: resumeDefinition, contract: resumeContract, originalContract: contract,
      streamKind: "example.resume", callers: [caller], originalResponseCodec: originalCodec) { _, _, observed, _ in
        await log.recordResume(observed); await hold.hold(); return result
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 2,
      checkpointPolicy: { (8192, 10_000) }, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 2,
      storage: environment.rpcServicesStorage(maximumGeneral: 2, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([1, 2, 3]); let request = try serverRequest(method, contract: contract, payload: payload)
    let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation {
      let frames = try? v4ServiceTestRPCFrames(await source.output())
      return server.generalPositionCount == 0 && frames?.count == 2
    }
    let saved = await log.issued; let issued = try XCTUnwrap(saved)
    let interrupted = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(interrupted?.state, 5); XCTAssertEqual(interrupted?.reservedBytes, 256)
    let target = V4ApplicationInputTransport(kind: "example.resume")
    let contextDigest = Data(repeating: 5, count: 32)
    try server.adoptStream(id: 17, kind: target.kind, source: target, facts: (contextDigest, 17, 8192, 10_000), readable: { false })
    let resumePayload = V4Crypto.map([(0, V4Crypto.bytes(selector.operation)), (1, V4Crypto.bytes(selector.request)),
      (2, V4NamespaceValue.head(0, issued.protection.rawValue)), (3, V4Crypto.bytes(issued.encodedToken)),
      (4, V4NamespaceValue.head(0, issued.generation)), (5, checkpoint.encoded()),
      (6, V4Crypto.bytes(contextDigest)), (7, V4NamespaceValue.head(0, 17))])
    let resumeRequest = try serverRequest(resumeMethod, contract: resumeContract, payload: resumePayload,
      kindOverride: "resume_request", operationByte: 5)
    await source.holdWrites()
    await source.push(try V4RPCFragment(kind: .begin, serial: 2, payload: resumeRequest.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 2, payload: resumePayload).encoded())
    try await waitForObservation { await source.publicationWaiting() }
    let beforePublication = await log.checkpoints; XCTAssertTrue(beforePublication.isEmpty)
    XCTAssertEqual(server.generalPositionCount, 2)
    await source.releaseWrites()
    try await waitForObservation { await log.checkpoints == [checkpoint] }
    try await waitForObservation { server.generalPositionCount == 1 }
    let frames = try v4ServiceTestRPCFrames(await source.output())
    let confirmation = try V4ApplicationHeader(encoded: frames[2].payload, registry: channel.registry)
    XCTAssertEqual(confirmation.kind, "resume_response"); try confirmation.checkResponse(to: resumeRequest, registry: channel.registry)
    let accepted = try V4NamespaceDocument(frames[3].payload, schema: "ResumeResult", bytes: 4248, nodes: 32,
      registry: V4NamespaceRegistry()).root
    XCTAssertEqual(try accepted.u("status"), 0)
    let confirmationFacts = try accepted.field("progress")
    XCTAssertEqual(try confirmationFacts.u("new_generation"), issued.generation + 1)
    XCTAssertEqual(try ApplicationCheckpoint(confirmationFacts.field("confirmed_checkpoint")), checkpoint)
    let running = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(running?.state, 2); XCTAssertEqual(running?.generation, issued.generation + 1)
    await hold.release()
    try await waitForObservation { await target.outputFinished() }
    let complete = try await store.lookup(selector, maximumBodyBytes: 256)
    XCTAssertEqual(complete?.state, 3); XCTAssertEqual(complete?.result, result)
    try await waitForObservation { server.generalPositionCount == 0 }
    do {
      _ = try await store.consume(selector, encodedToken: issued.encodedToken, protection: issued.protection,
        generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 8192)
      XCTFail("The accepted original generation cannot be consumed twice")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    await channel.close(); server.close(); registry.close(); await store.close()
  }

  func testStreamingResumeKeepsOriginalHeaderBoundsAndTerminalFacts() async throws {
    for failureMode in 0...2 {
      let applicationFailure = failureMode == 1
      let sdkFailure = failureMode == 2
      let environment = try environment(); defer { environment.beginClose() }
      let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-stream-resume-" + UUID().uuidString)
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: directory) }
      let store = try SQLiteServiceExecutionStore(environment: environment,
        configuration: executionStoreConfiguration(directory: directory, create: true, rows: 4, resultBytes: 16_384, active: 2))
      let errors = V4NamespaceValue.head(4, 1) + V4Crypto.map([(0, V4NamespaceValue.head(0, 7)),
        (1, V4Crypto.text("example_error_v1")), (2, V4NamespaceValue.head(0, 2)),
        (3, V4Crypto.bytes(Data(repeating: 6, count: 32)))])
      let (definition, method, contract) = try serverFixture(environment, vectorID: "service_stream_execution",
        replacing: [10: V4NamespaceValue.head(0, 16), 20: V4Crypto.text("cursor"),
          24: V4NamespaceValue.head(0, 2), 25: V4NamespaceValue.head(0, 3), 27: errors])
      let (resumeDefinition, resumeMethod, resumeContract) = try serverFixture(environment, vectorID: "service_unary_execution",
        replacing: [1: V4NamespaceValue.head(0, 2), 9: V4NamespaceValue.head(0, 4248),
          10: V4NamespaceValue.head(0, 4248), 20: V4Crypto.text("cursor")])
      let binding = try ServiceStreamBinding(method: method, kind: "example.resume-items")
      let caller = try serverCaller(); let log = V4ServiceServerResumeLog(); let originalCalls = V4ServiceServerInvocationLog()
      let hold = V4ControllerCallbackHold(); let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1]))
      let itemCodec = BytesMessageCodec(definition: try XCTUnwrap(method.options.response))
      let registry = try ServiceRegistry(environment: environment,
        configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
      try registry.registerStream(binding, in: definition, contract: contract, callers: [caller],
        requestCodec: BytesMessageCodec(definition: method.options.request), itemCodec: itemCodec) { _, invocation, input, output in
          await originalCalls.record(input); try await output.write(Data([1]))
          let issued = try await invocation.issueCheckpoint(checkpoint, lifetimeMS: 5000)
          await log.recordIssued(issued); throw ServiceFailure.serviceUnavailable
        }
      try registry.registerStreamingResume(resumeMethod, in: resumeDefinition, contract: resumeContract,
        originalContract: contract, streamKind: "example.recovered-items", callers: [caller], itemCodec: itemCodec) { _, _, observed, output in
          await log.recordResume(observed); await hold.hold()
          do {
            // The Resume exchange allows 4248 bytes; the original item bound
            // is still two bytes and must reject this before publication.
            try await output.write(Data([2, 3, 4])); XCTFail("Resume cannot widen the original item bound")
          } catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
          try await output.write(Data([2, 3]))
          if applicationFailure { throw ServiceServerApplicationError(code: 7, payload: Data([9])) }
          if sdkFailure { throw ServiceFailure.serviceUnavailable }
        }
      let oldServer = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 2,
        checkpointPolicy: { (8192, 10_000) }, check: {})
      let originalStream = V4ApplicationInputTransport(kind: binding.kind)
      let payload = Data([8]); let request = try serverRequest(method, contract: contract, payload: payload, responseLimitBytes: 2)
      let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
        caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
      try oldServer.adoptStream(id: 17, kind: binding.kind, source: originalStream, facts: nil, readable: { true })
      let encoded = request.encoded()
      await originalStream.push(V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded + payload); await originalStream.endInput()
      oldServer.pollStreams()
      try await waitForObservation { await originalStream.outputFinished() && oldServer.generalPositionCount == 0 }
      let saved = await log.issued; let issued = try XCTUnwrap(saved)
      let interrupted = try await store.lookup(selector, includeResult: false)
      XCTAssertEqual(interrupted?.state, 5); XCTAssertEqual(interrupted?.streamItems, 1); XCTAssertEqual(interrupted?.streamBytes, 1)
      oldServer.close()

      // The old stream is closed. Explicit recovery selects a fresh session
      // admission and an accepted target, without invoking the initial handler.
      let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 2,
        checkpointPolicy: { (8192, 10_000) }, check: {})
      let target = V4ApplicationInputTransport(kind: "example.recovered-items")
      let contextDigest = Data(repeating: 5, count: 32)
      try server.adoptStream(id: 19, kind: target.kind, source: target, facts: (contextDigest, 19, 8192, 10_000), readable: { false })
      let channel = try V4RPCChannel(environment: environment, maximumGeneral: 2,
        storage: environment.rpcServicesStorage(maximumGeneral: 2, execution: true))
      let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
      try await channel.bindInbound(server); try await channel.start { source }
      let resumePayload = V4Crypto.map([(0, V4Crypto.bytes(selector.operation)), (1, V4Crypto.bytes(selector.request)),
        (2, V4NamespaceValue.head(0, issued.protection.rawValue)), (3, V4Crypto.bytes(issued.encodedToken)),
        (4, V4NamespaceValue.head(0, issued.generation)), (5, checkpoint.encoded()),
        (6, V4Crypto.bytes(contextDigest)), (7, V4NamespaceValue.head(0, 19))])
      let resumeRequest = try serverRequest(resumeMethod, contract: resumeContract, payload: resumePayload,
        kindOverride: "resume_request", operationByte: 5)
      await source.holdWrites()
      await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: resumeRequest.encoded()).encoded())
      await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: resumePayload).encoded())
      try await waitForObservation { await source.publicationWaiting() }
      let notEntered = await log.checkpoints; XCTAssertTrue(notEntered.isEmpty)
      await source.releaseWrites()
      try await waitForObservation { await log.checkpoints == [checkpoint] }
      let confirmationFrames = try v4ServiceTestRPCFrames(await source.output())
      let confirmation = try V4ApplicationHeader(encoded: XCTUnwrap(confirmationFrames.first).payload, registry: channel.registry)
      try confirmation.checkResponse(to: resumeRequest, registry: channel.registry)
      let accepted = try V4NamespaceDocument(confirmationFrames[1].payload, schema: "ResumeResult", bytes: 4248, nodes: 32,
        registry: V4NamespaceRegistry()).root
      XCTAssertEqual(try accepted.u("status"), 0)
      XCTAssertEqual(try accepted.field("progress").u("new_generation"), issued.generation + 1)
      await hold.release()
      try await waitForObservation { await target.outputFinished() && server.generalPositionCount == 0 }
      let recovered = await target.output()
      let itemHeaderBytes = recovered.prefix(2).reduce(0) { $0 << 8 | Int($1) }
      let item = try V4ApplicationHeader(encoded: Data(recovered[2..<2 + itemHeaderBytes]), registry: channel.registry)
      XCTAssertEqual(item.kind, "execution_stream_item"); try item.checkResponse(to: request, registry: channel.registry)
      XCTAssertEqual(Data(recovered[2 + itemHeaderBytes..<2 + itemHeaderBytes + 2]), Data([2, 3]))
      let complete = try await store.lookup(selector, includeResult: false)
      XCTAssertEqual(complete?.state, sdkFailure ? 5 : applicationFailure ? 4 : 3)
      XCTAssertEqual(complete?.resultCode, applicationFailure ? 7 : 0)
      XCTAssertEqual(complete?.streamItems, 2); XCTAssertEqual(complete?.streamBytes, 3)
      XCTAssertEqual(complete?.originalStreamHeader, request.encoded()); XCTAssertFalse(complete?.resultPresent ?? true)
      if applicationFailure {
        let terminalOffset = 2 + itemHeaderBytes + 2
        let terminalBytes = try v4ServiceTestMessage(Data(recovered.dropFirst(terminalOffset)))
        XCTAssertEqual(terminalBytes.0.kind, "execution_stream_application_error")
        XCTAssertEqual(try terminalBytes.0.uint(10), 7); XCTAssertEqual(terminalBytes.1, Data([9]))
        try terminalBytes.0.checkResponse(to: request, registry: channel.registry)
      } else if sdkFailure {
        let terminalOffset = 2 + itemHeaderBytes + 2
        let terminalBytes = try v4ServiceTestMessage(Data(recovered.dropFirst(terminalOffset)))
        XCTAssertEqual(terminalBytes.0.kind, "execution_stream_sdk_error")
        try terminalBytes.0.checkResponse(to: request, registry: channel.registry)
      }
      let closes = await target.closeCount(); XCTAssertEqual(closes, 0)
      let calls = await originalCalls.values; XCTAssertEqual(calls, [payload])
      do {
        _ = try await store.consume(selector, encodedToken: issued.encodedToken, protection: issued.protection,
          generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 8192)
        XCTFail("Recovery consumes the original generation once")
      } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
      await channel.close(); server.close(); registry.close(); await store.close()
    }
  }

  func testServerInputTimerRemainsPendingUntilCanceledCloseActuallyReturns() async throws {
    try await serverHeldClose(cause: .inputTimer)
  }
  func testServerRunTimerRemainsPendingAfterApplicationWorkExits() async throws {
    try await serverHeldClose(cause: .runTimer)
  }
  func testServerUnselectedStreamCloseRemainsPendingUntilTransportReturns() async throws {
    try await serverHeldClose(cause: .sessionClose)
  }
  func testServerRejectedStreamCloseRemainsPendingUntilTransportReturns() async throws {
    try await serverHeldClose(cause: .rejectedInput)
  }
  private enum ServerHeldCloseCause { case inputTimer, runTimer, sessionClose, rejectedInput }
  private func serverHeldClose(cause: ServerHeldCloseCause) async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_stream_transient",
      replacing: [12: V4NamespaceValue.head(0, 40)])
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding()))
    let binding = try ServiceStreamBinding(method: method, kind: "example.held-close")
    let hold = V4ControllerCallbackHold(); let calls = V4ServiceServerInvocationLog()
    try registry.registerStream(binding, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      itemCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value, _ in
        await calls.record(value); await hold.hold()
      }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let source = V4ApplicationInputTransport(kind: binding.kind)
    await source.holdFirstClose()
    do {
      try server.adoptStream(id: 17, kind: binding.kind, source: source, facts: nil, readable: {
        if cause == .rejectedInput { throw ServiceFailure.protocolFailure }
        return cause != .sessionClose
      })
      if cause == .sessionClose { server.close() }
      else if cause == .rejectedInput { server.pollStreams() }
      else {
        let payload = Data([7]); let request = try serverRequest(method, contract: contract, payload: payload)
        let header = request.encoded()
        await source.push(V4Crypto.integer(UInt64(header.count), width: 2) + header)
        if cause == .runTimer { await source.push(payload); await source.endInput() }
        server.pollStreams()
        if cause == .inputTimer {
          try await waitForObservation { await source.inputIsWaiting() }
          try advanceTime(environment, to: request.uint(5))
        } else { try await waitForObservation { await calls.values == [payload] } }
      }
      try await waitForObservation { await source.closeIsWaiting() }
      await hold.release()
      // Only the original timer or close worker remains. Its input/application
      // worker has exited, and cancellation must not erase this last owner.
      try await waitForObservation { server.physicalPending == 1 }
      server.close()
      try await waitForObservation { server.physicalPending == 1 }
      let waiting = await source.closeIsWaiting(); XCTAssertTrue(waiting)
      await source.releaseClose()
      try await waitForObservation { server.physicalPending == 0 && server.generalPositionCount == 0 }
      registry.close()
    } catch {
      await hold.release(); await source.releaseClose(); server.close(); registry.close(); throw error
    }
  }

  func testServerDedicatedStreamSharesKAndFinishesTypedItemAfterAcceptance() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_stream_transient")
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding()))
    let binding = try ServiceStreamBinding(method: method, kind: "example.items")
    let log = V4ServiceServerInvocationLog()
    try registry.registerStream(binding, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      itemCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value, output in
        await log.record(value); try await output.write(value)
      }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let payload = Data([7, 8, 9]); let request = try serverRequest(method, contract: contract, payload: payload)
    var partial = try server.reserveRequest(request)
    let source = V4ApplicationInputTransport(kind: binding.kind); await source.holdWrites()
    try withExtendedLifetime(partial) {
      XCTAssertThrowsError(try server.adoptStream(id: 17, kind: binding.kind, source: source, facts: nil, readable: { true }))
    }
    partial = nil
    try server.adoptStream(id: 17, kind: binding.kind, source: source, facts: nil, readable: { true })
    let encoded = request.encoded()
    await source.push(V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded + payload); await source.endInput()
    server.pollStreams()
    try await waitForObservation { await source.publicationWaiting() }
    XCTAssertThrowsError(try server.reserveRequest(request))
    let values = await log.values; XCTAssertEqual(values, [payload])
    await source.releaseWrites()
    try await waitForObservation { await source.outputFinished() }
    let output = await source.output(); XCTAssertGreaterThan(output.count, 2)
    let length = output.prefix(2).reduce(0) { $0 << 8 | Int($1) }
    let item = try V4ApplicationHeader(encoded: Data(output[2..<2 + length]), registry: V4ApplicationWireRegistry())
    XCTAssertEqual(item.kind, "transient_stream_item"); XCTAssertEqual(Data(output.dropFirst(2 + length)), payload)
    try item.checkResponse(to: request, registry: V4ApplicationWireRegistry())
    try await waitForObservation { server.generalPositionCount == 0 }
    server.close(); registry.close(); withExtendedLifetime(partial) {}
  }
}

private actor V4ResponsePublicationLog {
  var original: ResponsePublication?
  func record(_ original: ResponsePublication) { self.original = original }
}
private func v4ServiceActorCallback(
  @_inheritActorContext _ callback: @escaping @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Data
) -> @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Data { callback }
private func v4ServiceActorCallback(
  @_inheritActorContext _ callback: @escaping @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Data) async throws -> Data
) -> @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Data) async throws -> Data { callback }
private actor V4ServiceEntryActor {
  nonisolated let entered = DispatchSemaphore(value: 0)
  nonisolated let release = DispatchSemaphore(value: 0)
  func block() { entered.signal(); release.wait() }
  var decoderCallback: @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Data {
    v4ServiceActorCallback { [self] bytes, context in try decode(bytes, context) }
  }
  var handlerCallback: @isolated(any) @Sendable (ApplicationInvocationContext, ServiceServerInvocation, Data) async throws -> Data {
    v4ServiceActorCallback { [self] context, invocation, bytes in try handle(context, invocation, bytes) }
  }
  func decode(_ bytes: Data, _ context: ApplicationInvocationContext) throws -> Data {
    try context.checkCancellation(); return bytes
  }
  func handle(_ context: ApplicationInvocationContext, _ invocation: ServiceServerInvocation, _ bytes: Data) throws -> Data {
    try invocation.checkCancellation(); return bytes
  }
}

extension ServiceApplicationOwnershipV4Tests {
  func testResponsePublicationWaitCancellationKeepsOriginalProviderOwnership() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let maintenance = try ServiceMaintenanceOwner(environment: environment, maximumPublications: 1)
    let original = try maintenance.reserve(deadlineMS: 10_000)
    try original.begin(bytes: 3, deadlineAction: {})
    let ticket = try original.ticket(); original.finishProduction()
    let waiter = Task { try await original.wait() }; await Task.yield(); waiter.cancel()
    do { _ = try await waiter.value; XCTFail("Canceling an observer must end only its wait") } catch is CancellationError {}
    XCTAssertEqual(original.state().state, .pending)
    XCTAssertThrowsError(try maintenance.reserve(deadlineMS: 100))
    ticket.completed(bytes: 3, success: true)
    let flushed = try await original.wait(); XCTAssertEqual(flushed.state, .flushed)
    original.fail(.ownerUnavailable); original.fail(.responseAborted)
    XCTAssertEqual(original.state().state, .flushed)
    let next = try maintenance.reserve(deadlineMS: 100); next.abandon(.responseSuperseded); maintenance.close()
  }

  private func restartPublicationFixture(deadlineMS: UInt64) async throws
    -> (V4EnvironmentFoundation, SQLiteServiceExecutionStore, URL, ServiceMaintenanceOwner, ServiceRegistry,
      V4ServiceServerSession, V4RPCChannel, V4ApplicationInputTransport, V4ResponsePublicationLog, V4ApplicationHeader, Data) {
    let environment = try environment()
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-publication-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let maintenance = try ServiceMaintenanceOwner(environment: environment, maximumPublications: 1)
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256), 21: Data([0xf5]), 22: V4NamespaceValue.head(0, deadlineMS)])
    let registry = try ServiceRegistry(environment: environment, configuration: ServiceRegistryConfiguration(
      authority: "example", queryBinding: serverQueryBinding(), executionStore: store, maintenanceOwner: maintenance))
    let log = V4ResponsePublicationLog(); let payload = Data([1, 2, 3])
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response))) { _, invocation, bytes in
        await log.record(invocation.responsePublication); return bytes
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4"); await source.holdHandoffs()
    try await channel.bindInbound(server); try await channel.start { source }
    let request = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    return (environment, store, directory, maintenance, registry, server, channel, source, log, request, payload)
  }

  func testRestartPublicationRemainsPendingUntilActualProviderHandoff() async throws {
    let (environment, store, directory, maintenance, registry, server, channel, source, log, request, payload) = try await restartPublicationFixture(deadlineMS: 10_000)
    defer { environment.beginClose(); try? FileManager.default.removeItem(at: directory) }
    try await waitForObservation { await source.handoffPending() }
    let captured = await log.original; let original = try XCTUnwrap(captured)
    XCTAssertEqual(original.state().state, .pending)
    XCTAssertEqual(server.generalPositionCount, 1)
    await source.releaseHandoffs()
    let observed = try await original.wait(); XCTAssertEqual(observed.state, .flushed)
    let frames = try v4ServiceTestRPCFrames(await source.output())
    XCTAssertEqual(frames.count, 2); XCTAssertEqual(frames[1].payload, payload)
    let reply = try V4ApplicationHeader(encoded: frames[0].payload, registry: channel.registry)
    try reply.checkResponse(to: request, registry: channel.registry)
    await channel.close(); maintenance.close(); registry.close(); await store.close()
    XCTAssertEqual(original.state().state, .flushed)
  }

  func testRestartPublicationStopIsUnknownAndCannotBecomeFlushed() async throws {
    let (environment, store, directory, maintenance, registry, _, channel, source, log, _, _) = try await restartPublicationFixture(deadlineMS: 10_000)
    defer { environment.beginClose(); try? FileManager.default.removeItem(at: directory) }
    try await waitForObservation { await source.handoffPending() }
    let captured = await log.original; let original = try XCTUnwrap(captured)
    await source.push(try V4RPCFragment(kind: .stopOutput, serial: 1).encoded())
    let observed = try await original.wait()
    XCTAssertEqual(observed.state, .unknown); XCTAssertEqual(observed.cause, .responseAborted)
    await source.releaseHandoffs(); await channel.close(); maintenance.close(); registry.close(); await store.close()
    XCTAssertEqual(original.state().state, .unknown)
  }

  func testRestartPublicationDeadlineClosesBlockedOriginalOwnerWithoutClaimingFlush() async throws {
    let (environment, store, directory, maintenance, registry, _, channel, source, log, _, _) = try await restartPublicationFixture(deadlineMS: 100)
    defer { environment.beginClose(); try? FileManager.default.removeItem(at: directory) }
    try await waitForObservation { await source.handoffPending() }
    let captured = await log.original; let original = try XCTUnwrap(captured)
    let observed = try await original.wait()
    XCTAssertEqual(observed.state, .unknown); XCTAssertEqual(observed.cause, .deadline)
    await channel.close(); maintenance.close(); registry.close(); await store.close()
  }

  func testActorQueuedDecoderStartsRunClockOnItsActualExecutor() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_transient",
      replacing: [12: V4NamespaceValue.head(0, 40)])
    let actor = V4ServiceEntryActor(); let decoder = await actor.decoderCallback
    XCTAssertTrue(decoder.isolation === actor)
    let blocking = Task.detached { await actor.block() }
    try await waitForObservation { v4ServiceSemaphoreSignaled(actor.entered) }
    defer { actor.release.signal() }
    let codec = AsyncClosureMessageCodec(definition: method.options.request, encode: { bytes, _ in bytes }, decode: decoder)
    let registry = try ServiceRegistry(environment: environment, configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding()))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()], requestCodec: codec,
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response))) { _, _, bytes in bytes }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([8, 9]); let request = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { server.generalPositionCount == 1 }
    try await Task.sleep(for: .milliseconds(120))
    let waiting = await source.output(); XCTAssertTrue(waiting.isEmpty)
    actor.release.signal(); await blocking.value
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()).count) == 2 }
    let frames = try v4ServiceTestRPCFrames(await source.output()); XCTAssertEqual(frames[1].payload, payload)
    let reply = try V4ApplicationHeader(encoded: frames[0].payload, registry: channel.registry)
    XCTAssertEqual(reply.kind, "transient_unary_response")
    await channel.close(); registry.close()
  }

  func testActorQueuedHandlerWithSDKParserStartsClockAtHandlerBody() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_transient",
      replacing: [12: V4NamespaceValue.head(0, 40)])
    let actor = V4ServiceEntryActor(); let handler = await actor.handlerCallback
    XCTAssertTrue(handler.isolation === actor)
    let blocking = Task.detached { await actor.block() }
    try await waitForObservation { v4ServiceSemaphoreSignaled(actor.entered) }
    defer { actor.release.signal() }
    let registry = try ServiceRegistry(environment: environment, configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding()))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)), handler: handler)
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([6, 7]); let request = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { server.generalPositionCount == 1 }
    try await Task.sleep(for: .milliseconds(120))
    let waiting = await source.output(); XCTAssertTrue(waiting.isEmpty)
    actor.release.signal(); await blocking.value
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()).count) == 2 }
    let frames = try v4ServiceTestRPCFrames(await source.output()); XCTAssertEqual(frames[1].payload, payload)
    await channel.close(); registry.close()
  }
}


extension ServiceApplicationOwnershipV4Tests {
  func testRetainedStreamContentUsesFixedPositionAndOriginalExpiry() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-content-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    var store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 2, resultBytes: 2048,
        contentItems: 2, contentBytes: 16))
    let selector = executionSelector(operation: 33, request: 44)
    let definition = try StreamContentDefinition(schemaRevision: "example_content_v1", canonical: Data([0xa0]), readTypeID: 501)
    let policy = V4ServiceStreamContentPolicy(definition: definition, origin: 1, retentionMS: 100,
      maximumItems: 2, maximumBytes: 16, durable: true)
    let admitted = try await store.admit(selector, deadline: 30_000, historyMS: 10, responseBytes: 0, contentPolicy: policy); XCTAssertTrue(admitted)
    try await store.started(selector)
    let position = Data([7]); let payload = Data([1, 2, 3])
    let first = try await store.saveContent(selector, policy: policy, position: position, payload: payload)
    XCTAssertTrue(first.available); XCTAssertEqual(first.expiresAtMS, 1100)
    let same = try await store.saveContent(selector, policy: policy, position: position, payload: payload)
    XCTAssertEqual(same.expiresAtMS, first.expiresAtMS)
    do { _ = try await store.saveContent(selector, policy: policy, position: position, payload: Data([3, 2, 1])); XCTFail("A position cannot be rewritten") }
    catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    try await store.complete(selector, payload: nil, resultRetentionMS: 0)
    await store.close()
    store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: false, rows: 2, resultBytes: 2048,
        contentItems: 2, contentBytes: 16))
    let available = try await store.readContent(selector, policy: policy, position: position, maximumBytes: 3)
    XCTAssertEqual(available.payload, payload); XCTAssertEqual(available.observation.digest, first.digest)
    do { _ = try await store.readContent(selector, policy: policy, position: position, maximumBytes: 2); XCTFail("Read bound must be checked before copying") }
    catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
    try advanceTime(environment, to: 1200)
    let expired = try await store.readContent(selector, policy: policy, position: position, maximumBytes: 3)
    XCTAssertTrue(expired.observation.expired); XCTAssertNil(expired.payload)
    await store.close()
  }

  func testTypedStreamContentReadsThroughDeclaredUnaryMethodAfterStreamExit() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-typed-content-reader-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 4, resultBytes: 2048,
        contentItems: 2, contentBytes: 32))
    let (_, readMethod, readContract) = try serverFixture(environment, vectorID: "service_unary_transient",
      replacing: [1: V4NamespaceValue.head(0, 501), 10: V4NamespaceValue.head(0, 256)])
    let content = try StreamContentDefinition(schemaRevision: "example_content_v1", canonical: Data([0xa0]), readTypeID: readMethod.typeID)
    let policy = V4Crypto.map([(0, V4NamespaceValue.head(0, 1)), (1, V4NamespaceValue.head(0, 1)),
      (2, V4NamespaceValue.head(0, 100)), (3, V4NamespaceValue.head(0, 2)), (4, V4NamespaceValue.head(0, 32)),
      (5, V4Crypto.text(content.schemaRevision)), (6, V4Crypto.bytes(content.canonical))])
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_stream_execution",
      replacing: [10: V4NamespaceValue.head(0, 16), 28: policy], content: content,
      additionalMethods: [ServiceMethod(name: "readContent", method: readMethod)])
    let payload = Data([7, 8, 9]); let position = Data([7])
    let request = try serverRequest(method, contract: contract, payload: payload)
    let caller = try serverCaller()
    let target = try StreamContentTarget(tenant: "tenant", audience: "service", serviceNamespace: contract.namespace,
      callerSubject: caller.subject, callerAuthority: caller.executionAuthority, operationID: request.bytes(1),
      requestDigest: request.bytes(4), serviceContractDigest: contract.digest)
    let binding = try ServiceStreamBinding(method: method, kind: "example.retained-items")
    let streamLog = V4ServiceServerInvocationLog(); let readLog = V4ServiceServerInvocationLog()
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerStream(binding, in: definition, contract: contract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      itemCodec: BytesMessageCodec(definition: XCTUnwrap(method.options.response))) { _, _, value, output in
        // Content commit and typed item publication are separate facts.
        let saved = try await output.saveContent(position: position, payload: value)
        guard saved.available else { throw ServiceFailure.serviceUnavailable }
        await streamLog.record(value); try await output.write(value)
      }
    try registry.registerUnary(readMethod, in: definition, contract: readContract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: readMethod.options.request),
      responseCodec: BytesMessageCodec(definition: XCTUnwrap(readMethod.options.response))) { _, invocation, value in
        guard value.count == 2 else { throw ServiceFailure.protocolFailure }
        let selected: StreamContentTarget
        if value.first == 1 {
          selected = try StreamContentTarget(tenant: target.tenant, audience: target.audience,
            serviceNamespace: target.serviceNamespace, callerSubject: "other-client", callerAuthority: target.callerAuthority,
            operationID: target.operationID, requestDigest: target.requestDigest, serviceContractDigest: target.serviceContractDigest)
        } else { selected = target }
        let result: Data
        do {
          let retained = try await invocation.readRetainedContent(selected, position: Data(value.suffix(1)), maximumBytes: 16)
          if retained.observation.available { result = Data([1]) + (retained.payload ?? Data()) }
          else { result = Data([retained.observation.expired ? 2 : 0]) }
        } catch ServiceFailure.permissionDenied { result = Data([3]) }
        await readLog.record(result); return result
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let stream = V4ApplicationInputTransport(kind: binding.kind)
    try server.adoptStream(id: 17, kind: binding.kind, source: stream, facts: nil, readable: { true })
    let encoded = request.encoded()
    await stream.push(V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded + payload); await stream.endInput()
    server.pollStreams()
    try await waitForObservation { await stream.outputFinished() && server.generalPositionCount == 0 }
    let streamOutput = await stream.output()
    let headerBytes = streamOutput.prefix(2).reduce(0) { $0 << 8 | Int($1) }
    let item = try V4ApplicationHeader(encoded: Data(streamOutput[2..<2 + headerBytes]), registry: V4ApplicationWireRegistry())
    XCTAssertEqual(item.kind, "execution_stream_item"); try item.checkResponse(to: request, registry: V4ApplicationWireRegistry())
    XCTAssertEqual(Data(streamOutput[2 + headerBytes..<2 + headerBytes + payload.count]), payload)
    let execution = try await store.lookup(target.selector, includeResult: false)
    XCTAssertEqual(execution?.state, 3); XCTAssertFalse(execution?.resultPresent ?? true)

    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    for (index, selection) in [Data([0, 7]), Data([0, 8]), Data([1, 7]), Data([0, 7])].enumerated() {
      if index == 3 {
        try advanceTime(environment, to: 1200)
      }
      let readRequest = try serverRequest(readMethod, contract: readContract, payload: selection)
      let serial = UInt64(index + 1)
      await source.push(try V4RPCFragment(kind: .begin, serial: serial, payload: readRequest.encoded()).encoded())
      await source.push(try V4RPCFragment(kind: .data, serial: serial, payload: selection).encoded())
      try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()))?.count == (index + 1) * 2 && server.generalPositionCount == 0 }
      let frames = try v4ServiceTestRPCFrames(await source.output())
      let response = try V4ApplicationHeader(encoded: frames[index * 2].payload, registry: channel.registry)
      XCTAssertEqual(frames[index * 2].replyTo, serial); try response.checkResponse(to: readRequest, registry: channel.registry)
    }
    let reads = await readLog.values; XCTAssertEqual(reads, [Data([1]) + payload, Data([0]), Data([3]), Data([2])])
    let streamCalls = await streamLog.values; XCTAssertEqual(streamCalls, [payload])
    await channel.close(); server.close(); registry.close(); await store.close()
  }

  func testRetainedContentAdmissionOriginDoesNotRenewAcrossExecutionCompletion() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-content-origin-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 2, resultBytes: 2048,
        contentItems: 2, contentBytes: 16))
    let selector = executionSelector(operation: 34, request: 45)
    let definition = try StreamContentDefinition(schemaRevision: "example_content_v1", canonical: Data([0xa0]), readTypeID: 501)
    let policy = V4ServiceStreamContentPolicy(definition: definition, origin: 0, retentionMS: 100,
      maximumItems: 2, maximumBytes: 16, durable: true)
    let admitted = try await store.admit(selector, deadline: 30_000, historyMS: 1, responseBytes: 0, contentPolicy: policy); XCTAssertTrue(admitted)
    try await store.started(selector)
    let saved = try await store.saveContent(selector, policy: policy, position: Data([9]), payload: Data([6]))
    XCTAssertEqual(saved.expiresAtMS, 1100)
    try advanceTime(environment, to: 1099)
    try await store.complete(selector, payload: nil, resultRetentionMS: 0)
    let stillOriginal = try await store.readContent(selector, policy: policy, position: Data([9]), maximumBytes: 1)
    XCTAssertEqual(stillOriginal.observation.expiresAtMS, 1100); XCTAssertTrue(stillOriginal.observation.available)
    await store.close()
  }
}

private actor V4LegacyServiceAsyncCodec: AsyncMessageCodec {
  typealias Value = Data
  nonisolated let definition: MessageDefinition
  nonisolated let publishesEntry: Bool
  nonisolated let queued = DispatchSemaphore(value: 0)
  nonisolated let release = DispatchSemaphore(value: 0)
  var decodes = 0
  var encodes = 0
  init(definition: MessageDefinition, publishesEntry: Bool = false) {
    self.definition = definition; self.publishesEntry = publishesEntry
  }
  nonisolated var applicationDecodeCallback: (@isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Data)? {
    if publishesEntry { return decodeAsync }
    return nil
  }
  func blockExecutor() { queued.signal(); release.wait() }
  var decoderCallback: @isolated(any) @Sendable (Data, ApplicationInvocationContext) async throws -> Data {
    v4ServiceActorCallback { [self] source, context in try decodeBody(source, context: context) }
  }
  func encodeAsync(_ value: Data, context: ApplicationInvocationContext) async throws -> Data {
    try context.checkCancellation(); encodes += 1; return Data([0xac]) + value
  }
  func decodeAsync(_ source: Data, context: ApplicationInvocationContext) async throws -> Data {
    try decodeBody(source, context: context)
  }
  private func decodeBody(_ source: Data, context: ApplicationInvocationContext) throws -> Data {
    try context.checkCancellation(); decodes += 1
    if source.first == 0xff { throw ServiceFailure.serviceFailed }
    return source
  }
}

extension ServiceApplicationOwnershipV4Tests {
  func testLegacyAsyncCodecAdaptsConcreteActorEntryAndPreservesItsEncoder() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_transient",
      replacing: [12: V4NamespaceValue.head(0, 40)])
    let codec = V4LegacyServiceAsyncCodec(definition: method.options.request)
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding()))
    let responseCodec = BytesMessageCodec(definition: try XCTUnwrap(method.options.response))
    do {
      try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
        requestCodec: codec, responseCodec: responseCodec) { _, _, bytes in bytes }
      XCTFail("An erased async witness needs concrete entry evidence for the server request role")
    } catch { XCTAssertEqual(error as? ApplicationCallbackEntryError, .asyncDecoderEntryUnavailable) }
    // The same existing async codec remains valid; adapt only the request role
    // using its actor-created callback, without changing its encoder.
    let decoder = await codec.decoderCallback
    XCTAssertTrue(decoder.isolation === codec)
    let adapted = codec.serverRequestCodec(decode: decoder)
    XCTAssertEqual(adapted.definition, codec.definition)
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: adapted, responseCodec: responseCodec) { context, _, bytes in
        try await adapted.encodeAsync(bytes, context: context)
      }
    let server = try registry.admission(identity: serverIdentity(), execution: false, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let blocked = Task.detached { await codec.blockExecutor() }
    try await waitForObservation { v4ServiceSemaphoreSignaled(codec.queued) }
    defer { codec.release.signal() }
    let payload = Data([1, 2, 3]); let request = try serverRequest(method, contract: contract, payload: payload)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { server.generalPositionCount == 1 }
    try await Task.sleep(for: .milliseconds(120))
    let queuedOutput = await source.output(); XCTAssertTrue(queuedOutput.isEmpty)
    codec.release.signal(); await blocked.value
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()).count) == 2 }
    let frames = try v4ServiceTestRPCFrames(await source.output()); XCTAssertEqual(frames[1].payload, Data([0xac]) + payload)
    let decodes = await codec.decodes; let encodes = await codec.encodes
    XCTAssertEqual(decodes, 1); XCTAssertEqual(encodes, 1)
    await channel.close(); registry.close()
  }

  func testDeclaredAsyncDecoderFailureKeepsDispatchedExecutionHistory() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-decoder-dispatch-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256)])
    let codec = V4LegacyServiceAsyncCodec(definition: method.options.request, publishesEntry: true)
    let called = V4ServiceServerInvocationLog()
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: codec, responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response))) { _, _, bytes in
        await called.record(bytes); return bytes
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let payload = Data([0xff]); let request = try serverRequest(method, contract: contract, payload: payload)
    let caller = try serverCaller()
    let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()).count) == 2 && server.generalPositionCount == 0 }
    let record = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(record?.state, 5); XCTAssertEqual(record?.dispatched, true)
    let handlerCalls = await called.values; XCTAssertTrue(handlerCalls.isEmpty)
    let decodeCalls = await codec.decodes; XCTAssertEqual(decodeCalls, 1)
    let frames = try v4ServiceTestRPCFrames(await source.output())
    let failure = try V4ApplicationHeader(encoded: frames[0].payload, registry: channel.registry)
    XCTAssertEqual(failure.kind, "execution_unary_sdk_error")
    await channel.close(); registry.close(); await store.close()
  }

  func testStreamingResumeContinuesOriginalContentAndOutputBoundsAfterConfirmation() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-stream-resume-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 4, resultBytes: 16_384,
        active: 2, contentItems: 2, contentBytes: 32))
    let (_, readMethod, readContract) = try serverFixture(environment, vectorID: "service_unary_transient",
      replacing: [1: V4NamespaceValue.head(0, 501), 10: V4NamespaceValue.head(0, 256)])
    let content = try StreamContentDefinition(schemaRevision: "example_content_v1", canonical: Data([0xa0]), readTypeID: readMethod.typeID)
    let policy = V4Crypto.map([(0, V4NamespaceValue.head(0, 1)), (1, V4NamespaceValue.head(0, 0)),
      (2, V4NamespaceValue.head(0, 10_000)), (3, V4NamespaceValue.head(0, 2)), (4, V4NamespaceValue.head(0, 32)),
      (5, V4Crypto.text(content.schemaRevision)), (6, V4Crypto.bytes(content.canonical))])
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_stream_execution",
      replacing: [10: V4NamespaceValue.head(0, 16), 20: V4Crypto.text("cursor"), 24: V4NamespaceValue.head(0, 2),
        25: V4NamespaceValue.head(0, 6), 28: policy], content: content,
      additionalMethods: [ServiceMethod(name: "readContent", method: readMethod)])
    let (resumeDefinition, resumeMethod, resumeContract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [1: V4NamespaceValue.head(0, 2), 9: V4NamespaceValue.head(0, 4248),
        10: V4NamespaceValue.head(0, 4248), 20: V4Crypto.text("cursor")])
    let caller = try serverCaller(); let log = V4ServiceServerResumeLog(); let calls = V4ServiceServerInvocationLog()
    let holding = V4ControllerCallbackHold(); let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1]))
    let first = Data([1, 2, 3]); let next = Data([4, 5, 6])
    let request = try serverRequest(method, contract: contract, payload: first, responseLimitBytes: 3)
    let target = try StreamContentTarget(tenant: "tenant", audience: "service", serviceNamespace: contract.namespace,
      callerSubject: caller.subject, callerAuthority: caller.executionAuthority, operationID: request.bytes(1),
      requestDigest: request.bytes(4), serviceContractDigest: contract.digest)
    let binding = try ServiceStreamBinding(method: method, kind: "example.original-items")
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    let itemCodec = BytesMessageCodec(definition: try XCTUnwrap(method.options.response))
    try registry.registerStream(binding, in: definition, contract: contract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: method.options.request), itemCodec: itemCodec) { _, invocation, bytes, output in
        await calls.record(bytes)
        _ = try await output.saveContent(position: Data([1]), payload: bytes)
        try await output.write(bytes)
        let issued = try await invocation.issueCheckpoint(checkpoint, lifetimeMS: 5000)
        await log.recordIssued(issued); throw ServiceFailure.serviceUnavailable
      }
    try registry.registerUnary(readMethod, in: definition, contract: readContract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: readMethod.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(readMethod.options.response))) { _, invocation, position in
        let retained = try await invocation.readRetainedContent(target, position: position, maximumBytes: 3)
        return retained.observation.available ? Data([1]) + (retained.payload ?? Data()) : Data([retained.observation.expired ? 2 : 0])
      }
    try registry.registerStreamingResume(resumeMethod, in: resumeDefinition, contract: resumeContract,
      originalContract: contract, streamKind: "example.resumed-items", callers: [caller], itemCodec: itemCodec) { _, _, observed, output in
        await log.recordResume(observed); await holding.hold()
        // The Resume RPC's 4248-byte response bound grants no larger item.
        do { try await output.write(Data([9, 9, 9, 9])); XCTFail("Original item bound must survive recovery") }
        catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
        _ = try await output.saveContent(position: Data([2]), payload: next)
        try await output.write(next)
        do { try await output.write(Data([7])); XCTFail("Original persisted count cannot be renewed by Resume") }
        catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 2,
      checkpointPolicy: { (8192, 10_000) }, check: {})
    let originalStream = V4ApplicationInputTransport(kind: binding.kind)
    try server.adoptStream(id: 17, kind: binding.kind, source: originalStream, facts: nil, readable: { true })
    let encoded = request.encoded()
    await originalStream.push(V4Crypto.integer(UInt64(encoded.count), width: 2) + encoded + first); await originalStream.endInput()
    server.pollStreams()
    try await waitForObservation { await originalStream.outputFinished() && server.generalPositionCount == 0 }
    let issuedValue = await log.issued; let issued = try XCTUnwrap(issuedValue)
    let interrupted = try await store.lookup(target.selector, includeResult: false)
    XCTAssertEqual(interrupted?.state, 5); XCTAssertEqual(interrupted?.originalStreamHeader, encoded)
    XCTAssertEqual(interrupted?.streamItems, 1); XCTAssertEqual(interrupted?.streamBytes, 3)
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 2,
      storage: environment.rpcServicesStorage(maximumGeneral: 2, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let resumedStream = V4ApplicationInputTransport(kind: "example.resumed-items"); let context = Data(repeating: 5, count: 32)
    try server.adoptStream(id: 19, kind: resumedStream.kind, source: resumedStream,
      facts: (context, 19, 8192, 10_000), readable: { false })
    let resumePayload = V4Crypto.map([(0, V4Crypto.bytes(target.operationID)), (1, V4Crypto.bytes(target.requestDigest)),
      (2, V4NamespaceValue.head(0, issued.protection.rawValue)), (3, V4Crypto.bytes(issued.encodedToken)),
      (4, V4NamespaceValue.head(0, issued.generation)), (5, checkpoint.encoded()),
      (6, V4Crypto.bytes(context)), (7, V4NamespaceValue.head(0, 19))])
    let resumeRequest = try serverRequest(resumeMethod, contract: resumeContract, payload: resumePayload,
      kindOverride: "resume_request", operationByte: 5)
    await source.holdWrites()
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: resumeRequest.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: resumePayload).encoded())
    try await waitForObservation { await source.publicationWaiting() }
    let before = await log.checkpoints; XCTAssertTrue(before.isEmpty)
    await source.releaseWrites()
    try await waitForObservation { await log.checkpoints == [checkpoint] }
    let frames = try v4ServiceTestRPCFrames(await source.output())
    let acceptedHeader = try V4ApplicationHeader(encoded: frames[0].payload, registry: channel.registry)
    XCTAssertEqual(acceptedHeader.kind, "resume_response"); try acceptedHeader.checkResponse(to: resumeRequest, registry: channel.registry)
    let accepted = try V4NamespaceDocument(frames[1].payload, schema: "ResumeResult", bytes: 4248, nodes: 32, registry: V4NamespaceRegistry()).root
    XCTAssertEqual(try accepted.u("status"), 0)
    XCTAssertEqual(try accepted.field("progress").u("new_generation"), issued.generation + 1)
    await holding.release()
    try await waitForObservation { await resumedStream.outputFinished() && server.generalPositionCount == 0 }
    let (item, payload) = try v4ServiceTestMessage(await resumedStream.output())
    XCTAssertEqual(item.kind, "execution_stream_item"); try item.checkResponse(to: request, registry: channel.registry)
    XCTAssertEqual(payload, next)
    let complete = try await store.lookup(target.selector, includeResult: false)
    XCTAssertEqual(complete?.state, 3); XCTAssertEqual(complete?.streamItems, 2); XCTAssertEqual(complete?.streamBytes, 6)
    XCTAssertFalse(complete?.resultPresent ?? true)
    let originalCalls = await calls.values; XCTAssertEqual(originalCalls, [first])
    // The same registered reader selects both old and resumed commits; Resume
    // neither changes the original key nor renews its admission-based expiry.
    for (index, position) in [Data([1]), Data([2])].enumerated() {
      let readRequest = try serverRequest(readMethod, contract: readContract, payload: position)
      let serial = UInt64(index + 2)
      await source.push(try V4RPCFragment(kind: .begin, serial: serial, payload: readRequest.encoded()).encoded())
      await source.push(try V4RPCFragment(kind: .data, serial: serial, payload: position).encoded())
      try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()).count) == (index + 2) * 2 && server.generalPositionCount == 0 }
      let replies = try v4ServiceTestRPCFrames(await source.output())
      XCTAssertEqual(replies[(index + 1) * 2 + 1].payload, Data([1]) + (index == 0 ? first : next))
    }
    let trustedPolicy = try XCTUnwrap(contract.streamContentPolicy(content))
    let old = try await store.readContent(target.selector, policy: trustedPolicy, position: Data([1]), maximumBytes: 3)
    let new = try await store.readContent(target.selector, policy: trustedPolicy, position: Data([2]), maximumBytes: 3)
    XCTAssertEqual(old.observation.expiresAtMS, 11_000); XCTAssertEqual(new.observation.expiresAtMS, 11_000)
    do {
      _ = try await store.consume(target.selector, encodedToken: issued.encodedToken, protection: issued.protection,
        generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 8192)
      XCTFail("A streaming recovery generation is consumed only once")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    await channel.close(); server.close(); registry.close(); await store.close()
  }
}


private actor V4CooperativeServiceCodec: EntryAwareAsyncMessageCodec {
  typealias Value = Data
  nonisolated let definition: MessageDefinition
  nonisolated let queued = DispatchSemaphore(value: 0)
  nonisolated let release = DispatchSemaphore(value: 0)
  var entries = 0
  init(definition: MessageDefinition) { self.definition = definition }
  func blockExecutor() { queued.signal(); release.wait() }
  func encodeAsync(_ value: Data, context: ApplicationInvocationContext) async throws -> Data {
    try context.checkCancellation(); return value
  }
  func decodeAsync(_ source: Data, context: ApplicationInvocationContext) async throws -> Data {
    try context.checkCancellation(); return source
  }
  func decodeAsync(_ source: Data, context: ApplicationInvocationContext, entry: ApplicationCallbackEntry) async throws -> Data {
    try await entry.enter()
    entries += 1; return source
  }
}
extension ServiceApplicationOwnershipV4Tests {
  func testCooperatingDecoderPreparesDurableDispatchOnActualActorEntry() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-cooperative-entry-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256), 18: V4NamespaceValue.head(0, 40)])
    let codec = V4CooperativeServiceCodec(definition: method.options.request)
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [serverCaller()],
      requestCodec: codec, responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response))) { _, _, bytes in bytes }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    let blocked = Task.detached { await codec.blockExecutor() }
    try await waitForObservation { v4ServiceSemaphoreSignaled(codec.queued) }
    defer { codec.release.signal() }
    let payload = Data([4, 5]); let request = try serverRequest(method, contract: contract, payload: payload)
    let caller = try serverCaller()
    let selector = try V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: request.bytes(1), request: request.bytes(4), contract: contract.digest)
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { (try? await store.lookup(selector, includeResult: false))?.state == 1 }
    try await Task.sleep(for: .milliseconds(120))
    let beforeEntry = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(beforeEntry?.dispatched, false)
    let waiting = await source.output(); XCTAssertTrue(waiting.isEmpty)
    codec.release.signal(); await blocked.value
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await source.output()).count) == 2 && server.generalPositionCount == 0 }
    let afterEntry = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(afterEntry?.dispatched, true); XCTAssertEqual(afterEntry?.state, 3)
    let entered = await codec.entries; XCTAssertEqual(entered, 1)
    let frames = try v4ServiceTestRPCFrames(await source.output()); XCTAssertEqual(frames[1].payload, payload)
    await channel.close(); registry.close(); await store.close()
  }
}

extension ServiceApplicationOwnershipV4Tests {
  func testCheckpointReissuePersistsExactReceiptAndOriginalResultPromise() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-reissue-receipt-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 4, resultBytes: 16_384, active: 2))
    let original = executionSelector(); let resume = executionSelector(operation: 5)
    let issuer = executionSelector(operation: 6); let retryIssuer = executionSelector(operation: 7)
    let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1]))
    _ = try await store.admit(original, deadline: 30_000, historyMS: 1000, responseBytes: 256)
    try await store.started(original)
    let issued = try await store.issue(original, checkpoint: checkpoint, lifetimeMS: 10_000)
    let previous = try ApplicationCheckpointToken(environment: environment, encoded: issued.encodedToken,
      protection: issued.protection, verificationKey: nil)
    try await store.complete(original, payload: nil, resultRetentionMS: 0)
    _ = try await store.admit(resume, deadline: 20_000, historyMS: 1000, responseBytes: 4248)
    try await store.started(resume)
    let generation = try await store.consume(original, encodedToken: issued.encodedToken, protection: issued.protection,
      generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 8192,
      confirmation: resume, resultRetentionMS: 5000)
    let confirmation = try await store.lookup(resume)
    XCTAssertEqual(confirmation?.state, 3); XCTAssertEqual(confirmation?.active, false)
    let confirmed = try V4NamespaceDocument(XCTUnwrap(confirmation?.result), schema: "ResumeResult", bytes: 4248,
      nodes: 32, registry: V4NamespaceRegistry()).root
    XCTAssertEqual(try confirmed.u("status"), 0)
    XCTAssertEqual(try confirmed.field("progress").u("new_generation"), generation)
    _ = try await store.admit(issuer, deadline: 30_000, historyMS: 1000, responseBytes: 8192)
    try await store.started(issuer)
    do {
      _ = try await store.reissue(original, issuer: issuer, previousToken: previous, lifetimeMS: 1000,
        maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192)
      XCTFail("An active original continuation cannot be fenced by issuance")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    // Confirmation is lost before actual callback entry. Unknown preserves the
    // original result promise instead of making the next result limit zero.
    try await store.complete(original, payload: nil, resultRetentionMS: 0, reason: 2)
    try advanceTime(environment, to: 2000)
    let fresh = try await store.reissue(original, issuer: issuer, previousToken: previous, lifetimeMS: 1000,
      maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192)
    XCTAssertEqual(fresh.generation, generation); XCTAssertEqual(fresh.checkpoint, checkpoint)
    XCTAssertEqual(fresh.expiresAtMS, 3000); XCTAssertNotEqual(fresh.encodedToken, issued.encodedToken)
    let saved = try await store.lookup(original, includeResult: false)
    XCTAssertEqual(saved?.reservedBytes, 256); XCTAssertEqual(saved?.checkpointIssues, 2)
    XCTAssertEqual(saved?.deadline, 30_000); XCTAssertEqual(saved?.recoveryEntered, false)
    XCTAssertEqual(saved?.runStartedMS, 1000)
    await store.close()

    let reopened = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: false, rows: 4, resultBytes: 16_384, active: 2))
    _ = try await reopened.admit(retryIssuer, deadline: 30_000, historyMS: 1000, responseBytes: 8192)
    try await reopened.started(retryIssuer)
    try advanceTime(environment, to: 2100)
    let retried = try await reopened.reissue(original, issuer: retryIssuer, previousToken: previous, lifetimeMS: 1000,
      maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192)
    XCTAssertEqual(retried.encodedToken, fresh.encodedToken); XCTAssertEqual(retried.expiresAtMS, fresh.expiresAtMS)
    do {
      _ = try await reopened.reissue(original, issuer: retryIssuer, previousToken: previous, lifetimeMS: 2000,
        maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192)
      XCTFail("An issuance retry cannot replace its original lifetime")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    do {
      _ = try await reopened.consume(original, encodedToken: issued.encodedToken, protection: issued.protection,
        generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 8192)
      XCTFail("Fresh issuance never revives the already consumed token")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    let nextGeneration = try await reopened.consume(original, encodedToken: fresh.encodedToken, protection: fresh.protection,
      generation: fresh.generation, checkpoint: checkpoint, maximumTokenBytes: 8192)
    XCTAssertEqual(nextGeneration, generation + 1)
    try await reopened.enteredRecovery(original)
    try await reopened.complete(original, payload: Data([9]), resultRetentionMS: 1000)
    let complete = try await reopened.lookup(original)
    XCTAssertEqual(complete?.state, 3); XCTAssertEqual(complete?.result, Data([9]))
    XCTAssertEqual(complete?.checkpointIssues, 2); XCTAssertEqual(complete?.runStartedMS, 1000)
    do {
      _ = try await reopened.reissue(original, issuer: retryIssuer, previousToken: previous, lifetimeMS: 1000,
        maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192)
      XCTFail("An entered or completed continuation cannot use the earlier issuance receipt")
    } catch { XCTAssertEqual(error as? ServiceFailure, .operationConflict) }
    await reopened.close()
  }

  func testAuthorizedDurableMethodReissuesAfterLostResumeConfirmationWithoutQueryMutation() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-reissue-callback-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 6, resultBytes: 65_536, active: 2))
    let (definition, method, contract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [10: V4NamespaceValue.head(0, 256), 20: V4Crypto.text("cursor")])
    let (resumeDefinition, resumeMethod, resumeContract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [1: V4NamespaceValue.head(0, 2), 9: V4NamespaceValue.head(0, 4248),
        10: V4NamespaceValue.head(0, 4248), 20: V4Crypto.text("cursor")])
    let (issueDefinition, issueMethod, issueContract) = try serverFixture(environment, vectorID: "service_unary_execution",
      replacing: [1: V4NamespaceValue.head(0, 3), 10: V4NamespaceValue.head(0, 8192)])
    let caller = try serverCaller(); let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1]))
    let payload = Data([8]); let request = try serverRequest(method, contract: contract, payload: payload)
    let peer = try ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 8, count: 32))
    let bindingTarget = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client", peers: [peer])
    let reference = try OperationReference(target: bindingTarget, authority: caller.executionAuthority, namespace: contract.namespace,
      operation: request.bytes(1), request: request.bytes(4), contract: contract.digest, shape: .unary,
      durable: true, deadline: request.uint(5), cancellation: true, limit: 256)
    let selector = V4ServerExecutionSelector(tenant: reference.tenant, audience: reference.audience, namespace: reference.serviceNamespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: reference.operationID,
      request: reference.requestDigest, contract: reference.serviceContractDigest)
    let log = V4ServiceServerResumeLog()
    let registry = try ServiceRegistry(environment: environment,
      configuration: ServiceRegistryConfiguration(authority: "example", queryBinding: serverQueryBinding(), executionStore: store))
    try registry.registerUnary(method, in: definition, contract: contract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response))) { _, invocation, _ in
        let token = try await invocation.issueCheckpoint(checkpoint, lifetimeMS: 5000)
        await log.recordIssued(token); throw ServiceFailure.serviceUnavailable
      }
    try registry.registerResume(resumeMethod, in: resumeDefinition, contract: resumeContract, originalContract: contract,
      streamKind: "example.reissue-target", callers: [caller],
      originalResponseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response))) { _, _, observed, _ in
        await log.recordResume(observed); return Data([9])
      }
    try registry.registerUnary(issueMethod, in: issueDefinition, contract: issueContract, callers: [caller],
      requestCodec: BytesMessageCodec(definition: issueMethod.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(issueMethod.options.response))) { _, invocation, bytes in
        let previous = try ApplicationCheckpointToken(environment: environment, encoded: bytes, protection: .hmacSHA256, verificationKey: nil)
        let fresh = try await invocation.reissueCheckpoint(reference, originalContract: contract, previousToken: previous, lifetimeMS: 1000)
        return fresh.encodedToken
      }
    let server = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 2,
      checkpointPolicy: { (8192, 10_000) }, check: {})
    let channel = try V4RPCChannel(environment: environment, maximumGeneral: 2,
      storage: environment.rpcServicesStorage(maximumGeneral: 2, execution: true))
    let source = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await channel.bindInbound(server); try await channel.start { source }
    await source.push(try V4RPCFragment(kind: .begin, serial: 1, payload: request.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 1, payload: payload).encoded())
    try await waitForObservation { (try? await store.lookup(selector, includeResult: false))?.state == 5 && server.generalPositionCount == 0 }
    let issuedValue = await log.issued; let issued = try XCTUnwrap(issuedValue)
    let target = V4ApplicationInputTransport(kind: "example.reissue-target"); let context = Data(repeating: 5, count: 32)
    try server.adoptStream(id: 19, kind: target.kind, source: target, facts: (context, 19, 8192, 10_000), readable: { false })
    let resumePayload = V4Crypto.map([(0, V4Crypto.bytes(selector.operation)), (1, V4Crypto.bytes(selector.request)),
      (2, V4NamespaceValue.head(0, issued.protection.rawValue)), (3, V4Crypto.bytes(issued.encodedToken)),
      (4, V4NamespaceValue.head(0, issued.generation)), (5, checkpoint.encoded()),
      (6, V4Crypto.bytes(context)), (7, V4NamespaceValue.head(0, 19))])
    let resumeRequest = try serverRequest(resumeMethod, contract: resumeContract, payload: resumePayload,
      kindOverride: "resume_request", operationByte: 5)
    await source.holdWrites()
    await source.push(try V4RPCFragment(kind: .begin, serial: 2, payload: resumeRequest.encoded()).encoded())
    await source.push(try V4RPCFragment(kind: .data, serial: 2, payload: resumePayload).encoded())
    try await waitForObservation { await source.publicationWaiting() }
    try await source.close()
    try await waitForObservation { (try? await store.lookup(selector, includeResult: false))?.active == false && server.generalPositionCount == 0 }
    let entered = await log.checkpoints; XCTAssertTrue(entered.isEmpty)
    let before = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(before?.generation, issued.generation + 1); XCTAssertEqual(before?.recoveryEntered, false)
    XCTAssertNil(before?.tokenDigest); XCTAssertEqual(before?.reservedBytes, 256)
    await channel.close(); server.close()

    // The new authorized issuance method is an ordinary durable RPC callback;
    // the original Query/management path does not create a replacement token.
    try advanceTime(environment, to: 2000)
    let current = try registry.admission(identity: serverIdentity(), execution: true, maximumGeneral: 1,
      checkpointPolicy: { (8192, 10_000) }, check: {})
    let currentChannel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: true))
    let currentSource = V4ApplicationInputTransport(kind: "flowersec.rpc.v4")
    try await currentChannel.bindInbound(current); try await currentChannel.start { currentSource }
    var fresh = Data()
    for index in 0...1 {
      let issueRequest = try serverRequest(issueMethod, contract: issueContract, payload: issued.encodedToken,
        operationByte: UInt8(index + 6), clockMS: 2000)
      let serial = UInt64(index + 1)
      await currentSource.push(try V4RPCFragment(kind: .begin, serial: serial, payload: issueRequest.encoded()).encoded())
      await currentSource.push(try V4RPCFragment(kind: .data, serial: serial, payload: issued.encodedToken).encoded())
      try await waitForObservation { (try? v4ServiceTestRPCFrames(await currentSource.output()).count) == (index + 1) * 2 && current.generalPositionCount == 0 }
      let frames = try v4ServiceTestRPCFrames(await currentSource.output())
      let response = try V4ApplicationHeader(encoded: frames[index * 2].payload, registry: currentChannel.registry)
      XCTAssertEqual(response.kind, "execution_unary_response")
      if index == 0 { fresh = frames[1].payload } else { XCTAssertEqual(frames[3].payload, fresh) }
    }
    let after = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(after?.state, 5); XCTAssertEqual(after?.active, false)
    XCTAssertEqual(after?.generation, before?.generation); XCTAssertEqual(after?.checkpoint, before?.checkpoint)
    XCTAssertEqual(after?.runStartedMS, before?.runStartedMS)
    XCTAssertEqual(after?.checkpointIssues, 2); XCTAssertEqual(after?.reissuedToken, fresh)
    let decoded = try ApplicationCheckpointToken(environment: environment, encoded: fresh, protection: .hmacSHA256, verificationKey: nil)
    XCTAssertEqual(decoded.expiresAtMS, 3000)
    try advanceTime(environment, to: 3100)
    let expiredRequest = try serverRequest(issueMethod, contract: issueContract, payload: issued.encodedToken,
      operationByte: 8, clockMS: 3100)
    await currentSource.push(try V4RPCFragment(kind: .begin, serial: 3, payload: expiredRequest.encoded()).encoded())
    await currentSource.push(try V4RPCFragment(kind: .data, serial: 3, payload: issued.encodedToken).encoded())
    try await waitForObservation { (try? v4ServiceTestRPCFrames(await currentSource.output()).count) == 6 && current.generalPositionCount == 0 }
    let frames = try v4ServiceTestRPCFrames(await currentSource.output())
    let expiredResponse = try V4ApplicationHeader(encoded: frames[4].payload, registry: currentChannel.registry)
    XCTAssertEqual(expiredResponse.kind, "execution_unary_sdk_error")
    let expired = try await store.lookup(selector, includeResult: false)
    XCTAssertEqual(expired?.reissuedToken, fresh); XCTAssertEqual(expired?.reissueExpiresAtMS, 3000)
    XCTAssertEqual(expired?.checkpointIssues, 2)
    await currentChannel.close(); current.close(); registry.close(); await store.close()
  }
}


extension ServiceApplicationOwnershipV4Tests {
  func testStreamingReissueKeepsOriginalRunCapCountersAndAtomicAcceptance() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let directory = v4ServiceTestDirectory.appendingPathComponent("flowersec-swift-reissue-stream-cap-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try SQLiteServiceExecutionStore(environment: environment,
      configuration: executionStoreConfiguration(directory: directory, create: true, rows: 3, resultBytes: 16_384, active: 1))
    let (_, method, contract) = try serverFixture(environment, vectorID: "service_stream_execution",
      replacing: [10: V4NamespaceValue.head(0, 16), 20: V4Crypto.text("cursor")])
    let request = try serverRequest(method, contract: contract, payload: Data([1])); let caller = try serverCaller()
    let original = V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: contract.namespace,
      caller: caller.subject, authority: caller.executionAuthority, operation: try request.bytes(1),
      request: try request.bytes(4), contract: contract.digest)
    let resume = executionSelector(operation: 5); let issuer = executionSelector(operation: 6)
    _ = try await store.admit(original, deadline: request.uint(5), historyMS: contract.uint(14), responseBytes: 0,
      originalStreamHeader: request.encoded())
    try await store.started(original)
    try await store.reserveStreamItem(original, bytes: 3, maximumItems: 2, maximumBytes: 6)
    let checkpoint = try ApplicationCheckpoint(format: "cursor", position: Data([1]))
    let issued = try await store.issue(original, checkpoint: checkpoint, lifetimeMS: 5000)
    let previous = try ApplicationCheckpointToken(environment: environment, encoded: issued.encodedToken,
      protection: issued.protection, verificationKey: nil)
    try await store.complete(original, payload: nil, resultRetentionMS: 0)
    _ = try await store.admit(resume, deadline: 20_000, historyMS: 1000, responseBytes: 4248)
    try await store.started(resume)
    // One active slot is transferred from the accepted recovery RPC to the
    // original continuation in the same transaction; it is never doubled.
    let generation = try await store.consume(original, encodedToken: issued.encodedToken, protection: issued.protection,
      generation: issued.generation, checkpoint: checkpoint, maximumTokenBytes: 8192,
      confirmation: resume, resultRetentionMS: 5000, maximumOriginalRunMS: 2000)
    let accepted = try await store.lookup(resume, includeResult: false)
    XCTAssertEqual(accepted?.state, 3); XCTAssertEqual(accepted?.active, false)
    try await store.complete(original, payload: nil, resultRetentionMS: 0, reason: 2)
    try advanceTime(environment, to: 2000)
    _ = try await store.admit(issuer, deadline: 20_000, historyMS: 1000, responseBytes: 8192)
    try await store.started(issuer)
    let fresh = try await store.reissue(original, issuer: issuer, previousToken: previous, lifetimeMS: 5000,
      maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192, maximumOriginalRunMS: 2000, maximumIssuerRunMS: 5000)
    XCTAssertEqual(fresh.generation, generation); XCTAssertEqual(fresh.expiresAtMS, 3000)
    let before = try await store.lookup(original, includeResult: false)
    XCTAssertEqual(before?.runStartedMS, 1000); XCTAssertEqual(before?.originalStreamHeader, request.encoded())
    XCTAssertEqual(before?.streamItems, 1); XCTAssertEqual(before?.streamBytes, 3)
    try advanceTime(environment, to: 3000)
    do {
      _ = try await store.reissue(original, issuer: issuer, previousToken: previous, lifetimeMS: 5000,
        maximumIssuedDurationMS: 5000, maximumTokenBytes: 8192, maximumOriginalRunMS: 2000, maximumIssuerRunMS: 5000)
      XCTFail("Issuance cannot reset the original stream run origin")
    } catch { XCTAssertEqual(error as? ServiceFailure, .deadlineExceeded) }
    let after = try await store.lookup(original, includeResult: false)
    XCTAssertEqual(after?.runStartedMS, before?.runStartedMS); XCTAssertEqual(after?.streamItems, before?.streamItems)
    XCTAssertEqual(after?.streamBytes, before?.streamBytes); XCTAssertEqual(after?.generation, before?.generation)
    XCTAssertEqual(after?.reissuedToken, before?.reissuedToken); XCTAssertEqual(after?.checkpointIssues, before?.checkpointIssues)
    await store.close()
  }
}


#endif
