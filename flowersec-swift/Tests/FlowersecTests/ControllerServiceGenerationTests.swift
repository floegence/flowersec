import Foundation
import XCTest
@testable import Flowersec

#if os(macOS) || os(iOS)
private final class ControllerDiagnosticEvents: @unchecked Sendable {
  private let gate = NSLock()
  private var recorded: [TransportDiagnosticEvent] = []
  var values: [TransportDiagnosticEvent] { gate.withLock { recorded } }
  func append(_ event: TransportDiagnosticEvent) { gate.withLock { recorded.append(event) } }
  func waitForClose() async throws {
    let until = ContinuousClock.now.advanced(by: .seconds(2))
    while !values.contains(where: { $0.state == .closed }) {
      guard ContinuousClock.now < until else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(2))
    }
  }
}
#endif

private final class ControllerGenerationSession: V4ServiceSession, @unchecked Sendable {
  let serviceEnvironment: V4EnvironmentFoundation
  let serviceChannel: V4RPCChannel?
  let serviceIdentity: ServiceCallerIdentity
  var serviceManagement: (any V4ExecutionManagementOwner)? { nil }
  var serviceNotifications: V4NotificationPublisher? { nil }
  var serviceNotificationReceiver: V4NotificationReceiver? { nil }
  private var closed = false
  var dedicatedStream: ControllerPreBeginCarrier?
  init(environment: V4EnvironmentFoundation, identity: ServiceCallerIdentity) throws {
    serviceEnvironment = environment; serviceIdentity = identity
    serviceChannel = try V4RPCChannel(environment: environment, maximumGeneral: 1,
      storage: environment.rpcServicesStorage(maximumGeneral: 1, execution: false))
  }
  func checkServiceSession() throws {
    try serviceEnvironment.gate.withLock {
      guard !closed else { throw ServiceFailure.closed }
      try serviceEnvironment.account.check()
    }
  }
  func captureServiceResumeTarget(_ stream: any ByteStream, kind: String) throws -> ServiceResumeTarget {
    throw ServiceFailure.serviceUnavailable
  }
  func openServiceTransport(kind: String) async throws -> any V4RPCTransport { throw ServiceFailure.serviceUnavailable }
  func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
    guard let dedicatedStream else { throw SessionError.closed }; return dedicatedStream
  }
  func acceptStream() async throws -> IncomingStream { throw SessionError.closed }
  func rekey() async throws { throw SessionError.closed }
  func probeLiveness() async throws -> Duration { throw SessionError.closed }
  func waitTermination() async -> SessionTermination { SessionTermination(error: .closed) }
  func close() async throws {
    serviceEnvironment.gate.withLock { closed = true }
    await serviceChannel?.close()
  }
}

private actor ControllerGenerationSource: V4FixedContractSource {
  let value: ServiceContractSnapshot
  private var held: Bool
  private var entered = false
  private var waiter: CheckedContinuation<Void, Never>?
  private(set) var requests: [ServiceContractSourceRequest] = []
  init(_ value: ServiceContractSnapshot, held: Bool = false) { self.value = value; self.held = held }
  func sdkSnapshot(_ request: ServiceContractSourceRequest, session: any Session) async throws -> ServiceContractSnapshot {
    requests.append(request); entered = true
    if held { await withCheckedContinuation { waiter = $0 } }
    return value
  }
  func snapshot(_ request: ServiceContractSourceRequest, session: any Session,
    context: ApplicationInvocationContext) async throws -> ServiceContractSnapshot {
    try context.checkCancellation(); return try await sdkSnapshot(request, session: session)
  }
  func waitForEntry() async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while !entered {
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(2))
    }
  }
  func hold() { held = true; entered = false }
  func release() { held = false; waiter?.resume(); waiter = nil }
}

/// Holds the publisher before the first real byte-acceptance guard so a
/// Controller switch happens after Start while the operation remains queued.
private actor ControllerPreBeginCarrier: V4RPCTransport {
  nonisolated let kind = "flowersec.rpc.v4"
  private var held: Bool
  private var writer: CheckedContinuation<Void, Never>?
  private var reader: CheckedContinuation<Void, Never>?
  private var closed = false
  private var accepted = Data()
  private var input = Data()
  private var inputEnded = false
  init(held: Bool) { self.held = held }
  var publicationWaiting: Bool { writer != nil }
  var inputWaiting: Bool { reader != nil }
  var output: Data { accepted }
  func receive(_ bytes: Data) { input += bytes; reader?.resume(); reader = nil }
  func finishInput() { inputEnded = true; reader?.resume(); reader = nil }
  func releasePublisher() { held = false; writer?.resume(); writer = nil }
  func read(maxBytes: Int) async throws -> Data? {
    while !closed && !inputEnded && input.isEmpty { await withCheckedContinuation { reader = $0 } }
    guard !input.isEmpty else { return nil }
    let count = min(maxBytes, input.count), bytes = Data(input.prefix(count)); input.removeFirst(count); return bytes
  }
  func write(_ bytes: Data) async throws -> Int { throw ServiceFailure.protocolFailure }
  func writeRPCChunk(_ bytes: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int {
    while held && !closed { await withCheckedContinuation { writer = $0 } }
    guard !closed else { throw ServiceFailure.closed }
    try beforeAccept(); self.accepted += bytes; accepted(bytes.count); return bytes.count
  }
  func closeWrite() async throws {}
  func finish() async throws {}
  func terminalError() async -> SessionError? { closed ? .closed : nil }
  func reset() async throws { try await close() }
  func close() async throws {
    closed = true; writer?.resume(); writer = nil; reader?.resume(); reader = nil
  }
}

@MainActor
final class ControllerServiceGenerationTests: XCTestCase {
  private func environment() throws -> V4EnvironmentFoundation {
    let limit = V4ResourceVector(sdkBytes: 1 << 30, providerBytes: 1 << 30, diskBytes: 1 << 30,
      items: 65_536, work: 512, tasks: 512, timers: 512, connections: 64, handshakes: 64, sessions: 64, handles: 1024)
    let root = try V4ResourceRoot(V4ResourceRootConfiguration(limit: limit, accounts: 16, reservations: 1024,
      references: 2048, cleanupWaiters: 16, runtimeOverheadBytes: 1024))
    let tenant = try root.account(kind: .tenant, identity: V4ResourceIdentity(high: 91, low: 1), limit: limit)
    let environment = try V4EnvironmentFoundation(root: root, tenant: tenant,
      configuration: V4EnvironmentConfiguration(identity: V4ResourceIdentity(high: 91, low: 2), limit: limit,
        maximumReadBudgets: 8, maximumWork: 8, runtimeOverheadBytes: 1024, cleanupTimeout: .seconds(1),
        verificationContinuity: .onlineBootstrap, applicationResources: .constrained),
      timeProfile: V4TimeProfile(rateNumerator: 0, rateDenominator: 1, quantizationMS: 0,
        maximumWidthMS: 100, maximumAnchorAgeMS: 100_000), monotonicSource: V4ContinuousTimeSource())
    try environment.clock.installTrusted(at: environment.clock.mark(), interval: V4TimeInterval(lowerMS: 1000, upperMS: 1000))
    return environment
  }
  private func fixture(_ environment: V4EnvironmentFoundation, streaming: Bool = false) throws ->
    (ServiceDefinition, MethodDefinition, ServiceContractSnapshot, ServiceBindingTarget, ServiceCallerIdentity, Data) {
    let corpus = try JSONDecoder().decode(V4JSON.self,
      from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
    let vector = try XCTUnwrap(corpus["vectors"].array!.first { $0["id"].text == (streaming ? "service_stream_transient" : "service_unary_transient") })
    let bytes = try v4RuleHex(XCTUnwrap(vector["hex"].text))
    let contract = try ServiceContract(environment: environment, canonical: bytes)
    let parsed = try V4NamespaceDocument(bytes, schema: "ServiceContract", bytes: 8192, nodes: 4096,
      registry: V4NamespaceRegistry()).root
    let request = try MessageDefinition(schemaDigest: Data(repeating: 7, count: 32),
      revision: parsed.t("request_schema_revision"), maxMessageBytes: 1_048_576)
    let response = try MessageDefinition(schemaDigest: Data(repeating: 8, count: 32),
      revision: parsed.t("response_schema_revision"), maxMessageBytes: 1_048_576)
    let errors = try parsed.field("application_error_catalog").children.map { entry in
      try ApplicationErrorDefinition(code: UInt32(entry.u("code")),
        message: MessageDefinition(schemaDigest: entry.b("schema_digest"), revision: entry.t("schema_revision"),
          maxMessageBytes: max(1, Int(entry.u("max_payload_bytes")))), maxPayloadBytes: Int(entry.u("max_payload_bytes")))
    }
    let limits: StreamingLimits?
    if streaming { limits = try StreamingLimits(maxItemCount: UInt32(contract.uint(24)), maxPayloadBytes: contract.uint(25), maxDurationMS: contract.uint(26)) }
    else { limits = nil }
    let method = try MethodDefinition(MethodDefinitionOptions(typeID: contract.typeID, shape: streaming ? .serverStreaming : .unary, semantics: .transient,
      request: request, response: response, responseRevision: response.revision, requestMaxBytes: 1_048_576,
      minResponseLimitBytes: Int(contract.uint(9)), maxResponseBytes: Int(contract.uint(10)), streaming: limits, errors: errors))
    let definition = try ServiceDefinition(namespace: contract.namespace, methods: [ServiceMethod(name: "read", method: method)])
    let peer = try ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 8, count: 32))
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client", peers: [peer])
    let identity = ServiceCallerIdentity(tenant: "tenant", audience: "service", subject: "client", identityDigest: Data(repeating: 9, count: 32),
      peerSubject: peer.subject, peerIdentityDigest: peer.identityDigest)
    return (definition, method, ServiceContractSnapshot(contract: contract), target, identity, bytes)
  }
  private func bind(_ session: ControllerGenerationSession, _ definition: ServiceDefinition, _ target: ServiceBindingTarget,
    _ source: ControllerGenerationSource, _ generation: V4ControllerServiceGeneration,
    previous: [(MethodDefinition, ServiceContractSnapshot, ContractAcceptance)] = [],
    acceptance: ContractAcceptance = .exact, streams: [ServiceStreamBinding] = []) async throws -> ServiceClient {
    let channel = try XCTUnwrap(session.serviceChannel)
    if !(await channel.isAvailable) {
      let transport = ControllerPreBeginCarrier(held: false)
      try await channel.start { transport }
    }
    return try await v4BindService(session: session, definition: definition, target: target, source: source,
      deadlineAtMS: 30_000, acceptance: acceptance, offerRefresh: .managed, streamBindings: streams, context: nil,
      generation: generation, previous: previous)
  }

  func testGenerationRetirementReleasesFacadeAliasWhilePreparedHandleKeepsOriginalSession() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, snapshot, target, identity, _) = try fixture(environment)
    let session = try ControllerGenerationSession(environment: environment, identity: identity)
    let generation = V4ControllerServiceGeneration(session: session, generation: 1)
    var client: ServiceClient? = try await bind(session, definition, target, ControllerGenerationSource(snapshot), generation)
    let slot = try generation.attach(try XCTUnwrap(client))
    weak var original = client
    let operation = try await XCTUnwrap(client).prepareOperation(method, request: Data([1]),
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)),
      options: ServiceCallOptions(deadlineAtMS: 20_000))
    generation.retire(); client = nil
    XCTAssertNil(slot.client)
    XCTAssertNotNil(original)
    // Existing Start/result checks use the fixed binding, while preparation
    // and refreshing must pass the retired Controller generation gate.
    try XCTUnwrap(original).checkAdmission()
    XCTAssertThrowsError(try XCTUnwrap(original).checkPreparation())
    XCTAssertEqual(operation.submission, .notSubmitted)
    operation.close()
    let releasedBy = ContinuousClock.now.advanced(by: .seconds(2))
    while original != nil, ContinuousClock.now < releasedBy {
      try await ContinuousClock().sleep(for: .milliseconds(2))
    }
    XCTAssertNil(original)
    try await session.close()
  }

  #if os(macOS) || os(iOS)
  func testUnaryDiagnosticsSurviveCanceledTypedAndEncodedWaits() async throws {
    for encoded in [false, true] {
      let environment = try environment(); defer { environment.beginClose() }
      let (definition, method, snapshot, target, identity, _) = try fixture(environment)
      let session = try ControllerGenerationSession(environment: environment, identity: identity)
      let carrier = ControllerPreBeginCarrier(held: false), channel = try XCTUnwrap(session.serviceChannel)
      try await channel.start { carrier }; try await channel.waitReady()
      let generation = V4ControllerServiceGeneration(session: session, generation: 1)
      let client = try await bind(session, definition, target, ControllerGenerationSource(snapshot), generation)
      let events = ControllerDiagnosticEvents()
      try environment.installDiagnosticSink(TransportDiagnosticSinkConfiguration { events.append($0) },
        random: { Data(repeating: $0 == 16 ? 1 : 0, count: $0) })
      let operation = try await client.prepareOperation(method, request: Data([1]),
        requestCodec: BytesMessageCodec(definition: method.options.request),
        responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)),
        options: ServiceCallOptions(deadlineAtMS: 20_000, responseLimitBytes: 32))
      try await operation.start()
      do { try await operation.start(); XCTFail("A repeated Start was admitted") } catch {}
      let waiting = Task { () throws -> Data in
        if encoded { return try await operation.takeEncodedResult().payload }
        return try await operation.takeResult().value
      }
      await Task.yield(); waiting.cancel()
      do { _ = try await waiting.value; XCTFail("Canceled waiter received a result") }
      catch { XCTAssertTrue(error is CancellationError || error as? SessionError == .canceled) }
      let until = ContinuousClock.now.advanced(by: .seconds(2))
      var output = await carrier.output
      while output.count < 4 || output.count < Int(V4Crypto.number(output.prefix(4))) + 4 {
        guard ContinuousClock.now < until else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(2)); output = await carrier.output
      }
      let first = try V4RPCFragment(encoded: Data(output.prefix(Int(V4Crypto.number(output.prefix(4))) + 4)))
      let request = try V4ApplicationHeader(encoded: first.payload, registry: channel.registry)
      let response = try V4ApplicationHeader(kind: "transient_unary_response", fields: [2: request.fields[2]!,
        3: .uint(2), 6: request.fields[6]!], registry: channel.registry)
      let bytes = try V4RPCFragment(kind: .begin, serial: 1, replyTo: first.serial, payload: response.encoded()).encoded()
        + V4RPCFragment(kind: .data, serial: 1, offset: 0, payload: Data([2, 3])).encoded()
      await carrier.receive(bytes)
      if encoded { let result = try await operation.takeEncodedResult(); XCTAssertEqual(result.payload, Data([2, 3])) }
      else { let result = try await operation.takeResult(); XCTAssertEqual(result.value, Data([2, 3])) }
      operation.close(); client.close(); try await session.close()
      try await events.waitForClose()
      XCTAssertEqual(events.values.map(\.state), [.started, .succeeded, .closed])
      XCTAssertEqual(Set(events.values.map(\.correlationID)).count, 1)
    }
  }

  func testStreamingDiagnosticsSurviveCanceledTypedAndEncodedWaitsUntilRealEOF() async throws {
    for encoded in [false, true] {
      let environment = try environment(); defer { environment.beginClose() }
      let (definition, method, snapshot, target, identity, _) = try fixture(environment, streaming: true)
      let session = try ControllerGenerationSession(environment: environment, identity: identity)
      let carrier = ControllerPreBeginCarrier(held: false); session.dedicatedStream = carrier
      let generation = V4ControllerServiceGeneration(session: session, generation: 1)
      let binding = try ServiceStreamBinding(method: method, kind: "example.diagnostic.stream")
      let client = try await bind(session, definition, target, ControllerGenerationSource(snapshot), generation, streams: [binding])
      let events = ControllerDiagnosticEvents()
      try environment.installDiagnosticSink(TransportDiagnosticSinkConfiguration { events.append($0) },
        random: { Data(repeating: $0 == 16 ? 1 : 0, count: $0) })
      let operation = try await client.prepareStream(method, request: Data([1]),
        requestCodec: BytesMessageCodec(definition: method.options.request),
        itemCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)),
        options: ServiceCallOptions(deadlineAtMS: 20_000, responseLimitBytes: 32))
      let waiting = Task { () throws -> Void in
        if encoded { _ = try await operation.readNextEncoded() } else { _ = try await operation.readNext() }
      }
      await Task.yield(); waiting.cancel()
      do { try await waiting.value; XCTFail("Canceled readiness wait completed") }
      catch { XCTAssertTrue(error is CancellationError || error as? SessionError == .canceled) }
      try await operation.start()
      do { try await operation.start(); XCTFail("A repeated Start was admitted") } catch {}
      let reading = Task { () throws -> Void in
        if encoded { _ = try await operation.readNextEncoded() } else { _ = try await operation.readNext() }
      }
      let until = ContinuousClock.now.advanced(by: .seconds(2))
      while !(await carrier.inputWaiting) {
        guard ContinuousClock.now < until else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(2))
      }
      do {
        if encoded { _ = try await operation.readNextEncoded() } else { _ = try await operation.readNext() }
        XCTFail("A concurrent receive waiter was admitted")
      } catch { XCTAssertEqual(error as? ServiceFailure, .resourceExhausted) }
      reading.cancel()
      do { try await reading.value; XCTFail("Canceled cursor wait completed") }
      catch { XCTAssertTrue(error is CancellationError || error as? SessionError == .canceled) }
      let response = try V4ApplicationHeader(kind: "transient_stream_item", fields: [2: .uint(UInt64(method.typeID)),
        3: .uint(2), 6: .bytes(snapshot.contract.digest)], registry: try XCTUnwrap(session.serviceChannel).registry).encoded()
      await carrier.receive(V4Crypto.integer(UInt64(response.count), width: 2) + response + Data([2, 3]))
      await carrier.finishInput()
      if encoded {
        let item = try await operation.readNextEncoded(); XCTAssertEqual(item?.payload, Data([2, 3]))
        let end = try await operation.readNextEncoded(); XCTAssertNil(end)
      } else {
        let item = try await operation.readNext(); XCTAssertEqual(item?.value, Data([2, 3]))
        let end = try await operation.readNext(); XCTAssertNil(end)
      }
      operation.close(); client.close(); try await session.close()
      try await events.waitForClose()
      XCTAssertEqual(events.values.map(\.state), [.started, .succeeded, .closed])
      XCTAssertEqual(Set(events.values.map(\.correlationID)).count, 1)
    }
  }
  func testOriginalRPCFailureStillEmitsAfterItsOnlyWaiterCancels() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, snapshot, target, identity, _) = try fixture(environment)
    let session = try ControllerGenerationSession(environment: environment, identity: identity)
    let generation = V4ControllerServiceGeneration(session: session, generation: 1)
    let client = try await bind(session, definition, target, ControllerGenerationSource(snapshot), generation)
    let events = ControllerDiagnosticEvents()
    try environment.installDiagnosticSink(TransportDiagnosticSinkConfiguration { events.append($0) },
      random: { Data(repeating: $0 == 16 ? 1 : 0, count: $0) })
    let operation = try await client.prepareOperation(method, request: Data([1]),
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)),
      options: ServiceCallOptions(deadlineAtMS: 20_000, responseLimitBytes: 32))
    try await operation.start()
    let waiter = Task { try await operation.takeResult() }
    await Task.yield(); waiter.cancel()
    do { _ = try await waiter.value; XCTFail("Canceled wait received an outcome") } catch {}
    await session.serviceChannel?.close()
    let until = ContinuousClock.now.advanced(by: .seconds(2))
    while !events.values.contains(where: { $0.state == .failed }) {
      guard ContinuousClock.now < until else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(2))
    }
    operation.close(); client.close(); try await session.close(); try await events.waitForClose()
    XCTAssertEqual(events.values.map(\.state), [.started, .failed, .closed])
  }
  #endif

  func testSuspendedCandidateDoesNotInstallAfterOriginalGenerationRetires() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, _, snapshot, target, identity, _) = try fixture(environment)
    let session = try ControllerGenerationSession(environment: environment, identity: identity)
    let generation = V4ControllerServiceGeneration(session: session, generation: 4)
    let source = ControllerGenerationSource(snapshot, held: true)
    let transport = ControllerPreBeginCarrier(held: false)
    try await XCTUnwrap(session.serviceChannel).start { transport }
    try await XCTUnwrap(session.serviceChannel).waitReady()
    _ = try environment.serviceContracts()
    let before = environment.root.snapshot().used
    let acquisition = Task { try await bind(session, definition, target, source, generation) }
    try await source.waitForEntry()
    generation.retire(); await source.release()
    do { _ = try await acquisition.value; XCTFail("retired candidate became a current binding") }
    catch { XCTAssertTrue(error is V4ControllerBindingFailure) }
    XCTAssertEqual(environment.root.snapshot().used, before)
    try await session.close()
  }

  func testManagedRefreshCannotInstallIntoRetiredGeneration() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, snapshot, target, identity, _) = try fixture(environment)
    let session = try ControllerGenerationSession(environment: environment, identity: identity)
    let generation = V4ControllerServiceGeneration(session: session, generation: 7)
    let source = ControllerGenerationSource(snapshot)
    let acceptance = try ContractAcceptance.bounded([ContractRange(field: .maxResponseBytes,
      lower: UInt64(method.options.minResponseLimitBytes), upper: UInt64(method.options.maxResponseBytes))])
    let client = try await bind(session, definition, target, source, generation, acceptance: acceptance)
    await source.hold()
    let refreshing = Task { try await client.refresh(method, deadlineAtMS: 30_000) }
    try await source.waitForEntry()
    generation.retire(); await source.release()
    do { _ = try await refreshing.value; XCTFail("late refresh installed into a retired generation") }
    catch { XCTAssertEqual(error as? ServiceFailure, .serviceUnavailable) }
    XCTAssertTrue(try client.contract(method).contract === snapshot.contract)
    let requests = await source.requests
    XCTAssertEqual(requests.count, 2)
    XCTAssertEqual(requests[1].known?.contract.digest, snapshot.contract.digest)
    XCTAssertNil(requests[1].wantedDigest)
    client.close(); try await session.close()
  }

  func testReplacementKeepsExactDigestAfterPreviousSessionCloses() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, snapshot, target, identity, raw) = try fixture(environment)
    let previous = try ControllerGenerationSession(environment: environment, identity: identity)
    let generation = V4ControllerServiceGeneration(session: previous, generation: 1)
    let old = try await bind(previous, definition, target, ControllerGenerationSource(snapshot), generation)
    let installed = try old.contractStateForReplacement()
    generation.retire(); old.close(); try await previous.close()
    let next = try ControllerGenerationSession(environment: environment, identity: identity)
    let nextGeneration = V4ControllerServiceGeneration(session: next, generation: 2)
    let reference = try V4ApplicationReference()
    guard case .map(let fields) = try reference.text.wireMap(raw, schema: "ServiceContract", cap: 8192) else {
      throw ServiceFailure.protocolFailure
    }
    let requestLimit = try snapshot.contract.uint(23)
    XCTAssertGreaterThan(requestLimit, 0)
    let changedBytes = V4CBORValue.map(fields.map { field in
      if case .uint(23) = field.key { return .init(key: field.key, value: .uint(requestLimit - 1)) }
      return field
    }).encoded()
    let changed = try ServiceContract(environment: environment, canonical: changedBytes)
    let source = ControllerGenerationSource(ServiceContractSnapshot(contract: changed))
    do {
      _ = try await bind(next, definition, target, source, nextGeneration, previous: installed)
      XCTFail("replacement silently installed another exact contract")
    } catch { XCTAssertTrue(error is ContractPolicyFailure) }
    let requests = await source.requests
    XCTAssertEqual(requests.count, 1)
    XCTAssertEqual(requests[0].wantedDigest, snapshot.contract.digest)
    XCTAssertTrue(requests[0].known?.contract === snapshot.contract)
    let accepted = try await bind(next, definition, target, ControllerGenerationSource(snapshot), nextGeneration, previous: installed)
    XCTAssertEqual(try accepted.contract(method).contract.digest, snapshot.contract.digest)
    accepted.close(); try await next.close()
  }

  func testPhysicalBindingTailKeepsOriginalMethodPositionAfterLogicalClose() throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, _, snapshot, target, identity, _) = try fixture(environment)
    let session = try ControllerGenerationSession(environment: environment, identity: identity)
    var client: ServiceClient? = try ServiceClient(session: session, definition: definition, target: target,
      contracts: [snapshot], acceptance: .exact)
    weak var original = client
    var tail: V4ServiceBindingTail? = try XCTUnwrap(client).bindingTail()
    client?.close(); client = nil
    var positions: [V4ServiceContractRegistration] = []
    let coordinator = try environment.serviceContracts()
    for _ in 0..<15 { positions.append(try coordinator.reserve(definition)) }
    XCTAssertThrowsError(try coordinator.reserve(definition))
    XCTAssertNotNil(original)
    tail = nil
    XCTAssertNil(original)
    positions.append(try coordinator.reserve(definition))
    XCTAssertEqual(positions.count, 16)
    withExtendedLifetime(tail) {}
  }

  func testQueryPositionsRemainOccupiedUntilOriginalPhysicalOwnerLeaves() throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (_, _, _, _, identity, _) = try fixture(environment)
    let first = try ControllerGenerationSession(environment: environment, identity: identity)
    let second = try ControllerGenerationSession(environment: environment, identity: identity)
    let coordinator = try environment.serviceContracts()
    var original: V4ContractFetchPosition? = try coordinator.acquire(session: first)
    let concurrent = try coordinator.acquire(session: first)
    XCTAssertThrowsError(try coordinator.acquire(session: first))
    XCTAssertThrowsError(try coordinator.acquire(session: second))
    original = nil
    let next = try coordinator.acquire(session: second)
    XCTAssertThrowsError(try coordinator.acquire(session: second))
    withExtendedLifetime((original, concurrent, next)) {}
  }

  func testQueuedUnaryReselectsTwiceAfterStartBeforeAnyBeginBytes() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, snapshot, target, identity, _) = try fixture(environment)
    let source = ControllerGenerationSource(snapshot)
    let sessions = try (0..<3).map { _ in try ControllerGenerationSession(environment: environment, identity: identity) }
    let generations = sessions.enumerated().map { V4ControllerServiceGeneration(session: $0.element, generation: UInt64($0.offset + 1)) }
    let carriers = [ControllerPreBeginCarrier(held: true), ControllerPreBeginCarrier(held: true), ControllerPreBeginCarrier(held: false)]
    let recipe = try ServiceMethodWorkload(method: method, requestBytes: 1, responseBytes: method.options.minResponseLimitBytes)
    var clients: [ServiceClient] = []
    for index in sessions.indices {
      let carrier = carriers[index]
      try await XCTUnwrap(sessions[index].serviceChannel).start { carrier }
      try await XCTUnwrap(sessions[index].serviceChannel).waitReady()
      let client = try await bind(sessions[index], definition, target, source, generations[index])
      let paid = try V4ServiceUnaryTarget(environment: environment, recipe: recipe)
      try await paid.attach(client); client.unaryTargets = [paid]; clients.append(client)
    }
    let declaration = try V4ControllerServiceDeclaration(client: clients[0], source: source, acceptance: .exact,
      offerRefresh: .explicit, streamBindings: [], required: [], workloads: [recipe])
    try declaration.install(clients[0], generation: generations[0])
    let operation = try await clients[0].prepareOperation(method, request: Data([1]),
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)),
      options: ServiceCallOptions(deadlineAtMS: 20_000, responseLimitBytes: recipe.responseBytes))
    try operation.attachControllerRoute(declaration); try await operation.start()
    for index in 0..<2 {
      let deadline = ContinuousClock.now.advanced(by: .seconds(2))
      while !(await carriers[index].publicationWaiting) {
        guard ContinuousClock.now < deadline else { throw SessionError.timeout }
        try await ContinuousClock().sleep(for: .milliseconds(2))
      }
      XCTAssertEqual(operation.submission, .notSubmitted)
      generations[index].retire(); try declaration.install(clients[index + 1], generation: generations[index + 1])
      await carriers[index].releasePublisher()
    }
    let deadline = ContinuousClock.now.advanced(by: .seconds(2))
    while operation.submission != .submitted {
      guard ContinuousClock.now < deadline else { throw SessionError.timeout }
      try await ContinuousClock().sleep(for: .milliseconds(2))
    }
    let oldOutput = await carriers[0].output, intermediateOutput = await carriers[1].output
    XCTAssertTrue(oldOutput.isEmpty); XCTAssertTrue(intermediateOutput.isEmpty)
    let selectedOutput = await carriers[2].output
    XCTAssertFalse(selectedOutput.isEmpty)
    operation.close(); declaration.close()
    for client in clients { client.close() }
    for session in sessions { try await session.close() }
  }


  func testTryNowControllerHandleRejectsRetiredPublicationWithoutReselection() async throws {
    let environment = try environment(); defer { environment.beginClose() }
    let (definition, method, snapshot, target, identity, _) = try fixture(environment)
    let session = try ControllerGenerationSession(environment: environment, identity: identity)
    let generation = V4ControllerServiceGeneration(session: session, generation: 1)
    let source = ControllerGenerationSource(snapshot)
    let client = try await bind(session, definition, target, source, generation)
    let declaration = try V4ControllerServiceDeclaration(client: client, source: source, acceptance: .exact,
      offerRefresh: .explicit, streamBindings: [], required: [], workloads: [])
    try declaration.install(client, generation: generation)
    let operation = try await client.prepareOperation(method, request: Data([1]),
      requestCodec: BytesMessageCodec(definition: method.options.request),
      responseCodec: BytesMessageCodec(definition: try XCTUnwrap(method.options.response)),
      options: ServiceCallOptions(deadlineAtMS: 20_000, admissionMode: .tryNow))
    try operation.attachControllerRoute(declaration); generation.retire()
    do { try await operation.start(); XCTFail("try_now used a retired Controller publication") }
    catch { XCTAssertEqual(error as? ServiceFailure, .serviceUnavailable) }
    XCTAssertEqual(operation.submission, .notSubmitted)
    operation.close(); declaration.close(); client.close(); try await session.close()
  }

}
