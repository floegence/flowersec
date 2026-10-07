import Foundation
import XCTest
@testable import Flowersec

final class TypedMessageStreamDefinitionTests: XCTestCase {
  private func message(_ byte: UInt8, revision: String = "bytes-v1", maximum: Int = 32) throws -> MessageDefinition {
    try MessageDefinition(schemaDigest: Data(repeating: byte, count: 32), revision: revision, maxMessageBytes: maximum)
  }

  func testOpenerRelativeDefinitionsUseIndependentCanonicalDigest() throws {
    let first = try message(1), second = try message(2)
    let definition = try MessageStreamDefinition(
      kind: "example/messages", revision: "messages-v1",
      openerToAcceptor: first, acceptorToOpener: second)
    let reversed = try MessageStreamDefinition(
      kind: "example/messages", revision: "messages-v1",
      openerToAcceptor: second, acceptorToOpener: first)
    var canonical = Data(count: 8192)
    let count = try definition.copyCanonical(into: &canonical)
    canonical = Data(canonical.prefix(count))
    let reference = try V4TextReference()
    XCTAssertEqual(definition.digest, try reference.definitionDigest(canonical, cap: 8192))
    XCTAssertNotEqual(definition.digest, reversed.digest)
  }

  func testTypedMetadataPreservesOrdinaryValuesAndEmptyApplication() throws {
    let digest = Data(repeating: 3, count: 32)
    let application = try StreamMetadata(
      namespace: "example/messages", version: 7,
      values: ["hello": Data([0, 255, 4])])
    let combined = try V4StreamMetadataCodec.typed(definition: digest, application: application)
    XCTAssertEqual(combined.namespace, "flowersec/typed-message")
    XCTAssertEqual(try V4StreamMetadataCodec.typedApplication(combined, definition: digest), application)
    XCTAssertThrowsError(try V4StreamMetadataCodec.typedApplication(combined, definition: Data(repeating: 9, count: 32)))
    let empty = try V4StreamMetadataCodec.typed(definition: digest, application: .empty)
    XCTAssertEqual(try empty.encoded().count, 88)
    XCTAssertEqual(try V4StreamMetadataCodec.typedApplication(empty, definition: digest), .empty)
    XCTAssertThrowsError(try V4StreamMetadataCodec.typed(definition: digest, application: combined))
  }

  func testTypedWrapperRejectsMissingUnknownAndDuplicateKeys() throws {
    let definition = V4Crypto.bytes(Data(repeating: 4, count: 32))
    let application = V4Crypto.bytes(Data())
    func wrapper(_ pairs: [(String, Data)]) -> Data {
      var values = V4NamespaceValue.head(5, UInt64(pairs.count))
      for (name, bytes) in pairs { values.append(V4Crypto.text(name)); values.append(bytes) }
      return V4Crypto.map([
        (0, V4Crypto.text("flowersec/typed-message")),
        (1, V4NamespaceValue.head(0, 1)), (2, values),
      ])
    }
    for bytes in [
      wrapper([("definition", definition)]),
      wrapper([("definition", definition), ("unexpected", application)]),
      wrapper([("definition", definition), ("definition", definition)]),
      wrapper([("application", application), ("definition", definition)]),
    ] {
      XCTAssertThrowsError(try StreamMetadata(encoded: bytes))
    }
  }

  func testCombinedMetadataBoundDoesNotBroadenOrdinaryValueCap() throws {
    let digest = Data(repeating: 5, count: 32)
    let ordinary = try StreamMetadata(
      namespace: "example/messages", version: 1,
      values: ["a": Data(repeating: 1, count: 1024), "b": Data(repeating: 2, count: 1024)])
    let combined = try V4StreamMetadataCodec.typed(definition: digest, application: ordinary)
    XCTAssertEqual(try V4StreamMetadataCodec.typedApplication(combined, definition: digest), ordinary)
    XCTAssertThrowsError(try StreamMetadata(
      namespace: "example/messages", version: 1, values: ["a": Data(count: 1025)]))
    var values: [String: Data] = [:]
    values["a"] = Data(count: 1024); values["b"] = Data(count: 1024)
    values["c"] = Data(count: 1024); values["d"] = Data(count: 921)
    let large = try StreamMetadata(namespace: "example/messages", version: 1, values: values)
    XCTAssertGreaterThan(try large.encoded().count, 4006)
    XCTAssertThrowsError(try V4StreamMetadataCodec.typed(definition: digest, application: large))
  }
}

@MainActor
final class TypedMessageStreamCursorTests: XCTestCase {
  private func fixture(maximum: Int = 32) throws -> (V4EnvironmentFoundation, MessageStreamDefinition, BytesMessageCodec) {
    let limits = V4ResourceVector(
      sdkBytes: 1 << 30, providerBytes: 1 << 30, items: 256, work: 64,
      tasks: 64, timers: 64, connections: 32, handshakes: 32, sessions: 32, handles: 256)
    let root = try V4ResourceRoot(V4ResourceRootConfiguration(
      limit: limits, accounts: 8, reservations: 128, references: 256,
      cleanupWaiters: 4, runtimeOverheadBytes: 1024))
    let tenant = try root.account(
      kind: .tenant, identity: V4ResourceIdentity(high: 8, low: 1), limit: limits)
    let environment = try V4EnvironmentFoundation(
      root: root, tenant: tenant,
      configuration: V4EnvironmentConfiguration(
        identity: V4ResourceIdentity(high: 8, low: 2), limit: limits,
        maximumReadBudgets: 2, maximumWork: 2, runtimeOverheadBytes: 1024,
        cleanupTimeout: .seconds(1), verificationContinuity: .onlineBootstrap),
      timeProfile: V4TimeProfile(
        rateNumerator: 0, rateDenominator: 1, quantizationMS: 0,
        maximumWidthMS: 100, maximumAnchorAgeMS: 1000),
      monotonicSource: V4ContinuousTimeSource())
    let message = try MessageDefinition(
      schemaDigest: Data(repeating: 1, count: 32), revision: "bytes-v1", maxMessageBytes: maximum)
    _ = try environment.applicationGroup()
    return (environment, try MessageStreamDefinition(
      kind: "example/messages", revision: "messages-v1",
      openerToAcceptor: message, acceptorToOpener: message), BytesMessageCodec(definition: message))
  }

  private func adapter<Codec: MessageCodec>(
    _ stream: TypedMessageTestStream, environment: V4EnvironmentFoundation,
    definition: MessageStreamDefinition, codec: Codec
  ) throws -> TypedMessageStream<Data, Data> where Codec.Value == Data {
    let storage = try environment.messageStreamStorage()
    return try TypedMessageStream(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition)
  }

  func testCancelingReceivePreservesThePartialPrefixAndOriginalRead() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data([0, 0]))
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let first = Task { try await messages.receiveEncoded() }
    await stream.waitForRead()
    first.cancel()
    do { _ = try await first.value; XCTFail("expected canceled wait") }
    catch { XCTAssertEqual(error as? SessionError, .canceled) }
    await stream.append(Data([0, 3, 7, 8, 9]))
    let resumed = try await messages.receiveEncoded()
    XCTAssertEqual(resumed?.payload, Data([7, 8, 9]))
    XCTAssertEqual(resumed?.codec, MessageCodecIdentity(definition.acceptorToOpener))
    XCTAssertEqual(resumed?.applicationInputDelivered, false)
    try await messages.close()
    let cleanup = try await messages.waitCleanup()
    XCTAssertTrue(cleanup.complete)
  }

  func testCloseKeepsTheResourceChargeUntilTheOriginalReadReturns() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data(), noncooperativeClose: true)
    let before = try environment.account.snapshot().used.sdkBytes
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let waiting = Task { try await messages.receiveEncoded() }
    await stream.waitForRead()
    try await messages.close()
    let pending = await messages.cleanupStatus()
    XCTAssertFalse(pending.complete)
    XCTAssertGreaterThan(try environment.account.snapshot().used.sdkBytes, before)
    await stream.releaseBlockedRead()
    _ = try? await waiting.value
    let cleanup = try await messages.waitCleanup()
    XCTAssertTrue(cleanup.complete)
    XCTAssertEqual(try environment.account.snapshot().used.sdkBytes, before)
  }

  func testEmptyPayloadIsAMessageAndTruncatedBodyResetsOnlyTheStream() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 0, 0, 0, 0, 3, 1]), eof: true)
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let empty = try await messages.receiveEncoded()
    XCTAssertEqual(empty?.payload, Data())
    do { _ = try await messages.receiveEncoded(); XCTFail("expected truncated frame") }
    catch { XCTAssertEqual(error as? SessionError, .streamReset) }
    let didClose = await stream.closedSnapshot()
    XCTAssertTrue(didClose)
  }

  func testControlledDecoderFailureResetsTheStreamWithoutScanningAnotherPrefix() async throws {
    let (environment, definition, _) = try fixture()
    let codec = UTF8MessageCodec(definition: definition.acceptorToOpener)
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 255, 0, 0, 0, 1, 65]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<String, String>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition)
    do { _ = try await messages.receive(); XCTFail("expected strict decoder failure") }
    catch let error as MessageReceiveError {
      XCTAssertEqual(error.code, .decodeFailed)
      XCTAssertFalse(error.applicationInputDelivered)
      XCTAssertEqual(error.codec, MessageCodecIdentity(definition.acceptorToOpener))
    }
    let closed = await stream.closedSnapshot()
    XCTAssertTrue(closed)
    do { _ = try await messages.receive(); XCTFail("invalid private codec input must terminate this stream") }
    catch { XCTAssertEqual(error as? SessionError, .closed) }
    _ = try await messages.waitCleanup()
  }

  func testCanceledSubmittedSendRetainsItsPublisherAndCompletesBeforeTheNextMessage() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data(), holdAfterPrefix: true)
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let first = Task { try await messages.send(Data([7, 8, 9])) }
    await stream.waitPrefixAccepted()
    do {
      _ = try await messages.send(Data([99]), admission: .tryNow)
      XCTFail("try_now must not enter behind an active publisher")
    } catch let error as MessageStreamError {
      XCTAssertEqual(error.code, .wouldBlock)
      XCTAssertEqual(error.progress.submission, .notSubmitted)
      XCTAssertEqual(error.progress.streamBytesAcceptedAtReturn, 0)
    }
    first.cancel()
    do { _ = try await first.value; XCTFail("expected canceled waiter") }
    catch let error as MessageStreamError {
      XCTAssertEqual(error.code, .canceled)
      XCTAssertEqual(error.progress.submission, .submitted)
      XCTAssertEqual(error.progress.streamBytesAcceptedAtReturn, 4)
      XCTAssertTrue(error.progress.publicationPending)
      XCTAssertFalse(error.progress.cleanup.complete)
    }
    let second = Task { try await messages.send(Data([4, 5])) }
    await stream.releaseWrite()
    let result = try await second.value
    XCTAssertEqual(result.submission, .submitted)
    XCTAssertEqual(result.streamBytesAcceptedAtReturn, 6)
    let bytes = await stream.writtenSnapshot()
    XCTAssertEqual(bytes, Data([0, 0, 0, 3, 7, 8, 9, 0, 0, 0, 2, 4, 5]))
    try await messages.finish()
    let finished = await stream.finishSnapshot()
    XCTAssertTrue(finished)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testSubmittedSendDeadlinePreservesPartialProgressAndPhysicalCustody() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data(), noncooperativeClose: true, holdAfterPrefix: true)
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition,
      options: MessageStreamOptions(sendTimeout: .milliseconds(50)))
    let send = Task { try await messages.send(Data([1, 2, 3])) }
    await stream.waitPrefixAccepted()
    do { _ = try await send.value; XCTFail("expected fixed publication deadline") }
    catch let error as MessageStreamError {
      XCTAssertEqual(error.code, .deadlineExceeded)
      XCTAssertEqual(error.progress.submission, .submitted)
      XCTAssertEqual(error.progress.streamBytesAcceptedAtReturn, 4)
      XCTAssertFalse(error.progress.cleanup.complete)
    }
    let incomplete = await messages.cleanupStatus()
    XCTAssertFalse(incomplete.complete)
    await stream.releaseWrite()
    try await messages.close()
    let cleanup = try await messages.waitCleanup()
    XCTAssertTrue(cleanup.complete)
  }

  func testAssemblyTimeoutStartsAtTheFirstTransferredByteAndSurvivesWaitCancellation() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data([0]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition,
      options: MessageStreamOptions(assemblyTimeout: .milliseconds(50)))
    let receiving = Task { try await messages.receiveEncoded() }
    await stream.waitForRead()
    receiving.cancel()
    do { _ = try await receiving.value; XCTFail("expected canceled wait") }
    catch { XCTAssertEqual(error as? SessionError, .canceled) }
    // Waiting through the original assembly interval cannot create a new one.
    try await ContinuousClock().sleep(for: .milliseconds(100))
    do { _ = try await messages.receiveEncoded(); XCTFail("expected original assembly deadline") }
    catch { XCTAssertEqual(error as? SessionError, .timeout) }
    let closed = await stream.closedSnapshot()
    XCTAssertTrue(closed)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }


  func testCleanupWaitReturnsAnIncompleteSnapshotWithoutRefundingTheBlockedRead() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data(), noncooperativeClose: true)
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition,
      options: MessageStreamOptions(cleanupTimeout: .milliseconds(30)))
    let waiting = Task { try await messages.receiveEncoded() }
    await stream.waitForRead()
    try await messages.close()
    let held = try environment.account.snapshot().used.sdkBytes
    let incomplete = try await messages.waitCleanup()
    XCTAssertFalse(incomplete.complete)
    XCTAssertTrue(incomplete.cleanupIncomplete)
    XCTAssertEqual(try environment.account.snapshot().used.sdkBytes, held)
    await stream.releaseBlockedRead()
    _ = try? await waiting.value
    let complete = try await messages.waitCleanup()
    XCTAssertTrue(complete.complete)
  }

  func testBudgetWaitUsesTheSharedSlabAndWakesOnPhysicalResourceRelease() async throws {
    let (environment, _, _) = try fixture()
    let remaining = environment.root.snapshot().used.sdkBytes
    // The TransportEnvironment limit is one GiB; this original charge leaves less than
    // the full payload vector and forces an atomic wait instead of a partial reservation.
    let released = V4MessageBudgetTestRelease(
      try environment.clientProviderStorage(bytes: (1 << 30) - remaining - 1024))
    let before = try environment.account.snapshot().used
    let acquisition = Task {
      try await environment.root.waitForResources(account: environment.account) {
        try environment.messageStreamPayloadStorage(bytes: 32, encoding: false)
      }
    }
    let observed = ContinuousClock.now.advanced(by: .seconds(2))
    while environment.root.snapshot().resourceWaiters == 0 && ContinuousClock.now < observed {
      await Task.yield()
    }
    XCTAssertEqual(environment.root.snapshot().resourceWaiters, 1)
    XCTAssertEqual(try environment.account.snapshot().used.sdkBytes, before.sdkBytes)
    released.release()
    let acquired = try await acquisition.value
    XCTAssertNoThrow(try acquired.check())
  }

  func testAssemblyTimeoutWhileWaitingForPayloadBudgetKeepsTheOriginalTimeout() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 32]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition,
      options: MessageStreamOptions(assemblyTimeout: .milliseconds(150)))
    let used = environment.root.snapshot().used.sdkBytes
    let blocker = V4MessageBudgetTestRelease(
      try environment.clientProviderStorage(bytes: (1 << 30) - used - 1024))
    let receiving = Task { try await messages.receiveEncoded() }
    let observe = ContinuousClock.now.advanced(by: .milliseconds(100))
    while environment.root.snapshot().resourceWaiters == 0 && ContinuousClock.now < observe {
      await Task.yield()
    }
    XCTAssertEqual(environment.root.snapshot().resourceWaiters, 1)
    do { _ = try await receiving.value; XCTFail("expected original assembly timeout") }
    catch { XCTAssertEqual(error as? SessionError, .timeout) }
    XCTAssertEqual(environment.root.snapshot().resourceWaiters, 0)
    let closed = await stream.closedSnapshot()
    XCTAssertTrue(closed)
    blocker.release()
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testControlledBytesUseActualGrowthWhileApplicationWrappersKeepMaximumResponsibility() async throws {
    let (environment, definition, codec) = try fixture(maximum: 1_048_576)
    let stream = TypedMessageTestStream(bytes: Data())
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let customStorage = try environment.messageStreamStorage()
    let custom = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(
        stream: TypedMessageTestStream(bytes: Data()), storage: customStorage,
        check: { try customStorage.check() }),
      definition: definition, opener: true, inboundCodec: codec,
      outboundCodec: V4TestWrappedBytesCodec(definition: codec.definition),
      inboundDefinition: codec.definition, outboundDefinition: codec.definition)
    let used = environment.root.snapshot().used.sdkBytes
    let blocker = V4MessageBudgetTestRelease(
      try environment.clientProviderStorage(bytes: (1 << 30) - used - 150_000))
    do { _ = try await custom.send(Data([7])); XCTFail("custom encoder must prepay its maximum") }
    catch let error as MessageStreamError {
      XCTAssertEqual(error.code, .resourceExhausted)
      XCTAssertEqual(error.progress.submission, .notSubmitted)
    }
    let payload = Data(repeating: 7, count: 257)
    let result = try await messages.send(payload)
    XCTAssertEqual(result.streamBytesAcceptedAtReturn, 261)
    let wire = await stream.writtenSnapshot()
    XCTAssertEqual(wire, Data([0, 0, 1, 1]) + payload)
    blocker.release()
    try await custom.close()
    _ = try await custom.waitCleanup()
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testControlledPrimitiveUTF8PublishesTheSameCompleteFrame() async throws {
    let (environment, definition, _) = try fixture(maximum: 20_000)
    let codec = UTF8MessageCodec(definition: definition.openerToAcceptor)
    let stream = TypedMessageTestStream(bytes: Data())
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<String, String>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: codec,
      inboundDefinition: codec.definition, outboundDefinition: codec.definition)
    let value = String(repeating: "A", count: 16_700) + "é"
    let payload = Data(value.utf8)
    let result = try await messages.send(value)
    XCTAssertEqual(result.streamBytesAcceptedAtReturn, UInt64(payload.count + 4))
    let wire = await stream.writtenSnapshot()
    XCTAssertEqual(wire, Data([0, 0, 65, 62]) + payload)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testControlledWriterFailureRemainsStickyThroughFinalizeAndEmptyOutputAllocatesNothing() throws {
    let (environment, _, _) = try fixture()
    let empty = V4MessageSegments(
      maximum: 32, gate: environment.gate,
      reserve: { _, _ in XCTFail("empty output must not allocate a block"); throw V4ResourceFailure.capacity },
      check: {})
    XCTAssertEqual(try empty.finalize().length, 0)
    let writer = V4MessageSegments(
      maximum: 32, gate: environment.gate,
      reserve: { _, _ in throw V4ResourceFailure.capacity }, check: {})
    XCTAssertThrowsError(try writer.tryAppend(UInt8(1)))
    // Ignoring an append failure cannot turn the original candidate into a
    // successful message, including by trying a zero-byte append afterwards.
    XCTAssertThrowsError(try writer.tryAppend(Data()))
    XCTAssertThrowsError(try writer.finalize())
  }


  func testCanceledTypedReceiverJoinsTheOriginalApplicationDecodeAndPreservesModeConflict() async throws {
    let (environment, definition, outbound) = try fixture()
    let decoder = V4BlockedMessageDecoder()
    let inbound = V4BlockingMessageCodec(definition: outbound.definition, decoder: decoder)
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 7, 0, 0, 0, 1, 8]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: inbound, outboundCodec: outbound,
      inboundDefinition: inbound.definition, outboundDefinition: outbound.definition)
    let first = Task { try await messages.receive() }
    await decoder.waitForEntry()
    first.cancel()
    do { _ = try await first.value; XCTFail("expected detached receiver") }
    catch { XCTAssertEqual(error as? SessionError, .canceled) }
    do { _ = try await messages.receiveEncoded(); XCTFail("application input cannot be handed out twice") }
    catch let error as MessageResultModeConflict { XCTAssertEqual(error.cause, .decoderStarted) }
    decoder.release()
    let received = try await messages.receive()
    XCTAssertEqual(received?.value, Data([7]))
    XCTAssertEqual(received?.codec, MessageCodecIdentity(definition.acceptorToOpener))
    XCTAssertEqual(received?.applicationInputDelivered, true)
    XCTAssertEqual(decoder.calls, 1)
    let next = try await messages.receiveEncoded()
    XCTAssertEqual(next?.payload, Data([8]))
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testCanceledDecoderFailureIsDeliveredOnceBeforeAdvancingTheCurrentMessage() async throws {
    let (environment, definition, outbound) = try fixture()
    let decoder = V4BlockedMessageDecoder(failure: true)
    let inbound = V4BlockingMessageCodec(definition: outbound.definition, decoder: decoder)
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 7, 0, 0, 0, 1, 8]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: inbound, outboundCodec: outbound,
      inboundDefinition: inbound.definition, outboundDefinition: outbound.definition)
    let first = Task { try await messages.receive() }
    await decoder.waitForEntry()
    first.cancel()
    _ = try? await first.value
    decoder.release()
    do { _ = try await messages.receive(); XCTFail("expected the original bounded decode failure") }
    catch let error as MessageReceiveError {
      XCTAssertEqual(error.code, .decodeFailed)
      XCTAssertTrue(error.applicationInputDelivered)
      XCTAssertEqual(error.codec, MessageCodecIdentity(definition.acceptorToOpener))
    }
    XCTAssertEqual(decoder.calls, 1)
    let next = try await messages.receiveEncoded()
    XCTAssertEqual(next?.payload, Data([8]))
    let reset = await stream.closedSnapshot()
    XCTAssertFalse(reset)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testClosedMessageOwnerKeepsTheNoncooperativeDecoderChargedUntilActualExit() async throws {
    let (environment, definition, outbound) = try fixture()
    let decoder = V4BlockedMessageDecoder()
    let inbound = V4BlockingMessageCodec(definition: outbound.definition, decoder: decoder)
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 7]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: inbound, outboundCodec: outbound,
      inboundDefinition: inbound.definition, outboundDefinition: outbound.definition,
      options: MessageStreamOptions(cleanupTimeout: .milliseconds(30)))
    let receiving = Task { try await messages.receive() }
    await decoder.waitForEntry()
    try await messages.close()
    do { _ = try await receiving.value; XCTFail("closed owner cannot deliver a new result") }
    catch { XCTAssertEqual(error as? SessionError, .closed) }
    let pending = try await messages.waitCleanup()
    XCTAssertFalse(pending.complete)
    XCTAssertTrue(pending.cleanupIncomplete)
    XCTAssertGreaterThan(try environment.account.snapshot().executionTails, 0)
    decoder.release()
    let complete = try await messages.waitCleanup()
    XCTAssertTrue(complete.complete)
    XCTAssertEqual(try environment.account.snapshot().executionTails, 0)
  }


  #if os(macOS) || os(iOS)
  func testFinishedSynchronousChildClearsRetainedContextAfterRealSend() async throws {
    let (environment, definition, codec) = try fixture()
    defer { environment.beginClose() }
    let group = try environment.applicationGroup()
    let permit = try group.executor.tryOrdinary(group: group, context: nil)
    try group.executor.beginOrdinary(permit)
    let parent = V4ApplicationInvocation(permit: permit, ancestors: [])
    let parentContext = ApplicationInvocationContext(parent)
    let captured = V4CapturedInvocationContext()
    let sending = V4CapturingBytesCodec(definition: codec.definition, capture: captured)
    let stream = TypedMessageTestStream(bytes: Data())
    let messages = try adapter(stream, environment: environment, definition: definition, codec: sending)
    let result = try await messages.send(Data([7]), context: parentContext)
    XCTAssertEqual(result.streamBytesAcceptedAtReturn, 5)
    let retained = try XCTUnwrap(captured.context)
    XCTAssertTrue(retained.isCancelled)
    XCTAssertThrowsError(try retained.checkCancellation()) { error in
      XCTAssertEqual(error as? ApplicationInvocationFailure, .closed)
    }
    try await messages.close()
    _ = try await messages.waitCleanup()
    parent.close()
  }
  #endif

  func testSynchronousSendReusesItsLiveOrdinaryStageWhenAllOtherPositionsAreTaken() async throws {
    let (environment, definition, codec) = try fixture()
    let group = try environment.applicationGroup()
    let permit = try group.executor.tryOrdinary(group: group, context: nil)
    try group.executor.beginOrdinary(permit)
    let invocation = V4ApplicationInvocation(permit: permit, ancestors: [])
    let context = ApplicationInvocationContext(invocation)
    var occupied: [V4ApplicationPermit] = []
    for _ in 0..<25 { occupied.append(try group.executor.tryOrdinary(group: group, context: nil)) }
    defer { for permit in occupied { permit.release() }; invocation.close() }
    let stream = TypedMessageTestStream(bytes: Data())
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let before = group.workload
    XCTAssertEqual(before.ordinaryRunning, 1)
    XCTAssertEqual(before.ordinaryReserved, 25)
    let result = try await messages.send(Data([7]), context: context)
    XCTAssertEqual(result.streamBytesAcceptedAtReturn, 5)
    XCTAssertEqual(group.workload.ordinaryRunning, 1)
    XCTAssertEqual(group.workload.ordinaryReserved, 25)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testProtectedCompletionRunsWhileEveryOrdinaryPositionIsOccupied() async throws {
    let (environment, definition, codec) = try fixture()
    let group = try environment.applicationGroup()
    var occupied: [V4ApplicationPermit] = []
    for _ in 0..<26 { occupied.append(try group.executor.tryOrdinary(group: group, context: nil)) }
    defer { for permit in occupied { permit.release() } }
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 7]))
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let result = try await messages.receive()
    XCTAssertEqual(result?.value, Data([7]))
    XCTAssertEqual(group.workload.ordinaryReserved, 26)
    XCTAssertEqual(group.workload.completionRunning, 0)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testEncodedReceiveUsesNoCompletionOwnerOrExecutionPosition() async throws {
    let (environment, definition, codec) = try fixture()
    let group = try environment.applicationGroup()
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 7]))
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let before = group.workload
    let encoded = try await messages.receiveEncoded()
    XCTAssertEqual(encoded?.payload, Data([7]))
    XCTAssertEqual(group.workload, before)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }


  func testAsynchronousCodecKeepsItsOrdinaryPermitUntilActualEncodeExit() async throws {
    let (environment, definition, inbound) = try fixture()
    let gate = V4AsyncCodecGate()
    let codec = V4AsyncTestMessageCodec(definition: inbound.definition, gate: gate)
    let stream = TypedMessageTestStream(bytes: Data())
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: inbound, outboundCodec: codec,
      inboundDefinition: inbound.definition, outboundDefinition: codec.definition)
    let group = try environment.applicationGroup()
    let sending = Task { try await messages.send(Data([7])) }
    await gate.waitEntry()
    XCTAssertEqual(group.workload.ordinaryRunning, 1)
    sending.cancel()
    do { _ = try await sending.value; XCTFail("expected a canceled send waiter") }
    catch let error as MessageStreamError {
      XCTAssertEqual(error.code, .canceled)
      XCTAssertEqual(error.progress.submission, .notSubmitted)
      XCTAssertFalse(error.progress.cleanup.complete)
    }
    XCTAssertEqual(group.workload.ordinaryRunning, 1)
    await gate.release()
    try await messages.close()
    _ = try await messages.waitCleanup()
    XCTAssertEqual(group.workload.ordinaryRunning, 0)
    let written = await stream.writtenSnapshot()
    XCTAssertTrue(written.isEmpty)
  }

  func testAsynchronousDecoderWaitCancellationRetainsTheSameCompletionOutcome() async throws {
    let (environment, definition, outbound) = try fixture()
    let gate = V4AsyncCodecGate()
    let codec = V4AsyncTestMessageCodec(definition: outbound.definition, gate: gate)
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 1, 7]))
    let storage = try environment.messageStreamStorage()
    let messages = try TypedMessageStream<Data, Data>(
      prepared: V4PreparedMessageStream(stream: stream, storage: storage, check: { try storage.check() }),
      definition: definition, opener: true, inboundCodec: codec, outboundCodec: outbound,
      inboundDefinition: codec.definition, outboundDefinition: outbound.definition)
    let receiving = Task { try await messages.receive() }
    await gate.waitEntry()
    receiving.cancel()
    do { _ = try await receiving.value; XCTFail("expected detached receiver") }
    catch { XCTAssertEqual(error as? SessionError, .canceled) }
    XCTAssertEqual(try environment.applicationGroup().workload.completionRunning, 1)
    await gate.release()
    let value = try await messages.receive()
    XCTAssertEqual(value?.value, Data([7]))
    let entries = await gate.entries
    XCTAssertEqual(entries, 1)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testPendingAndAcceptedRegistrationsShareTheOriginalKindCapacity() throws {
    let lifetime = V4MessageRegistrationLifetime()
    var first: V4MessageRegistrationCapture? = try lifetime.capture(kind: "example/one", maximum: 1)
    XCTAssertThrowsError(try lifetime.capture(kind: "example/one", maximum: 1))
    let other = try lifetime.capture(kind: "example/two", maximum: 1)
    XCTAssertEqual(try first?.commit { Optional(7) }, 7)
    XCTAssertThrowsError(try lifetime.capture(kind: "example/one", maximum: 1))
    first = nil
    let replacement = try lifetime.capture(kind: "example/one", maximum: 1)
    XCTAssertEqual(try replacement.commit { Optional(9) }, 9)
    withExtendedLifetime(other) {}
  }

  func testEncodedEmptyMessageAndEOFRemainDistinctWithBoundedCodecIdentity() async throws {
    let (environment, definition, codec) = try fixture()
    let stream = TypedMessageTestStream(bytes: Data([0, 0, 0, 0]), eof: true)
    let messages = try adapter(stream, environment: environment, definition: definition, codec: codec)
    let result = try await messages.receiveEncoded()
    let empty = try XCTUnwrap(result)
    XCTAssertEqual(empty.payload, Data())
    XCTAssertEqual(empty.codec, MessageCodecIdentity(definition.acceptorToOpener))
    XCTAssertFalse(empty.applicationInputDelivered)
    let end = try await messages.receiveEncoded()
    XCTAssertNil(end)
    try await messages.close()
    _ = try await messages.waitCleanup()
  }

  func testRegistrationCloseFencesPendingCapturesAndRetainsAcceptedCaptures() throws {
    let lifetime = V4MessageRegistrationLifetime()
    let accepted = try lifetime.capture()
    XCTAssertEqual(try accepted.commit { Optional(7) }, 7)
    let pending = try lifetime.capture()
    lifetime.close()
    XCTAssertThrowsError(try pending.commit { Optional(8) })
    XCTAssertThrowsError(try lifetime.capture())
    XCTAssertThrowsError(try accepted.commit { Optional(9) })
  }


}

private actor TypedMessageTestStream: V4MessageStreamWriter {
  nonisolated let kind = "example/messages"
  private var bytes: Data
  private var eof: Bool
  private var closed = false
  private let noncooperativeClose: Bool
  private var pendingRead: (Int, CheckedContinuation<Data?, Error>)?
  private var readStarted: CheckedContinuation<Void, Never>?
  private var holdAfterPrefix: Bool
  private var written = Data()
  private var pendingWrite: CheckedContinuation<Void, Never>?
  private var prefixWaiter: CheckedContinuation<Void, Never>?
  private var finishedWrite = false

  init(
    bytes: Data, eof: Bool = false, noncooperativeClose: Bool = false,
    holdAfterPrefix: Bool = false
  ) {
    self.bytes = bytes; self.eof = eof; self.noncooperativeClose = noncooperativeClose
    self.holdAfterPrefix = holdAfterPrefix
  }

  func read(maxBytes: Int) async throws -> Data? {
    guard !closed else { throw SessionError.streamReset }
    if !bytes.isEmpty { return consume(maxBytes) }
    if eof { return nil }
    return try await withCheckedThrowingContinuation { continuation in
      pendingRead = (maxBytes, continuation)
      readStarted?.resume()
      readStarted = nil
    }
  }

  private func consume(_ maximum: Int) -> Data {
    let count = min(maximum, bytes.count)
    let result = Data(bytes.prefix(count))
    bytes.removeFirst(count)
    return result
  }

  func waitForRead() async {
    if pendingRead != nil { return }
    await withCheckedContinuation { readStarted = $0 }
  }

  func append(_ next: Data) {
    bytes.append(next)
    if let (maximum, continuation) = pendingRead, !bytes.isEmpty {
      pendingRead = nil
      continuation.resume(returning: consume(maximum))
    }
  }

  func releaseBlockedRead() {
    if let (_, continuation) = pendingRead {
      pendingRead = nil
      continuation.resume(throwing: SessionError.streamReset)
    }
  }

  func write(_ data: Data) async throws -> Int { data.count }
  func writeMessageChunk(
    _ data: Data, beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void
  ) async throws -> Int {
    if holdAfterPrefix && written.count >= 4 {
      await withCheckedContinuation { pendingWrite = $0 }
    }
    guard !closed, !finishedWrite else { throw SessionError.streamReset }
    try beforeAccept()
    written.append(data)
    accepted(data.count)
    if written.count >= 4 { prefixWaiter?.resume(); prefixWaiter = nil }
    return data.count
  }
  func waitPrefixAccepted() async {
    if written.count >= 4 { return }
    await withCheckedContinuation { prefixWaiter = $0 }
  }
  func releaseWrite() {
    holdAfterPrefix = false
    pendingWrite?.resume()
    pendingWrite = nil
  }
  func writtenSnapshot() -> Data { written }
  func finishSnapshot() -> Bool { finishedWrite }
  func closeWrite() async throws { finishedWrite = true }
  func finish() async throws {}
  func reset() async throws {
    closed = true
    if !noncooperativeClose { releaseBlockedRead(); releaseWrite() }
  }
  func close() async throws { try await reset() }
  func terminalError() async -> SessionError? { closed ? .streamReset : nil }
  func closedSnapshot() -> Bool { closed }
}

private final class V4MessageBudgetTestRelease {
  private var storage: V4CryptoReservation?
  init(_ storage: V4CryptoReservation) { self.storage = storage }
  func release() { storage = nil }
}

private final class V4CapturedInvocationContext: @unchecked Sendable {
  private let gate = NSLock()
  private var value: ApplicationInvocationContext?
  var context: ApplicationInvocationContext? { gate.withLock { value } }
  func capture(_ context: ApplicationInvocationContext) { gate.withLock { value = context } }
}

private struct V4CapturingBytesCodec: MessageCodec {
  let definition: MessageDefinition
  let capture: V4CapturedInvocationContext
  func encode(_ value: Data, into destination: inout Data) throws -> Int { destination = value; return value.count }
  func decode(_ source: Data) throws -> Data { source }
  func encode(_ value: Data, context: ApplicationInvocationContext, into destination: inout Data) throws -> Int {
    capture.capture(context); try context.checkCancellation(); destination = value; return value.count
  }
  func decode(_ source: Data, context: ApplicationInvocationContext) throws -> Data { try context.checkCancellation(); return source }
}

private struct V4TestWrappedBytesCodec: MessageCodec {
  let definition: MessageDefinition
  func encode(_ value: Data, into destination: inout Data) throws -> Int {
    XCTFail("resource rejection must precede an arbitrary application encoder")
    destination = value
    return destination.count
  }
  func decode(_ source: Data) throws -> Data { source }
}

private struct V4BlockingMessageCodec: MessageCodec {
  let definition: MessageDefinition
  let decoder: V4BlockedMessageDecoder
  func encode(_ value: Data, into destination: inout Data) throws -> Int {
    destination = value
    return value.count
  }
  func decode(_ source: Data) throws -> Data { try decoder.decode(source) }
  func decode(_ source: Data, context: ApplicationInvocationContext) throws -> Data {
    try context.checkCancellation()
    return try decoder.decode(source)
  }
}

private final class V4BlockedMessageDecoder: @unchecked Sendable {
  private let condition = NSCondition()
  private let failure: Bool
  private var entered = false
  private var released = false
  private var count = 0
  private var entry: CheckedContinuation<Void, Never>?
  init(failure: Bool = false) { self.failure = failure }
  var calls: Int {
    condition.lock()
    defer { condition.unlock() }
    return count
  }
  func waitForEntry() async {
    await withCheckedContinuation { continuation in
      condition.lock()
      if entered { condition.unlock(); continuation.resume() }
      else { entry = continuation; condition.unlock() }
    }
  }
  func decode(_ source: Data) throws -> Data {
    condition.lock()
    count += 1
    entered = true
    let observer = entry
    entry = nil
    observer?.resume()
    while !released { condition.wait() }
    condition.unlock()
    if failure { throw MessageCodecFailure.decodeFailed }
    return source
  }
  func release() {
    condition.lock()
    released = true
    condition.broadcast()
    condition.unlock()
  }
}

private actor V4AsyncCodecGate {
  private var continuation: CheckedContinuation<Void, Never>?
  private var entryWaiter: CheckedContinuation<Void, Never>?
  private var entered = false
  private var released = false
  private(set) var entries = 0
  func enter() async {
    entries += 1
    entered = true
    entryWaiter?.resume(); entryWaiter = nil
    if !released { await withCheckedContinuation { continuation = $0 } }
  }
  func waitEntry() async {
    if !entered { await withCheckedContinuation { entryWaiter = $0 } }
  }
  func release() { released = true; continuation?.resume(); continuation = nil }
}

private struct V4AsyncTestMessageCodec: AsyncMessageCodec {
  typealias Value = Data
  let definition: MessageDefinition
  let gate: V4AsyncCodecGate
  func encodeAsync(_ value: Data, context: ApplicationInvocationContext) async throws -> Data {
    try context.checkCancellation()
    await gate.enter()
    return value
  }
  func decodeAsync(_ source: Data, context: ApplicationInvocationContext) async throws -> Data {
    try context.checkCancellation()
    await gate.enter()
    return source
  }
}
