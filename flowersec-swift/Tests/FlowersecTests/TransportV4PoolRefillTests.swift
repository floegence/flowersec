#if os(macOS) || os(iOS)
import Foundation
import XCTest
@testable import Flowersec

final class TransportPoolRefillTests: XCTestCase {
  private func directory() throws -> URL {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let directory = root.appendingPathComponent(".flowersec/swift-pool-refill-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory
  }
  func testPendingRecoveryKeepsOriginalIntentAndGenerationAcrossUnknownResponse() throws {
    let fixture = try NamespaceFixture()
    let directory = try directory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let identity = Data(repeating: 31, count: 32); let source = Data(repeating: 32, count: 16); let pool = Data(repeating: 33, count: 32)
    func open(_ create: Bool) throws -> V4PoolRefillJournal {
      try V4PoolRefillJournal(environment: fixture.environment,
        configuration: .init(directory: directory, backingIdentity: identity, create: create,
          maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }), tenant: "tenant", source: source, pool: pool)
    }
    var journal: V4PoolRefillJournal? = try open(true)
    let original = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 2,
      maximumItemBytes: 65_536, deadline: 1500, identity: Data(repeating: 34, count: 32))
    let bound = try journal!.bindOriginalGeneration(7, intent: original.intent)
    journal!.close(); journal = nil
    journal = try open(false)
    let recovered = try XCTUnwrap(journal!.recover())
    XCTAssertEqual(recovered.phase, .pending); XCTAssertEqual(recovered.intent, original.intent)
    XCTAssertEqual(recovered.generation, bound.generation)
    let reobserved = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1600, identity: Data(repeating: 35, count: 32))
    XCTAssertEqual(reobserved.intent, original.intent)
    XCTAssertEqual(try journal!.bindOriginalGeneration(8, intent: original.intent).generation, 7)
    XCTAssertThrowsError(try open(false))
    journal!.close()
  }
  func testInstalledRecoveryAndLostAckNeverReinstallAcquiredMaterial() throws {
    let fixture = try CredentialFixture()
    let directory = try directory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let backing = Data(repeating: 41, count: 32); let source = Data(repeating: 42, count: 16); let pool = Data(repeating: 43, count: 32)
    func open(_ create: Bool) throws -> V4PoolRefillJournal {
      try V4PoolRefillJournal(environment: fixture.base.environment,
        configuration: .init(directory: directory, backingIdentity: backing, create: create,
          maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }), tenant: "tenant", source: source, pool: pool)
    }
    let input = try fixture.input(source: .preauthorizedPool)
    let admission = try fixture.verify(input)
    defer { admission.close() }
    let certificate = try V4NamespaceDocument(input.clientCertificate, schema: "IdentityCertificate", bytes: 8192,
      nodes: 4096, registry: V4NamespaceRegistry()).root
    let client = try certificate.digest("certificate_digest")
    let material = V4NamespaceValue.head(4, 4) + V4Crypto.bytes(input.artifact) + V4Crypto.bytes(input.activation)
      + V4Crypto.bytes(input.clientCertificate) + V4Crypto.bytes(input.serverCertificate)
    var journal: V4PoolRefillJournal? = try open(true)
    let pending = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1500, identity: client)
    let original = try journal!.bindOriginalGeneration(1, intent: pending.intent)
    let entry = V4Crypto.map([(0, V4NamespaceValue.head(0, 1)), (1, V4NamespaceValue.head(0, 1)),
      (2, V4NamespaceValue.head(0, 1800)), (3, V4Crypto.bytes(material)),
      (4, V4Crypto.bytes(V4Crypto.hash(material))), (5, V4Crypto.bytes(client))])
    let fields: [(UInt64, Data)] = [(0, V4Crypto.bytes(original.intent.operation)), (1, V4Crypto.text("tenant")),
      (2, V4Crypto.bytes(source)), (3, V4NamespaceValue.head(0, 1)), (4, Data([0x81]) + entry),
      (5, V4NamespaceValue.head(0, 1)), (6, Data([0xf4])), (8, Data([0xf5]))]
    let projected = V4Crypto.map(fields)
    let wire = V4Crypto.map(fields + [(9, V4Crypto.bytes(V4Crypto.hash(projected)))])
    let response = try V4PoolRefillWire.response(wire, intent: original.intent, originalGeneration: 1,
      previousHighest: 0, registry: V4NamespaceRegistry())
    try journal!.install(response, intent: original.intent)
    XCTAssertEqual(try journal!.take(), material)
    XCTAssertEqual(try journal!.count, 0)
    journal!.close(); journal = nil
    journal = try open(false)
    XCTAssertEqual(try journal!.recover()?.phase, .installed)
    try journal!.install(response, intent: original.intent)
    XCTAssertNil(try journal!.take())
    try journal!.acknowledge(intent: original.intent, response: response.wire)
    journal!.close(); journal = nil
    journal = try open(false)
    XCTAssertEqual(try journal!.recover()?.phase, .acked)
    XCTAssertNil(try journal!.take())
    journal!.close()
  }
  private func terminalEnvelope(_ original: V4PoolRefillJournal.Recovery, retired: Bool,
    permanent: Bool = false, code: String = "capacity_exhausted", facts: Data = Data([0x80]),
    highest: UInt64? = nil) throws -> Data {
    let intent = original.intent
    var request = V4NamespaceValue.head(4, 10) + V4Crypto.text(intent.tenant)
    for bytes in [intent.source, intent.operation, intent.pool, intent.identity, try intent.digest()] {
      request.append(V4Crypto.bytes(bytes))
    }
    for number in [original.generation, intent.deadlineMS, intent.desired, intent.maximumItemBytes] {
      request.append(V4NamespaceValue.head(0, number))
    }
    var terminal = V4NamespaceValue.head(4, 9) + request + V4Crypto.text(retired ? "retired" : "terminal")
    for number in [original.generation, intent.sequence + 1, retired ? intent.sequence : intent.sequence - 1,
      highest ?? original.previousHighest, 0] { terminal.append(V4NamespaceValue.head(0, number)) }
    terminal.append(Data([permanent ? 0xf5 : 0xf4])); terminal.append(facts)
    return V4NamespaceValue.head(4, 4) + V4Crypto.text(code) + V4Crypto.bytes(Data()) + terminal + Data([0x80])
  }
  func testTerminalRetirementKeepsOriginalOperationUntilAuthorityReleasesIt() throws {
    let fixture = try NamespaceFixture()
    let directory = try directory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let backing = Data(repeating: 51, count: 32); let source = Data(repeating: 52, count: 16)
    let pool = Data(repeating: 53, count: 32); let identity = Data(repeating: 54, count: 32)
    let registry = try V4NamespaceRegistry()
    func open(_ create: Bool) throws -> V4PoolRefillJournal {
      try V4PoolRefillJournal(environment: fixture.environment,
        configuration: .init(directory: directory, backingIdentity: backing, create: create,
          maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }), tenant: "tenant", source: source, pool: pool)
    }
    var journal: V4PoolRefillJournal? = try open(true)
    let pending = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1500, identity: identity)
    let original = try journal!.bindOriginalGeneration(7, intent: pending.intent)
    let reply = try V4PoolRefillWire.reply(terminalEnvelope(original, retired: false), applicationError: true)
    let terminal = try XCTUnwrap(V4PoolRefillWire.terminal(reply, original: original, currentGeneration: 7, registry: registry))
    try journal!.confirmTerminal(terminal, original: original)
    XCTAssertThrowsError(try journal!.acknowledge(intent: original.intent, response: Data()))
    journal!.close(); journal = nil
    journal = try open(false)
    let recovered = try XCTUnwrap(journal!.recover())
    XCTAssertEqual(recovered.phase, .terminal)
    XCTAssertTrue(recovered.response.isEmpty)
    XCTAssertEqual(recovered.terminalReceipt, terminal.receipt)
    let blocked = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1600, identity: identity)
    XCTAssertEqual(blocked.intent, original.intent)
    let retiredReply = try V4PoolRefillWire.reply(terminalEnvelope(original, retired: true), applicationError: true)
    let retired = try XCTUnwrap(V4PoolRefillWire.terminal(retiredReply, original: recovered, currentGeneration: 7, registry: registry))
    try journal!.confirmTerminal(retired, original: recovered)
    XCTAssertThrowsError(try journal!.confirmTerminal(terminal, original: journal!.recover()!))
    let next = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1600, identity: identity)
    XCTAssertEqual(next.phase, .pending)
    XCTAssertEqual(next.intent.sequence, original.intent.sequence + 1)
    journal!.close()
  }
  func testUnknownCommittedTerminalFactsNeverInstallMaterial() throws {
    let fixture = try NamespaceFixture()
    let directory = try directory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let backing = Data(repeating: 61, count: 32); let source = Data(repeating: 62, count: 16)
    let pool = Data(repeating: 63, count: 32); let identity = Data(repeating: 64, count: 32)
    let journal = try V4PoolRefillJournal(environment: fixture.environment,
      configuration: .init(directory: directory, backingIdentity: backing, create: true,
        maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }), tenant: "tenant", source: source, pool: pool)
    defer { journal.close() }
    let pending = try journal.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1500, identity: identity)
    let original = try journal.bindOriginalGeneration(7, intent: pending.intent)
    let entry = V4NamespaceValue.head(4, 5) + V4NamespaceValue.head(0, 1) + V4NamespaceValue.head(0, 7)
      + V4NamespaceValue.head(0, 1800) + V4Crypto.bytes(Data(repeating: 65, count: 32)) + V4Crypto.bytes(identity)
    let facts = V4NamespaceValue.head(4, 6) + V4NamespaceValue.head(0, 7) + V4NamespaceValue.head(0, 1)
      + Data([0, 0xf4]) + V4Crypto.bytes(Data(repeating: 66, count: 32)) + Data([0x81]) + entry
    let reply = try V4PoolRefillWire.reply(terminalEnvelope(original, retired: true, permanent: true,
      code: "source_reset_required", facts: facts, highest: 1), applicationError: true)
    let terminal = try XCTUnwrap(V4PoolRefillWire.terminal(reply, original: original,
      currentGeneration: 7, registry: V4NamespaceRegistry()))
    try journal.confirmTerminal(terminal, original: original)
    XCTAssertTrue(try journal.recover()!.response.isEmpty)
    XCTAssertEqual(try journal.count, 0)
    XCTAssertThrowsError(try journal.take())
    XCTAssertThrowsError(try journal.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1600, identity: identity))
    let malformed = V4NamespaceValue.head(4, 4) + V4Crypto.text("source_unavailable")
      + V4Crypto.bytes(Data()) + reply.terminal + Data([0x80])
    XCTAssertThrowsError(try V4PoolRefillWire.reply(malformed, applicationError: true))
  }
  func testPermanentFenceRemainsSeparateFromUnknownHistoryAcrossRestart() throws {
    let fixture = try NamespaceFixture()
    let directory = try directory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let backing = Data(repeating: 71, count: 32); let source = Data(repeating: 72, count: 16)
    let pool = Data(repeating: 73, count: 32); let identity = Data(repeating: 74, count: 32)
    let registry = try V4NamespaceRegistry()
    func open(_ create: Bool) throws -> V4PoolRefillJournal {
      try V4PoolRefillJournal(environment: fixture.environment,
        configuration: .init(directory: directory, backingIdentity: backing, create: create,
          maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }), tenant: "tenant", source: source, pool: pool)
    }
    var journal: V4PoolRefillJournal? = try open(true)
    let pending = try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1500, identity: identity)
    let original = try journal!.bindOriginalGeneration(7, intent: pending.intent)
    let fence = V4NamespaceValue.head(4, 3) + V4Crypto.text("tenant") + V4Crypto.bytes(source) + V4NamespaceValue.head(0, 7)
    let wire = V4NamespaceValue.head(4, 4) + V4Crypto.text("source_reset_required") + V4Crypto.bytes(Data()) + Data([0x80]) + fence
    let reply = try V4PoolRefillWire.reply(wire, applicationError: true)
    let terminal = try XCTUnwrap(V4PoolRefillWire.terminal(reply, original: original, currentGeneration: 7, registry: registry))
    XCTAssertTrue(terminal.permanent); XCTAssertFalse(terminal.retired)
    try journal!.confirmTerminal(terminal, original: original)
    journal!.close(); journal = nil
    journal = try open(false)
    let recovered = try XCTUnwrap(journal!.recover())
    let retained = try journal!.terminal(recovered)
    XCTAssertEqual(retained.receipt, wire)
    XCTAssertTrue(retained.permanent); XCTAssertFalse(retained.retired)
    XCTAssertTrue(recovered.response.isEmpty)
    XCTAssertThrowsError(try journal!.begin(tenant: "tenant", source: source, pool: pool, desired: 1,
      maximumItemBytes: 65_536, deadline: 1600, identity: identity))
    journal!.close()
  }
  func testCanonicalIntentRejectsChangedDigestProjectionAndMalformedControlEnvelope() throws {
    let intent = V4PoolRefillIntent(operation: Data(repeating: 0, count: 8) + V4Crypto.integer(1, width: 8),
      tenant: "tenant", source: Data(repeating: 1, count: 16), desired: 1, maximumItemBytes: 65_536,
      pool: Data(repeating: 2, count: 32), deadlineMS: 1500, identity: Data(repeating: 3, count: 32))
    XCTAssertEqual(try V4PoolRefillIntent.decode(intent.encoded()), intent)
    let proof = Data([0xa0])
    XCTAssertNotEqual(try V4PoolRefillWire.request(intent, generation: 1, proof: proof),
      try V4PoolRefillWire.request(intent, generation: 2, proof: proof))
    XCTAssertEqual(try intent.digest(), V4Crypto.hash(try intent.encoded()))
    let good = Data([0x84]) + V4Crypto.text("success") + V4Crypto.bytes(Data()) + Data([0x80, 0x80])
    XCTAssertEqual(try V4PoolRefillWire.reply(good, applicationError: false).code, "success")
    XCTAssertThrowsError(try V4PoolRefillWire.reply(good, applicationError: true))
    XCTAssertThrowsError(try V4PoolRefillWire.reply(good + Data([0]), applicationError: false))
    XCTAssertThrowsError(try V4PoolRefillWire.reply(Data([0x9f, 0xff]), applicationError: false))
  }
}
#endif
