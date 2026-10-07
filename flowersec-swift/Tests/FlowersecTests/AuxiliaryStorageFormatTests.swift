#if os(macOS) || os(iOS)
import Darwin
import Foundation
import SQLite3
import XCTest
@testable import Flowersec

@MainActor
final class AuxiliaryStorageFormatTests: XCTestCase {
  private struct Mutation {
    let sql: String
    let reason: StorageFormatReason
    let observed: StorageRevision
    var manifestSchemaRevision: UInt32? = nil
    var manifestRowRevision: UInt32? = nil
    var manifestUserVersion: UInt32? = nil
  }
  private var mutations: [Mutation] {
    [
      .init(sql: "CREATE TABLE unexpected(value INTEGER)", reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2)),
      .init(sql: "PRAGMA user_version=3", reason: .revisionConflict, observed: .unknown),
      .init(sql: "UPDATE manifest SET identity=x'00'", reason: .identityMismatch, observed: .unknown),
      .init(sql: "", reason: .newerRevision, observed: .init(known: true, value: 3), manifestSchemaRevision: 3, manifestRowRevision: 3, manifestUserVersion: 3),
      .init(sql: "", reason: .olderRevision, observed: .init(known: true, value: 1), manifestSchemaRevision: 1, manifestRowRevision: 1, manifestUserVersion: 1),
      .init(sql: "DROP TABLE manifest; CREATE TABLE manifest(id INTEGER PRIMARY KEY, binding BLOB NOT NULL); INSERT INTO manifest VALUES(1,x'00')", reason: .manifestUnknownOrInvalid, observed: .unknown),
    ]
  }
  private func directory() throws -> URL {
    let path = packageRoot().appendingPathComponent(".flowersec/swift-auxiliary-format-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return path
  }
  private func edit(_ path: URL, _ sql: String) throws {
    var database: OpaquePointer?
    guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let database else {
      if let database { sqlite3_close_v2(database) }; throw ServiceFailure.serviceUnavailable
    }
    defer { sqlite3_close_v2(database) }
    guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
  }
  private func projection(_ error: any Error, group: String, mutation: Mutation) throws {
    let value = try XCTUnwrap(error as? StorageFormatError).projection
    XCTAssertEqual(value.code, "storage_format_incompatible")
    XCTAssertEqual(value.transactionGroup, group)
    XCTAssertEqual(value.wireProfile, "flowersec-v4-transport-security")
    XCTAssertEqual(value.requiredRevision, 2); XCTAssertEqual(value.observedRevision, mutation.observed)
    XCTAssertEqual(value.reason, mutation.reason); XCTAssertFalse(value.exactConversionAvailable)
    XCTAssertLessThan(try JSONEncoder().encode(value).count, 512)
  }
  func testRefillJournalInspectsFormatAndPendingIntentBeforeConfiguration() throws {
    let cases = mutations + [
      Mutation(sql: "UPDATE operation SET intent=x'00'", reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2)),
      Mutation(sql: "UPDATE manifest SET next_operation=x'0000000000000001'", reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2)),
    ]
    for mutation in cases {
      let fixture = try NamespaceFixture(); defer { fixture.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      let source = Data(repeating: 32, count: 16), pool = Data(repeating: 33, count: 32)
      func open(_ create: Bool) throws -> V4PoolRefillJournal {
        try V4PoolRefillJournal(environment: fixture.environment,
          configuration: .init(directory: directory, backingIdentity: Data(repeating: 31, count: 32), create: create,
            maximumRows: 4, maximumBytes: 4_194_304, continuity: { _ in }), tenant: "tenant", source: source, pool: pool)
      }
      let original = try open(true)
      let pending = try original.begin(tenant: "tenant", source: source, pool: pool, desired: 2,
        maximumItemBytes: 65_536, deadline: 1500, identity: Data(repeating: 34, count: 32))
      original.close()
      let current = try open(false); XCTAssertEqual(try current.recover()?.intent, pending.intent); current.close()
      let path = directory.appendingPathComponent("refill.sqlite3")
      // An admitted future header must be refused before its changed tables
      // can select the current operation/material reader.
      if let schemaRevision = mutation.manifestSchemaRevision {
        try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!)
      }
      let sql = mutation.sql + (mutation.reason == .newerRevision ? "; DROP TABLE operation; CREATE TABLE future_operation(value TEXT)" : "")
      if !sql.isEmpty { try edit(path, sql) }
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path))
      XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path), files = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do { let unexpected = try open(false); unexpected.close(); XCTFail("Incompatible refill journal opened") }
      catch { try projection(error, group: "flowersec-swift-v4-pool-journal", mutation: mutation) }
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), files)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
    }
  }
  func testRelayClaimGroupRejectsMalformedRowsAndIncompatibleFormatsWithoutWrites() throws {
    let cases = mutations + [
      Mutation(sql: "INSERT INTO publications VALUES(x'00',x'00')", reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2)),
      Mutation(sql: "INSERT INTO claims VALUES(x'00',x'00')", reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2)),
      Mutation(sql: "INSERT INTO claim_originals VALUES(x'00',x'00')", reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2)),
    ]
    for mutation in cases {
      let fixture = try NamespaceFixture(nativeResources: true); defer { fixture.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      func open(_ create: Bool) throws -> V4RelayClaimLedger {
        try V4RelayClaimLedger(environment: fixture.environment,
          configuration: .init(directory: directory, backingIdentity: Data(repeating: 9, count: 16), create: create,
            maximumRows: 8, maximumBytes: 1 << 20, checkContinuity: { _ in }), tenant: "tenant", relay: Data(repeating: 8, count: 32))
      }
      let original = try open(true); original.close()
      let current = try open(false); try current.check(); current.close()
      let path = directory.appendingPathComponent("relay-claims.sqlite3")
      if let schemaRevision = mutation.manifestSchemaRevision {
        try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!)
      }
      let sql = mutation.sql + (mutation.reason == .newerRevision ? "; DROP TABLE claims; CREATE TABLE future_claims(value TEXT)" : "")
      if !sql.isEmpty { try edit(path, sql) }
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path)); XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path), files = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do { let unexpected = try open(false); unexpected.close(); XCTFail("Incompatible relay claims opened") }
      catch { try projection(error, group: "flowersec-swift-v4-relay", mutation: mutation) }
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), files)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
    }
  }
  func testReferenceAdmissionChecksCanonicalBytesAndOriginalOperationKey() async throws {
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [.init(subject: "server", identityDigest: Data(repeating: 1, count: 32))])
    let operation = V4Crypto.integer(1000, width: 8) + Data(repeating: 4, count: 24)
    let reference = try OperationReference(target: target, authority: Data(repeating: 5, count: 32), namespace: "example.files",
      operation: operation, request: Data(repeating: 6, count: 32), contract: Data(repeating: 7, count: 32),
      shape: .unary, durable: true, deadline: 2000, cancellation: true, limit: 256)
    func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    for sql in ["UPDATE refs SET reference=x'00'", "UPDATE refs SET operation=zeroblob(32)", "CREATE INDEX unexpected_index ON refs(reference)"] {
      let fixture = try NamespaceFixture(nativeResources: true); defer { fixture.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      func open(_ create: Bool) throws -> SQLiteOperationReferenceStore {
        try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: .init(directory: directory,
          target: target, storeID: Data(repeating: 2, count: 16), generation: 1, create: create,
          maximumRows: 2, maximumBytes: 1 << 20, checkContinuity: {}))
      }
      let original = try open(true); await original.close()
      let path = directory.appendingPathComponent("operation-references.sqlite3")
      try edit(path, "INSERT INTO refs VALUES(x'\(hex(operation))',x'\(hex(reference.encoded()))')")
      let current = try open(false)
      let loaded = try await current.load(operationID: operation); XCTAssertEqual(loaded?.encoded(), reference.encoded())
      await current.close()
      try edit(path, sql)
      let before = try Data(contentsOf: path), files = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do { let unexpected = try open(false); await unexpected.close(); XCTFail("Malformed reference group opened") }
      catch { try projection(error, group: "flowersec-swift-v4-references", mutation: .init(sql: sql, reason: .schemaOrStateInvalid, observed: .init(known: true, value: 2))) }
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), files)
    }
  }
}
#endif
