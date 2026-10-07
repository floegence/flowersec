#if os(macOS) || os(iOS)
import Darwin
import Foundation
import SQLite3
import XCTest
@testable import Flowersec

@MainActor
final class LiveServerStorageFormatTests: XCTestCase {
  private struct Mutation {
    let sql: String
    let reason: StorageFormatReason
    let observed: StorageRevision
    var manifestSchemaRevision: UInt32? = nil
    var manifestRowRevision: UInt32? = nil
    var manifestUserVersion: UInt32? = nil
  }
  func testLiveAdmissionRefusesUnknownAndIncompatibleGroupsBeforeConfiguration() async throws {
    let variants: [Mutation] = [
      Mutation(sql: "CREATE TABLE unexpected(value TEXT)", reason: .schemaOrStateInvalid, observed: StorageRevision(known: true, value: 2)),
      Mutation(sql: "PRAGMA user_version=3", reason: .revisionConflict, observed: .unknown),
      Mutation(sql: "UPDATE manifest SET identity=x'00'", reason: .identityMismatch, observed: .unknown),
      Mutation(sql: "", reason: .newerRevision, observed: StorageRevision(known: true, value: 3), manifestSchemaRevision: 3, manifestRowRevision: 3, manifestUserVersion: 3),
      Mutation(sql: "", reason: .olderRevision, observed: StorageRevision(known: true, value: 1), manifestSchemaRevision: 1, manifestRowRevision: 1, manifestUserVersion: 1),
      Mutation(sql: "DROP TABLE manifest; CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), binding BLOB NOT NULL) STRICT; INSERT INTO manifest VALUES(1,x'00')", reason: .manifestUnknownOrInvalid, observed: .unknown),
      Mutation(sql: "INSERT INTO originals VALUES(x'00',x'00')", reason: .schemaOrStateInvalid, observed: StorageRevision(known: true, value: 2)),
    ]
    for mutation in variants {
      let sql = mutation.sql + (mutation.reason == .newerRevision ? "; DROP TABLE admissions; CREATE TABLE future_admissions(value TEXT)" : "")
      let reason = mutation.reason, observed = mutation.observed
      let fixture = try NamespaceFixture(nativeResources: true)
      defer { fixture.environment.beginClose() }
      let directory = packageRoot().appendingPathComponent(".flowersec/swift-live-storage-format-\(UUID().uuidString)")
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: directory) }
      func open(_ create: Bool) throws -> V4LiveServerAdmissionLedger {
        try V4LiveServerAdmissionLedger(environment: fixture.environment,
          configuration: LiveServerAdmissionStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 9, count: 16),
            create: create, maximumRows: 8, maximumBytes: 1 << 20, checkContinuity: { _ in }),
          tenant: "tenant", audience: "service", serverIdentity: Data(repeating: 8, count: 32))
      }
      let original = try open(true); original.close(); await original.waitPhysicalCleanup()
      let current = try open(false); current.close(); await current.waitPhysicalCleanup()
      let path = directory.appendingPathComponent("live-server-admissions.sqlite3")
      if let schemaRevision = mutation.manifestSchemaRevision {
        try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!)
      }
      var database: OpaquePointer?
      guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let database else {
        if let database { sqlite3_close_v2(database) }; throw ServiceFailure.serviceUnavailable
      }
      let changed = sql.isEmpty ? SQLITE_OK : sqlite3_exec(database, sql, nil, nil, nil); sqlite3_close_v2(database)
      XCTAssertEqual(changed, SQLITE_OK)
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path))
      XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path)
      let files = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do {
        let unexpected = try open(false); unexpected.close(); await unexpected.waitPhysicalCleanup()
        XCTFail("Incompatible live admission storage opened")
      } catch {
        let projection = try XCTUnwrap(error as? StorageFormatError).projection
        XCTAssertEqual(projection.code, "storage_format_incompatible")
        XCTAssertEqual(projection.transactionGroup, "flowersec-swift-v4-live-server-admission")
        XCTAssertEqual(projection.wireProfile, "flowersec-v4-transport-security")
        XCTAssertEqual(projection.requiredRevision, 2); XCTAssertEqual(projection.observedRevision, observed)
        XCTAssertEqual(projection.reason, reason); XCTAssertFalse(projection.exactConversionAvailable)
        XCTAssertLessThan(try JSONEncoder().encode(projection).count, 512)
      }
      // A failed initializer still owns asynchronous SQLite cleanup. Observe
      // the real original lock release before removing this test's files.
      let lock = Darwin.open(path.path + ".lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
      guard lock >= 0 else { throw ServiceFailure.serviceUnavailable }
      defer { Darwin.close(lock) }
      let deadline = ContinuousClock.now.advanced(by: .seconds(2))
      while flock(lock, LOCK_EX | LOCK_NB) != 0 {
        guard ContinuousClock.now < deadline else { throw ServiceFailure.deadlineExceeded }
        try await Task.sleep(for: .milliseconds(1))
      }
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), files)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
      XCTAssertEqual(flock(lock, LOCK_UN), 0)
    }
  }
}
#endif
