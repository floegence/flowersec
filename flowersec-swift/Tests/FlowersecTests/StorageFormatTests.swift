#if os(macOS) || os(iOS)
import Darwin
import Foundation
import SQLite3
import XCTest
@testable import Flowersec

@MainActor
final class StorageFormatTests: XCTestCase {
  private struct Mutation {
    let sql: String
    let reason: StorageFormatReason
    let observed: StorageRevision
    var poolFactField: UInt64? = nil
    var manifestSchemaRevision: UInt32? = nil
    var manifestRowRevision: UInt32? = nil
    var manifestUserVersion: UInt32? = nil
  }
  private let mutations: [Mutation] = [
    Mutation(sql: "CREATE TABLE unexpected(value INTEGER)", reason: .schemaOrStateInvalid, observed: StorageRevision(known: true, value: 2)),
    Mutation(sql: "PRAGMA user_version=3", reason: .revisionConflict, observed: .unknown),
    Mutation(sql: "PRAGMA ignore_check_constraints=ON; UPDATE manifest SET revision=3", reason: .revisionConflict, observed: .unknown),
    Mutation(sql: "UPDATE manifest SET identity=x'00'", reason: .identityMismatch, observed: .unknown),
    Mutation(sql: "", reason: .revisionConflict, observed: .unknown, manifestSchemaRevision: 3, manifestRowRevision: 3, manifestUserVersion: 2),
    Mutation(sql: "", reason: .newerRevision, observed: StorageRevision(known: true, value: 3), manifestSchemaRevision: 3, manifestRowRevision: 3, manifestUserVersion: 3),
    Mutation(sql: "", reason: .olderRevision, observed: StorageRevision(known: true, value: 1), manifestSchemaRevision: 1, manifestRowRevision: 1, manifestUserVersion: 1),
    Mutation(sql: "DROP TABLE manifest; CREATE TABLE manifest(id INTEGER PRIMARY KEY, identity BLOB NOT NULL); INSERT INTO manifest VALUES(1,x'00'); PRAGMA user_version=2", reason: .manifestUnknownOrInvalid, observed: .unknown),
  ]
  private func directory() throws -> URL {
    let value = packageRoot().appendingPathComponent(".flowersec/swift-storage-format-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: value, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return value
  }
  private func edit(_ path: URL, sql: String, blobs: [Data] = []) throws {
    var database: OpaquePointer?
    guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let database else {
      if let database { sqlite3_close_v2(database) }; throw ServiceFailure.serviceUnavailable
    }
    defer { sqlite3_close_v2(database) }
    if blobs.isEmpty {
      guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
    } else {
      var statement: OpaquePointer?
      guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw ServiceFailure.serviceUnavailable }
      defer { sqlite3_finalize(statement) }
      for (index, data) in blobs.enumerated() {
        guard data.withUnsafeBytes({ sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count),
          unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
      }
      guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
    }
  }
  private func poolIdentity(_ path: URL) throws -> Data {
    var database: OpaquePointer?
    guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let database else {
      if let database { sqlite3_close_v2(database) }; throw ServiceFailure.serviceUnavailable
    }
    defer { sqlite3_close_v2(database) }
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, "SELECT identity FROM manifest WHERE id=1", -1, &statement, nil) == SQLITE_OK,
      let statement else { throw ServiceFailure.serviceUnavailable }
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW, sqlite3_column_type(statement, 0) == SQLITE_BLOB,
      (1...2048).contains(sqlite3_column_bytes(statement, 0)), let bytes = sqlite3_column_blob(statement, 0) else { throw ServiceFailure.serviceUnavailable }
    return Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 0)))
  }
  private func assertProjection(_ error: any Error, group: String, mutation: Mutation) throws {
    let projection = try XCTUnwrap(error as? StorageFormatError, "Unexpected storage refusal for \(mutation.sql): \(error)").projection
    XCTAssertEqual(projection.code, "storage_format_incompatible")
    XCTAssertEqual(projection.transactionGroup, group)
    XCTAssertEqual(projection.wireProfile, "flowersec-v4-transport-security")
    XCTAssertEqual(projection.observedRevision, mutation.observed)
    XCTAssertEqual(projection.requiredRevision, 2)
    XCTAssertEqual(projection.reason, mutation.reason)
    XCTAssertFalse(projection.exactConversionAvailable)
    let encoded = try JSONEncoder().encode(projection)
    XCTAssertLessThan(encoded.count, 512)
    let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    XCTAssertEqual(Set(fields.keys), Set(["code", "transaction_group", "wire_profile", "observed_revision", "required_revision", "reason", "exact_conversion_available"]))
  }
  func testReferenceOpenValidatesOneCurrentHeaderAndRefusesWithoutRewriting() async throws {
    for mutation in mutations {
      let fixture = try NamespaceFixture(nativeResources: true)
      defer { fixture.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client",
        peers: [ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 1, count: 32))])
      func configuration(_ create: Bool) -> SQLiteOperationReferenceConfiguration {
        SQLiteOperationReferenceConfiguration(directory: directory, target: target, storeID: Data(repeating: 2, count: 16),
          generation: 1, create: create, maximumRows: 2, maximumBytes: 1 << 20, checkContinuity: {})
      }
      let original = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(true))
      await original.close()
      let current = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(false))
      let missing = try await current.load(operationID: Data(repeating: 4, count: 32)); XCTAssertNil(missing)
      await current.close()
      let path = directory.appendingPathComponent("operation-references.sqlite3")
      if let schemaRevision = mutation.manifestSchemaRevision { try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!) }
      else { try edit(path, sql: mutation.sql) }
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path))
      XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path), entries = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do {
        let unexpected = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(false))
        await unexpected.close(); XCTFail("Incompatible reference storage opened")
      } catch { try assertProjection(error, group: "flowersec-swift-v4-references", mutation: mutation) }
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), entries)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
    }
  }
  func testReferenceOpenRejectsActiveWALReaderWithoutChangingFiles() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    defer { fixture.environment.beginClose() }
    let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 1, count: 32))])
    func configuration(_ create: Bool) -> SQLiteOperationReferenceConfiguration {
      SQLiteOperationReferenceConfiguration(directory: directory, target: target, storeID: Data(repeating: 2, count: 16),
        generation: 1, create: create, maximumRows: 2, maximumBytes: 1 << 20, checkContinuity: {})
    }
    let original = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(true))
    await original.close()
    let reader = try StorageFormatWALReader(directory.appendingPathComponent("operation-references.sqlite3"))
    defer { reader.close() }
    let snapshot = try storageFormatFileSnapshot(directory)
    do {
      let unexpected = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(false))
      await unexpected.close()
      XCTFail("admitted a store while a foreign WAL reader owns its locks")
    } catch {
      XCTAssertEqual(error as? ServiceFailure, .serviceUnavailable)
    }
    try assertStorageFormatFileSnapshot(directory, expected: snapshot)
    reader.close()
    let reopened = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(false))
    await reopened.close()
  }

  func testReferenceOpenRecoversCurrentStoreWithLegalWALSnapshot() async throws {
    let fixture = try NamespaceFixture(nativeResources: true)
    defer { fixture.environment.beginClose() }
    let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
    let target = try ServiceBindingTarget(authority: "example", tenant: "tenant", audience: "service", localSubject: "client",
      peers: [ServiceBindingTarget.Peer(subject: "server", identityDigest: Data(repeating: 1, count: 32))])
    func configuration(_ create: Bool, directory storeDirectory: URL) -> SQLiteOperationReferenceConfiguration {
      SQLiteOperationReferenceConfiguration(directory: storeDirectory, target: target, storeID: Data(repeating: 2, count: 16),
        generation: 1, create: create, maximumRows: 2, maximumBytes: 1 << 20, checkContinuity: {})
    }
    let original = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(true, directory: directory))
    await original.close()
    let operation = Data([0, 0, 0, 0, 0, 0, 0, 1]) + Data(repeating: 4, count: 24)
    let reference = try OperationReference(target: target, authority: Data(repeating: 5, count: 32), namespace: "example.files",
      operation: operation, request: Data(repeating: 6, count: 32), contract: Data(repeating: 7, count: 32),
      shape: .unary, durable: true, deadline: 2000, cancellation: true, limit: 256)
    let path = directory.appendingPathComponent("operation-references.sqlite3")
    let writer = try StorageFormatWALWriter(path, operation: operation, reference: reference.encoded())
    defer { writer.close() }
    let snapshot = try storageFormatFileSnapshot(directory)
    let walName = path.lastPathComponent + "-wal"
    let shmName = path.lastPathComponent + "-shm"
    XCTAssertGreaterThan(snapshot[walName]?.count ?? 0, 32)
    XCTAssertGreaterThan(snapshot[shmName]?.count ?? 0, 0)

    let mainOnlyDirectory = directory.appendingPathComponent("main-only")
    try FileManager.default.createDirectory(at: mainOnlyDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: mainOnlyDirectory) }
    let mainOnlyPath = mainOnlyDirectory.appendingPathComponent(path.lastPathComponent)
    try snapshot[path.lastPathComponent]!.write(to: mainOnlyPath, options: .atomic)
    var mainOnly: OpaquePointer?
    guard sqlite3_open_v2(mainOnlyPath.path, &mainOnly, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
      let mainOnly else {
      if let mainOnly { sqlite3_close_v2(mainOnly) }
      throw ServiceFailure.serviceUnavailable
    }
    defer { sqlite3_close_v2(mainOnly) }
    guard sqlite3_exec(mainOnly, "PRAGMA journal_mode=DELETE", nil, nil, nil) == SQLITE_OK else {
      throw ServiceFailure.serviceUnavailable
    }
    let operationHex = operation.map { String(format: "%02x", $0) }.joined()
    var mainStatement: OpaquePointer?
    guard sqlite3_prepare_v2(mainOnly, "SELECT count(*) FROM refs WHERE operation=x'\(operationHex)'", -1, &mainStatement, nil) == SQLITE_OK,
      let mainStatement, sqlite3_step(mainStatement) == SQLITE_ROW else {
      if let mainStatement { sqlite3_finalize(mainStatement) }
      throw ServiceFailure.serviceUnavailable
    }
    XCTAssertEqual(sqlite3_column_int64(mainStatement, 0), 0)
    sqlite3_finalize(mainStatement)

    let crashDirectory = directory.appendingPathComponent("crash-image")
    try FileManager.default.createDirectory(at: crashDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: crashDirectory) }
    for name in [path.lastPathComponent, walName, shmName] {
      let copied = crashDirectory.appendingPathComponent(name)
      try snapshot[name]!.write(to: copied, options: .atomic)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: copied.path)
    }
    let crashLock = crashDirectory.appendingPathComponent(path.lastPathComponent + ".lock")
    guard FileManager.default.createFile(atPath: crashLock.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
      throw ServiceFailure.serviceUnavailable
    }
    let recovered = try SQLiteOperationReferenceStore(environment: fixture.environment, configuration: configuration(false, directory: crashDirectory))
    let loaded = try await recovered.load(operationID: operation)
    XCTAssertEqual(loaded?.encoded(), reference.encoded())
    await recovered.close()
  }

  func testPoolOpenValidatesOneCurrentHeaderAndRefusesWithoutRewriting() async throws {
    let known = StorageRevision(known: true, value: 2)
    let cases = mutations + [
      Mutation(sql: "UPDATE refusals SET original=x'00'", reason: .schemaOrStateInvalid, observed: known),
      Mutation(sql: "UPDATE spend SET consumed=x'00'", reason: .schemaOrStateInvalid, observed: known),
      Mutation(sql: "UPDATE spend SET consumed=(SELECT original FROM refusals ORDER BY lease LIMIT 1) WHERE lease IN (SELECT lease FROM refusals)", reason: .schemaOrStateInvalid, observed: known),
      Mutation(sql: "UPDATE refusals SET lease=x'00' WHERE lease=(SELECT lease FROM refusals ORDER BY lease LIMIT 1)", reason: .schemaOrStateInvalid, observed: known),
      Mutation(sql: "UPDATE manifest SET rows=0", reason: .schemaOrStateInvalid, observed: known),
      Mutation(sql: "PRAGMA ignore_check_constraints=ON; UPDATE spend SET source=0", reason: .schemaOrStateInvalid, observed: known),
    ] + (UInt64(0)...7).map { Mutation(sql: "", reason: .schemaOrStateInvalid, observed: known, poolFactField: $0) }
    for mutation in cases {
      let fixture = try CredentialFixture(nativeResources: true)
      defer { fixture.base.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      let backing = try V4PoolStoreBacking(environment: fixture.base.environment, directory: directory,
        identity: V4PoolStoreIdentity(storeID: Data(repeating: 7, count: 16), generation: 1, tenant: "tenant",
          issuer: Data(repeating: 5, count: 16), spendAuthority: "spend", winnerAuthority: "winner"),
        maximumBytes: 1 << 20, maximumRows: 8, continuity: { _ in })
      let original = try backing.open(create: true); original.close(); await original.waitPhysicalCleanup()
      let path = directory.appendingPathComponent("spend.sqlite3")
      let identity = try poolIdentity(path)
      var invalidProjection: (Data, Data)?
      // These are persisted historical facts only. They cannot create a
      // prepared carrier, admission or original consumption continuation.
      for (offset, lease) in [UInt8(30), 31, 32].enumerated() {
        let nonce = Data(repeating: lease, count: 32)
        let input = try fixture.input(source: .preauthorizedPool, indices: [0],
          artifact: [6: .bytes(Data(repeating: lease, count: 16)), 7: .bytes(nonce)], activation: [5: .bytes(Data(repeating: lease, count: 16))])
        let admission = try fixture.verify(input)
        defer { admission.close() }
        let facts = try admission.poolSpendFacts(in: fixture.base.environment)
        let projection = V4Crypto.map([(0, V4Crypto.bytes(identity)),
          (1, V4Crypto.bytes(Data(repeating: lease, count: 16))), (2, V4Crypto.bytes(Data(repeating: lease + 10, count: 16))),
          (3, V4Crypto.bytes(facts.projection))])
        if offset != 1 { try edit(path, sql: "INSERT INTO refusals VALUES(?1,?2)", blobs: [facts.key, projection]) }
        if offset != 0 { try edit(path, sql: "INSERT INTO spend VALUES(?1,1,?2)", blobs: [facts.key, projection]) }
        if offset == 1, let changed = mutation.poolFactField {
          var fields: [(UInt64, Data)] = [(0, V4Crypto.text("flowersec/swift/pool-consume/1")),
            (1, V4Crypto.bytes(admission.artifactDigest)), (2, V4Crypto.bytes(admission.activationDigest)),
            (3, V4Crypto.bytes(nonce)), (4, V4Crypto.bytes(admission.candidateID)),
            (5, V4Crypto.bytes(admission.routeDigest)), (6, V4NamespaceValue.head(0, 0)), (7, V4Crypto.bytes(input.activation))]
          let replacement: Data
          switch changed {
          case 0: replacement = V4Crypto.text("private-untrusted-domain")
          case 1, 2, 3: replacement = V4Crypto.bytes(Data(repeating: 0, count: 32))
          case 4, 5: replacement = V4Crypto.bytes(Data([1]))
          case 6: replacement = V4NamespaceValue.head(0, 15)
          default: replacement = V4Crypto.bytes(Data([0]))
          }
          fields[Int(changed)].1 = replacement
          let corrupt = V4Crypto.map([(0, V4Crypto.bytes(identity)),
            (1, V4Crypto.bytes(Data(repeating: lease, count: 16))), (2, V4Crypto.bytes(Data(repeating: lease + 10, count: 16))),
            (3, V4Crypto.bytes(V4Crypto.map(fields)))])
          invalidProjection = (facts.key, corrupt)
        }
      }
      try edit(path, sql: "UPDATE manifest SET rows=2")
      let current = try backing.open(create: false); current.close(); await current.waitPhysicalCleanup()
      if let (lease, corrupt) = invalidProjection {
        try edit(path, sql: "UPDATE spend SET consumed=?2 WHERE lease=?1", blobs: [lease, corrupt])
      } else if let schemaRevision = mutation.manifestSchemaRevision { try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!) }
      else { try edit(path, sql: mutation.sql) }
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path)); XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path), entries = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do {
        let unexpected = try backing.open(create: false); unexpected.close(); await unexpected.waitPhysicalCleanup()
        XCTFail("Incompatible pool storage opened")
      } catch { try assertProjection(error, group: "flowersec-swift-v4-pool-spend", mutation: mutation) }
      await backing.waitPhysicalCleanup()
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), entries)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
    }
  }
  func testParentWinnerChecksCanonicalFactsBeforeWritableConfiguration() async throws {
    let current = StorageRevision(known: true, value: 2)
    let cases = mutations + [Mutation(sql: "UPDATE winners SET projection=x'00'", reason: .schemaOrStateInvalid, observed: current)]
    for mutation in cases {
      let fixture = try CredentialFixture(nativeResources: true)
      defer { fixture.base.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      func configuration(_ create: Bool) -> ParentWinnerStoreConfiguration {
        ParentWinnerStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 111, count: 16),
          authority: "winner", create: create, maximumRows: 16, maximumBytes: 1 << 20, checkContinuity: { _ in })
      }
      let admission = try fixture.base.environment.verifyDirectCredentials(configuration: fixture.configuration(), input: fixture.input())
      defer { admission.close() }
      let selection = try admission.parentWinnerSelection(authority: "winner")
      let original = try ParentWinnerAuthority(environment: fixture.base.environment, configuration: configuration(true))
      XCTAssertEqual(try original.configuration.compareAndSelect(selection), selection)
      original.close(); await original.waitPhysicalCleanup()
      let reopened = try ParentWinnerAuthority(environment: fixture.base.environment, configuration: configuration(false))
      XCTAssertEqual(try reopened.configuration.compareAndSelect(selection), selection)
      reopened.close(); await reopened.waitPhysicalCleanup()
      let path = directory.appendingPathComponent("parent-winner.sqlite3")
      if let schemaRevision = mutation.manifestSchemaRevision { try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!) }
      else { try edit(path, sql: mutation.sql) }
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path)); XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path), entries = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do {
        let unexpected = try ParentWinnerAuthority(environment: fixture.base.environment, configuration: configuration(false))
        unexpected.close(); await unexpected.waitPhysicalCleanup(); XCTFail("Incompatible parent-winner storage opened")
      } catch { try assertProjection(error, group: "flowersec-swift-v4-parent-winner", mutation: mutation) }
      fixture.base.environment.beginClose()
      _ = try await fixture.base.environment.waitCleanup()
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), entries)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
    }
  }
  func testExecutionOpenChecksCurrentStateBeforeRecoveryOrStorageWrites() async throws {
    let current = StorageRevision(known: true, value: 2)
    let cases = mutations + [
      Mutation(sql: "UPDATE executions SET history_until=x'0000000000000000'", reason: .schemaOrStateInvalid, observed: current),
      Mutation(sql: "UPDATE executions SET checkpoint=x'00'", reason: .schemaOrStateInvalid, observed: current),
      Mutation(sql: "UPDATE executions SET original_stream_header=x'00'", reason: .schemaOrStateInvalid, observed: current),
      Mutation(sql: "UPDATE executions SET state=3,active=0,result=x'01',result_digest=zeroblob(32),result_bytes=1,reserved_bytes=1", reason: .schemaOrStateInvalid, observed: current),
      Mutation(sql: "UPDATE identity SET checkpoint_key_identity=zeroblob(32)", reason: .schemaOrStateInvalid, observed: current),
    ]
    for mutation in cases {
      let fixture = try NamespaceFixture(nativeResources: true)
      defer { fixture.environment.beginClose() }
      let directory = try directory(); defer { try? FileManager.default.removeItem(at: directory) }
      let key = try ServiceCheckpointSigningKey(protection: .hmacSHA256,
        keyID: Data(repeating: 12, count: 16), secret: Data(repeating: 13, count: 32))
      func configuration(_ create: Bool) -> SQLiteServiceExecutionConfiguration {
        SQLiteServiceExecutionConfiguration(directory: directory, authority: "example", storeID: Data(repeating: 11, count: 16),
          generation: 1, create: create, maximumHistoryRows: 2, maximumActive: 1, maximumResultBytes: 2048,
          maximumDatabaseBytes: 2 << 20, checkpointKey: key, checkContinuity: {})
      }
      func selector(_ operation: UInt8) -> V4ServerExecutionSelector {
        V4ServerExecutionSelector(tenant: "tenant", audience: "service", namespace: "example.files", caller: "client",
          authority: Data(repeating: 3, count: 32), operation: Data(repeating: operation, count: 32),
          request: Data(repeating: 4, count: 32), contract: Data(repeating: 5, count: 32))
      }
      let original = try SQLiteServiceExecutionStore(environment: fixture.environment, configuration: configuration(true))
      let admitted = try await original.admit(selector(1), deadline: 30_000, historyMS: 1000, responseBytes: 256)
      XCTAssertTrue(admitted)
      await original.close()
      let reopened = try SQLiteServiceExecutionStore(environment: fixture.environment, configuration: configuration(false))
      let recovered = try await reopened.lookup(selector(1)); XCTAssertEqual(recovered?.state, 5)
      XCTAssertFalse(recovered?.active ?? true)
      let second = try await reopened.admit(selector(2), deadline: 30_000, historyMS: 1000, responseBytes: 256)
      XCTAssertTrue(second)
      await reopened.close()
      let path = directory.appendingPathComponent("execution.sqlite3")
      if let schemaRevision = mutation.manifestSchemaRevision { try rewriteManifestRevisionForTest(path, schemaRevision: schemaRevision, rowRevision: mutation.manifestRowRevision!, userVersion: mutation.manifestUserVersion!) }
      else { try edit(path, sql: mutation.sql) }
      try prepareStorageFormatWALCrashImage(path)
      let beforeFiles = try storageFormatFileSnapshot(directory)
      let walPath = URL(fileURLWithPath: path.path + "-wal")
      XCTAssertTrue(FileManager.default.fileExists(atPath: walPath.path)); XCTAssertGreaterThan(try Data(contentsOf: walPath).count, 0)
      let before = try Data(contentsOf: path), entries = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
      do {
        let unexpected = try SQLiteServiceExecutionStore(environment: fixture.environment, configuration: configuration(false))
        await unexpected.close(); XCTFail("Incompatible execution storage opened")
      } catch { try assertProjection(error, group: "flowersec-swift-v4-execution", mutation: mutation) }
      XCTAssertEqual(try Data(contentsOf: path), before)
      XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), entries)
      try assertStorageFormatFileSnapshot(directory, expected: beforeFiles)
    }
  }
}
#endif
