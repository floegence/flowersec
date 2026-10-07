#if os(macOS) || os(iOS)
import Foundation
import SQLite3
import XCTest
@testable import Flowersec


final class StorageFormatWALReader: @unchecked Sendable {
  private var database: OpaquePointer?
  private var statement: OpaquePointer?
  init(_ path: URL) throws {
    guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
      database != nil else {
      if let database { sqlite3_close_v2(database) }
      throw ServiceFailure.serviceUnavailable
    }
    do {
      try execute("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
      try execute("BEGIN IMMEDIATE; CREATE TABLE __flowersec_wal_probe(value INTEGER); INSERT INTO __flowersec_wal_probe VALUES(1); COMMIT; BEGIN IMMEDIATE; DROP TABLE __flowersec_wal_probe; COMMIT;")
      guard let database,
        sqlite3_exec(database, "BEGIN", nil, nil, nil) == SQLITE_OK,
        sqlite3_prepare_v2(database, "SELECT name FROM sqlite_schema", -1, &statement, nil) == SQLITE_OK,
        let statement,
        sqlite3_step(statement) == SQLITE_ROW else {
        throw ServiceFailure.serviceUnavailable
      }
    } catch {
      close()
      throw error
    }
  }
  func close() {
    if let statement { sqlite3_finalize(statement); self.statement = nil }
    if let database {
      sqlite3_exec(database, "ROLLBACK", nil, nil, nil)
      sqlite3_close_v2(database)
      self.database = nil
    }
  }
  deinit { close() }
  private func execute(_ sql: String) throws {
    guard let database, sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
      throw ServiceFailure.serviceUnavailable
    }
  }

}


// Retain a committed main/WAL/SHM image without keeping a foreign reader lock.
// Restoring the complete snapshot after close models process loss while keeping
// every byte that admission must leave unchanged when refusing an old format.
func prepareStorageFormatWALCrashImage(_ path: URL) throws {
  let reader = try StorageFormatWALReader(path)
  defer { reader.close() }
  let files = [path, URL(fileURLWithPath: path.path + "-wal"), URL(fileURLWithPath: path.path + "-shm")]
  let contents = try files.map { try Data(contentsOf: $0) }
  reader.close()
  for (file, content) in zip(files, contents) {
    try content.write(to: file, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
  }
}


final class StorageFormatWALWriter: @unchecked Sendable {
  private var database: OpaquePointer?
  init(_ path: URL, operation: Data, reference: Data) throws {
    func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
      database != nil else {
      if let database { sqlite3_close_v2(database) }
      throw ServiceFailure.serviceUnavailable
    }
    do {
      try execute("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
      let sql = "BEGIN IMMEDIATE; INSERT INTO refs(operation,reference) VALUES(x'\(hex(operation))',x'\(hex(reference))'); COMMIT;"
      try execute(sql)
    } catch {
      close()
      throw error
    }
  }
  func close() {
    if let database { sqlite3_close_v2(database); self.database = nil }
  }
  deinit { close() }
  private func execute(_ sql: String) throws {
    guard let database, sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
      throw ServiceFailure.serviceUnavailable
    }
  }
}


func storageFormatFileSnapshot(_ directory: URL) throws -> [String: Data] {
  let names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
  var snapshot: [String: Data] = [:]
  for name in names {
    let path = directory.appendingPathComponent(name)
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: path.path, isDirectory: &isDirectory), !isDirectory.boolValue else { continue }
    snapshot[name] = try Data(contentsOf: path)
  }
  return snapshot
}

func assertStorageFormatFileSnapshot(_ directory: URL, expected: [String: Data], file: StaticString = #filePath, line: UInt = #line) throws {
  XCTAssertEqual(try storageFormatFileSnapshot(directory), expected, file: file, line: line)
  XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), expected.keys.sorted(), file: file, line: line)
}

func rewriteManifestRevisionForTest(_ path: URL, schemaRevision: UInt32, rowRevision: UInt32, userVersion: UInt32) throws {
  var database: OpaquePointer?
  guard sqlite3_open_v2(path.path, &database, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK, let database else {
    if let database { sqlite3_close_v2(database) }; throw ServiceFailure.serviceUnavailable
  }
  defer { sqlite3_close_v2(database) }
  var schemaStatement: OpaquePointer?
  guard sqlite3_prepare_v2(database, "SELECT sql FROM sqlite_schema WHERE type='table' AND name='manifest'", -1, &schemaStatement, nil) == SQLITE_OK,
    let schemaStatement, sqlite3_step(schemaStatement) == SQLITE_ROW, let raw = sqlite3_column_text(schemaStatement, 0) else {
    if let schemaStatement { sqlite3_finalize(schemaStatement) }; throw ServiceFailure.serviceUnavailable
  }
  let schema = String(cString: raw); sqlite3_finalize(schemaStatement)
  guard schema.contains("CREATE TABLE manifest") || schema.contains("CREATE TABLE \"manifest\""), schema.contains("CHECK(revision=2)") else {
    throw ServiceFailure.serviceUnavailable
  }
  let create = schema
    .replacingOccurrences(of: "CREATE TABLE \"manifest\"", with: "CREATE TABLE manifest")
    .replacingOccurrences(of: "CHECK(revision=2)", with: "CHECK(revision=\(schemaRevision))")
  let quote: (String) -> String = { "\"" + $0.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
  let sql = "BEGIN IMMEDIATE; ALTER TABLE manifest RENAME TO manifest_source; \(create);"
  guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else {
    sqlite3_exec(database, "ROLLBACK", nil, nil, nil); throw ServiceFailure.serviceUnavailable
  }
  var columnsStatement: OpaquePointer?
  guard sqlite3_prepare_v2(database, "PRAGMA table_info(manifest_source)", -1, &columnsStatement, nil) == SQLITE_OK,
    let columnsStatement else {
    sqlite3_exec(database, "ROLLBACK", nil, nil, nil); throw ServiceFailure.serviceUnavailable
  }
  var columns: [String] = []
  while sqlite3_step(columnsStatement) == SQLITE_ROW {
    guard let rawName = sqlite3_column_text(columnsStatement, 1) else {
      sqlite3_finalize(columnsStatement); sqlite3_exec(database, "ROLLBACK", nil, nil, nil); throw ServiceFailure.serviceUnavailable
    }
    columns.append(String(cString: rawName))
  }
  sqlite3_finalize(columnsStatement)
  guard !columns.isEmpty, columns.contains("revision") else {
    sqlite3_exec(database, "ROLLBACK", nil, nil, nil); throw ServiceFailure.serviceUnavailable
  }
  let names = columns.map(quote).joined(separator: ",")
  let values = columns.map { $0 == "revision" ? String(rowRevision) : quote($0) }.joined(separator: ",")
  let copy = "INSERT INTO manifest(\(names)) SELECT \(values) FROM manifest_source; DROP TABLE manifest_source; PRAGMA user_version=\(userVersion); COMMIT;"
  guard sqlite3_exec(database, copy, nil, nil, nil) == SQLITE_OK else {
    sqlite3_exec(database, "ROLLBACK", nil, nil, nil); throw ServiceFailure.serviceUnavailable
  }
}
#endif
