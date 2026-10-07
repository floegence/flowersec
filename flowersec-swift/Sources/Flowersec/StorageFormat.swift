import Foundation

public enum StorageFormatReason: String, Sendable, Encodable {
  case backendConfiguration = "backend_configuration"
  case manifestUnknownOrInvalid = "manifest_unknown_or_invalid"
  case identityMismatch = "identity_mismatch"
  case revisionConflict = "revision_conflict"
  case olderRevision = "older_revision"
  case newerRevision = "newer_revision"
  case schemaOrStateInvalid = "schema_or_state_invalid"
}

public struct StorageRevision: Sendable, Equatable, Encodable {
  public let known: Bool
  public let value: UInt32
  static let unknown = StorageRevision(known: false, value: 0)
}

/// Detached refusal facts. No stored identity, path, provider text, database
/// contents or executable reference is included in this projection.
public struct StorageFormatProjection: Sendable, Equatable, Encodable {
  public let code: String
  public let transactionGroup: String
  public let wireProfile: String
  public let observedRevision: StorageRevision
  public let requiredRevision: UInt32
  public let reason: StorageFormatReason
  public let exactConversionAvailable: Bool
  enum CodingKeys: String, CodingKey {
    case code, reason
    case transactionGroup = "transaction_group", wireProfile = "wire_profile"
    case observedRevision = "observed_revision", requiredRevision = "required_revision"
    case exactConversionAvailable = "exact_conversion_available"
  }
}

public struct StorageFormatError: Error, Sendable, Equatable, CustomStringConvertible {
  public let projection: StorageFormatProjection
  public var description: String { "storage_format_incompatible" }
}

#if os(macOS) || os(iOS)
import SQLite3
import FlowersecSQLite

/// Admission settings for a pinned SQLite connection. Read-only inspection uses
/// the same connection that will later perform writes, so a WAL/SHM image cannot
/// be reopened through a separate read-only handle.
enum V4SQLiteAdmission {
  static func prepare(_ database: OpaquePointer) throws {
    guard flowersec_sqlite_no_checkpoint_on_close(database, 1) == SQLITE_OK,
      sqlite3_exec(database, "PRAGMA locking_mode=EXCLUSIVE; PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-128; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF;", nil, nil, nil) == SQLITE_OK else {
      throw ServiceFailure.serviceUnavailable
    }
  }
  static func allowWrites(_ database: OpaquePointer) throws {
    guard sqlite3_exec(database, "PRAGMA query_only=OFF;", nil, nil, nil) == SQLITE_OK else {
      throw ServiceFailure.serviceUnavailable
    }
  }
  static func restoreCloseCheckpoint(_ database: OpaquePointer) throws {
    guard flowersec_sqlite_no_checkpoint_on_close(database, 0) == SQLITE_OK else {
      throw ServiceFailure.serviceUnavailable
    }
  }
}

/// Reads the fixed physical header only. It has no historical record decoder,
/// migration capability or authority to turn a revision hint into a fact.
struct V4SQLiteStorageFormat: Sendable {
  enum Group: String, Sendable {
    case references = "flowersec-swift-v4-references"
    case pool = "flowersec-swift-v4-pool-spend"
    case execution = "flowersec-swift-v4-execution"
    case liveServer = "flowersec-swift-v4-live-server-admission"
    case parentWinner = "flowersec-swift-v4-parent-winner"
    case relay = "flowersec-swift-v4-relay"
    case poolJournal = "flowersec-swift-v4-pool-journal"
  }
  let group: Group
  let requiredRevision: UInt32 = 2
  func refusal(_ reason: StorageFormatReason, observed: StorageRevision = .unknown) -> StorageFormatError {
    StorageFormatError(projection: StorageFormatProjection(code: "storage_format_incompatible",
      transactionGroup: group.rawValue, wireProfile: "flowersec-v4-transport-security",
      observedRevision: observed, requiredRevision: requiredRevision, reason: reason,
      // This runtime ships no trusted exact source-to-target conversion tool.
      exactConversionAvailable: false))
  }
  private var prefix: String {
    "CREATE TABLE manifest(id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='\(group.rawValue)'), revision INTEGER NOT NULL CHECK(revision="
  }
  private let identityHeader = "), identity BLOB NOT NULL CHECK(length(identity) BETWEEN 1 AND 2048)"
  func manifest(suffix: String = "") -> String { prefix + String(requiredRevision) + identityHeader + suffix + ") STRICT" }

  func inspect(_ database: OpaquePointer, identity: Data) throws -> StorageRevision {
    var schema: OpaquePointer?
    guard sqlite3_prepare_v2(database, "SELECT substr(CAST(sql AS BLOB),1,512) FROM sqlite_schema WHERE type='table' AND name='manifest'", -1, &schema, nil) == SQLITE_OK,
      let schema else { throw refusal(.manifestUnknownOrInvalid) }
    defer { sqlite3_finalize(schema) }
    guard sqlite3_step(schema) == SQLITE_ROW, sqlite3_column_type(schema, 0) == SQLITE_BLOB,
      let bytes = sqlite3_column_blob(schema, 0), (1...512).contains(Int(sqlite3_column_bytes(schema, 0))) else {
      throw refusal(.manifestUnknownOrInvalid)
    }
    let header = String(decoding: UnsafeRawBufferPointer(start: bytes, count: Int(sqlite3_column_bytes(schema, 0))), as: UTF8.self)
    guard sqlite3_step(schema) == SQLITE_DONE, header.hasPrefix(prefix) else { throw refusal(.manifestUnknownOrInvalid) }
    let declaration = header.dropFirst(prefix.count)
    guard let end = declaration.firstIndex(of: ")"), let revision = UInt32(declaration[..<end]), revision > 0,
      String(revision) == String(declaration[..<end]), declaration[end...].hasPrefix(identityHeader) else {
      throw refusal(.manifestUnknownOrInvalid)
    }
    var row: OpaquePointer?
    guard sqlite3_prepare_v2(database, "SELECT id=1,typeof(format)='text' AND format=?1,CASE WHEN typeof(revision)='integer' AND revision BETWEEN 1 AND 4294967295 THEN revision ELSE NULL END,typeof(identity)='blob' AND identity=?2 FROM manifest LIMIT 2", -1, &row, nil) == SQLITE_OK,
      let row else { throw refusal(.manifestUnknownOrInvalid) }
    defer { sqlite3_finalize(row) }
    let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    guard sqlite3_bind_text(row, 1, group.rawValue, -1, transient) == SQLITE_OK,
      identity.withUnsafeBytes({ sqlite3_bind_blob(row, 2, $0.baseAddress, Int32($0.count), transient) }) == SQLITE_OK,
      sqlite3_step(row) == SQLITE_ROW, sqlite3_column_int(row, 0) == 1, sqlite3_column_int(row, 1) == 1 else {
      throw refusal(.manifestUnknownOrInvalid)
    }
    let revisionMatches = sqlite3_column_type(row, 2) == SQLITE_INTEGER && sqlite3_column_int64(row, 2) == Int64(revision)
    let identityMatches = sqlite3_column_int(row, 3) == 1
    guard sqlite3_step(row) == SQLITE_DONE else { throw refusal(.manifestUnknownOrInvalid) }
    guard identityMatches else { throw refusal(.identityMismatch) }
    var hint: OpaquePointer?
    guard sqlite3_prepare_v2(database, "PRAGMA user_version", -1, &hint, nil) == SQLITE_OK, let hint else {
      throw refusal(.revisionConflict)
    }
    defer { sqlite3_finalize(hint) }
    guard revisionMatches, sqlite3_step(hint) == SQLITE_ROW, sqlite3_column_type(hint, 0) == SQLITE_INTEGER,
      sqlite3_column_int64(hint, 0) == Int64(revision), sqlite3_step(hint) == SQLITE_DONE else {
      throw refusal(.revisionConflict)
    }
    let observed = StorageRevision(known: true, value: revision)
    if revision < requiredRevision { throw refusal(.olderRevision, observed: observed) }
    if revision > requiredRevision { throw refusal(.newerRevision, observed: observed) }
    return observed
  }
}
#endif
