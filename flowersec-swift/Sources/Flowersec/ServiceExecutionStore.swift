import Foundation
import Crypto

public struct ServiceCheckpointSigningKey: Sendable {
  public let protection: CheckpointTokenProtection
  public let keyID: Data
  public let secret: Data
  public init(protection: CheckpointTokenProtection, keyID: Data, secret: Data) throws {
    guard keyID.count == 16, secret.count == 32, keyID.contains(where: { $0 != 0 }),
      secret.contains(where: { $0 != 0 }) else { throw ServiceFailure.configurationCapacity }
    self.protection = protection; self.keyID = Data(keyID); self.secret = secret.withUnsafeBytes { Data($0) }
  }
}
public struct IssuedServiceCheckpoint: Sendable {
  public let encodedToken: Data
  public let protection: CheckpointTokenProtection
  public let generation: UInt64
  public let checkpoint: ApplicationCheckpoint
  public let expiresAtMS: UInt64
}

#if os(macOS) || os(iOS)
import Darwin
import SQLite3
import Dispatch

public struct SQLiteServiceExecutionConfiguration: Sendable {
  public let directory: URL
  public let authority: String
  public let storeID: Data
  public let generation: UInt64
  public let create: Bool
  public let maximumHistoryRows: Int
  public let maximumActive: Int
  public let maximumResultBytes: Int
  public let maximumDatabaseBytes: Int
  public let maximumContentItems: Int
  public let maximumContentBytes: Int
  public let checkpointKey: ServiceCheckpointSigningKey
  public let maximumCheckpointIssuesPerOperation: Int
  public let minimumCheckpointIntervalMS: UInt64
  public let checkContinuity: @Sendable () throws -> Void
  public init(directory: URL, authority: String, storeID: Data, generation: UInt64, create: Bool,
    maximumHistoryRows: Int = 64, maximumActive: Int = 16, maximumResultBytes: Int = 16 << 20,
    maximumDatabaseBytes: Int = 32 << 20, checkpointKey: ServiceCheckpointSigningKey,
    maximumCheckpointIssuesPerOperation: Int = 16, minimumCheckpointIntervalMS: UInt64 = 1000,
    maximumContentItems: Int = 0, maximumContentBytes: Int = 0, checkContinuity: @escaping @Sendable () throws -> Void) {
    self.directory = directory; self.authority = authority; self.storeID = Data(storeID); self.generation = generation
    self.create = create; self.maximumHistoryRows = maximumHistoryRows; self.maximumActive = maximumActive
    self.maximumResultBytes = maximumResultBytes; self.maximumDatabaseBytes = maximumDatabaseBytes
    self.checkpointKey = checkpointKey; self.maximumContentItems = maximumContentItems; self.maximumContentBytes = maximumContentBytes
    self.maximumCheckpointIssuesPerOperation = maximumCheckpointIssuesPerOperation
    self.minimumCheckpointIntervalMS = minimumCheckpointIntervalMS; self.checkContinuity = checkContinuity
  }
}
struct V4ServerExecutionSelector: Sendable {
  let tenant: String
  let audience: String
  let namespace: String
  let caller: String
  let authority: Data
  let operation: Data
  let request: Data
  let contract: Data
  var key: Data { V4Crypto.map([(0, V4Crypto.text(tenant)), (1, V4Crypto.text(audience)), (2, V4Crypto.text(namespace)),
    (3, V4Crypto.text(caller)), (4, V4Crypto.bytes(authority)), (5, V4Crypto.bytes(operation))]) }
  func check(_ record: V4ServerExecutionRecord) throws {
    guard record.key == key, record.request == request, record.contract == contract else { throw ServiceFailure.operationConflict }
  }
}
struct V4ServerExecutionRecord: Sendable {
  let key: Data
  let request: Data
  let contract: Data
  var state: UInt64
  var reason: UInt64
  var cancelled: Bool
  var dispatched: Bool
  var active: Bool
  let deadline: UInt64
  let historyUntil: UInt64
  var resultUntil: UInt64
  var result: Data?
  var resultDigest: Data?
  var resultBytes: UInt64
  var resultCode: UInt64
  var resultDeleted: Bool
  var reservedBytes: UInt64
  var generation: UInt64
  var checkpoint: Data?
  var tokenDigest: Data?
  var resultPresent: Bool = false
  var checkpointIssues: UInt64 = 0
  var lastCheckpointIssueMS: UInt64 = 0
  var originalStreamHeader: Data? = nil
  var streamItems: UInt64 = 0
  var streamBytes: UInt64 = 0
  var consumedTokenDigest: Data? = nil
  var recoveryEntered = false
  var reissuedPreviousDigest: Data? = nil
  var reissuedToken: Data? = nil
  var reissueLifetimeMS: UInt64 = 0
  var reissueExpiresAtMS: UInt64 = 0
  var runStartedMS: UInt64? = nil
  func originalRunDeadline(maximumRunMS: UInt64?) throws -> UInt64 {
    guard let maximumRunMS else { return deadline }
    guard maximumRunMS > 0, let runStartedMS else { throw ServiceFailure.historyUnknown }
    let (cap, overflow) = runStartedMS.addingReportingOverflow(maximumRunMS)
    guard !overflow else { throw ServiceFailure.deadlineExceeded }
    return min(deadline, cap)
  }
}
private final class V4ExecutionSQLiteExecutor: SerialExecutor, @unchecked Sendable {
  let queue = DispatchQueue(label: "flowersec.execution-store", qos: .utility)
  func enqueue(_ job: consuming ExecutorJob) {
    let original = UnownedJob(job)
    queue.async { [self] in original.runSynchronously(on: asUnownedSerialExecutor()) }
  }
}
private struct V4ExecutionSQLiteHandles: @unchecked Sendable {
  let database: OpaquePointer
  let lock: Int32
  let directory: Int32
  let directoryDevice: dev_t
  let directoryInode: ino_t
  let databaseDevice: dev_t
  let databaseInode: ino_t
  let lockDevice: dev_t
  let lockInode: ino_t
}

/// Exact durable history owns its bounded rows and result capacity before
/// dispatch. Reopening marks interrupted work unknown and never restarts it.
public actor SQLiteServiceExecutionStore {
  nonisolated private let executor = V4ExecutionSQLiteExecutor()
  nonisolated public var unownedExecutor: UnownedSerialExecutor { executor.asUnownedSerialExecutor() }
  nonisolated let environment: V4EnvironmentFoundation
  nonisolated public let authority: String
  private let directoryURL: URL
  private let maximumHistoryRows: Int
  private let maximumActive: Int
  private let maximumResultBytes: Int
  private let maximumDatabaseBytes: Int
  nonisolated let maximumContentItems: Int
  nonisolated let maximumContentBytes: Int
  private let contentIncarnation = UUID()
  private var checkpointKey: ServiceCheckpointSigningKey?
  private let maximumCheckpointIssuesPerOperation: Int
  private let minimumCheckpointIntervalMS: UInt64
  private var checkContinuity: (@Sendable () throws -> Void)?
  private let storage: V4CryptoReservation
  private let namespace: V4NamespaceRegistry
  private var handles: V4ExecutionSQLiteHandles?
  private let path: String
  private var closed = false

  init(environment: V4EnvironmentFoundation, configuration: SQLiteServiceExecutionConfiguration) throws {
    let c = configuration
    guard c.directory.isFileURL, c.directory.path == c.directory.resolvingSymlinksInPath().path,
      !c.directory.path.utf8.contains(0), V4NamespaceRegistry.securityID(c.authority.utf8),
      c.storeID.count == 16, c.storeID.contains(where: { $0 != 0 }), c.generation > 0,
      (1...8192).contains(c.maximumHistoryRows), (1...1024).contains(c.maximumActive), c.maximumActive <= c.maximumHistoryRows,
      (1...1 << 30).contains(c.maximumResultBytes), (0...131_072).contains(c.maximumContentItems),
      (0...1 << 30).contains(c.maximumContentBytes), (c.maximumContentItems == 0) == (c.maximumContentBytes == 0),
      c.maximumDatabaseBytes >= c.maximumResultBytes + c.maximumContentBytes + c.maximumContentItems * 8192 + c.maximumHistoryRows * 16_384 + 1_048_576,
      c.maximumDatabaseBytes <= 2 << 30, (1...65535).contains(c.maximumCheckpointIssuesPerOperation),
      c.minimumCheckpointIntervalMS > 0, c.minimumCheckpointIntervalMS < 1 << 63 else { throw ServiceFailure.configurationCapacity }
    try c.checkContinuity()
    let keyIdentity = try Self.checkpointKeyIdentity(c.checkpointKey)
    self.environment = environment; authority = c.authority; directoryURL = c.directory
    maximumHistoryRows = c.maximumHistoryRows; maximumActive = c.maximumActive
    maximumResultBytes = c.maximumResultBytes; maximumDatabaseBytes = c.maximumDatabaseBytes
    maximumContentItems = c.maximumContentItems; maximumContentBytes = c.maximumContentBytes
    checkpointKey = c.checkpointKey; checkContinuity = c.checkContinuity
    maximumCheckpointIssuesPerOperation = c.maximumCheckpointIssuesPerOperation; minimumCheckpointIntervalMS = c.minimumCheckpointIntervalMS
    storage = try environment.serviceExecutionStoreStorage(rows: c.maximumHistoryRows, active: c.maximumActive,
      databaseBytes: c.maximumDatabaseBytes, contentItems: c.maximumContentItems)
    namespace = try V4NamespaceRegistry(); path = c.directory.appendingPathComponent("execution.sqlite3").path
    do { handles = try Self.openDatabase(configuration: c, keyIdentity: keyIdentity, path: path, registry: namespace) }
    catch { environment.root.diagnosticCounters.increment(.storeFailures); throw error }
  }
  private static let format = V4SQLiteStorageFormat(group: .execution)
  private static let manifestSchema = format.manifest()
  private static func identity(_ c: SQLiteServiceExecutionConfiguration, keyIdentity: Data) -> Data {
    V4Crypto.hash(V4Crypto.map([(0, V4Crypto.text("flowersec/swift/execution-store/2")),
      (1, V4Crypto.text(c.authority)), (2, V4Crypto.bytes(c.storeID)), (3, V4NamespaceValue.head(0, c.generation)),
      (4, V4NamespaceValue.head(0, UInt64(c.maximumHistoryRows))), (5, V4NamespaceValue.head(0, UInt64(c.maximumActive))),
      (6, V4NamespaceValue.head(0, UInt64(c.maximumResultBytes))), (7, V4NamespaceValue.head(0, UInt64(c.maximumDatabaseBytes))),
      (8, V4NamespaceValue.head(0, UInt64(c.maximumCheckpointIssuesPerOperation))), (9, V4NamespaceValue.head(0, c.minimumCheckpointIntervalMS)),
      (10, V4Crypto.bytes(keyIdentity)), (11, V4NamespaceValue.head(0, UInt64(c.maximumContentItems))),
      (12, V4NamespaceValue.head(0, UInt64(c.maximumContentBytes)))]))
  }
  private static func openDatabase(configuration c: SQLiteServiceExecutionConfiguration,
    keyIdentity: Data, path: String, registry: V4NamespaceRegistry) throws -> V4ExecutionSQLiteHandles {
    let directory = open(c.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard directory >= 0 else { throw ServiceFailure.configurationCapacity }
    var directoryStat = stat()
    guard fstat(directory, &directoryStat) == 0, directoryStat.st_mode & S_IFMT == S_IFDIR,
      directoryStat.st_uid == geteuid(), directoryStat.st_mode & 0o077 == 0 else { Darwin.close(directory); throw ServiceFailure.permissionDenied }
    let lock = openat(directory, "execution.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    var lockStat = stat()
    guard lock >= 0, fstat(lock, &lockStat) == 0, lockStat.st_mode & S_IFMT == S_IFREG,
      lockStat.st_uid == geteuid(), lockStat.st_nlink == 1, lockStat.st_mode & 0o077 == 0, lockStat.st_size == 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else {
      if lock >= 0 { Darwin.close(lock) }; Darwin.close(directory); throw ServiceFailure.resourceExhausted
    }
    let descriptor = openat(directory, "execution.sqlite3", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
    var databaseStat = stat()
    guard descriptor >= 0, fstat(descriptor, &databaseStat) == 0, databaseStat.st_mode & S_IFMT == S_IFREG,
      databaseStat.st_uid == geteuid(), databaseStat.st_nlink == 1, databaseStat.st_mode & 0o077 == 0,
      databaseStat.st_size >= 0, databaseStat.st_size <= c.maximumDatabaseBytes else {
      if descriptor >= 0 { Darwin.close(descriptor) }; Darwin.close(lock); Darwin.close(directory); throw ServiceFailure.permissionDenied
    }
    do { try Self.checkSidecars(directory: directory, maximumBytes: c.maximumDatabaseBytes) }
    catch { Darwin.close(descriptor); Darwin.close(lock); Darwin.close(directory); throw error }
    Darwin.close(descriptor)
    var connection: OpaquePointer?
    guard sqlite3_open_v2(path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK, let initial = connection else {
      if let connection { sqlite3_close(connection) }; Darwin.close(lock); Darwin.close(directory)
      throw format.refusal(.manifestUnknownOrInvalid)
    }
    let database = initial
    let opened = V4ExecutionSQLiteHandles(database: database, lock: lock, directory: directory,
      directoryDevice: directoryStat.st_dev, directoryInode: directoryStat.st_ino,
      databaseDevice: databaseStat.st_dev, databaseInode: databaseStat.st_ino, lockDevice: lockStat.st_dev, lockInode: lockStat.st_ino)
    do {
      try Self.checkPaths(opened, path: path, directoryPath: c.directory.path, maximumBytes: c.maximumDatabaseBytes)
      if !c.create { try V4SQLiteAdmission.prepare(database) }
      Self.configureReadLimits(database)
      try Self.exec(database, "PRAGMA trusted_schema=OFF; PRAGMA busy_timeout=0; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048")
      if c.create { try Self.exec(database, "PRAGMA page_size=4096") }
      else {
        try admitCurrentFormat(opened, configuration: c, keyIdentity: keyIdentity, registry: registry, path: path)
        try V4SQLiteAdmission.allowWrites(database)
        try V4SQLiteAdmission.restoreCloseCheckpoint(database)
      }
      guard try Self.scalar(database, "PRAGMA page_size") == 4096 else { throw ServiceFailure.permissionDenied }
      try Self.exec(database, "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048; PRAGMA busy_timeout=0; PRAGMA wal_autocheckpoint=64;")
      let pages = c.maximumDatabaseBytes / 4096
      try Self.exec(database, "PRAGMA max_page_count=\(pages)")
      if c.create {
        try Self.exec(database, "BEGIN IMMEDIATE; " + Self.manifestSchema + "; " + Self.identitySchema + "; " + Self.executionSchema + "; " + Self.contentPolicySchema + "; " + Self.contentSchema + "; PRAGMA user_version=\(format.requiredRevision);")
        let manifest = try Self.prepare(database, "INSERT INTO manifest VALUES(1,'\(format.group.rawValue)',\(format.requiredRevision),?)")
        defer { sqlite3_finalize(manifest) }
        try Self.bind(manifest, 1, identity(c, keyIdentity: keyIdentity))
        guard sqlite3_step(manifest) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
        let statement = try Self.prepare(database, "INSERT INTO identity VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?)"); defer { sqlite3_finalize(statement) }
        try Self.bindText(statement, 1, c.authority); try Self.bind(statement, 2, c.storeID); try Self.bind(statement, 3, Self.integer(c.generation))
        for (index, value) in [(Int32(4), c.maximumHistoryRows), (5, c.maximumActive), (6, c.maximumResultBytes), (7, c.maximumDatabaseBytes)] {
          guard sqlite3_bind_int64(statement, index, Int64(value)) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
        }
        guard sqlite3_bind_int64(statement, 8, Int64(c.maximumCheckpointIssuesPerOperation)) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
        try Self.bind(statement, 9, Self.integer(c.minimumCheckpointIntervalMS)); try Self.bind(statement, 10, keyIdentity)
        guard sqlite3_bind_int64(statement, 11, Int64(c.maximumContentItems)) == SQLITE_OK,
          sqlite3_bind_int64(statement, 12, Int64(c.maximumContentBytes)) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
        guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
        try Self.exec(database, "COMMIT")
      } else {
        try Self.exec(database, "BEGIN IMMEDIATE")
        try Self.exec(database, "UPDATE stream_content SET payload=NULL WHERE key IN (SELECT key FROM content_policies WHERE durable=0)")
        try Self.exec(database, "UPDATE content_policies SET reserved_bytes=0 WHERE durable=0")
        try Self.exec(database, "UPDATE executions SET state=5, reason=3, active=0, reserved_bytes=CASE WHEN result IS NOT NULL THEN result_bytes WHEN token_digest IS NOT NULL THEN reserved_bytes ELSE 0 END WHERE active=1")
        try Self.exec(database, "UPDATE content_policies SET reserved_items=(SELECT count(*) FROM stream_content WHERE key=content_policies.key),reserved_bytes=(SELECT coalesce(sum(length(payload)),0) FROM stream_content WHERE key=content_policies.key)")
        try Self.exec(database, "COMMIT")
      }
      try Self.checkPaths(opened, path: path, directoryPath: c.directory.path, maximumBytes: c.maximumDatabaseBytes)
      try c.checkContinuity()
      return opened
    } catch {
      sqlite3_exec(database, "ROLLBACK", nil, nil, nil); sqlite3_close(database); Darwin.close(lock); Darwin.close(directory); throw error
    }
  }
  private static func admitCurrentFormat(_ opened: V4ExecutionSQLiteHandles, configuration c: SQLiteServiceExecutionConfiguration,
    keyIdentity: Data, registry: V4NamespaceRegistry, path: String) throws {
    let database = opened.database
    var observed = StorageRevision.unknown
    do {
      try checkPaths(opened, path: path, directoryPath: c.directory.path, maximumBytes: c.maximumDatabaseBytes)
      try exec(database, "BEGIN")
      observed = try format.inspect(database, identity: identity(c, keyIdentity: keyIdentity))
      try preflight(database, configuration: c, keyIdentity: keyIdentity, registry: registry)
      try checkPaths(opened, path: path, directoryPath: c.directory.path, maximumBytes: c.maximumDatabaseBytes)
      try exec(database, "ROLLBACK")
    } catch {
      let code = sqlite3_errcode(database)
      try? exec(database, "ROLLBACK")
      if let format = error as? StorageFormatError { throw format }
      throw format.refusal(.schemaOrStateInvalid,
        observed: code == SQLITE_CORRUPT || code == SQLITE_NOTADB ? .unknown : observed)
    }
  }
  private static func configureReadLimits(_ database: OpaquePointer) {
    sqlite3_limit(database, SQLITE_LIMIT_LENGTH, 2 << 20)
    sqlite3_limit(database, SQLITE_LIMIT_SQL_LENGTH, 16_384)
    sqlite3_limit(database, SQLITE_LIMIT_ATTACHED, 0)
  }
  private static let identitySchema = "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), authority TEXT NOT NULL, store_id BLOB NOT NULL CHECK(length(store_id)=16), generation BLOB NOT NULL CHECK(length(generation)=8), history_rows INTEGER NOT NULL CHECK(history_rows BETWEEN 1 AND 8192), active_limit INTEGER NOT NULL CHECK(active_limit BETWEEN 1 AND history_rows), result_limit INTEGER NOT NULL CHECK(result_limit BETWEEN 1 AND 1073741824), database_limit INTEGER NOT NULL CHECK(database_limit BETWEEN 1 AND 2147483648), checkpoint_issue_limit INTEGER NOT NULL CHECK(checkpoint_issue_limit BETWEEN 1 AND 65535), checkpoint_interval BLOB NOT NULL CHECK(length(checkpoint_interval)=8), checkpoint_key_identity BLOB NOT NULL CHECK(length(checkpoint_key_identity)=32), content_item_limit INTEGER NOT NULL CHECK(content_item_limit BETWEEN 0 AND 131072), content_byte_limit INTEGER NOT NULL CHECK(content_byte_limit BETWEEN 0 AND 1073741824)) STRICT"
  private static let executionSchema = "CREATE TABLE executions (key BLOB PRIMARY KEY CHECK(length(key) BETWEEN 1 AND 4096), request BLOB NOT NULL CHECK(length(request)=32), contract BLOB NOT NULL CHECK(length(contract)=32), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 5), reason INTEGER NOT NULL CHECK(reason BETWEEN 0 AND 6), cancelled INTEGER NOT NULL CHECK(cancelled IN (0,1)), dispatched INTEGER NOT NULL CHECK(dispatched IN (0,1)), active INTEGER NOT NULL CHECK(active IN (0,1)), deadline BLOB NOT NULL CHECK(length(deadline)=8), history_until BLOB NOT NULL CHECK(length(history_until)=8), result_until BLOB NOT NULL CHECK(length(result_until)=8), result BLOB, result_digest BLOB CHECK(result_digest IS NULL OR length(result_digest)=32), result_bytes INTEGER NOT NULL CHECK(result_bytes BETWEEN 0 AND 1048576), result_code INTEGER NOT NULL CHECK(result_code BETWEEN 0 AND 4294967295), result_deleted INTEGER NOT NULL CHECK(result_deleted IN (0,1)), reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes BETWEEN 0 AND 1048576), generation BLOB NOT NULL CHECK(length(generation)=8), checkpoint BLOB CHECK(checkpoint IS NULL OR length(checkpoint) BETWEEN 1 AND 8192), token_digest BLOB CHECK(token_digest IS NULL OR length(token_digest)=32), checkpoint_issues INTEGER NOT NULL CHECK(checkpoint_issues BETWEEN 0 AND 65535), last_checkpoint_issue BLOB NOT NULL CHECK(length(last_checkpoint_issue)=8), original_stream_header BLOB CHECK(original_stream_header IS NULL OR length(original_stream_header) BETWEEN 1 AND 512), stream_items INTEGER NOT NULL CHECK(stream_items BETWEEN 0 AND 4294967295), stream_bytes BLOB NOT NULL CHECK(length(stream_bytes)=8), consumed_token_digest BLOB CHECK(consumed_token_digest IS NULL OR length(consumed_token_digest)=32), recovery_entered INTEGER NOT NULL CHECK(recovery_entered IN (0,1)), reissued_previous_digest BLOB CHECK(reissued_previous_digest IS NULL OR length(reissued_previous_digest)=32), reissued_token BLOB CHECK(reissued_token IS NULL OR length(reissued_token) BETWEEN 1 AND 4980), reissue_lifetime BLOB NOT NULL CHECK(length(reissue_lifetime)=8), reissue_expires BLOB NOT NULL CHECK(length(reissue_expires)=8), run_started BLOB CHECK(run_started IS NULL OR length(run_started)=8), CHECK((reissued_previous_digest IS NULL)=(reissued_token IS NULL)), CHECK(result IS NULL OR (state IN (3,4) AND length(result)=result_bytes AND result_digest IS NOT NULL AND result_deleted=0 AND reserved_bytes=result_bytes)), CHECK(token_digest IS NULL OR checkpoint IS NOT NULL), CHECK(active=0 OR state IN (1,2))) STRICT"
  private static func number(_ statement: OpaquePointer, _ column: Int32, maximum: UInt64) throws -> UInt64 {
    guard sqlite3_column_type(statement, column) == SQLITE_INTEGER else { throw ServiceFailure.serviceUnavailable }
    let value = sqlite3_column_int64(statement, column)
    guard value >= 0, UInt64(value) <= maximum else { throw ServiceFailure.serviceUnavailable }
    return UInt64(value)
  }
  private static func nullableUInt(_ statement: OpaquePointer, _ column: Int32) throws -> UInt64? {
    if sqlite3_column_type(statement, column) == SQLITE_NULL { return nil }
    return try uint(statement, column)
  }
  private static func text(_ statement: OpaquePointer, _ column: Int32) -> String? {
    guard sqlite3_column_type(statement, column) == SQLITE_TEXT, sqlite3_column_bytes(statement, column) <= 8192,
      let value = sqlite3_column_text(statement, column) else { return nil }
    return String(cString: value)
  }
  private static func scalar(_ database: OpaquePointer, _ sql: String) throws -> UInt64 {
    let statement = try prepare(database, sql); defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { throw ServiceFailure.serviceUnavailable }
    let value = try number(statement, 0, maximum: UInt64(Int64.max))
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }; return value
  }
  private static func checkSchema(_ database: OpaquePointer) throws {
    let statement = try prepare(database, "SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name LIMIT 6")
    defer { sqlite3_finalize(statement) }
    for (name, schema) in [("content_policies", contentPolicySchema), ("executions", executionSchema),
      ("identity", identitySchema), ("manifest", manifestSchema), ("stream_content", contentSchema)] {
      guard sqlite3_step(statement) == SQLITE_ROW, text(statement, 0) == name, text(statement, 1) == schema else { throw ServiceFailure.permissionDenied }
    }
    guard sqlite3_step(statement) == SQLITE_DONE, try scalar(database, "SELECT count(*) FROM identity") == 1,
      try scalar(database, "SELECT count(*) FROM manifest") == 1,
      try scalar(database, "SELECT count(*) FROM sqlite_schema WHERE type NOT IN ('table','index') OR (type='index' AND sql IS NOT NULL)") == 0 else { throw ServiceFailure.permissionDenied }
  }
  private static func preflight(_ database: OpaquePointer, configuration c: SQLiteServiceExecutionConfiguration,
    keyIdentity: Data, registry: V4NamespaceRegistry) throws {
    try checkSchema(database)
    guard try scalar(database, "PRAGMA page_size") == 4096,
      try scalar(database, "PRAGMA page_count") <= UInt64(c.maximumDatabaseBytes / 4096) else { throw ServiceFailure.permissionDenied }
    let statement = try prepare(database, "SELECT authority,store_id,generation,history_rows,active_limit,result_limit,database_limit,checkpoint_issue_limit,checkpoint_interval,checkpoint_key_identity,content_item_limit,content_byte_limit FROM identity WHERE id=1")
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW, text(statement, 0) == c.authority,
      blob(statement, 1) == c.storeID, blob(statement, 2) == integer(c.generation),
      try number(statement, 3, maximum: 8192) == UInt64(c.maximumHistoryRows),
      try number(statement, 4, maximum: 1024) == UInt64(c.maximumActive),
      try number(statement, 5, maximum: 1 << 30) == UInt64(c.maximumResultBytes),
      try number(statement, 6, maximum: 2 << 30) == UInt64(c.maximumDatabaseBytes),
      try number(statement, 7, maximum: 65535) == UInt64(c.maximumCheckpointIssuesPerOperation),
      blob(statement, 8) == integer(c.minimumCheckpointIntervalMS), blob(statement, 9) == keyIdentity,
      try number(statement, 10, maximum: 131_072) == UInt64(c.maximumContentItems),
      try number(statement, 11, maximum: 1 << 30) == UInt64(c.maximumContentBytes), sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.permissionDenied }
    let check = try prepare(database, "PRAGMA quick_check"); defer { sqlite3_finalize(check) }
    guard sqlite3_step(check) == SQLITE_ROW, text(check, 0) == "ok", sqlite3_step(check) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
    let foreignKeys = try prepare(database, "PRAGMA foreign_key_check"); defer { sqlite3_finalize(foreignKeys) }
    guard sqlite3_step(foreignKeys) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
    try checkQuotas(database, historyRows: c.maximumHistoryRows, active: c.maximumActive, resultBytes: c.maximumResultBytes)
    try checkContentQuotas(database, maximumItems: c.maximumContentItems, maximumBytes: c.maximumContentBytes)
    let records = try prepare(database, "SELECT key FROM executions ORDER BY key LIMIT \(c.maximumHistoryRows + 1)")
    defer { sqlite3_finalize(records) }
    let wire = try V4ApplicationWireRegistry()
    var count = 0
    while true {
      let status = sqlite3_step(records); if status == SQLITE_DONE { break }
      count += 1
      guard status == SQLITE_ROW, count <= c.maximumHistoryRows, let key = blob(records, 0, maximum: 4096), !key.isEmpty,
        let record = try readRecord(key, database: database, includeResult: true, maximumBodyBytes: nil,
          maximumResultBytes: c.maximumResultBytes, maximumCheckpointIssuesPerOperation: c.maximumCheckpointIssuesPerOperation),
        record.result == nil || Data(SHA256.hash(data: record.result!)) == record.resultDigest else { throw ServiceFailure.serviceUnavailable }
      try checkRecordEncoding(record, registry: registry, wire: wire, key: c.checkpointKey)
    }
    try checkContentState(database, configuration: c)
  }
  private static func checkRecordEncoding(_ record: V4ServerExecutionRecord, registry: V4NamespaceRegistry, wire: V4ApplicationWireRegistry,
    key: ServiceCheckpointSigningKey) throws {
    var selector = V4PoolWireCursor(record.key, maximum: 4096)
    try selector.map(6); try selector.key(0); let tenant = try selector.text(maximum: 128)
    try selector.key(1); let audience = try selector.text(maximum: 128)
    try selector.key(2); let namespace = try selector.text(maximum: 128)
    try selector.key(3); let caller = try selector.text(maximum: 128)
    try selector.key(4); let authority = try selector.bytes(maximum: 32)
    try selector.key(5); let operation = try selector.bytes(maximum: 32); try selector.end()
    guard [tenant, audience, namespace, caller].allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
      authority.count == 32, operation.count == 32 else { throw ServiceFailure.serviceUnavailable }
    if let checkpoint = record.checkpoint {
      _ = try ApplicationCheckpoint(V4NamespaceDocument(checkpoint, schema: "ResumeCheckpoint",
        bytes: 8192, nodes: 16, registry: registry).root)
    }
    if let header = record.originalStreamHeader {
      let request = try V4ApplicationHeader(encoded: header, registry: wire)
      guard request.kind == "execution_stream_request", try request.bytes(1) == operation,
        try request.bytes(4) == record.request, try request.bytes(6) == record.contract,
        try request.uint(5) == record.deadline else { throw ServiceFailure.serviceUnavailable }
    }
    if let encoded = record.reissuedToken {
      let schema = key.protection == .ed25519 ? "ResumeSignedToken" : "ResumeMACToken"
      let token = try V4NamespaceDocument(encoded, schema: schema, bytes: 4980, nodes: 128, registry: registry).root
      let claims = try token.field("claims")
      guard try token.b("key_id") == key.keyID, try claims.t("tenant_id") == tenant,
        try claims.t("audience") == audience, try claims.t("service_namespace") == namespace,
        try claims.t("caller_identity") == caller, try claims.b("operation_id") == operation,
        try claims.b("request_digest") == record.request, try claims.u("expires_at_ms") == record.reissueExpiresAtMS,
        try claims.u("issued_at_ms") < record.reissueExpiresAtMS,
        try claims.u("generation") <= record.generation else { throw ServiceFailure.serviceUnavailable }
      if key.protection == .ed25519 {
        try token.verify("resume_token_signature", publicKey: Curve25519.Signing.PrivateKey(rawRepresentation: key.secret).publicKey.rawRepresentation)
      } else {
        let unsigned = V4Crypto.map([(0, Data(claims.raw)), (1, V4Crypto.bytes(key.keyID))])
        let (label, projection) = try registry.domain("resume_token_mac", schema: schema, operation: "hmac-sha256")
        guard projection == "without_mac", HMAC<SHA256>.isValidAuthenticationCode(try token.b("mac"),
          authenticating: label + V4Crypto.integer(UInt64(unsigned.count), width: 4) + unsigned,
          using: SymmetricKey(data: key.secret)) else { throw ServiceFailure.serviceUnavailable }
      }
    }
  }
  private static func checkContentState(_ database: OpaquePointer, configuration c: SQLiteServiceExecutionConfiguration) throws {
    let policies = try prepare(database, "SELECT revision,definition,read_type,retention,max_items,max_bytes,admitted,owner,reserved_items,reserved_bytes,(SELECT count(*) FROM stream_content WHERE key=content_policies.key),(SELECT coalesce(sum(length(payload)),0) FROM stream_content WHERE key=content_policies.key) FROM content_policies LIMIT \(c.maximumHistoryRows + 1)")
    defer { sqlite3_finalize(policies) }
    var count = 0
    while true {
      let status = sqlite3_step(policies); if status == SQLITE_DONE { break }
      count += 1
      guard status == SQLITE_ROW, count <= c.maximumHistoryRows,
        let revision = text(policies, 0), let definition = blob(policies, 1, maximum: 2048),
        let owner = text(policies, 7), UUID(uuidString: owner) != nil else { throw ServiceFailure.serviceUnavailable }
      _ = try StreamContentDefinition(schemaRevision: revision, canonical: definition,
        readTypeID: UInt32(number(policies, 2, maximum: UInt64(UInt32.max))))
      let retention = try uint(policies, 3), admitted = try uint(policies, 6)
      let items = try number(policies, 4, maximum: UInt64(c.maximumContentItems)), bytes = try number(policies, 5, maximum: UInt64(c.maximumContentBytes))
      let reservedItems = try number(policies, 8, maximum: items), reservedBytes = try number(policies, 9, maximum: bytes)
      guard retention > 0, !admitted.addingReportingOverflow(retention).overflow,
        try number(policies, 10, maximum: reservedItems) <= reservedItems,
        try number(policies, 11, maximum: reservedBytes) <= reservedBytes else { throw ServiceFailure.serviceUnavailable }
    }
    let content = try prepare(database, "SELECT committed,expires,bytes,digest,payload FROM stream_content LIMIT \(c.maximumContentItems + 1)")
    defer { sqlite3_finalize(content) }
    count = 0
    while true {
      let status = sqlite3_step(content); if status == SQLITE_DONE { break }
      count += 1
      guard status == SQLITE_ROW, count <= c.maximumContentItems, try uint(content, 0) < uint(content, 1),
        let digest = blob(content, 3, maximum: 32), digest.count == 32 else { throw ServiceFailure.serviceUnavailable }
      let bytes = try number(content, 2, maximum: 1_048_576), payload = try nullableBlob(content, 4, maximum: 1_048_576)
      guard payload == nil || (payload?.count == Int(bytes) && Data(SHA256.hash(data: payload!)) == digest) else { throw ServiceFailure.serviceUnavailable }
    }
  }
  private static func checkQuotas(_ database: OpaquePointer, historyRows: Int, active: Int, resultBytes: Int) throws {
    let statement = try prepare(database, "SELECT count(*),coalesce(sum(active),0),coalesce(sum(reserved_bytes),0),coalesce(sum(result_bytes),0) FROM executions")
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { throw ServiceFailure.serviceUnavailable }
    _ = try number(statement, 0, maximum: UInt64(historyRows)); _ = try number(statement, 1, maximum: UInt64(active))
    _ = try number(statement, 2, maximum: UInt64(resultBytes))
    // Expired metadata retains original result sizes after the body is deleted.
    _ = try number(statement, 3, maximum: UInt64(historyRows) * UInt64(resultBytes))
  }
  private static func checkDatabasePath(_ database: OpaquePointer) throws {
    var moved: Int32 = 0
    guard sqlite3_file_control(database, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK,
      moved == 0 else { throw ServiceFailure.permissionDenied }
  }
  private static func checkSidecars(directory: Int32, maximumBytes: Int) throws {
    for name in ["execution.sqlite3-journal", "execution.sqlite3-wal", "execution.sqlite3-shm"] {
      var sidecar = stat()
      if fstatat(directory, name, &sidecar, AT_SYMLINK_NOFOLLOW) == 0 {
        guard sidecar.st_mode & S_IFMT == S_IFREG, sidecar.st_nlink == 1, sidecar.st_uid == geteuid(), sidecar.st_mode & 0o077 == 0,
          sidecar.st_size >= 0, sidecar.st_size <= maximumBytes else { throw ServiceFailure.permissionDenied }
      } else if errno != ENOENT { throw ServiceFailure.serviceUnavailable }
    }
  }
  private static func checkpointKeyIdentity(_ key: ServiceCheckpointSigningKey) throws -> Data {
    let material: Data
    if key.protection == .ed25519 { material = try Curve25519.Signing.PrivateKey(rawRepresentation: key.secret).publicKey.rawRepresentation }
    else { material = key.secret }
    return V4Crypto.hash(V4Crypto.map([(0, V4Crypto.text("flowersec/swift/checkpoint-key/1")),
      (1, V4NamespaceValue.head(0, key.protection.rawValue)), (2, V4Crypto.bytes(key.keyID)), (3, V4Crypto.bytes(material))]))
  }
  private static func integer(_ value: UInt64) -> Data { V4Crypto.integer(value, width: 8) }
  private static func uint(_ statement: OpaquePointer, _ column: Int32) throws -> UInt64 {
    guard let bytes = blob(statement, column), bytes.count == 8 else { throw ServiceFailure.serviceUnavailable }
    return bytes.reduce(0) { $0 << 8 | UInt64($1) }
  }
  private static func blob(_ statement: OpaquePointer, _ column: Int32, maximum: Int = 1_048_576) -> Data? {
    guard sqlite3_column_type(statement, column) == SQLITE_BLOB else { return nil }
    let count = Int(sqlite3_column_bytes(statement, column))
    guard count >= 0, count <= maximum else { return nil }
    if count == 0 { return Data() }
    guard let pointer = sqlite3_column_blob(statement, column) else { return nil }
    return Data(bytes: pointer, count: count)
  }
  private static func nullableBlob(_ statement: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data? {
    if sqlite3_column_type(statement, column) == SQLITE_NULL { return nil }
    guard let value = blob(statement, column, maximum: maximum) else { throw ServiceFailure.serviceUnavailable }
    return value
  }
  private static func exec(_ database: OpaquePointer, _ sql: String) throws {
    guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
  }
  private static func prepare(_ database: OpaquePointer, _ sql: String) throws -> OpaquePointer {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw ServiceFailure.serviceUnavailable }
    return statement
  }
  private static func bind(_ statement: OpaquePointer, _ index: Int32, _ data: Data?) throws {
    let result: Int32
    if let data, data.isEmpty { result = sqlite3_bind_zeroblob(statement, index, 0) }
    else if let data {
      result = data.withUnsafeBytes { sqlite3_bind_blob(statement, index, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
    } else { result = sqlite3_bind_null(statement, index) }
    guard result == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
  }
  private static func bindText(_ statement: OpaquePointer, _ index: Int32, _ value: String) throws {
    guard value.withCString({ sqlite3_bind_text(statement, index, $0, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
  }
  private static func checkPaths(_ handles: V4ExecutionSQLiteHandles, path: String, directoryPath: String, maximumBytes: Int) throws {
    var directory = stat(); var database = stat(); var lock = stat()
    guard fstat(handles.directory, &directory) == 0, directory.st_dev == handles.directoryDevice, directory.st_ino == handles.directoryInode,
      lstat(directoryPath, &directory) == 0, directory.st_dev == handles.directoryDevice, directory.st_ino == handles.directoryInode,
      directory.st_mode & S_IFMT == S_IFDIR, directory.st_uid == geteuid(), directory.st_mode & 0o077 == 0,
      lstat(path, &database) == 0, database.st_dev == handles.databaseDevice, database.st_ino == handles.databaseInode,
      database.st_mode & S_IFMT == S_IFREG, database.st_uid == geteuid(), database.st_nlink == 1, database.st_mode & 0o077 == 0,
      fstat(handles.lock, &lock) == 0, lock.st_dev == handles.lockDevice, lock.st_ino == handles.lockInode,
      fstatat(handles.directory, "execution.lock", &lock, AT_SYMLINK_NOFOLLOW) == 0,
      lock.st_dev == handles.lockDevice, lock.st_ino == handles.lockInode, lock.st_mode & S_IFMT == S_IFREG,
      lock.st_uid == geteuid(), lock.st_nlink == 1, lock.st_mode & 0o077 == 0, lock.st_size == 0 else { throw ServiceFailure.permissionDenied }
    guard database.st_size >= 0, database.st_size <= maximumBytes else { throw ServiceFailure.resourceExhausted }
    try checkSidecars(directory: handles.directory, maximumBytes: maximumBytes)
    try checkDatabasePath(handles.database)
  }
  private func check() throws -> OpaquePointer {
    guard !closed, let handles, let checkContinuity else { throw ServiceFailure.closed }; try storage.check(); try checkContinuity()
    try Self.checkPaths(handles, path: path, directoryPath: directoryURL.path, maximumBytes: maximumDatabaseBytes)
    return handles.database
  }
  private func read(_ key: Data, database: OpaquePointer, includeResult: Bool = true, maximumBodyBytes: Int? = nil) throws -> V4ServerExecutionRecord? {
    try Self.readRecord(key, database: database, includeResult: includeResult, maximumBodyBytes: maximumBodyBytes,
      maximumResultBytes: maximumResultBytes, maximumCheckpointIssuesPerOperation: maximumCheckpointIssuesPerOperation)
  }
  private static func readRecord(_ key: Data, database: OpaquePointer, includeResult: Bool, maximumBodyBytes: Int?,
    maximumResultBytes: Int, maximumCheckpointIssuesPerOperation: Int) throws -> V4ServerExecutionRecord? {
    // M reads only fixed execution facts. Large original result bodies belong
    // to the ordinary result-read position, never the protected control lane.
    let body = includeResult ? "result" : "NULL"
    let requestedBodyLimit = maximumBodyBytes ?? maximumResultBytes
    guard requestedBodyLimit >= 0 else { throw ServiceFailure.configurationCapacity }
    let bodyLimit = min(requestedBodyLimit, min(maximumResultBytes, 1_048_576))
    let statement = try Self.prepare(database, "SELECT key,request,contract,state,reason,cancelled,dispatched,active,deadline,history_until,result_until,\(body),result_digest,result_bytes,result_code,result_deleted,reserved_bytes,generation,checkpoint,token_digest,result IS NOT NULL,coalesce(length(result),0),checkpoint_issues,last_checkpoint_issue,original_stream_header,stream_items,stream_bytes,consumed_token_digest,recovery_entered,reissued_previous_digest,reissued_token,reissue_lifetime,reissue_expires,run_started FROM executions WHERE key=?"); defer { sqlite3_finalize(statement) }
    try Self.bind(statement, 1, key)
    let outcome = sqlite3_step(statement); if outcome == SQLITE_DONE { return nil }; guard outcome == SQLITE_ROW else { throw ServiceFailure.serviceUnavailable }
    guard let originalKey = Self.blob(statement, 0), let request = Self.blob(statement, 1), let contract = Self.blob(statement, 2),
      originalKey == key, request.count == 32, contract.count == 32 else { throw ServiceFailure.serviceUnavailable }
    let storedBodyBytes = try Self.number(statement, 21, maximum: UInt64(min(maximumResultBytes, 1_048_576)))
    if includeResult, storedBodyBytes > UInt64(bodyLimit) { throw ServiceFailure.resourceExhausted }
    let result = V4ServerExecutionRecord(key: originalKey, request: request, contract: contract,
      state: try Self.number(statement, 3, maximum: 5), reason: try Self.number(statement, 4, maximum: 6),
      cancelled: try Self.number(statement, 5, maximum: 1) == 1, dispatched: try Self.number(statement, 6, maximum: 1) == 1, active: try Self.number(statement, 7, maximum: 1) == 1,
      deadline: try Self.uint(statement, 8), historyUntil: try Self.uint(statement, 9), resultUntil: try Self.uint(statement, 10),
      result: try Self.nullableBlob(statement, 11, maximum: bodyLimit), resultDigest: try Self.nullableBlob(statement, 12, maximum: 32), resultBytes: try Self.number(statement, 13, maximum: UInt64(min(maximumResultBytes, 1_048_576))),
      resultCode: try Self.number(statement, 14, maximum: UInt64(UInt32.max)), resultDeleted: try Self.number(statement, 15, maximum: 1) == 1,
      reservedBytes: try Self.number(statement, 16, maximum: UInt64(min(maximumResultBytes, 1_048_576))), generation: try Self.uint(statement, 17),
      checkpoint: try Self.nullableBlob(statement, 18, maximum: 8192), tokenDigest: try Self.nullableBlob(statement, 19, maximum: 32),
      resultPresent: try Self.number(statement, 20, maximum: 1) == 1,
      checkpointIssues: try Self.number(statement, 22, maximum: UInt64(maximumCheckpointIssuesPerOperation)), lastCheckpointIssueMS: try Self.uint(statement, 23),
      originalStreamHeader: try Self.nullableBlob(statement, 24, maximum: 512),
      streamItems: try Self.number(statement, 25, maximum: UInt64(UInt32.max)), streamBytes: try Self.uint(statement, 26),
      consumedTokenDigest: try Self.nullableBlob(statement, 27, maximum: 32), recoveryEntered: try Self.number(statement, 28, maximum: 1) == 1,
      reissuedPreviousDigest: try Self.nullableBlob(statement, 29, maximum: 32), reissuedToken: try Self.nullableBlob(statement, 30, maximum: 4980),
      reissueLifetimeMS: try Self.uint(statement, 31), reissueExpiresAtMS: try Self.uint(statement, 32),
      runStartedMS: try Self.nullableUInt(statement, 33))
    guard result.state > 0, result.historyUntil >= result.deadline, !result.active || result.state <= 2,
      !result.resultPresent || ((result.state == 3 || result.state == 4) && !result.resultDeleted && result.resultDigest != nil),
      result.resultDigest == nil || result.resultDigest?.count == 32,
      result.tokenDigest == nil || (result.tokenDigest?.count == 32 && result.checkpoint != nil),
      result.consumedTokenDigest == nil || result.consumedTokenDigest?.count == 32,
      (result.reissuedPreviousDigest == nil) == (result.reissuedToken == nil),
      result.reissuedPreviousDigest == nil || (result.reissuedPreviousDigest?.count == 32 && result.reissueLifetimeMS > 0 && result.reissueExpiresAtMS > 0),
      result.checkpoint == nil || (result.checkpoint!.count > 0 && result.checkpoint!.count <= 8192),
      storedBodyBytes == (result.resultPresent ? result.resultBytes : 0),
      !includeResult || !result.resultPresent || (result.result != nil && result.result?.count == Int(result.resultBytes)),
      result.result == nil || (!result.resultDeleted && result.resultDigest != nil && result.reservedBytes == result.resultBytes),
      sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }; return result
  }
  private func write(_ record: V4ServerExecutionRecord, database: OpaquePointer) throws {
    let statement = try Self.prepare(database, "INSERT INTO executions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET state=excluded.state,reason=excluded.reason,cancelled=excluded.cancelled,dispatched=excluded.dispatched,active=excluded.active,result_until=excluded.result_until,result=excluded.result,result_digest=excluded.result_digest,result_bytes=excluded.result_bytes,result_code=excluded.result_code,result_deleted=excluded.result_deleted,reserved_bytes=excluded.reserved_bytes,generation=excluded.generation,checkpoint=excluded.checkpoint,token_digest=excluded.token_digest,checkpoint_issues=excluded.checkpoint_issues,last_checkpoint_issue=excluded.last_checkpoint_issue,stream_items=excluded.stream_items,stream_bytes=excluded.stream_bytes,consumed_token_digest=excluded.consumed_token_digest,recovery_entered=excluded.recovery_entered,reissued_previous_digest=excluded.reissued_previous_digest,reissued_token=excluded.reissued_token,reissue_lifetime=excluded.reissue_lifetime,reissue_expires=excluded.reissue_expires,run_started=excluded.run_started")
    defer { sqlite3_finalize(statement) }
    let blobs: [Int32: Data?] = [1: record.key, 2: record.request, 3: record.contract, 9: Self.integer(record.deadline),
      10: Self.integer(record.historyUntil), 11: Self.integer(record.resultUntil), 12: record.result, 13: record.resultDigest,
      18: Self.integer(record.generation), 19: record.checkpoint, 20: record.tokenDigest, 22: Self.integer(record.lastCheckpointIssueMS), 23: record.originalStreamHeader, 25: Self.integer(record.streamBytes),
      26: record.consumedTokenDigest, 28: record.reissuedPreviousDigest, 29: record.reissuedToken,
      30: Self.integer(record.reissueLifetimeMS), 31: Self.integer(record.reissueExpiresAtMS), 32: record.runStartedMS.map(Self.integer)]
    for (index, data) in blobs { try Self.bind(statement, index, data) }
    let numbers: [Int32: UInt64] = [4: record.state, 5: record.reason, 6: record.cancelled ? 1 : 0, 7: record.dispatched ? 1 : 0,
      8: record.active ? 1 : 0, 14: record.resultBytes, 15: record.resultCode, 16: record.resultDeleted ? 1 : 0, 17: record.reservedBytes, 21: record.checkpointIssues, 24: record.streamItems, 27: record.recoveryEntered ? 1 : 0]
    for (index, value) in numbers {
      guard value <= UInt64(Int64.max), sqlite3_bind_int64(statement, index, Int64(value)) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
    }
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.resourceExhausted }
  }
    private func transaction<T>(
      beforeCommit: (() throws -> Void)? = nil, _ body: (OpaquePointer) throws -> T
    ) throws -> T {
      let database = try check()
      try beforeCommit?(); try Self.exec(database, "BEGIN IMMEDIATE")
      do {
        let result = try body(database); _ = try check()
        try beforeCommit?(); try Self.exec(database, "COMMIT"); try checkContinuity?();
        return result
      } catch { sqlite3_exec(database, "ROLLBACK", nil, nil, nil); throw error }
    }
    func lookup(
      _ selector: V4ServerExecutionSelector, includeResult: Bool = true,
      maximumBodyBytes: Int? = nil,
      before: (@Sendable () throws -> Void)? = nil
    ) throws -> V4ServerExecutionRecord? {
      let database = try check()
      try before?();
      guard var record = try read(selector.key, database: database, includeResult: false) else {
        try before?()
        return nil
      }; try selector.check(record)
      guard let now = environment.clock.sample().interval else {
        throw ServiceFailure.serviceUnavailable
      }
      if record.resultPresent, now.lowerMS >= record.resultUntil {
        try transaction(beforeCommit: before) { database in
          let statement = try Self.prepare(
            database,
            "UPDATE executions SET result=NULL,result_deleted=1,reserved_bytes=0 WHERE key=? AND result IS NOT NULL"
          )
          defer { sqlite3_finalize(statement) }; try Self.bind(statement, 1, selector.key)
          guard sqlite3_step(statement) == SQLITE_DONE else {
            throw ServiceFailure.serviceUnavailable
          }
        }
        record.result = nil; record.resultPresent = false; record.resultDeleted = true;
        record.reservedBytes = 0
      }
      // Check expiry and the caller's prepaid body bound before copying any
      // original BLOB. Expired bodies can be removed through fixed metadata.
      if includeResult, record.resultPresent {
        guard
          let complete = try read(
            selector.key, database: database, maximumBodyBytes: maximumBodyBytes)
        else { throw ServiceFailure.historyUnknown }
        record = complete
      }
      // Rows deliberately remain bounded tombstones rather than becoming new
      // execution rights after GC. Full capacity rejects a new original key.
      try before?()
      return record
    }
    func admit(_ selector: V4ServerExecutionSelector, deadline: UInt64, historyMS: UInt64, responseBytes: Int,
    contentPolicy: V4ServiceStreamContentPolicy? = nil, originalStreamHeader: Data? = nil) throws -> Bool {
    try transaction { database in
      guard let now = environment.clock.sample().interval, now.upperMS < deadline else { throw ServiceFailure.admissionWindowClosed }
      if let record = try read(selector.key, database: database, includeResult: false) { try selector.check(record); return false }
      let statement = try Self.prepare(database, "SELECT count(*),coalesce(sum(active),0),coalesce(sum(reserved_bytes),0) FROM executions"); defer { sqlite3_finalize(statement) }
      guard sqlite3_step(statement) == SQLITE_ROW,
        try Self.number(statement, 0, maximum: UInt64(maximumHistoryRows)) < UInt64(maximumHistoryRows),
        try Self.number(statement, 1, maximum: UInt64(maximumActive)) < UInt64(maximumActive),
        (0...1_048_576).contains(responseBytes), responseBytes <= maximumResultBytes - Int(try Self.number(statement, 2, maximum: UInt64(maximumResultBytes))) else { throw ServiceFailure.resourceExhausted }
      let (historyUntil, overflow) = deadline.addingReportingOverflow(historyMS); guard !overflow else { throw ServiceFailure.contractPolicyRejected }
      let record = V4ServerExecutionRecord(key: selector.key, request: selector.request, contract: selector.contract, state: 1,
        reason: 0, cancelled: false, dispatched: false, active: true, deadline: deadline, historyUntil: historyUntil, resultUntil: 0,
        result: nil, resultDigest: nil, resultBytes: 0, resultCode: 0, resultDeleted: false, reservedBytes: UInt64(responseBytes),
        generation: 0, checkpoint: nil, tokenDigest: nil, originalStreamHeader: originalStreamHeader)
      try write(record, database: database)
      if let contentPolicy { try admitContent(selector, policy: contentPolicy, database: database) }
      return true
    }
  }
  func started(_ selector: V4ServerExecutionSelector) throws {
    try transaction { database in
      guard var record = try read(selector.key, database: database, includeResult: false) else { throw ServiceFailure.historyUnknown }; try selector.check(record)
      guard record.active, !record.dispatched, !record.cancelled,
        let now = environment.clock.sample().interval, now.upperMS < record.deadline else { throw ServiceFailure.closed }
      record.state = 2; record.dispatched = true; record.runStartedMS = record.runStartedMS ?? now.lowerMS
      try write(record, database: database)
    }
  }
  func runDeadline(_ selector: V4ServerExecutionSelector, maximumRunMS: UInt64) throws -> UInt64 {
    let database = try check()
    guard let record = try read(selector.key, database: database, includeResult: false),
      let now = environment.clock.sample().interval else { throw ServiceFailure.historyUnknown }
    try selector.check(record); let deadline = try record.originalRunDeadline(maximumRunMS: maximumRunMS)
    guard now.upperMS < deadline else { throw ServiceFailure.deadlineExceeded }; return deadline
  }
  func enteredRecovery(_ selector: V4ServerExecutionSelector) throws {
    try transaction { database in
      guard var record = try read(selector.key, database: database, includeResult: false), record.active, record.dispatched,
        !record.cancelled, record.consumedTokenDigest != nil, !record.recoveryEntered,
        let now = environment.clock.sample().interval, now.upperMS < record.deadline else { throw ServiceFailure.closed }
      try selector.check(record); record.recoveryEntered = true; try write(record, database: database)
    }
  }
  func reserveStreamItem(_ selector: V4ServerExecutionSelector, bytes: Int, maximumItems: UInt64, maximumBytes: UInt64) throws {
    try transaction { database in
      guard var record = try read(selector.key, database: database, includeResult: false), record.active, record.dispatched,
        !record.cancelled, record.originalStreamHeader != nil,
        let now = environment.clock.sample().interval, now.upperMS < record.deadline else { throw ServiceFailure.closed }
      try selector.check(record)
      guard bytes >= 0, record.streamItems < maximumItems, record.streamBytes <= maximumBytes,
        UInt64(bytes) <= maximumBytes - record.streamBytes else { throw ServiceFailure.resourceExhausted }
      // Precharge before provider publication: a crash cannot refund already
      // possible output or increase the original signed stream promise.
      record.streamItems += 1; record.streamBytes += UInt64(bytes); try write(record, database: database)
    }
  }
  func complete(_ selector: V4ServerExecutionSelector, payload: Data?, applicationCode: UInt32 = 0,
    resultRetentionMS: UInt64, reason: UInt64 = 0, metadataOnly: Bool = false) throws {
    try transaction { database in
      guard var record = try read(selector.key, database: database, includeResult: false) else { throw ServiceFailure.historyUnknown }; try selector.check(record)
      guard record.active else { return }
      guard let interval = environment.clock.sample().interval else { throw ServiceFailure.serviceUnavailable }
      record.active = false
      if metadataOnly, payload != nil {
        record.state = applicationCode == 0 ? 3 : 4; record.reason = 0; record.reservedBytes = 0
        record.resultCode = UInt64(applicationCode)
      } else if let payload {
        guard payload.count <= record.reservedBytes else { throw ServiceFailure.resourceExhausted }
        record.state = applicationCode == 0 ? 3 : 4; record.reason = 0
        record.resultBytes = UInt64(payload.count); record.resultDigest = Data(SHA256.hash(data: payload)); record.resultCode = UInt64(applicationCode)
        if resultRetentionMS > 0 {
          let (until, overflow) = interval.upperMS.addingReportingOverflow(resultRetentionMS); guard !overflow else { throw ServiceFailure.contractPolicyRejected }
          record.result = payload; record.resultUntil = until; record.reservedBytes = UInt64(payload.count)
        } else {
          // An absent retention promise records the original result facts,
          // without ever storing a body or claiming an expired retained body.
          record.result = nil; record.resultUntil = 0; record.reservedBytes = 0
        }
      } else {
        record.state = record.dispatched ? 5 : 4; record.reason = reason == 0 ? (record.dispatched ? 3 : 2) : reason
        if record.tokenDigest == nil && (record.consumedTokenDigest == nil || record.recoveryEntered) { record.reservedBytes = 0 }
      }
      try write(record, database: database)
      try settleContentCapacity(selector.key, database: database)
    }
  }
  func cancel(_ selector: V4ServerExecutionSelector, before: (@Sendable () throws -> Void)? = nil) throws -> V4ServerExecutionRecord? {
    try transaction(beforeCommit: before) { database in
      guard var record = try read(selector.key, database: database, includeResult: false) else { return nil }; try selector.check(record)
      if record.active { record.cancelled = true; try write(record, database: database) }; return record
    }
  }
  func issue(_ selector: V4ServerExecutionSelector, checkpoint: ApplicationCheckpoint, lifetimeMS: UInt64,
    maximumIssuedDurationMS: UInt64 = 60_000, maximumTokenBytes: Int = 8192,
    maximumOriginalRunMS: UInt64? = nil) throws -> IssuedServiceCheckpoint {
    try transaction { database in
      guard var record = try read(selector.key, database: database, includeResult: false), record.active, record.dispatched, !record.cancelled,
        record.generation < .max, let now = environment.clock.sample().interval, now.upperMS < record.deadline,
        lifetimeMS > 0, lifetimeMS <= maximumIssuedDurationMS, maximumTokenBytes > 0 else { throw ServiceFailure.admissionWindowClosed }
      try selector.check(record)
      guard record.checkpointIssues < UInt64(maximumCheckpointIssuesPerOperation),
        record.checkpointIssues == 0 || (now.lowerMS >= record.lastCheckpointIssueMS && now.lowerMS - record.lastCheckpointIssueMS >= minimumCheckpointIntervalMS) else { throw ServiceFailure.resourceExhausted }
      let runCap = try record.originalRunDeadline(maximumRunMS: maximumOriginalRunMS)
      guard now.upperMS < runCap else { throw ServiceFailure.deadlineExceeded }
      record.generation += 1; record.checkpointIssues += 1; record.lastCheckpointIssueMS = now.lowerMS
      let (requestedExpiry, overflow) = now.lowerMS.addingReportingOverflow(lifetimeMS)
      let expires = min(requestedExpiry, min(runCap, record.historyUntil))
      guard !overflow, now.upperMS < expires else { throw ServiceFailure.admissionWindowClosed }
      let (encoded, protection) = try encodeCheckpoint(selector, checkpoint: checkpoint, generation: record.generation,
        issuedAtMS: now.lowerMS, expiresAtMS: expires, maximumTokenBytes: maximumTokenBytes)
      record.checkpoint = checkpoint.encoded(); record.tokenDigest = Data(SHA256.hash(data: encoded)); try write(record, database: database)
      return IssuedServiceCheckpoint(encodedToken: encoded, protection: protection, generation: record.generation, checkpoint: checkpoint, expiresAtMS: expires)
    }
  }
  private func encodeCheckpoint(_ selector: V4ServerExecutionSelector, checkpoint: ApplicationCheckpoint, generation: UInt64,
    issuedAtMS: UInt64, expiresAtMS: UInt64, maximumTokenBytes: Int) throws -> (Data, CheckpointTokenProtection) {
    let claims = V4Crypto.map([(0, V4Crypto.text(selector.tenant)), (1, V4Crypto.text(selector.caller)),
      (2, V4Crypto.text(selector.audience)), (3, V4Crypto.text(selector.namespace)), (4, V4Crypto.bytes(selector.operation)),
      (5, V4Crypto.bytes(selector.request)), (6, checkpoint.encoded()), (7, V4NamespaceValue.head(0, generation)),
      (8, V4NamespaceValue.head(0, issuedAtMS)), (9, V4NamespaceValue.head(0, expiresAtMS)), (10, V4Crypto.bytes(try V4Crypto.random(32)))])
    guard let key = checkpointKey else { throw ServiceFailure.closed }; let unsigned = V4Crypto.map([(0, claims), (1, V4Crypto.bytes(key.keyID))])
    let schema = key.protection == .ed25519 ? "ResumeSignedToken" : "ResumeMACToken"
    let (label, projection) = try namespace.domain(key.protection == .ed25519 ? "resume_token_signature" : "resume_token_mac",
      schema: schema, operation: key.protection == .ed25519 ? "ed25519" : "hmac-sha256")
    guard projection == (key.protection == .ed25519 ? "without_signature" : "without_mac") else { throw ServiceFailure.configurationCapacity }
    let preimage = label + V4Crypto.integer(UInt64(unsigned.count), width: 4) + unsigned
    let proof = try key.protection == .ed25519 ? Curve25519.Signing.PrivateKey(rawRepresentation: key.secret).signature(for: preimage)
      : Data(HMAC<SHA256>.authenticationCode(for: preimage, using: SymmetricKey(data: key.secret)))
    let encoded = V4Crypto.map([(0, claims), (1, V4Crypto.bytes(key.keyID)), (2, V4Crypto.bytes(proof))])
    guard encoded.count <= maximumTokenBytes else { throw ServiceFailure.contractPolicyRejected }
    return (encoded, key.protection)
  }

  /// The caller is an independent, currently authorized durable invocation.
  /// One receipt per original execution is retained and fenced by the exact
  /// last consumed token; retries neither sign again nor extend that receipt.
  func reissue(_ selector: V4ServerExecutionSelector, issuer: V4ServerExecutionSelector,
    previousToken: ApplicationCheckpointToken, lifetimeMS: UInt64,
    maximumIssuedDurationMS: UInt64, maximumTokenBytes: Int,
    maximumOriginalRunMS: UInt64? = nil, maximumIssuerRunMS: UInt64? = nil) throws -> IssuedServiceCheckpoint {
    try previousToken.check(in: environment)
    guard let key = checkpointKey else { throw ServiceFailure.closed }
    let verification = try CheckpointVerificationKey(protection: key.protection, keyID: key.keyID,
      key: key.protection == .ed25519 ? Curve25519.Signing.PrivateKey(rawRepresentation: key.secret).publicKey.rawRepresentation : key.secret)
    // Authenticate the previous bytes again under this store's fixed key. The
    // old token may have expired since its already proven consumption.
    let previous = try ApplicationCheckpointToken(environment: environment, encoded: previousToken.encoded,
      protection: previousToken.protection, verificationKey: verification)
    guard previous.tenant == selector.tenant, previous.audience == selector.audience,
      previous.caller == selector.caller, previous.namespace == selector.namespace,
      previous.operation == selector.operation, previous.request == selector.request,
      previous.generation < .max, issuer.key != selector.key else { throw ServiceFailure.permissionDenied }
    let digest = Data(SHA256.hash(data: previous.encoded))
    return try transaction { database in
      guard let current = environment.clock.sample().interval,
        let issuing = try read(issuer.key, database: database, includeResult: false), issuing.active, issuing.dispatched,
        !issuing.cancelled, current.upperMS < issuing.deadline,
        var record = try read(selector.key, database: database, includeResult: false), !record.active, record.state == 5,
        !record.cancelled, record.dispatched, !record.recoveryEntered, current.upperMS < record.deadline,
        record.consumedTokenDigest == digest, record.generation == previous.generation + 1,
        record.checkpoint == previous.checkpoint.encoded() else { throw ServiceFailure.operationConflict }
      try issuer.check(issuing); try selector.check(record)
      let originalCap = try record.originalRunDeadline(maximumRunMS: maximumOriginalRunMS)
      guard current.upperMS < originalCap,
        current.upperMS < (try issuing.originalRunDeadline(maximumRunMS: maximumIssuerRunMS)) else { throw ServiceFailure.deadlineExceeded }
      if record.reissuedPreviousDigest == digest, let encoded = record.reissuedToken {
        guard lifetimeMS == record.reissueLifetimeMS, encoded.count <= maximumTokenBytes else { throw ServiceFailure.operationConflict }
        guard current.upperMS < record.reissueExpiresAtMS else { throw ServiceFailure.resultExpired }
        guard record.tokenDigest == Data(SHA256.hash(data: encoded)) else { throw ServiceFailure.operationConflict }
        return IssuedServiceCheckpoint(encodedToken: encoded, protection: key.protection, generation: record.generation,
          checkpoint: previous.checkpoint, expiresAtMS: record.reissueExpiresAtMS)
      }
      guard record.tokenDigest == nil, lifetimeMS > 0, lifetimeMS <= maximumIssuedDurationMS,
        maximumTokenBytes > 0 else { throw ServiceFailure.admissionWindowClosed }
      guard record.checkpointIssues < UInt64(maximumCheckpointIssuesPerOperation),
        current.lowerMS >= record.lastCheckpointIssueMS,
        current.lowerMS - record.lastCheckpointIssueMS >= minimumCheckpointIntervalMS else { throw ServiceFailure.resourceExhausted }
      let (requestedExpiry, overflow) = current.lowerMS.addingReportingOverflow(lifetimeMS)
      let expires = min(requestedExpiry, min(originalCap, record.historyUntil))
      guard !overflow, current.upperMS < expires else { throw ServiceFailure.admissionWindowClosed }
      let (encoded, protection) = try encodeCheckpoint(selector, checkpoint: previous.checkpoint, generation: record.generation,
        issuedAtMS: current.lowerMS, expiresAtMS: expires, maximumTokenBytes: maximumTokenBytes)
      record.checkpointIssues += 1; record.lastCheckpointIssueMS = current.lowerMS
      record.tokenDigest = Data(SHA256.hash(data: encoded)); record.reissuedPreviousDigest = digest; record.reissuedToken = encoded
      record.reissueLifetimeMS = lifetimeMS; record.reissueExpiresAtMS = expires
      try write(record, database: database)
      return IssuedServiceCheckpoint(encodedToken: encoded, protection: protection, generation: record.generation,
        checkpoint: previous.checkpoint, expiresAtMS: expires)
    }
  }

  func consume(_ selector: V4ServerExecutionSelector, encodedToken: Data, protection: CheckpointTokenProtection,
    generation: UInt64, checkpoint: ApplicationCheckpoint, maximumTokenBytes: Int,
    confirmation: V4ServerExecutionSelector? = nil, resultRetentionMS: UInt64 = 0,
    maximumOriginalRunMS: UInt64? = nil) throws -> UInt64 {
    guard encodedToken.count <= maximumTokenBytes, maximumTokenBytes > 0 else { throw ServiceFailure.contractPolicyRejected }
    _ = try check()
    guard let key = checkpointKey else { throw ServiceFailure.closed }
    let verification = try CheckpointVerificationKey(protection: key.protection, keyID: key.keyID,
      key: key.protection == .ed25519 ? Curve25519.Signing.PrivateKey(rawRepresentation: key.secret).publicKey.rawRepresentation : key.secret)
    let token = try ApplicationCheckpointToken(environment: environment, encoded: encodedToken, protection: protection, verificationKey: verification)
    guard token.tenant == selector.tenant, token.audience == selector.audience, token.caller == selector.caller,
      token.namespace == selector.namespace, token.operation == selector.operation, token.request == selector.request,
      token.generation == generation, token.checkpoint == checkpoint, let now = environment.clock.sample().interval,
      now.lowerMS >= token.issuedAtMS, now.upperMS < token.expiresAtMS else { throw ServiceFailure.permissionDenied }
    return try transaction { database in
      guard var record = try read(selector.key, database: database, includeResult: false) else { throw ServiceFailure.historyUnknown }; try selector.check(record)
      guard let current = environment.clock.sample().interval, current.lowerMS >= token.issuedAtMS, current.upperMS < token.expiresAtMS,
        !record.active, record.state == 5, !record.cancelled, token.expiresAtMS <= record.historyUntil, record.generation == generation,
        generation < .max, record.checkpoint == checkpoint.encoded(), record.tokenDigest == Data(SHA256.hash(data: encodedToken)),
        current.upperMS < record.deadline else { throw ServiceFailure.operationConflict }
      guard current.upperMS < (try record.originalRunDeadline(maximumRunMS: maximumOriginalRunMS)) else { throw ServiceFailure.deadlineExceeded }
      let statement = try Self.prepare(database, "SELECT coalesce(sum(active),0) FROM executions"); defer { sqlite3_finalize(statement) }
      guard sqlite3_step(statement) == SQLITE_ROW else { throw ServiceFailure.serviceUnavailable }
      let active = try Self.number(statement, 0, maximum: UInt64(maximumActive))
      // Accepted confirmation releases its own active execution in this same
      // transaction, so only the original continuation remains active.
      guard active < UInt64(maximumActive) || confirmation != nil && active == UInt64(maximumActive) else { throw ServiceFailure.resourceExhausted }
      try reviveContentCapacity(selector.key, database: database)
      record.generation += 1; record.consumedTokenDigest = record.tokenDigest; record.tokenDigest = nil
      record.recoveryEntered = false; record.active = true; record.dispatched = true; record.state = 2; record.reason = 0
      try write(record, database: database)
      if let confirmation {
        guard confirmation.key != selector.key,
          var accepted = try read(confirmation.key, database: database, includeResult: false), accepted.active,
          accepted.dispatched, !accepted.cancelled, current.upperMS < accepted.deadline else { throw ServiceFailure.operationConflict }
        try confirmation.check(accepted)
        let payload = V4Crypto.map([(0, V4NamespaceValue.head(0, 0)), (1, V4Crypto.map([(0, checkpoint.encoded()), (1, V4NamespaceValue.head(0, record.generation))]))])
        guard payload.count <= accepted.reservedBytes else { throw ServiceFailure.resourceExhausted }
        accepted.active = false; accepted.state = 3; accepted.reason = 0
        accepted.resultBytes = UInt64(payload.count); accepted.resultDigest = Data(SHA256.hash(data: payload)); accepted.resultCode = 0
        if resultRetentionMS > 0 {
          let (until, overflow) = current.upperMS.addingReportingOverflow(resultRetentionMS)
          guard !overflow else { throw ServiceFailure.contractPolicyRejected }
          accepted.result = payload; accepted.resultUntil = until; accepted.reservedBytes = UInt64(payload.count)
        } else { accepted.result = nil; accepted.resultUntil = 0; accepted.reservedBytes = 0 }
        try write(accepted, database: database); try settleContentCapacity(confirmation.key, database: database)
      }
      return record.generation
    }
  }
  private static let contentPolicySchema = "CREATE TABLE content_policies (key BLOB PRIMARY KEY CHECK(length(key) BETWEEN 1 AND 4096), revision TEXT NOT NULL CHECK(length(revision) BETWEEN 1 AND 128), definition BLOB NOT NULL CHECK(length(definition) BETWEEN 1 AND 2048), read_type INTEGER NOT NULL CHECK(read_type BETWEEN 1 AND 4294967295), origin INTEGER NOT NULL CHECK(origin IN (0,1)), retention BLOB NOT NULL CHECK(length(retention)=8), max_items INTEGER NOT NULL CHECK(max_items BETWEEN 1 AND 131072), max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 1073741824), admitted BLOB NOT NULL CHECK(length(admitted)=8), durable INTEGER NOT NULL CHECK(durable IN (0,1)), owner TEXT NOT NULL CHECK(length(owner)=36), reserved_items INTEGER NOT NULL CHECK(reserved_items BETWEEN 0 AND max_items), reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes BETWEEN 0 AND max_bytes), FOREIGN KEY(key) REFERENCES executions(key)) STRICT"
  private static let contentSchema = "CREATE TABLE stream_content (key BLOB NOT NULL CHECK(length(key) BETWEEN 1 AND 4096), position BLOB NOT NULL CHECK(length(position) BETWEEN 1 AND 256), committed BLOB NOT NULL CHECK(length(committed)=8), expires BLOB NOT NULL CHECK(length(expires)=8), bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND 1048576), digest BLOB NOT NULL CHECK(length(digest)=32), payload BLOB CHECK(payload IS NULL OR length(payload)=bytes), PRIMARY KEY(key,position), FOREIGN KEY(key) REFERENCES content_policies(key)) STRICT"

  private static func checkContentQuotas(_ database: OpaquePointer, maximumItems: Int, maximumBytes: Int) throws {
    let statement = try prepare(database, "SELECT coalesce(sum(reserved_items),0),coalesce(sum(reserved_bytes),0),(SELECT count(*) FROM stream_content),(SELECT coalesce(sum(length(payload)),0) FROM stream_content) FROM content_policies")
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { throw ServiceFailure.serviceUnavailable }
    let items = try number(statement, 0, maximum: UInt64(maximumItems)), bytes = try number(statement, 1, maximum: UInt64(maximumBytes))
    guard try number(statement, 2, maximum: items) <= items, try number(statement, 3, maximum: bytes) <= bytes,
      sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
  }

  nonisolated func supportsContent(_ policy: V4ServiceStreamContentPolicy) -> Bool {
    policy.maximumItems <= maximumContentItems && policy.maximumBytes <= maximumContentBytes
  }

  private func admitContent(_ selector: V4ServerExecutionSelector, policy: V4ServiceStreamContentPolicy, database: OpaquePointer) throws {
    guard supportsContent(policy), let now = environment.clock.sample().interval else { throw ServiceFailure.configurationCapacity }
    try expireContent(database: database, lowerMS: now.lowerMS)
    let quota = try Self.prepare(database, "SELECT coalesce(sum(reserved_items),0),coalesce(sum(reserved_bytes),0) FROM content_policies")
    defer { sqlite3_finalize(quota) }
    guard sqlite3_step(quota) == SQLITE_ROW,
      policy.maximumItems <= maximumContentItems - Int(try Self.number(quota, 0, maximum: UInt64(maximumContentItems))),
      policy.maximumBytes <= maximumContentBytes - Int(try Self.number(quota, 1, maximum: UInt64(maximumContentBytes))) else { throw ServiceFailure.resourceExhausted }
    if policy.origin == 0 {
      let (_, overflow) = now.lowerMS.addingReportingOverflow(policy.retentionMS)
      guard !overflow else { throw ServiceFailure.contractPolicyRejected }
    }
    let statement = try Self.prepare(database, "INSERT INTO content_policies VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
    defer { sqlite3_finalize(statement) }
    try Self.bind(statement, 1, selector.key); try Self.bindText(statement, 2, policy.definition.schemaRevision)
    try Self.bind(statement, 3, policy.definition.canonical); try Self.bind(statement, 6, Self.integer(policy.retentionMS))
    try Self.bind(statement, 9, Self.integer(now.lowerMS)); try Self.bindText(statement, 11, contentIncarnation.uuidString)
    for (index, value) in [(Int32(4), UInt64(policy.definition.readTypeID)), (5, policy.origin), (7, UInt64(policy.maximumItems)),
      (8, UInt64(policy.maximumBytes)), (10, policy.durable ? 1 : 0), (12, UInt64(policy.maximumItems)), (13, UInt64(policy.maximumBytes))] {
      guard sqlite3_bind_int64(statement, index, Int64(value)) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
    }
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.resourceExhausted }
  }

  private func contentPolicy(_ key: Data, expected: V4ServiceStreamContentPolicy, database: OpaquePointer) throws -> UInt64 {
    let statement = try Self.prepare(database, "SELECT revision,definition,read_type,origin,retention,max_items,max_bytes,admitted,durable,owner,reserved_items,reserved_bytes FROM content_policies WHERE key=?")
    defer { sqlite3_finalize(statement) }; try Self.bind(statement, 1, key)
    guard sqlite3_step(statement) == SQLITE_ROW else { throw ServiceFailure.historyUnknown }
    guard Self.text(statement, 0) == expected.definition.schemaRevision,
      try Self.nullableBlob(statement, 1, maximum: 2048) == expected.definition.canonical,
      try Self.number(statement, 2, maximum: UInt64(UInt32.max)) == UInt64(expected.definition.readTypeID),
      try Self.number(statement, 3, maximum: 1) == expected.origin, try Self.uint(statement, 4) == expected.retentionMS,
      try Self.number(statement, 5, maximum: UInt64(maximumContentItems)) == UInt64(expected.maximumItems),
      try Self.number(statement, 6, maximum: UInt64(maximumContentBytes)) == UInt64(expected.maximumBytes),
      try Self.number(statement, 8, maximum: 1) == (expected.durable ? 1 : 0) else { throw ServiceFailure.contractMismatch }
    guard expected.durable || Self.text(statement, 9) == contentIncarnation.uuidString else { throw ServiceFailure.historyUnknown }
    let admitted = try Self.uint(statement, 7)
    _ = try Self.number(statement, 10, maximum: UInt64(expected.maximumItems)); _ = try Self.number(statement, 11, maximum: UInt64(expected.maximumBytes))
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }; return admitted
  }

  private func settleContentCapacity(_ key: Data, database: OpaquePointer) throws {
    let statement = try Self.prepare(database, "UPDATE content_policies SET reserved_items=(SELECT count(*) FROM stream_content WHERE key=?),reserved_bytes=(SELECT coalesce(sum(length(payload)),0) FROM stream_content WHERE key=?) WHERE key=? AND EXISTS(SELECT 1 FROM executions WHERE key=? AND active=0)")
    defer { sqlite3_finalize(statement) }
    for index in Int32(1)...4 { try Self.bind(statement, index, key) }
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
  }

  private func reviveContentCapacity(_ key: Data, database: OpaquePointer) throws {
    let statement = try Self.prepare(database, "SELECT max_items,max_bytes,reserved_items,reserved_bytes,durable,owner FROM content_policies WHERE key=?")
    defer { sqlite3_finalize(statement) }; try Self.bind(statement, 1, key)
    let status = sqlite3_step(statement); if status == SQLITE_DONE { return }
    guard status == SQLITE_ROW, try Self.number(statement, 4, maximum: 1) == 1 || Self.text(statement, 5) == contentIncarnation.uuidString else { throw ServiceFailure.historyUnknown }
    let items = try Self.number(statement, 0, maximum: UInt64(maximumContentItems)), bytes = try Self.number(statement, 1, maximum: UInt64(maximumContentBytes))
    let originalItems = try Self.number(statement, 2, maximum: items), originalBytes = try Self.number(statement, 3, maximum: bytes)
    let totals = try Self.prepare(database, "SELECT coalesce(sum(reserved_items),0),coalesce(sum(reserved_bytes),0) FROM content_policies")
    defer { sqlite3_finalize(totals) }
    guard sqlite3_step(totals) == SQLITE_ROW,
      items - originalItems <= UInt64(maximumContentItems) - (try Self.number(totals, 0, maximum: UInt64(maximumContentItems))),
      bytes - originalBytes <= UInt64(maximumContentBytes) - (try Self.number(totals, 1, maximum: UInt64(maximumContentBytes))) else { throw ServiceFailure.resourceExhausted }
    let update = try Self.prepare(database, "UPDATE content_policies SET reserved_items=max_items,reserved_bytes=max_bytes WHERE key=?")
    defer { sqlite3_finalize(update) }; try Self.bind(update, 1, key)
    guard sqlite3_step(update) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
  }
  private func expireContent(database: OpaquePointer, lowerMS: UInt64) throws {
    // Encoded unsigned timestamps have fixed width and compare in numeric order.
    let statement = try Self.prepare(database, "UPDATE stream_content SET payload=NULL WHERE payload IS NOT NULL AND expires<=?")
    defer { sqlite3_finalize(statement) }; try Self.bind(statement, 1, Self.integer(lowerMS))
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
    try Self.exec(database, "UPDATE content_policies SET reserved_bytes=(SELECT coalesce(sum(length(payload)),0) FROM stream_content WHERE key=content_policies.key) WHERE EXISTS(SELECT 1 FROM executions WHERE key=content_policies.key AND active=0)")
  }

  private func contentFacts(_ key: Data, position: Data, database: OpaquePointer, upperMS: UInt64) throws -> StreamContentObservation {
    let statement = try Self.prepare(database, "SELECT committed,expires,bytes,digest,payload IS NOT NULL,coalesce(length(payload),0) FROM stream_content WHERE key=? AND position=?")
    defer { sqlite3_finalize(statement) }; try Self.bind(statement, 1, key); try Self.bind(statement, 2, position)
    let status = sqlite3_step(statement); if status == SQLITE_DONE { return .missing }
    guard status == SQLITE_ROW, let digest = try Self.nullableBlob(statement, 3, maximum: 32), digest.count == 32 else { throw ServiceFailure.serviceUnavailable }
    let committed = try Self.uint(statement, 0), expires = try Self.uint(statement, 1)
    let bytes = Int(try Self.number(statement, 2, maximum: 1_048_576)), present = try Self.number(statement, 4, maximum: 1) == 1
    guard committed < expires, try Self.number(statement, 5, maximum: 1_048_576) == (present ? UInt64(bytes) : 0),
      sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
    return StreamContentObservation(found: true, available: present && upperMS < expires, expired: !present || upperMS >= expires,
      committedAtMS: committed, expiresAtMS: expires, bytes: bytes, digest: digest)
  }

  func saveContent(_ selector: V4ServerExecutionSelector, policy: V4ServiceStreamContentPolicy, position: Data, payload: Data) throws -> StreamContentObservation {
    guard (1...256).contains(position.count), payload.count <= 1_048_576 else { throw ServiceFailure.configurationCapacity }
    return try transaction { database in
      guard let record = try read(selector.key, database: database, includeResult: false), record.active, record.dispatched,
        !record.cancelled, let now = environment.clock.sample().interval, now.upperMS < record.deadline else { throw ServiceFailure.closed }
      try selector.check(record); let admitted = try contentPolicy(selector.key, expected: policy, database: database)
      try expireContent(database: database, lowerMS: now.lowerMS)
      let digest = Data(SHA256.hash(data: payload)), original = try contentFacts(selector.key, position: position, database: database, upperMS: now.upperMS)
      if original.found {
        guard original.bytes == payload.count, original.digest == digest else { throw ServiceFailure.operationConflict }
        return original
      }
      let totals = try Self.prepare(database, "SELECT count(*),coalesce(sum(length(payload)),0) FROM stream_content WHERE key=?")
      defer { sqlite3_finalize(totals) }; try Self.bind(totals, 1, selector.key)
      guard sqlite3_step(totals) == SQLITE_ROW,
        try Self.number(totals, 0, maximum: UInt64(policy.maximumItems)) < UInt64(policy.maximumItems),
        payload.count <= policy.maximumBytes - Int(try Self.number(totals, 1, maximum: UInt64(policy.maximumBytes))) else { throw ServiceFailure.resourceExhausted }
      let origin = policy.origin == 0 ? admitted : now.lowerMS
      let (expires, overflow) = origin.addingReportingOverflow(policy.retentionMS)
      guard !overflow, now.upperMS < expires else { throw ServiceFailure.resultExpired }
      let statement = try Self.prepare(database, "INSERT INTO stream_content VALUES(?,?,?,?,?,?,?)")
      defer { sqlite3_finalize(statement) }
      try Self.bind(statement, 1, selector.key); try Self.bind(statement, 2, position); try Self.bind(statement, 3, Self.integer(now.lowerMS))
      try Self.bind(statement, 4, Self.integer(expires)); try Self.bind(statement, 6, digest); try Self.bind(statement, 7, payload)
      guard sqlite3_bind_int64(statement, 5, Int64(payload.count)) == SQLITE_OK, sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.resourceExhausted }
      return StreamContentObservation(found: true, available: true, expired: false, committedAtMS: now.lowerMS, expiresAtMS: expires, bytes: payload.count, digest: digest)
    }
  }

  func readContent(_ selector: V4ServerExecutionSelector, policy: V4ServiceStreamContentPolicy, position: Data, maximumBytes: Int) throws -> RetainedStreamContent {
    guard (1...256).contains(position.count), (0...1_048_576).contains(maximumBytes) else { throw ServiceFailure.configurationCapacity }
    return try transaction { database in
      guard let record = try read(selector.key, database: database, includeResult: false),
        let now = environment.clock.sample().interval else { throw ServiceFailure.historyUnknown }
      // Content has its own signed retention promise. The bounded original
      // execution tombstone still authenticates its selector after history TTL.
      try selector.check(record); _ = try contentPolicy(selector.key, expected: policy, database: database)
      try expireContent(database: database, lowerMS: now.lowerMS)
      let facts = try contentFacts(selector.key, position: position, database: database, upperMS: now.upperMS)
      guard facts.available else { return RetainedStreamContent(observation: facts, payload: nil) }
      guard facts.bytes <= maximumBytes else { throw ServiceFailure.resourceExhausted }
      let statement = try Self.prepare(database, "SELECT payload FROM stream_content WHERE key=? AND position=?")
      defer { sqlite3_finalize(statement) }; try Self.bind(statement, 1, selector.key); try Self.bind(statement, 2, position)
      guard sqlite3_step(statement) == SQLITE_ROW, let bytes = try Self.nullableBlob(statement, 0, maximum: maximumBytes),
        bytes.count == facts.bytes, Data(SHA256.hash(data: bytes)) == facts.digest, sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
      return RetainedStreamContent(observation: facts, payload: bytes)
    }
  }

  public func close() {
    guard !closed else { return }; closed = true
    if let handles { sqlite3_wal_checkpoint_v2(handles.database, nil, SQLITE_CHECKPOINT_TRUNCATE, nil, nil); sqlite3_close(handles.database); Darwin.close(handles.lock); Darwin.close(handles.directory) }
    handles = nil; checkpointKey = nil; checkContinuity = nil; storage.seal()
  }
  deinit {
    if let original = handles {
      let originalStorage = storage
      executor.queue.async {
        sqlite3_close(original.database); Darwin.close(original.lock); Darwin.close(original.directory)
        originalStorage.seal(); withExtendedLifetime(originalStorage) {}
      }
    }
  }
}
#endif
