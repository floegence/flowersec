import Foundation

public enum ReferenceSaveOutcome: String, Sendable { case saved, notSaved = "not_saved", saveUnknown = "save_unknown" }
public protocol OperationReferenceStore: Sendable {
  var targetDomain: String { get }
  func save(_ reference: OperationReference, context: ApplicationInvocationContext) async throws -> ReferenceSaveOutcome
}
public enum OperationPreparationStatus: String, Sendable { case prepared, canceled, expired, saveFailed = "save_failed" }
public struct PreparedAndSavedOperation<Response: Sendable>: Sendable {
  public typealias Status = OperationPreparationStatus
  public let status: Status
  public let operation: ServiceOperation<Response>?
  public let reference: OperationReference
  public let save: ReferenceSaveOutcome
  public let saveAttempted: Bool
}

private final class V4ReferenceSaveReceipt: @unchecked Sendable {
  private let gate = NSLock()
  private var entered = false
  private var returned: ReferenceSaveOutcome?
  func enter() { gate.withLock { entered = true } }
  func record(_ outcome: ReferenceSaveOutcome) { gate.withLock { returned = outcome } }
  var observation: (Bool, ReferenceSaveOutcome) { gate.withLock { (entered, returned ?? (entered ? .saveUnknown : .notSaved)) } }
}

extension ServiceClient {
  public func prepareAndSave<Request: Sendable, Response: Sendable>(
    _ method: MethodDefinition, request: Request, requestCodec: any MessageCodec<Request>,
    responseCodec: any MessageCodec<Response>, store: any OperationReferenceStore, options: ServiceCallOptions
  ) async throws -> PreparedAndSavedOperation<Response> {
    guard method.semantics == .execution, store.targetDomain == target.authority else { throw ServiceFailure.configurationCapacity }
    let operation = try await prepareOperation(method, request: request, requestCodec: requestCodec, responseCodec: responseCodec, options: options)
    guard let reference = operation.reference else { operation.close(); throw ServiceFailure.configurationCapacity }
    let receipt = V4ReferenceSaveReceipt()
    // A store callback is arbitrary application work. Cancellation detaches the
    // caller while its original admitted callback and receipt remain charged.
    let storeStorage = try environment.operationReferenceStorage()
    let tail = V4ServiceInputTail(try storeStorage.executionTail())
    do {
      let saved = try await group.invoke(context: options.context) { ctx in
        defer { withExtendedLifetime(tail) {} }
        try ctx.checkCancellation()
        receipt.enter()
        let outcome: ReferenceSaveOutcome
        do { outcome = try await store.save(reference, context: ctx) }
        catch { outcome = .saveUnknown }
        receipt.record(outcome)
        return outcome
      }
      let (attempted, _) = receipt.observation
      if Task.isCancelled || options.context?.isCancelled == true {
        operation.close()
        return PreparedAndSavedOperation(status: .canceled, operation: nil, reference: reference, save: saved, saveAttempted: attempted)
      }
      if operation.preparationExpired {
        operation.close()
        return PreparedAndSavedOperation(status: .expired, operation: nil, reference: reference, save: saved, saveAttempted: attempted)
      }
      guard saved == .saved else {
        operation.close()
        return PreparedAndSavedOperation(status: .saveFailed, operation: nil, reference: reference, save: saved, saveAttempted: attempted)
      }
      return PreparedAndSavedOperation(status: .prepared, operation: operation, reference: reference, save: saved, saveAttempted: attempted)
    } catch {
      let (attempted, outcome) = receipt.observation
      operation.close()
      let canceled = error is CancellationError || Task.isCancelled || options.context?.isCancelled == true
      return PreparedAndSavedOperation(status: canceled ? .canceled : .saveFailed, operation: nil,
        reference: reference, save: outcome, saveAttempted: attempted)
    }
  }
}

#if os(macOS) || os(iOS)
import Darwin
import SQLite3
import Dispatch

public struct SQLiteOperationReferenceConfiguration: Sendable {
  public let directory: URL
  public let target: ServiceBindingTarget
  public let storeID: Data
  public let generation: UInt64
  public let create: Bool
  public let maximumRows: Int
  public let maximumBytes: Int
  public let checkContinuity: @Sendable () throws -> Void
  public init(directory: URL, target: ServiceBindingTarget, storeID: Data, generation: UInt64, create: Bool,
    maximumRows: Int = 4096, maximumBytes: Int = 16 << 20, checkContinuity: @escaping @Sendable () throws -> Void) {
    self.directory = directory; self.target = target; self.storeID = storeID; self.generation = generation; self.create = create
    self.maximumRows = maximumRows; self.maximumBytes = maximumBytes; self.checkContinuity = checkContinuity
  }
}

/// Local reference persistence never reconstructs an operation handle. SQLite
/// transactions install exact selectors only; reads still need a current
/// authenticated service binding before any Query/ReadResult can be sent.
private final class V4ReferenceSQLiteExecutor: SerialExecutor, @unchecked Sendable {
  let queue = DispatchQueue(label: "flowersec.reference-store", qos: .utility)
  func enqueue(_ job: consuming ExecutorJob) {
    let original = UnownedJob(job)
    queue.async { [self] in original.runSynchronously(on: asUnownedSerialExecutor()) }
  }
}
private final class V4ReferenceStoreIOAdmission: @unchecked Sendable {
  private let gate = NSLock()
  private let storage: V4CryptoReservation
  private var pending = 0
  private var closed = false
  init(storage: V4CryptoReservation) { self.storage = storage }
  func enter() throws -> V4ServiceInputTail {
    try gate.withLock {
      guard !closed, pending < 2 else { throw ServiceFailure.resourceExhausted }
      try storage.check(); let tail = V4ServiceInputTail(try storage.executionTail()); pending += 1; return tail
    }
  }
  func leave() { gate.withLock { pending -= 1 } }
  func close() { gate.withLock { closed = true } }
}
private struct V4ReferenceSQLiteHandles: @unchecked Sendable {
  var database: OpaquePointer
  let lock: Int32
  let directory: Int32
  let directoryDevice: dev_t
  let directoryInode: ino_t
  let databaseDevice: dev_t
  let databaseInode: ino_t
  let lockDevice: dev_t
  let lockInode: ino_t
}

public actor SQLiteOperationReferenceStore: OperationReferenceStore {
  public nonisolated let targetDomain: String
  private nonisolated let ioExecutor: V4ReferenceSQLiteExecutor
  private nonisolated let ioAdmission: V4ReferenceStoreIOAdmission
  public nonisolated var unownedExecutor: UnownedSerialExecutor { ioExecutor.asUnownedSerialExecutor() }
  private let target: ServiceBindingTarget
  private let directoryURL: URL
  private let maximumRows: Int
  private let maximumBytes: Int
  private var checkContinuity: (@Sendable () throws -> Void)?
  private let storage: V4CryptoReservation
  private let disk: V4PersistentDiskCharge
  private let codec: OperationReferenceCodec
  private let path: String
  private var handles: V4ReferenceSQLiteHandles?
  private var database: OpaquePointer? { handles?.database }
  private var closed = false
  private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
  init(environment: V4EnvironmentFoundation, configuration: SQLiteOperationReferenceConfiguration) throws {
    let executor = V4ReferenceSQLiteExecutor()
    ioExecutor = executor
    let directory = configuration.directory
    guard directory.isFileURL, directory.standardizedFileURL.path == directory.resolvingSymlinksInPath().path,
      directory.path.utf8.count <= 2048, !directory.path.utf8.contains(0),
      configuration.storeID.count == 16, configuration.storeID.contains(where: { $0 != 0 }), configuration.generation > 0,
      (1...65536).contains(configuration.maximumRows), ((1 << 20)...(1 << 30)).contains(configuration.maximumBytes),
      configuration.maximumBytes % 4096 == 0 else { throw ServiceFailure.configurationCapacity }
    var directoryStat = stat()
    guard lstat(directory.path, &directoryStat) == 0, directoryStat.st_mode & S_IFMT == S_IFDIR,
      directoryStat.st_uid == geteuid(), directoryStat.st_mode & 0o077 == 0 else { throw ServiceFailure.configurationCapacity }
    try configuration.checkContinuity()
    target = configuration.target; directoryURL = directory; maximumRows = configuration.maximumRows
    maximumBytes = configuration.maximumBytes; checkContinuity = configuration.checkContinuity
    targetDomain = configuration.target.authority
    let databasePath = directory.appendingPathComponent("operation-references.sqlite3").path
    path = databasePath
    storage = try environment.operationReferenceStoreStorage()
    ioAdmission = V4ReferenceStoreIOAdmission(storage: storage)
    disk = try environment.poolDiskStorage(diskBytes: UInt64(configuration.maximumBytes) * 3)
    let referenceCodec = try OperationReferenceCodec(environment: environment)
    codec = referenceCodec
    do {
      handles = try executor.queue.sync { try Self.openDatabase(path: databasePath, configuration: configuration, codec: referenceCodec) }
    } catch {
      referenceCodec.close(); storage.seal()
      if error is StorageFormatError { environment.root.diagnosticCounters.increment(.storeFailures) }
      throw error
    }
  }
  private static let format = V4SQLiteStorageFormat(group: .references)
  private static let manifestSchema = format.manifest()
  private static let refsSchema = "CREATE TABLE refs(operation BLOB PRIMARY KEY CHECK(length(operation)=32), reference BLOB NOT NULL CHECK(length(reference) BETWEEN 1 AND 2048)) STRICT"
  private static func checkSidecars(directory: Int32, maximumBytes: Int) throws {
    for name in ["operation-references.sqlite3-journal", "operation-references.sqlite3-wal", "operation-references.sqlite3-shm"] {
      var info = stat()
      if fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) == 0 {
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
          info.st_mode & 0o077 == 0, info.st_size >= 0, info.st_size <= maximumBytes else { throw ServiceFailure.permissionDenied }
      } else if errno != ENOENT { throw ServiceFailure.serviceUnavailable }
    }
  }
  private static func checkPaths(_ handles: V4ReferenceSQLiteHandles, path: String, directoryPath: String, maximumBytes: Int) throws {
    var directory = stat(); var file = stat(); var lock = stat(); var moved: Int32 = 0
    guard fstat(handles.directory, &directory) == 0, directory.st_dev == handles.directoryDevice, directory.st_ino == handles.directoryInode,
      lstat(directoryPath, &directory) == 0, directory.st_dev == handles.directoryDevice, directory.st_ino == handles.directoryInode,
      directory.st_mode & S_IFMT == S_IFDIR, directory.st_uid == geteuid(), directory.st_mode & 0o077 == 0,
      lstat(path, &file) == 0, file.st_dev == handles.databaseDevice, file.st_ino == handles.databaseInode,
      file.st_mode & S_IFMT == S_IFREG, file.st_uid == geteuid(), file.st_nlink == 1, file.st_mode & 0o077 == 0,
      file.st_size >= 0, file.st_size <= maximumBytes,
      fstat(handles.lock, &lock) == 0, lock.st_dev == handles.lockDevice, lock.st_ino == handles.lockInode,
      fstatat(handles.directory, "operation-references.sqlite3.lock", &lock, AT_SYMLINK_NOFOLLOW) == 0,
      lock.st_dev == handles.lockDevice, lock.st_ino == handles.lockInode, lock.st_mode & S_IFMT == S_IFREG,
      lock.st_uid == geteuid(), lock.st_nlink == 1, lock.st_mode & 0o077 == 0, lock.st_size == 0,
      sqlite3_file_control(handles.database, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else { throw ServiceFailure.permissionDenied }
    try checkSidecars(directory: handles.directory, maximumBytes: maximumBytes)
  }
  private static func scalar(_ database: OpaquePointer, sql: String) throws -> UInt64 {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw ServiceFailure.serviceUnavailable }
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW, sqlite3_column_type(statement, 0) == SQLITE_INTEGER else { throw ServiceFailure.serviceUnavailable }
    let result = sqlite3_column_int64(statement, 0)
    guard result >= 0, sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.historyUnknown }; return UInt64(result)
  }
  private static func text(_ statement: OpaquePointer, _ column: Int32) -> String? {
    guard sqlite3_column_type(statement, column) == SQLITE_TEXT, sqlite3_column_bytes(statement, column) <= 4096,
      let bytes = sqlite3_column_text(statement, column) else { return nil }; return String(cString: bytes)
  }
  private static func checkSchema(_ database: OpaquePointer, maximumRows: Int) throws {
    guard try scalar(database, sql: "PRAGMA page_size") == 4096,
      try scalar(database, sql: "SELECT count(*) FROM refs") <= UInt64(maximumRows),
      try scalar(database, sql: "SELECT count(*) FROM manifest") == 1,
      try scalar(database, sql: "SELECT count(*) FROM sqlite_schema WHERE type IN ('view','trigger') OR (type='index' AND sql IS NOT NULL)") == 0 else { throw ServiceFailure.historyUnknown }
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, "SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name", -1, &statement, nil) == SQLITE_OK,
      let statement else { throw ServiceFailure.serviceUnavailable }; defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW, text(statement, 0) == "manifest", text(statement, 1) == manifestSchema,
      sqlite3_step(statement) == SQLITE_ROW, text(statement, 0) == "refs", text(statement, 1) == refsSchema,
      sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.historyUnknown }
    var integrity: OpaquePointer?
    guard sqlite3_prepare_v2(database, "PRAGMA quick_check", -1, &integrity, nil) == SQLITE_OK, let integrity else { throw ServiceFailure.serviceUnavailable }
    defer { sqlite3_finalize(integrity) }
    guard sqlite3_step(integrity) == SQLITE_ROW, text(integrity, 0) == "ok", sqlite3_step(integrity) == SQLITE_DONE else { throw ServiceFailure.historyUnknown }
  }
  private static func inspectCurrent(_ database: OpaquePointer, configuration: SQLiteOperationReferenceConfiguration,
    codec: OperationReferenceCodec) throws {
    try execute(database, "BEGIN")
    do {
      let observed = try format.inspect(database, identity: identity(configuration))
      do {
        try checkSchema(database, maximumRows: configuration.maximumRows)
        var rows: OpaquePointer?
        guard sqlite3_prepare_v2(database, "SELECT operation,reference FROM refs ORDER BY operation", -1, &rows, nil) == SQLITE_OK,
          let rows else { throw ServiceFailure.historyUnknown }
        defer { sqlite3_finalize(rows) }
        var count = 0
        while true {
          let step = sqlite3_step(rows); if step == SQLITE_DONE { break }
          guard step == SQLITE_ROW, count < configuration.maximumRows,
            sqlite3_column_type(rows, 0) == SQLITE_BLOB, sqlite3_column_bytes(rows, 0) == 32,
            sqlite3_column_type(rows, 1) == SQLITE_BLOB, (1...2048).contains(Int(sqlite3_column_bytes(rows, 1))),
            let operation = sqlite3_column_blob(rows, 0), let encoded = sqlite3_column_blob(rows, 1) else { throw ServiceFailure.historyUnknown }
          let bytes = Data(bytes: encoded, count: Int(sqlite3_column_bytes(rows, 1)))
          let reference = try codec.importReference(bytes, target: configuration.target)
          guard reference.operationID == Data(bytes: operation, count: 32), reference.encoded() == bytes else { throw ServiceFailure.historyUnknown }
          count += 1
        }
      } catch { throw format.refusal(.schemaOrStateInvalid, observed: observed) }
      try execute(database, "ROLLBACK")
    } catch { try? execute(database, "ROLLBACK"); throw error }
  }
  private static func openDatabase(path: String, configuration: SQLiteOperationReferenceConfiguration,
    codec: OperationReferenceCodec) throws -> V4ReferenceSQLiteHandles {
    let directory = open(configuration.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    var directoryStat = stat()
    guard directory >= 0, fstat(directory, &directoryStat) == 0, directoryStat.st_mode & S_IFMT == S_IFDIR,
      directoryStat.st_uid == geteuid(), directoryStat.st_mode & 0o077 == 0 else {
      if directory >= 0 { Darwin.close(directory) }; throw ServiceFailure.permissionDenied
    }
    let locked = openat(directory, "operation-references.sqlite3.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
    var lockStat = stat()
    guard locked >= 0, fstat(locked, &lockStat) == 0, lockStat.st_mode & S_IFMT == S_IFREG,
      lockStat.st_uid == geteuid(), lockStat.st_nlink == 1, lockStat.st_mode & 0o077 == 0, lockStat.st_size == 0, flock(locked, LOCK_EX | LOCK_NB) == 0 else {
      if locked >= 0 { Darwin.close(locked) }; Darwin.close(directory); throw ServiceFailure.serviceUnavailable
    }
    var info = stat(); let exists = fstatat(directory, "operation-references.sqlite3", &info, AT_SYMLINK_NOFOLLOW) == 0
    if !exists && (!configuration.create || errno != ENOENT) { Darwin.close(locked); Darwin.close(directory); throw ServiceFailure.configurationCapacity }
    let descriptor = openat(directory, "operation-references.sqlite3", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (exists ? 0 : O_CREAT | O_EXCL), 0o600)
    guard descriptor >= 0, fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
      info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0,
      info.st_size >= 0, info.st_size <= configuration.maximumBytes else {
      if descriptor >= 0 { Darwin.close(descriptor) }; Darwin.close(locked); Darwin.close(directory); throw ServiceFailure.permissionDenied
    }
    Darwin.close(descriptor)
    do { try checkSidecars(directory: directory, maximumBytes: configuration.maximumBytes) }
    catch { Darwin.close(locked); Darwin.close(directory); throw error }
    var handle: OpaquePointer?
    guard sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK, let handle else {
      if let handle { sqlite3_close_v2(handle) }; Darwin.close(locked); Darwin.close(directory); throw ServiceFailure.serviceUnavailable
    }
    let handles = V4ReferenceSQLiteHandles(database: handle, lock: locked, directory: directory,
      directoryDevice: directoryStat.st_dev, directoryInode: directoryStat.st_ino, databaseDevice: info.st_dev, databaseInode: info.st_ino,
      lockDevice: lockStat.st_dev, lockInode: lockStat.st_ino)
    do {
      try checkPaths(handles, path: path, directoryPath: configuration.directory.path, maximumBytes: configuration.maximumBytes)
      if exists { try V4SQLiteAdmission.prepare(handle) }
      sqlite3_limit(handle, SQLITE_LIMIT_LENGTH, 65_536); sqlite3_limit(handle, SQLITE_LIMIT_SQL_LENGTH, 4096)
      sqlite3_limit(handle, SQLITE_LIMIT_ATTACHED, 0)
      try execute(handle, "PRAGMA trusted_schema=OFF")
      if exists {
        try inspectCurrent(handle, configuration: configuration, codec: codec)
        try V4SQLiteAdmission.allowWrites(handle)
        try V4SQLiteAdmission.restoreCloseCheckpoint(handle)
      }
      let handle = handles.database
      if !exists { try execute(handle, "PRAGMA page_size=4096") }
      guard try scalar(handle, sql: "PRAGMA page_size") == 4096 else { throw ServiceFailure.historyUnknown }
      try execute(handle, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=0; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-256; PRAGMA max_page_count=\(configuration.maximumBytes / 4096)")
      if !exists {
        try execute(handle, "BEGIN IMMEDIATE")
        do {
          try execute(handle, manifestSchema); try execute(handle, refsSchema)
          try execute(handle, "PRAGMA user_version=\(format.requiredRevision)")
          try bindAndStep(handle, sql: "INSERT INTO manifest(id,format,revision,identity) VALUES(1,'\(format.group.rawValue)',\(format.requiredRevision),?)", values: [identity(configuration)])
          try execute(handle, "COMMIT")
        } catch { try? execute(handle, "ROLLBACK"); throw error }
      }
      _ = try format.inspect(handle, identity: identity(configuration))
      try checkPaths(handles, path: path, directoryPath: configuration.directory.path, maximumBytes: configuration.maximumBytes)
      try configuration.checkContinuity(); return handles
    } catch { sqlite3_close_v2(handle); Darwin.close(locked); Darwin.close(directory); throw error }
  }
  private static func identity(_ configuration: SQLiteOperationReferenceConfiguration) -> Data {
    V4Crypto.map([(0, V4Crypto.text("flowersec/swift/operation-reference-store/1")), (1, V4Crypto.bytes(configuration.storeID)),
      (2, V4NamespaceValue.head(0, configuration.generation)), (3, V4Crypto.text(configuration.target.authority)),
      (4, V4Crypto.text(configuration.target.tenant)), (5, V4Crypto.text(configuration.target.audience)),
      (6, V4Crypto.text(configuration.target.localSubject)), (7, V4NamespaceValue.head(0, UInt64(configuration.maximumRows))),
      (8, V4NamespaceValue.head(0, UInt64(configuration.maximumBytes)))])
  }
  private func check() throws -> OpaquePointer {
    guard !closed, let handles, let checkContinuity else { throw ServiceFailure.closed }
    try storage.check(); try disk.check(); try checkContinuity()
    try Self.checkPaths(handles, path: path, directoryPath: directoryURL.path, maximumBytes: maximumBytes)
    return handles.database
  }
  public nonisolated func save(_ reference: OperationReference, context: ApplicationInvocationContext) async throws -> ReferenceSaveOutcome {
    let tail = try ioAdmission.enter()
    defer { ioAdmission.leave(); withExtendedLifetime(tail) {} }
    return try await saveOnIO(reference, context: context)
  }
  private func saveOnIO(_ reference: OperationReference, context: ApplicationInvocationContext) throws -> ReferenceSaveOutcome {
    try context.checkCancellation()
    let database = try check()
    guard reference.targetDomain == targetDomain, reference.tenant == target.tenant,
      reference.audience == target.audience, reference.callerSubject == target.localSubject else {
      throw ServiceFailure.permissionDenied
    }
    var bytes = Data(count: 2048)
    let length = try codec.export(reference, into: &bytes)
    bytes = Data(bytes.prefix(length))
    try Self.execute(database, "BEGIN IMMEDIATE")
    do {
      if let old = try Self.readOne(database, sql: "SELECT reference FROM refs WHERE operation=?", argument: reference.operationID) {
        guard old == bytes else { throw ServiceFailure.operationConflict }
      } else {
        var count: OpaquePointer?
        guard sqlite3_prepare_v2(database, "SELECT count(*) FROM refs", -1, &count, nil) == SQLITE_OK, let count else { throw ServiceFailure.serviceUnavailable }
        defer { sqlite3_finalize(count) }
        guard sqlite3_step(count) == SQLITE_ROW, sqlite3_column_int64(count, 0) >= 0, sqlite3_column_int64(count, 0) < maximumRows else {
          throw ServiceFailure.resourceExhausted
        }
        try Self.bindAndStep(database, sql: "INSERT INTO refs(operation,reference) VALUES(?,?)", values: [reference.operationID, bytes])
      }
      try context.checkCancellation(); _ = try check()
      // Once COMMIT is attempted, only an exact authoritative readback may
      // confirm success. No second write or fabricated not_saved receipt.
      do { try Self.execute(database, "COMMIT") }
      catch {
        try? Self.execute(database, "ROLLBACK")
        if sqlite3_get_autocommit(database) != 0, (try? check()) != nil,
          (try? Self.readOne(database, sql: "SELECT reference FROM refs WHERE operation=?", argument: reference.operationID)) == bytes { return .saved }
        return .saveUnknown
      }
      return .saved
    } catch {
      try? Self.execute(database, "ROLLBACK")
      return .notSaved
    }
  }
  public nonisolated func load(operationID: Data) async throws -> OperationReference? {
    let tail = try ioAdmission.enter()
    defer { ioAdmission.leave(); withExtendedLifetime(tail) {} }
    return try await loadOnIO(operationID: operationID)
  }
  private func loadOnIO(operationID: Data) throws -> OperationReference? {
    guard operationID.count == 32 else { throw ServiceFailure.configurationCapacity }
    guard let bytes = try Self.readOne(check(), sql: "SELECT reference FROM refs WHERE operation=?", argument: operationID) else { return nil }
    return try codec.importReference(bytes, target: target)
  }
  public nonisolated func remove(operationID: Data) async throws {
    let tail = try ioAdmission.enter()
    defer { ioAdmission.leave(); withExtendedLifetime(tail) {} }
    try await removeOnIO(operationID: operationID)
  }
  private func removeOnIO(operationID: Data) throws {
    guard operationID.count == 32 else { throw ServiceFailure.configurationCapacity }
    let database = try check()
    try Self.bindAndStep(database, sql: "DELETE FROM refs WHERE operation=?", values: [operationID])
  }
  public nonisolated func close() async {
    ioAdmission.close(); await closeOnIO()
  }
  private func closeOnIO() {
    guard !closed else { return }; closed = true
    codec.close(); storage.seal()
    if let original = handles {
      handles = nil
      sqlite3_close_v2(original.database)
      flock(original.lock, LOCK_UN); Darwin.close(original.lock); Darwin.close(original.directory)
    }
    checkContinuity = nil
    // Persistent files and their tenant disk quota survive Close and ARC.
  }
  private static func execute(_ database: OpaquePointer, _ sql: String) throws {
    guard sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
  }
  private static func bindAndStep(_ database: OpaquePointer, sql: String, values: [Data]) throws {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw ServiceFailure.serviceUnavailable }
    defer { sqlite3_finalize(statement) }
    for (index, bytes) in values.enumerated() {
      let code = bytes.withUnsafeBytes { sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress, Int32($0.count), transient) }
      guard code == SQLITE_OK else { throw ServiceFailure.serviceUnavailable }
    }
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.serviceUnavailable }
  }
  private static func readOne(_ database: OpaquePointer, sql: String, argument: Data?) throws -> Data? {
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw ServiceFailure.serviceUnavailable }
    defer { sqlite3_finalize(statement) }
    if let argument {
      guard argument.withUnsafeBytes({ sqlite3_bind_blob(statement, 1, $0.baseAddress, Int32($0.count), transient) }) == SQLITE_OK else {
        throw ServiceFailure.serviceUnavailable
      }
    }
    let step = sqlite3_step(statement)
    if step == SQLITE_DONE { return nil }
    guard step == SQLITE_ROW, sqlite3_column_type(statement, 0) == SQLITE_BLOB else { throw ServiceFailure.serviceUnavailable }
    let count = Int(sqlite3_column_bytes(statement, 0))
    guard count > 0, count <= 2048, let pointer = sqlite3_column_blob(statement, 0) else { throw ServiceFailure.historyUnknown }
    let result = Data(bytes: pointer, count: count)
    guard sqlite3_step(statement) == SQLITE_DONE else { throw ServiceFailure.historyUnknown }
    return result
  }
  deinit {
    let original = handles; let originalStorage = storage; let originalDisk = disk; let originalCodec = codec
    ioExecutor.queue.async {
      if let original {
        sqlite3_close_v2(original.database)
        flock(original.lock, LOCK_UN); Darwin.close(original.lock); Darwin.close(original.directory)
      }
      originalCodec.close(); originalStorage.seal()
      withExtendedLifetime(originalDisk) {}; withExtendedLifetime(originalStorage) {}
    }
  }
}
#endif
