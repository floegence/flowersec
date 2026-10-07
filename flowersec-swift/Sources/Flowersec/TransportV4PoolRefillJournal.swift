#if os(macOS) || os(iOS)
import Darwin
import Foundation
import SQLite3

/// Durable local storage is independently named and fenced by the deployment.
/// Continuity must refuse a restored, replaced or no-longer-authorized backing;
/// possession of the filename and matching manifest is not rollback protection.
public struct TransportPoolRefillJournalConfiguration: Sendable, CustomStringConvertible, CustomReflectable {
  public let directory: URL
  public let backingIdentity: Data
  public let create: Bool
  public let maximumRows: Int
  public let maximumBytes: Int
  public let continuity: @Sendable (Data) throws -> Void
  public init(directory: URL, backingIdentity: Data, create: Bool,
    maximumRows: Int = 64, maximumBytes: Int = 16_777_216,
    continuity: @escaping @Sendable (Data) throws -> Void) {
    self.directory = directory; self.backingIdentity = backingIdentity; self.create = create
    self.maximumRows = maximumRows; self.maximumBytes = maximumBytes; self.continuity = continuity
  }
  public var description: String { "Flowersec.PoolRefillJournalConfiguration(<redacted>)" }
  public var customMirror: Mirror { Mirror(self, children: EmptyCollection<(label: String?, value: Any)>()) }
}

/// One logical source journal and one exclusive physical owner. Pending and
/// installed states survive lost replies; Ack never reads old material or keys.
final class V4PoolRefillJournal: V4NativeConnectionLifecycle, @unchecked Sendable {
  enum Phase: Int64, Sendable { case pending = 1, installed = 2, acked = 3, terminal = 4 }
  struct Recovery: Sendable {
    let intent: V4PoolRefillIntent
    let phase: Phase
    let generation: UInt64
    let previousHighest: UInt64
    let response: Data
    let terminalReceipt: Data
    init(intent: V4PoolRefillIntent, phase: Phase, generation: UInt64, previousHighest: UInt64,
      response: Data, terminalReceipt: Data = Data()) {
      self.intent = intent; self.phase = phase; self.generation = generation
      self.previousHighest = previousHighest; self.response = response; self.terminalReceipt = terminalReceipt
    }
  }
  private static let format = V4SQLiteStorageFormat(group: .poolJournal)
  private static let manifestSQL = format.manifest(suffix: ", max_rows INTEGER NOT NULL, max_bytes INTEGER NOT NULL, next_operation BLOB NOT NULL, highest BLOB NOT NULL")
  private static let operationSQL = "CREATE TABLE operation (id INTEGER PRIMARY KEY CHECK(id=1), intent BLOB NOT NULL, phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 4), generation BLOB NOT NULL, previous_highest BLOB NOT NULL, response BLOB NOT NULL, terminal BLOB NOT NULL) STRICT"
  private static let materialSQL = "CREATE TABLE material (sequence BLOB PRIMARY KEY, expiry BLOB NOT NULL, wire BLOB NOT NULL) STRICT, WITHOUT ROWID"
  let environment: V4EnvironmentFoundation
  private let configuration: TransportPoolRefillJournalConfiguration
  private let binding: Data
  private let tenant: String
  private let source: Data
  private let pool: Data
  private let registry: V4NamespaceRegistry
  let storage: V4CryptoReservation
  private let path: String
  private var db: OpaquePointer?
  private var descriptor: Int32 = -1
  private var lockDescriptor: Int32 = -1
  private var directoryIdentity = stat()
  private var fileIdentity = stat()
  private var lockIdentity = stat()
  private var closed = false
  init(environment: V4EnvironmentFoundation, configuration: TransportPoolRefillJournalConfiguration,
    tenant: String, source: Data, pool: Data, preparedStorage: V4CryptoReservation? = nil,
    preparedRegistry: V4NamespaceRegistry? = nil) throws {
    let c = configuration
    guard c.directory.isFileURL, c.directory.standardizedFileURL.path == c.directory.resolvingSymlinksInPath().path,
      c.directory.path.utf8.count <= 2048, !c.directory.path.utf8.contains(0), c.backingIdentity.count == 32, c.backingIdentity.contains(where: { $0 != 0 }),
      source.count == 16, source.contains(where: { $0 != 0 }), pool.count == 32,
      V4NamespaceRegistry.securityID(tenant.utf8), (4...64).contains(c.maximumRows),
      (4_194_304...67_108_864).contains(c.maximumBytes), c.maximumBytes % 4096 == 0
    else { throw V4PoolFailure.configuration }
    var directoryInfo = stat()
    guard lstat(c.directory.path, &directoryInfo) == 0, directoryInfo.st_mode & S_IFMT == S_IFDIR,
      directoryInfo.st_mode & 0o077 == 0, directoryInfo.st_uid == geteuid() else { throw V4PoolFailure.configuration }
    directoryIdentity = directoryInfo
    self.environment = environment; self.configuration = c; self.tenant = tenant; self.source = source; self.pool = pool
    registry = try preparedRegistry ?? V4NamespaceRegistry()
    binding = V4Crypto.map([(0, V4Crypto.bytes(c.backingIdentity)), (1, V4Crypto.text(tenant)),
      (2, V4Crypto.bytes(source)), (3, V4Crypto.bytes(pool))])
    path = c.directory.appendingPathComponent("refill.sqlite3").path
    storage = try preparedStorage ?? environment.managedPoolStorage(maximumRows: c.maximumRows, maximumBytes: c.maximumBytes)
    guard storage.environment === environment else { throw V4ResourceFailure.owner }
    try storage.check()
    try c.continuity(c.backingIdentity)
    do {
      lockDescriptor = Darwin.open(path + ".lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard lockDescriptor >= 0, fstat(lockDescriptor, &lockIdentity) == 0, safe(lockIdentity),
        flock(lockDescriptor, LOCK_EX | LOCK_NB) == 0 else { throw V4PoolFailure.storage }
      descriptor = Darwin.open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard descriptor >= 0, fstat(descriptor, &fileIdentity) == 0, safe(fileIdentity), fileIdentity.st_size <= c.maximumBytes,
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK
      else { throw V4PoolFailure.storage }
      if !c.create { try V4SQLiteAdmission.prepare(db!) }
      sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 524_288)
      sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 4096)
      sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 8)
      sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 8)
      sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0)
      try exec("PRAGMA trusted_schema=OFF")
      if !c.create {
        try inspectCurrentFormat()
          try V4SQLiteAdmission.allowWrites(db!)
          try V4SQLiteAdmission.restoreCloseCheckpoint(db!)
      }
      try exec("PRAGMA journal_mode=DELETE")
      try exec("PRAGMA synchronous=FULL")
      try exec("PRAGMA fullfsync=ON")
      try exec("PRAGMA trusted_schema=OFF")
      try exec("PRAGMA mmap_size=0")
      try exec("PRAGMA temp_store=MEMORY")
      try exec("PRAGMA cache_size=-256")
      if c.create { try exec("PRAGMA page_size=4096") }
      guard try scalar("PRAGMA page_size") == 4096,
        try scalar("PRAGMA max_page_count=\(c.maximumBytes / 4096)") == c.maximumBytes / 4096 else { throw V4PoolFailure.storage }
      if c.create {
        try transaction {
          try exec(Self.manifestSQL); try exec(Self.operationSQL); try exec(Self.materialSQL)
          try exec("PRAGMA user_version=\(Self.format.requiredRevision)")
          try execute("INSERT INTO manifest VALUES(1,'\(Self.format.group.rawValue)',\(Self.format.requiredRevision),?1,?2,?3,?4,?5)",
            [.blob(binding), .integer(Int64(c.maximumRows)), .integer(Int64(c.maximumBytes)), .blob(number(1)), .blob(number(0))])
        }
        let directory = Darwin.open(c.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw V4PoolFailure.storage }
        defer { Darwin.close(directory) }
        guard fsync(directory) == 0 else { throw V4PoolFailure.storage }
      }
      try check(); try validate()
      try environment.registerNativeConnection(self)
    } catch {
      if error is StorageFormatError || (error as? V4PoolFailure) == .storage { environment.root.diagnosticCounters.increment(.storeFailures) }
      close(); throw error
    }
  }
  private func inspectCurrentFormat() throws {
    guard let db else { throw V4PoolFailure.closed }
    try exec("BEGIN")
    do {
      let observed = try Self.format.inspect(db, identity: binding)
      do { try validate(); _ = try recover() }
      catch { throw Self.format.refusal(.schemaOrStateInvalid, observed: observed) }
      guard try scalar("PRAGMA page_size") == 4096 else { throw Self.format.refusal(.backendConfiguration, observed: observed) }
      try exec("ROLLBACK")
    } catch { try? exec("ROLLBACK"); throw error }
  }
  private func safe(_ info: stat) -> Bool {
    info.st_mode & S_IFMT == S_IFREG && info.st_mode & 0o077 == 0 && info.st_uid == geteuid() && info.st_nlink == 1
  }
  func check() throws {
    try environment.gate.withLock {
      guard !closed, db != nil else { throw V4PoolFailure.closed }
      try storage.check(); try configuration.continuity(configuration.backingIdentity)
      guard !closed, let db else { throw V4PoolFailure.closed }
      var info = stat(); var moved: Int32 = 0
      guard lstat(configuration.directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
        info.st_mode & 0o077 == 0, info.st_uid == geteuid(), info.st_dev == directoryIdentity.st_dev,
        info.st_ino == directoryIdentity.st_ino,
        sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else { throw V4PoolFailure.storage }
      guard lstat(path, &info) == 0, safe(info), info.st_ino == fileIdentity.st_ino,
        info.st_dev == fileIdentity.st_dev, info.st_size <= configuration.maximumBytes else { throw V4PoolFailure.storage }
      guard lstat(path + ".lock", &info) == 0, safe(info), info.st_ino == lockIdentity.st_ino,
        info.st_dev == lockIdentity.st_dev else { throw V4PoolFailure.storage }
      for suffix in ["-journal", "-wal", "-shm"] {
        if lstat(path + suffix, &info) == 0 {
          guard suffix == "-journal", safe(info), info.st_size <= configuration.maximumBytes else { throw V4PoolFailure.storage }
        } else { guard errno == ENOENT else { throw V4PoolFailure.storage } }
      }
      try storage.check()
    }
  }
  private func number(_ value: UInt64) -> Data { V4Crypto.integer(value, width: 8) }
  private func value(_ statement: OpaquePointer, _ column: Int32) throws -> UInt64 {
    let bytes = try blob(statement, column, maximum: 8)
    guard bytes.count == 8 else { throw V4PoolFailure.storage }
    return V4Crypto.number(bytes)
  }
  private enum Parameter { case blob(Data), integer(Int64) }
  private func statement(_ sql: String) throws -> OpaquePointer {
    guard let db else { throw V4PoolFailure.closed }
    var statement: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK, let statement else { throw V4PoolFailure.storage }
    return statement
  }
  private func exec(_ sql: String) throws {
    guard let db, sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw V4PoolFailure.storage }
  }
  private func execute(_ sql: String, _ parameters: [Parameter] = []) throws {
    let statement = try self.statement(sql)
    defer { sqlite3_finalize(statement) }
    for (index, value) in parameters.enumerated() {
      let code: Int32
      switch value {
      case .blob(let bytes):
        if bytes.isEmpty { code = sqlite3_bind_zeroblob(statement, Int32(index + 1), 0) }
        else { code = bytes.withUnsafeBytes { sqlite3_bind_blob(statement, Int32(index + 1), $0.baseAddress,
          Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) } }
      case .integer(let value): code = sqlite3_bind_int64(statement, Int32(index + 1), value)
      }
      guard code == SQLITE_OK else { throw V4PoolFailure.storage }
    }
    let result = sqlite3_step(statement)
    if result == SQLITE_CONSTRAINT { throw V4PoolFailure.conflict }
    guard result == SQLITE_DONE else { throw V4PoolFailure.storage }
  }
  private func scalar(_ sql: String) throws -> Int64 {
    let statement = try self.statement(sql)
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW, sqlite3_column_type(statement, 0) == SQLITE_INTEGER else { throw V4PoolFailure.storage }
    let value = sqlite3_column_int64(statement, 0)
    guard value >= 0, sqlite3_step(statement) == SQLITE_DONE else { throw V4PoolFailure.storage }
    return value
  }
  private func blob(_ statement: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
    let count = Int(sqlite3_column_bytes(statement, column))
    guard sqlite3_column_type(statement, column) == SQLITE_BLOB, count <= maximum else { throw V4PoolFailure.storage }
    if count == 0 { return Data() }
    guard let bytes = sqlite3_column_blob(statement, column) else { throw V4PoolFailure.storage }
    return Data(bytes: bytes, count: count)
  }
  private func transaction<T>(_ body: () throws -> T) throws -> T {
    try exec("BEGIN IMMEDIATE")
    do { let result = try body(); try check(); try exec("COMMIT"); try check(); return result }
    catch { try? exec("ROLLBACK"); throw error }
  }
  private func validate() throws {
    guard let db else { throw V4PoolFailure.closed }
    _ = try Self.format.inspect(db, identity: binding)
    let schema = try statement("SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
    defer { sqlite3_finalize(schema) }
    for expected in [Self.manifestSQL, Self.materialSQL, Self.operationSQL] {
      guard sqlite3_step(schema) == SQLITE_ROW, let sql = sqlite3_column_text(schema, 0),
        String(cString: sql) == expected else { throw V4PoolFailure.storage }
    }
    guard sqlite3_step(schema) == SQLITE_DONE else { throw V4PoolFailure.storage }
    let manifest = try statement("SELECT identity,max_rows,max_bytes,next_operation,highest FROM manifest WHERE id=1")
    defer { sqlite3_finalize(manifest) }
    guard sqlite3_step(manifest) == SQLITE_ROW, try blob(manifest, 0, maximum: 1024) == binding,
      sqlite3_column_int64(manifest, 1) == configuration.maximumRows,
      sqlite3_column_int64(manifest, 2) == configuration.maximumBytes, try value(manifest, 3) > 0, try blob(manifest, 4, maximum: 8).count == 8,
      sqlite3_step(manifest) == SQLITE_DONE, try scalar("SELECT count(*) FROM manifest") == 1,
      try scalar("SELECT count(*) FROM operation") <= 1, try scalar("SELECT count(*) FROM material") <= configuration.maximumRows
    else { throw V4PoolFailure.storage }
    let rows = try statement("SELECT sequence,expiry,wire FROM material ORDER BY sequence")
    defer { sqlite3_finalize(rows) }
    let highest = try manifestNumber("highest")
    var previous: UInt64 = 0
    while true {
      let step = sqlite3_step(rows)
      if step == SQLITE_DONE { break }
      guard step == SQLITE_ROW else { throw V4PoolFailure.storage }
      let sequence = try value(rows, 0)
      guard sequence > previous, sequence <= highest, try value(rows, 1) > 0,
        !(try blob(rows, 2, maximum: 65_536)).isEmpty else { throw V4PoolFailure.storage }
      previous = sequence
    }
  }
  private func manifestNumber(_ column: String) throws -> UInt64 {
    let statement = try self.statement("SELECT \(column) FROM manifest WHERE id=1")
    defer { sqlite3_finalize(statement) }
    guard sqlite3_step(statement) == SQLITE_ROW else { throw V4PoolFailure.storage }
    let result = try value(statement, 0)
    guard sqlite3_step(statement) == SQLITE_DONE else { throw V4PoolFailure.storage }
    return result
  }
  func recover() throws -> Recovery? {
    try environment.gate.withLock {
      try check(); try validate()
      let statement = try self.statement("SELECT intent,phase,generation,previous_highest,response,terminal FROM operation WHERE id=1")
      defer { sqlite3_finalize(statement) }
      let result = sqlite3_step(statement)
      if result == SQLITE_DONE { return nil }
      guard result == SQLITE_ROW, let phase = Phase(rawValue: sqlite3_column_int64(statement, 1)) else { throw V4PoolFailure.storage }
      let intent = try V4PoolRefillIntent.decode(blob(statement, 0, maximum: 4096))
      let generation = try value(statement, 2); let highest = try value(statement, 3)
      let response = try blob(statement, 4, maximum: 524_288)
      let receipt = try blob(statement, 5, maximum: 8192)
      let next = try manifestNumber("next_operation"); let frontier = try manifestNumber("highest")
      guard sqlite3_step(statement) == SQLITE_DONE, intent.sequence < .max, intent.sequence + 1 == next,
        highest <= frontier, intent.tenant == tenant, intent.source == source, intent.pool == pool,
        (phase == .terminal ? (!receipt.isEmpty && generation > 0) : receipt.isEmpty),
        phase != .pending || (response.isEmpty && highest == frontier),
        phase != .installed && phase != .acked || (!response.isEmpty && generation > 0)
      else { throw V4PoolFailure.storage }
      let recovery = Recovery(intent: intent, phase: phase, generation: generation, previousHighest: highest,
        response: response, terminalReceipt: receipt)
      if !response.isEmpty {
        let installed = try V4PoolRefillWire.response(response, intent: intent,
          originalGeneration: generation, previousHighest: highest, registry: registry)
        guard installed.highest == frontier else { throw V4PoolFailure.storage }
        let material = try self.statement("SELECT expiry,wire FROM material WHERE sequence=?1")
        defer { sqlite3_finalize(material) }
        for entry in installed.entries {
          sqlite3_reset(material); sqlite3_clear_bindings(material)
          let sequence = number(entry.sequence)
          let bound = sequence.withUnsafeBytes { sqlite3_bind_blob(material, 1, $0.baseAddress,
            Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
          guard bound == SQLITE_OK else { throw V4PoolFailure.storage }
          let step = sqlite3_step(material)
          if step == SQLITE_DONE { continue }
          guard step == SQLITE_ROW, try value(material, 0) == entry.expiry,
            try blob(material, 1, maximum: 65_536) == entry.material,
            sqlite3_step(material) == SQLITE_DONE else { throw V4PoolFailure.storage }
        }
      }
      if phase == .terminal { _ = try terminal(recovery) }
      return recovery
    }
  }
  func terminal(_ recovery: Recovery) throws -> V4PoolRefillTerminal {
    guard recovery.phase == .terminal, !recovery.terminalReceipt.isEmpty else { throw V4PoolFailure.conflict }
    let reply = try V4PoolRefillWire.reply(recovery.terminalReceipt, applicationError: true)
    guard let terminal = try V4PoolRefillWire.terminal(reply, original: recovery,
      currentGeneration: .max, registry: registry) else { throw V4PoolFailure.storage }
    return terminal
  }
  func begin(tenant: String, source: Data, pool: Data, desired: Int, maximumItemBytes: Int,
    deadline: UInt64, identity: Data) throws -> Recovery {
    try environment.gate.withLock {
      try check()
      return try transaction {
        guard tenant == self.tenant, source == self.source, pool == self.pool else { throw V4PoolFailure.conflict }
        if let old = try recover(), old.phase != .acked {
          guard old.phase == .terminal else { return old }
          let receipt = try terminal(old)
          guard !receipt.permanent else { throw V4PoolFailure.conflict }
          guard receipt.retired else { return old }
        }
        let sequence = try manifestNumber("next_operation")
        guard sequence < .max, desired > 0, desired <= 4,
          try scalar("SELECT count(*) FROM material") + Int64(desired) <= configuration.maximumRows else { throw V4PoolFailure.capacity }
        let operation = try V4Crypto.random(8) + number(sequence)
        let intent = V4PoolRefillIntent(operation: operation, tenant: tenant, source: source, desired: UInt64(desired),
          maximumItemBytes: UInt64(maximumItemBytes), pool: pool, deadlineMS: deadline, identity: identity)
        let highest = try manifestNumber("highest")
        try execute("DELETE FROM operation")
        try execute("INSERT INTO operation VALUES(1,?1,1,?2,?3,?4,x'')", [.blob(try intent.encoded()), .blob(number(0)), .blob(number(highest)), .blob(Data())])
        try execute("UPDATE manifest SET next_operation=?1 WHERE id=1", [.blob(number(sequence + 1))])
        return Recovery(intent: intent, phase: .pending, generation: 0, previousHighest: highest, response: Data())
      }
    }
  }
  func bindOriginalGeneration(_ generation: UInt64, intent: V4PoolRefillIntent) throws -> Recovery {
    try environment.gate.withLock {
      try check()
      return try transaction {
        guard let old = try recover(), old.intent == intent, old.phase == .pending, generation > 0,
          old.generation == 0 || old.generation <= generation else { throw V4PoolFailure.conflict }
        if old.generation == 0 { try execute("UPDATE operation SET generation=?1 WHERE id=1", [.blob(number(generation))]) }
        return Recovery(intent: intent, phase: .pending, generation: old.generation == 0 ? generation : old.generation, previousHighest: old.previousHighest, response: Data())
      }
    }
  }
  /// All credential and private-key pairing verification must complete before
  /// this one local install transaction. Recovery never reinstalls taken rows.
  func install(_ response: V4PoolRefillResponse, intent: V4PoolRefillIntent) throws {
    try environment.gate.withLock {
      try check()
      try transaction {
        guard let old = try recover(), old.intent == intent else { throw V4PoolFailure.conflict }
        if old.phase != .pending {
          guard old.phase == .installed || old.phase == .acked, old.response == response.wire
          else { throw V4PoolFailure.conflict }; return
        }
        let validated = try V4PoolRefillWire.response(response.wire, intent: intent,
          originalGeneration: old.generation, previousHighest: old.previousHighest, registry: registry)
        guard validated.digest == response.digest, validated.highest == response.highest,
          validated.entries.count == response.entries.count,
          zip(validated.entries, response.entries).allSatisfy({ pair in
            pair.0.sequence == pair.1.sequence && pair.0.expiry == pair.1.expiry && pair.0.material == pair.1.material
          }) else { throw V4PoolFailure.conflict }
        guard old.generation == response.generation,
          try manifestNumber("highest") == old.previousHighest,
          try scalar("SELECT count(*) FROM material") + Int64(response.entries.count) <= configuration.maximumRows else { throw V4PoolFailure.capacity }
        for entry in response.entries {
          try execute("INSERT INTO material VALUES(?1,?2,?3)", [.blob(number(entry.sequence)), .blob(number(entry.expiry)), .blob(entry.material)])
        }
        try execute("UPDATE manifest SET highest=?1 WHERE id=1", [.blob(number(response.highest))])
        try execute("UPDATE operation SET phase=2,response=?1 WHERE id=1", [.blob(response.wire)])
      }
    }
  }
  func confirmTerminal(_ terminal: V4PoolRefillTerminal, original: Recovery) throws {
    try environment.gate.withLock {
      try check()
      try transaction {
        guard let old = try recover(), old.intent == original.intent, old.generation == original.generation,
          old.phase == original.phase, old.response == original.response, old.terminalReceipt == original.terminalReceipt,
          old.phase == .pending || old.phase == .installed || old.phase == .terminal,
          terminal.highest >= old.previousHighest else { throw V4PoolFailure.conflict }
        let reply = try V4PoolRefillWire.reply(terminal.receipt, applicationError: true)
        guard let checked = try V4PoolRefillWire.terminal(reply, original: old,
          currentGeneration: .max, registry: registry), checked == terminal else { throw V4PoolFailure.conflict }
        // Preserve installed response history independently from the receipt.
        // A terminal cannot install material or assert consumption/Applied.
        if old.phase == .terminal {
          let prior = try self.terminal(old)
          guard !prior.permanent || terminal.permanent,
            !prior.retired || terminal.retired, terminal.highest == prior.highest,
            terminal.retiredArtifact >= prior.retiredArtifact,
            terminal.responseFacts == prior.responseFacts,
            terminal.code == prior.code || terminal.permanent else { throw V4PoolFailure.conflict }
        }
        // Terminal/fence confirmation revokes access to any locally retained
        // rows for that operation. Pending unknown response facts never install
        // rows; installed rows must not outlive a source reset receipt.
        try execute("DELETE FROM material")
        try execute("UPDATE operation SET phase=4,terminal=?1 WHERE id=1", [.blob(terminal.receipt)])
      }
    }
  }
  func acknowledge(intent: V4PoolRefillIntent, response: Data) throws {
    try environment.gate.withLock {
      try check()
      try transaction {
        guard let old = try recover(), old.intent == intent, old.phase == .installed || old.phase == .acked, old.response == response else { throw V4PoolFailure.conflict }
        try execute("UPDATE operation SET phase=3 WHERE id=1")
      }
    }
  }
  func retireExpired(at upperMS: UInt64) throws {
    try environment.gate.withLock {
      try check()
      try transaction {
        try execute("DELETE FROM material WHERE expiry<=?1", [.blob(number(upperMS))])
      }
    }
  }
  var count: Int { get throws { try environment.gate.withLock { try check(); return Int(try scalar("SELECT count(*) FROM material")) } } }
  func take(remove: Bool = true, validate: (Data) throws -> Void = { _ in }) throws -> Data? {
    try environment.gate.withLock {
      try check()
      return try transaction {
        if let saved = try recover(), saved.phase == .terminal {
          if try terminal(saved).permanent { throw V4PoolFailure.closed }
          return nil
        }
        let statement = try self.statement("SELECT sequence,wire FROM material ORDER BY sequence LIMIT 1")
        defer { sqlite3_finalize(statement) }
        let result = sqlite3_step(statement)
        if result == SQLITE_DONE { return nil }
        guard result == SQLITE_ROW else { throw V4PoolFailure.storage }
        let sequence = try blob(statement, 0, maximum: 8)
        let wire = try blob(statement, 1, maximum: 65_536)
        guard sequence.count == 8, !wire.isEmpty, try V4Crypto.number(sequence) <= manifestNumber("highest"),
          sqlite3_step(statement) == SQLITE_DONE else { throw V4PoolFailure.storage }
        try validate(wire)
        // Acquisition removes availability durably before returning bytes.
        // It does not consume the separate once right in spend.sqlite3.
        if remove { try execute("DELETE FROM material WHERE sequence=?1", [.blob(sequence)]) }
        return wire
      }
    }
  }
  func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true
      if let db { sqlite3_close_v2(db); self.db = nil }
      if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
      if lockDescriptor >= 0 { Darwin.close(lockDescriptor); lockDescriptor = -1 }
      storage.seal()
    }
  }
  deinit { close() }
}
#endif
