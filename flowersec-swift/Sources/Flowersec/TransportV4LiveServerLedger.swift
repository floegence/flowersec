#if os(macOS) || os(iOS)
import Darwin
import Foundation
import SQLite3

// Closing can be requested while an outer Environment gate is still held.
// Detach only the original handles there; physical close runs on this bounded
// cleanup owner, whose execution tail was reserved before storage was opened.
final class V4SQLiteCleanup: @unchecked Sendable {
  private final class Waiter: @unchecked Sendable {
    var continuation: CheckedContinuation<Void, Error>?
    var timer: Task<Void, Never>?
    var canceled = false
  }
  private let gate: NSRecursiveLock
  private let timeout: Duration
  private let events = V4SessionEvents(maximum: 4)
  private var tail: V4ResourceReference?
  private var waiter: Waiter?
  private var deadline: ContinuousClock.Instant?
  private var physicallyClosed = false
  private(set) var started = false
  private(set) var complete = false
  init(environment: V4EnvironmentFoundation, storage: V4CryptoReservation) throws {
    gate = environment.gate
    timeout = environment.cleanupTimeout
    tail = try storage.executionTail()
  }
  func beginClose() {
    gate.withLock {
      if deadline == nil { deadline = ContinuousClock.now.advanced(by: timeout) }
    }
  }
  func start(database: OpaquePointer?, file: Int32, lockFile: Int32,
    onClose: @escaping @Sendable () -> Void = {}) {
    gate.withLock {
      guard !started else { return }
      beginClose()
      started = true
      let handles = Handles(database: database, file: file, lockFile: lockFile)
      DispatchQueue.global(qos: .utility).async { [self, handles] in
        if let database = handles.database { sqlite3_close_v2(database) }
        if handles.file >= 0 { Darwin.close(handles.file) }
        if handles.lockFile >= 0 { Darwin.close(handles.lockFile) }
        gate.withLock {
          onClose()
          physicallyClosed = true
          if let waiter { waiter.timer?.cancel() }
          else { finish() }
        }
      }
    }
  }
  private func finish() {
    guard physicallyClosed, waiter == nil else { return }
    complete = true
    tail?.release(); tail = nil
    events.signal()
  }
  func wait() async throws {
    let token = Waiter()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        gate.withLock {
          if token.canceled { continuation.resume(throwing: CancellationError()); return }
          if complete { continuation.resume(); return }
          guard let deadline else { continuation.resume(throwing: V4PoolFailure.closed); return }
          if ContinuousClock.now >= deadline { continuation.resume(); return }
          // poolStoreStorage prepaid exactly one observer Task and timer.
          // Cancellation keeps this slot occupied until that timer exits.
          guard waiter == nil else { continuation.resume(throwing: V4PoolFailure.capacity); return }
          token.continuation = continuation
          waiter = token
          token.timer = Task { [self, token] in
            do { try await ContinuousClock().sleep(until: deadline) } catch {}
            gate.withLock {
              guard waiter === token else { return }
              waiter = nil; token.timer = nil
              finish()
              let continuation = token.continuation; token.continuation = nil
              continuation?.resume()
            }
          }
        }
      }
    } onCancel: {
      gate.withLock {
        token.canceled = true
        let continuation = token.continuation; token.continuation = nil
        token.timer?.cancel()
        continuation?.resume(throwing: CancellationError())
      }
    }
  }
  func waitPhysicalCleanup() async {
    while true {
      let revision = events.revision
      if gate.withLock({ complete }) { return }
      try? await events.wait(after: revision)
    }
  }
  private struct Handles: @unchecked Sendable {
    let database: OpaquePointer?
    let file: Int32
    let lockFile: Int32
  }
  deinit { tail?.release() }
}

// Only the original successful server admission COMMIT creates this
// continuation. Durable rows and raw claims cannot instantiate it.
final class V4OriginalLiveServerAdmission: @unchecked Sendable {
  private let registration: V4LiveServerRegistration
  private let claim: V4PreparedPoolClaim
  private var used = false
  fileprivate init(registration: V4LiveServerRegistration, claim: V4PreparedPoolClaim) {
    self.registration = registration; self.claim = claim
  }
  func takeClaim() throws -> V4PreparedPoolClaim {
    try claim.environment.gate.withLock {
      guard !used else { throw V4CryptoFailure.phase }
      try registration.checkCarrierAdmission(); try claim.check()
      used = true; return claim
    }
  }
}

final class V4LiveServerAdmissionLedger: V4NativeConnectionLifecycle, @unchecked Sendable {
  private static let format = V4SQLiteStorageFormat(group: .liveServer)
  private static let manifestSchema = format.manifest()
  private static let originalsSchema = "CREATE TABLE originals (claim_key BLOB PRIMARY KEY, projection BLOB NOT NULL) WITHOUT ROWID, STRICT"
  private static let admissionsSchema = "CREATE TABLE admissions (claim_key BLOB PRIMARY KEY, projection BLOB NOT NULL) WITHOUT ROWID, STRICT"
  private let environment: V4EnvironmentFoundation
  private let configuration: LiveServerAdmissionStoreConfiguration
  private let path: String
  private let binding: Data
  private let tenant: String
  private let audience: String
  private let serverIdentity: Data
  private let storage: V4CryptoReservation
  private let disk: V4PersistentDiskCharge
  private let cleanup: V4SQLiteCleanup
  private var db: OpaquePointer?
  private var file: Int32 = -1
  private var lockFile: Int32 = -1
  private var fileIdentity = stat()
  private var lockIdentity = stat()
  private var directoryIdentity = stat()
  private var closed = false
  private var retiring = false
  private var sourceCleanupTransferred = false
  private var originalOwners: Set<Data> = []
  private var admitting = false
  private var registering = false
  init(environment: V4EnvironmentFoundation, configuration: LiveServerAdmissionStoreConfiguration, tenant: String, audience: String, serverIdentity: Data) throws {
    let setup = try environment.poolStoreStorage()
    let tail = try setup.executionTail()
    defer { tail.release() }
    let c = configuration
    guard c.directory.isFileURL, c.directory.standardizedFileURL.path == c.directory.resolvingSymlinksInPath().path,
      c.directory.path.utf8.count <= 2048, c.backingIdentity.count == 16, c.backingIdentity.contains(where: { $0 != 0 }),
      (4...65_536).contains(c.maximumRows), ((1 << 20)...(1 << 30)).contains(c.maximumBytes), c.maximumBytes % 4096 == 0,
      lstat(c.directory.path, &directoryIdentity) == 0, Self.safe(directoryIdentity, directory: true) else { throw V4PoolFailure.configuration }
    self.environment = environment; self.configuration = c; self.tenant = tenant; self.audience = audience; self.serverIdentity = serverIdentity
    path = c.directory.appendingPathComponent("live-server-admissions.sqlite3").path
    binding = V4Crypto.map([(0, V4Crypto.bytes(c.backingIdentity)), (1, V4Crypto.text(tenant)), (2, V4Crypto.text(audience)), (5, V4Crypto.bytes(serverIdentity)), (6, V4Crypto.text("flowersec/live-server-admissions/1")),
      (3, V4NamespaceValue.head(0, UInt64(c.maximumRows))), (4, V4NamespaceValue.head(0, UInt64(c.maximumBytes)))])
    storage = setup
    disk = try environment.poolDiskStorage(diskBytes: UInt64(c.maximumBytes) * 3)
    cleanup = try V4SQLiteCleanup(environment: environment, storage: setup)
    try c.checkContinuity(c.backingIdentity)
    do {
      lockFile = Darwin.open(path + ".lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard lockFile >= 0, fstat(lockFile, &lockIdentity) == 0, Self.safe(lockIdentity),
        flock(lockFile, LOCK_EX | LOCK_NB) == 0 else { throw V4PoolFailure.storage }
      file = Darwin.open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard file >= 0, fstat(file, &fileIdentity) == 0, Self.safe(fileIdentity),
        fileIdentity.st_size >= 0, fileIdentity.st_size <= c.maximumBytes,
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK
      else { throw V4PoolFailure.storage }
      if !c.create { try V4SQLiteAdmission.prepare(db!) }
      sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 65_536); sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 4096)
      sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0)
      try execute("PRAGMA trusted_schema=OFF")
      if !c.create {
          try execute("BEGIN")
        do {
          let observed = try Self.format.inspect(db!, identity: binding)
          do { try validateStorage(writable: false); try validateCurrentStorage() }
          catch { throw Self.format.refusal(.schemaOrStateInvalid, observed: observed) }
          guard try scalar("PRAGMA page_size") == 4096 else { throw Self.format.refusal(.backendConfiguration, observed: observed) }
          try execute("ROLLBACK")
        } catch { try? execute("ROLLBACK"); throw error }
        try V4SQLiteAdmission.allowWrites(db!); try V4SQLiteAdmission.restoreCloseCheckpoint(db!) }
      try execute("PRAGMA journal_mode=DELETE"); try execute("PRAGMA synchronous=FULL")
      try execute("PRAGMA fullfsync=ON"); try execute("PRAGMA trusted_schema=OFF"); try execute("PRAGMA mmap_size=0")
      try execute("PRAGMA temp_store=MEMORY"); try execute("PRAGMA cache_size=-256")
      if c.create { try execute("PRAGMA page_size=4096") }
      guard try scalar("PRAGMA page_size") == 4096,
        try scalar("PRAGMA max_page_count=\(c.maximumBytes / 4096)") == c.maximumBytes / 4096 else { throw V4PoolFailure.storage }
      if c.create {
        try execute("BEGIN IMMEDIATE")
        try execute(Self.manifestSchema); try execute(Self.originalsSchema); try execute(Self.admissionsSchema)
        try execute("PRAGMA user_version=\(Self.format.requiredRevision)")
        try write("INSERT INTO manifest VALUES(1,'\(Self.format.group.rawValue)',\(Self.format.requiredRevision),?1)", blobs: [binding]); try execute("COMMIT")
        guard fsync(file) == 0 else { throw V4PoolFailure.storage }
        let directory = Darwin.open(c.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw V4PoolFailure.storage }
        defer { Darwin.close(directory) }; guard fsync(directory) == 0 else { throw V4PoolFailure.storage }
      }
      try validateStorage()
      try environment.gate.withLock {
        try setup.check(); try Task.checkCancellation()
        try environment.registerNativeConnection(self)
      }
    } catch {
      if error is StorageFormatError || (error as? V4PoolFailure) == .storage { environment.root.diagnosticCounters.increment(.storeFailures) }
      close(); throw error
    }
  }
  static func safe(_ info: stat, directory: Bool = false) -> Bool {
    info.st_uid == geteuid() && info.st_mode & 0o077 == 0
      && info.st_mode & S_IFMT == (directory ? S_IFDIR : S_IFREG) && (directory || info.st_nlink == 1)
  }
  func check() throws {
    try environment.gate.withLock {
      guard !closed, db != nil else { throw V4PoolFailure.closed }
      try storage.check(); try disk.check()
    }
  }
  private func validateStorage(writable: Bool = true) throws {
    try check()
    try configuration.checkContinuity(configuration.backingIdentity)
    try check()
    guard let db else { throw V4PoolFailure.closed }
    var current = stat(); var directory = stat(); var lock = stat()
    guard lstat(configuration.directory.path, &directory) == 0, Self.safe(directory, directory: true),
      directory.st_dev == directoryIdentity.st_dev, directory.st_ino == directoryIdentity.st_ino,
      lstat(path, &current) == 0, Self.safe(current), current.st_dev == fileIdentity.st_dev, current.st_ino == fileIdentity.st_ino,
      lstat(path + ".lock", &lock) == 0, Self.safe(lock), lock.st_dev == lockIdentity.st_dev, lock.st_ino == lockIdentity.st_ino
    else { throw V4PoolFailure.storage }
    var moved: Int32 = 0
    guard current.st_size >= 0, current.st_size <= configuration.maximumBytes,
      sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else { throw V4PoolFailure.storage }
    for suffix in ["-journal", "-wal", "-shm"] {
      var sidecar = stat()
      if lstat(path + suffix, &sidecar) == 0 {
        guard Self.safe(sidecar), sidecar.st_size >= 0, sidecar.st_size <= configuration.maximumBytes else { throw V4PoolFailure.storage }
      } else if errno != ENOENT { throw V4PoolFailure.storage }
    }
    _ = try Self.format.inspect(db, identity: binding)
    guard (!writable || sqlite3_db_readonly(db, "main") == 0),
      try scalar("SELECT (SELECT count(*) FROM admissions) + (SELECT count(*) FROM originals)") <= configuration.maximumRows else { throw V4PoolFailure.storage }
  }
  private func validateCurrentStorage() throws {
    guard try scalar("SELECT count(*) FROM sqlite_schema") == 3 else { throw V4PoolFailure.storage }
    for (table, expected) in [("manifest", Self.manifestSchema), ("originals", Self.originalsSchema), ("admissions", Self.admissionsSchema)] {
      let schema = try statement("SELECT sql=?1 FROM sqlite_schema WHERE type='table' AND name='\(table)'")
      defer { sqlite3_finalize(schema) }
      guard sqlite3_bind_text(schema, 1, expected, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK,
        sqlite3_step(schema) == SQLITE_ROW, sqlite3_column_int(schema, 0) == 1, sqlite3_step(schema) == SQLITE_DONE else { throw V4PoolFailure.storage }
    }
    guard try scalar("SELECT (SELECT count(*) FROM admissions)+(SELECT count(*) FROM originals)") <= configuration.maximumRows,
      try scalar("SELECT count(*) FROM admissions a LEFT JOIN originals o ON a.claim_key=o.claim_key WHERE o.claim_key IS NULL") == 0 else { throw V4PoolFailure.storage }
    for table in ["originals", "admissions"] {
      let rows = try statement("SELECT claim_key,projection FROM \(table) ORDER BY claim_key LIMIT \(configuration.maximumRows + 1)")
      defer { sqlite3_finalize(rows) }
      var count = 0
      while true {
        let step = sqlite3_step(rows); if step == SQLITE_DONE { break }
        guard step == SQLITE_ROW, count < configuration.maximumRows else { throw V4PoolFailure.storage }; count += 1
        let key = try storedBlob(rows, 0, maximum: 256), projection = try storedBlob(rows, 1, maximum: 512)
        var cursor = V4PoolWireCursor(key, maximum: 256)
        try cursor.map(3); try cursor.key(0)
        guard try cursor.text(maximum: 128) == tenant else { throw V4PoolFailure.storage }
        for field in 1...2 { try cursor.key(UInt64(field)); guard try cursor.bytes(maximum: 16).count == 16 else { throw V4PoolFailure.storage } }
        try cursor.end()
        _ = try projectionFields(projection, admission: table == "admissions")
      }
    }
    let joined = try statement("SELECT o.projection,a.projection FROM originals o JOIN admissions a ON o.claim_key=a.claim_key LIMIT \(configuration.maximumRows + 1)")
    defer { sqlite3_finalize(joined) }
    var count = 0
    while true {
      let step = sqlite3_step(joined); if step == SQLITE_DONE { break }
      guard step == SQLITE_ROW, count < configuration.maximumRows else { throw V4PoolFailure.storage }; count += 1
      let original = try projectionFields(storedBlob(joined, 0, maximum: 512), admission: false)
      let admission = try projectionFields(storedBlob(joined, 1, maximum: 512), admission: true)
      for (left, right) in [(0, 0), (2, 3), (3, 1), (4, 4), (5, 5)] {
        guard original[left] == admission[right] else { throw V4PoolFailure.storage }
      }
    }
  }
  private func storedBlob(_ row: OpaquePointer, _ column: Int32, maximum: Int) throws -> Data {
    let length = Int(sqlite3_column_bytes(row, column))
    guard sqlite3_column_type(row, column) == SQLITE_BLOB, (1...maximum).contains(length), let bytes = sqlite3_column_blob(row, column) else { throw V4PoolFailure.storage }
    return Data(bytes: bytes, count: length)
  }
  private func projectionFields(_ bytes: Data, admission: Bool) throws -> [Data] {
    let lengths = admission ? [16, 32, 32, 16, 16, 32, 16, 16, 32, 32] : [16, 16, 16, 32, 16, 32]
    var cursor = V4PoolWireCursor(bytes, maximum: 512); try cursor.map(UInt64(lengths.count))
    var fields: [Data] = []; fields.reserveCapacity(lengths.count)
    for (index, length) in lengths.enumerated() {
      try cursor.key(UInt64(index)); let value = try cursor.bytes(maximum: length)
      guard value.count == length else { throw V4PoolFailure.storage }; fields.append(value)
    }
    try cursor.end(); return fields
  }
  private func key(_ registration: V4LiveServerRegistration) throws -> Data {
    let artifact = registration.plan.artifact
    guard try artifact.t("tenant_id") == tenant, try artifact.t("audience") == audience,
      try registration.plan.server.b("ed25519_public_key") == serverIdentity else { throw V4CryptoFailure.authentication }
    return V4Crypto.map([(0, V4Crypto.text(tenant)), (1, V4Crypto.bytes(try artifact.b("issuer_key_id"))),
      (2, V4Crypto.bytes(try artifact.b("lease_id")))])
  }
  func registerOriginal(_ registration: V4LiveServerRegistration) throws {
    let tail = try environment.gate.withLock { () throws -> V4ResourceReference in
      guard !retiring, !admitting, !registering else { throw V4PoolFailure.closed }
      try check(); try registration.plan.credential.checkPreparation(in: environment); try Task.checkCancellation()
      let tail = try storage.executionTail()
      registering = true
      return tail
    }
    defer {
      let closing = environment.gate.withLock { () -> Bool in
        if !closed { registering = false }
        return closed
      }
      if closing {
        closeStorage()
        environment.gate.withLock { registering = false }
      }
      tail.release()
    }
    let originalKey = try key(registration)
    let binding = registration.binding
    let projection = V4Crypto.map([(0, V4Crypto.bytes(binding.incarnation)), (1, V4Crypto.bytes(binding.recipient)),
        (2, V4Crypto.bytes(binding.attempt)), (3, V4Crypto.bytes(binding.artifactDigest)),
        (4, V4Crypto.bytes(binding.candidateID)), (5, V4Crypto.bytes(binding.routeDigest))])
    try validateStorage()
    try execute("BEGIN IMMEDIATE")
    do {
      try validateStorage()
      guard try scalar("SELECT 2 * count(*) FROM originals") <= configuration.maximumRows - 2 else {
        throw V4PoolFailure.capacity
      }
      try write("INSERT INTO originals VALUES(?1,?2)", blobs: [originalKey, projection])
      try validateStorage(); try registration.plan.credential.checkPreparation(in: environment); try execute("COMMIT")
      try validateStorage(); try registration.plan.credential.checkPreparation(in: environment)
      try environment.gate.withLock {
        try Task.checkCancellation()
        guard !closed, !retiring else { throw V4PoolFailure.closed }
        originalOwners.insert(binding.incarnation)
      }
    } catch {
      try? execute("ROLLBACK")
      if (error as? V4PoolFailure) == .storage || error is StorageFormatError { close() }
      throw error
    }
  }
  func admitOriginal(_ registration: V4LiveServerRegistration, claim: V4PreparedPoolClaim, fsb: Data, context: Data) throws -> V4OriginalLiveServerAdmission {
    let tail = try environment.gate.withLock { () throws -> V4ResourceReference in
      guard !closed, !admitting, !registering, originalOwners.contains(registration.binding.incarnation) else { throw V4PoolFailure.closed }
      try check(); try registration.checkCarrierAdmission(); try claim.check()
      let plan = registration.plan
      guard plan.environment === environment, claim.environment === environment, claim.facts == nil else { throw V4CryptoFailure.authentication }
      let tail = try storage.executionTail()
      admitting = true
      return tail
    }
    defer {
      let closing = environment.gate.withLock { () -> Bool in
        if !closed { admitting = false }
        return closed
      }
      if closing {
        closeStorage()
        environment.gate.withLock { admitting = false }
      }
      tail.release()
    }
    do {
      let plan = registration.plan
      try validateStorage()
      let admissionKey = try key(registration)
      let projection = V4Crypto.map([(0, V4Crypto.bytes(registration.binding.incarnation)),
        (1, V4Crypto.bytes(plan.credential.artifactDigest)), (2, V4Crypto.bytes(plan.credential.activationDigest)),
        (3, V4Crypto.bytes(plan.credential.attemptID)), (4, V4Crypto.bytes(plan.credential.candidateID)),
        (5, V4Crypto.bytes(plan.credential.routeDigest)), (6, V4Crypto.bytes(claim.operationID)), (7, V4Crypto.bytes(claim.carrierID)),
        (8, V4Crypto.bytes(V4Crypto.hash(fsb))), (9, V4Crypto.bytes(V4Crypto.hash(context)))])
      let winner = try V4OriginalParentWinner.select(configuration: configuration.parentWinner,
        claim: claim,
        willDispatch: { plan.credential.connectionFacts.spendDispatched() },
        didCommit: { plan.credential.connectionFacts.spent() }) {
        try self.validateStorage(); try registration.checkCarrierAdmission(); try claim.check(); try Task.checkCancellation()
      }
      try winner.consume(owner: claim, admission: plan.credential)
      try execute("BEGIN IMMEDIATE")
      var commitDispatched = false
      do {
        try validateStorage(); try registration.checkCarrierAdmission(); try claim.check(); try Task.checkCancellation()
        guard try scalar("SELECT (SELECT count(*) FROM originals) + (SELECT count(*) FROM admissions)") < configuration.maximumRows else {
          throw V4PoolFailure.capacity
        }
        try write("INSERT INTO admissions VALUES(?1,?2)", blobs: [admissionKey, projection])
        try validateStorage(); try registration.checkCarrierAdmission(); try claim.check(); try Task.checkCancellation()
        plan.credential.connectionFacts.admissionDispatched()
        commitDispatched = true
        try execute("COMMIT")
        plan.credential.connectionFacts.spent(); plan.credential.connectionFacts.admitted()
        try validateStorage(); try registration.checkCarrierAdmission(); try claim.check(); try Task.checkCancellation()
        return V4OriginalLiveServerAdmission(registration: registration, claim: claim)
      } catch {
        if (try? execute("ROLLBACK")) != nil, !commitDispatched { plan.credential.connectionFacts.admissionRejected() }
        if commitDispatched { close() }
        throw error
      }
    }
  }
  private func statement(_ sql: String) throws -> OpaquePointer {
    guard let db else { throw V4PoolFailure.closed }
    var value: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &value, nil) == SQLITE_OK, let value else { throw V4PoolFailure.storage }
    return value
  }
  private func execute(_ sql: String) throws {
    guard let db, sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw V4PoolFailure.storage }
  }
  private func scalar(_ sql: String) throws -> Int {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    guard sqlite3_step(value) == SQLITE_ROW else { throw V4PoolFailure.storage }
    return Int(sqlite3_column_int64(value, 0))
  }
  private func write(_ sql: String, blobs: [Data]) throws {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    for (offset, blob) in blobs.enumerated() {
      let result = blob.withUnsafeBytes { sqlite3_bind_blob(value, Int32(offset + 1), $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }
      guard result == SQLITE_OK else { throw V4PoolFailure.storage }
    }
    guard sqlite3_step(value) == SQLITE_DONE else { throw V4PoolFailure.conflict }
  }
  func releaseOriginal(_ registration: V4LiveServerRegistration) {
    environment.gate.withLock {
      originalOwners.remove(registration.binding.incarnation)
      if retiring && originalOwners.isEmpty { close() }
    }
  }
  func retireWhenIdle() {
    environment.gate.withLock { retiring = true; cleanup.beginClose(); if originalOwners.isEmpty { close() } }
  }
  func cleanupStatus() -> CleanupStatus {
    environment.gate.withLock {
      let pending = admitting || registering || ((closed || retiring) && !cleanup.complete)
      return CleanupStatus(complete: closed && !pending,
        cleanupIncomplete: closed && pending, pendingCallbacks: pending ? 1 : 0)
    }
  }
  // Material takes an independent ledger lifetime at the original transfer.
  // Its final release may start physical cleanup long after Source completion;
  // that cleanup remains charged to this ledger and must not rejoin the Source.
  func transferSourceCleanup() {
    environment.gate.withLock { sourceCleanupTransferred = true }
  }
  func sourceCleanupPending() -> UInt64 {
    environment.gate.withLock {
      if sourceCleanupTransferred { return 0 }
      return cleanupStatus().pendingCallbacks
    }
  }
  func waitSourceCleanup() async {
    let transferred = environment.gate.withLock { sourceCleanupTransferred }
    if !transferred { await cleanup.waitPhysicalCleanup() }
  }
  func waitCleanup() async throws -> CleanupStatus {
    try await cleanup.wait()
    return cleanupStatus()
  }
  func waitPhysicalCleanup() async { await cleanup.waitPhysicalCleanup() }
  func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true
      cleanup.beginClose()
      storage.seal()
      if !admitting && !registering { closeStorage() }
    }
  }
  private func closeStorage() {
    environment.gate.withLock {
      guard !cleanup.started else { return }
      cleanup.start(database: db, file: file, lockFile: lockFile) { [storage] in
        storage.release()
      }
      db = nil; file = -1; lockFile = -1
    }
  }
  deinit { close() }
}
#endif
