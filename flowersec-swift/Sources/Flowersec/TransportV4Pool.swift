#if os(macOS) || os(iOS)
  import Darwin
  import Foundation
  import SQLite3

  enum V4PoolFailure: Error, Equatable { case configuration, storage, conflict, capacity, closed }

  // Trusted deployment configuration, independent of all received material.
  // The directory must be application-owned on a qualified local filesystem.
  // Restore requires the host's complete-history/anti-rollback continuity gate;
  // this local consumer deliberately has no restore-to-activation operation.
  struct V4PoolStoreIdentity: Equatable, Sendable {
    let storeID: Data
    let generation: UInt64
    let tenant: String
    let issuer: Data
    let spendAuthority: String
    let winnerAuthority: String
    fileprivate var bytes: Data {
      V4Crypto.map([
        (0, V4Crypto.text("flowersec/swift/pool-store/1")),
        (1, V4Crypto.bytes(storeID)), (2, V4NamespaceValue.head(0, generation)),
        (3, V4Crypto.text(tenant)), (4, V4Crypto.bytes(issuer)),
        (5, V4Crypto.text(spendAuthority)), (6, V4Crypto.text(winnerAuthority)),
      ])
    }
    fileprivate func check(_ facts: V4PoolSpendFacts) throws {
      guard tenant == facts.tenant, issuer == facts.issuer,
        spendAuthority == facts.spendAuthority, winnerAuthority == facts.winnerAuthority
      else { throw V4PoolFailure.configuration }
    }
  }

  // The disk reference is deliberately not released by ARC or Store.close().
  // Dropping this owner leaves its finite quota charged until root teardown;
  // only explicit verification of host removal retires persistent disk usage.
  final class V4PoolStoreBacking {
    let environment: V4EnvironmentFoundation
    let identity: V4PoolStoreIdentity
    fileprivate let path: String
    fileprivate let maximumBytes: Int
    fileprivate let maximumRows: Int
    fileprivate let continuity: (V4PoolStoreIdentity) throws -> Void
    private let disk: V4PersistentDiskCharge
    private var retired = false
    private var opening = false
    fileprivate weak var active: V4SQLitePoolStore?

    init(
      environment: V4EnvironmentFoundation, directory: URL, identity: V4PoolStoreIdentity,
      maximumBytes: Int, maximumRows: Int,
      continuity: @escaping (V4PoolStoreIdentity) throws -> Void
    ) throws {
      guard directory.isFileURL,
        directory.standardizedFileURL.path == directory.resolvingSymlinksInPath().path,
        directory.path.utf8.count <= 2048, !directory.path.utf8.contains(0),
        identity.storeID.count == 16, identity.storeID.contains(where: { $0 != 0 }),
        identity.generation > 0, identity.issuer.count == 16,
        [identity.tenant, identity.spendAuthority, identity.winnerAuthority]
          .allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
        ((1 << 20)...(1 << 30)).contains(maximumBytes), maximumBytes % 4096 == 0,
        (1...65536).contains(maximumRows)
      else { throw V4PoolFailure.configuration }
      var info = stat()
      guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
        info.st_uid == geteuid(), info.st_mode & 0o077 == 0
      else { throw V4PoolFailure.configuration }
      self.environment = environment
      self.identity = identity
      path = directory.appendingPathComponent("spend.sqlite3").path
      self.maximumBytes = maximumBytes
      self.maximumRows = maximumRows
      self.continuity = continuity
      try continuity(identity)
      disk = try environment.poolDiskStorage(diskBytes: UInt64(maximumBytes) * 3)
    }
    fileprivate func check() throws {
      guard !retired else { throw V4PoolFailure.closed }
      try disk.check()
      try continuity(identity)
      guard !retired else { throw V4PoolFailure.closed }
      try disk.check()
    }
    func open(create: Bool) throws -> V4SQLitePoolStore {
      try environment.gate.withLock {
        guard active == nil, !opening else { throw V4PoolFailure.conflict }
        opening = true
        defer { opening = false }
        try check()
        let store = try V4SQLitePoolStore(backing: self, create: create)
        do { try environment.registerNativeConnection(store) } catch {
          store.close()
          throw error
        }
        active = store
        return store
      }
    }
    func retireRemovedFiles() throws {
      try environment.gate.withLock {
        guard !retired, active == nil else { throw V4PoolFailure.closed }
        for suffix in ["", ".lock", "-journal", "-wal", "-shm"] {
          var info = stat()
          guard lstat(path + suffix, &info) != 0, errno == ENOENT else {
            throw V4PoolFailure.storage
          }
        }
        retired = true
        disk.retire()
      }
    }
  }

  final class V4SQLitePoolStore: V4NativeConnectionLifecycle, @unchecked Sendable {
    private static let manifest =
      "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), identity BLOB NOT NULL, rows INTEGER NOT NULL CHECK(rows>=0), max_rows INTEGER NOT NULL, max_bytes INTEGER NOT NULL) STRICT"
    private static let spend =
      "CREATE TABLE spend (lease BLOB PRIMARY KEY, source INTEGER NOT NULL CHECK(source=1), consumed BLOB NOT NULL) STRICT, WITHOUT ROWID"
    private let backing: V4PoolStoreBacking
    private let runtime: V4CryptoReservation
    private var db: OpaquePointer?
    private var descriptor: Int32 = -1
    private var lockDescriptor: Int32 = -1
    private var fileIdentity = stat()
    private var lockIdentity = stat()
    private var busy = false
    fileprivate init(backing: V4PoolStoreBacking, create: Bool) throws {
      self.backing = backing
      runtime = try backing.environment.poolStoreStorage()
      do {
        // Darwin flock and SQLite's fcntl locks conflict on the same inode.
        // Keep the exclusive deployment lease on a separately owned sidecar.
        lockDescriptor = Darwin.open(
          backing.path + ".lock",
          O_RDWR | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
        guard lockDescriptor >= 0, fstat(lockDescriptor, &lockIdentity) == 0,
          lockIdentity.st_mode & S_IFMT == S_IFREG, lockIdentity.st_mode & 0o077 == 0,
          lockIdentity.st_uid == geteuid(), lockIdentity.st_nlink == 1,
          flock(lockDescriptor, LOCK_EX | LOCK_NB) == 0
        else { throw V4PoolFailure.storage }
        descriptor = Darwin.open(
          backing.path,
          O_RDWR | O_NOFOLLOW | O_CLOEXEC | (create ? O_CREAT | O_EXCL : 0), 0o600)
        guard descriptor >= 0, fstat(descriptor, &fileIdentity) == 0,
          fileIdentity.st_mode & S_IFMT == S_IFREG, fileIdentity.st_mode & 0o077 == 0,
          fileIdentity.st_uid == geteuid(), fileIdentity.st_nlink == 1,
          sqlite3_open_v2(
            backing.path, &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
              | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK
        else { throw V4PoolFailure.storage }
        sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 32768)
        sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 4096)
        sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 8)
        sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 8)
        sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0)
        try exec("PRAGMA journal_mode=DELETE")
        try exec("PRAGMA synchronous=FULL")
        try exec("PRAGMA fullfsync=ON")
        try exec("PRAGMA trusted_schema=OFF")
        try exec("PRAGMA mmap_size=0")
        try exec("PRAGMA temp_store=MEMORY")
        try exec("PRAGMA cache_size=-256")
        if create { try exec("PRAGMA page_size=4096") }
        guard try scalar("PRAGMA page_size") == 4096,
          try scalar("PRAGMA max_page_count=\(backing.maximumBytes / 4096)")
            == backing.maximumBytes / 4096
        else { throw V4PoolFailure.storage }
        if create {
          try exec("BEGIN IMMEDIATE")
          try exec(Self.manifest)
          try exec(Self.spend)
          try execute(
            "INSERT INTO manifest VALUES(1,?1,0,?2,?3)",
            blobs: [backing.identity.bytes], integers: [backing.maximumRows, backing.maximumBytes])
          try exec("COMMIT")
          let directory = Darwin.open(
            URL(fileURLWithPath: backing.path).deletingLastPathComponent().path,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
          guard directory >= 0 else { throw V4PoolFailure.storage }
          defer { Darwin.close(directory) }
          guard fsync(directory) == 0 else { throw V4PoolFailure.storage }
        }
        try check()
        try validate()
      } catch {
        close()
        throw error
      }
    }
    private func statement(_ sql: String) throws -> OpaquePointer {
      guard let db else { throw V4PoolFailure.closed }
      var result: OpaquePointer?
      guard sqlite3_prepare_v2(db, sql, -1, &result, nil) == SQLITE_OK, let result else {
        throw V4PoolFailure.storage
      }
      return result
    }
    private func exec(_ sql: String) throws {
      guard let db, sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
        throw V4PoolFailure.storage
      }
    }
    private func bind(_ bytes: Data, to statement: OpaquePointer, at index: Int32) throws {
      let code = bytes.withUnsafeBytes {
        sqlite3_bind_blob(
          statement, index, $0.baseAddress, Int32($0.count),
          unsafeBitCast(-1, to: sqlite3_destructor_type.self))
      }
      guard code == SQLITE_OK else { throw V4PoolFailure.storage }
    }
    private func execute(_ sql: String, blobs: [Data], integers: [Int] = []) throws {
      let s = try statement(sql)
      defer { sqlite3_finalize(s) }
      for (index, bytes) in blobs.enumerated() { try bind(bytes, to: s, at: Int32(index + 1)) }
      for (index, integer) in integers.enumerated() {
        guard sqlite3_bind_int64(s, Int32(blobs.count + index + 1), Int64(integer)) == SQLITE_OK
        else {
          throw V4PoolFailure.storage
        }
      }
      let result = sqlite3_step(s)
      if result == SQLITE_CONSTRAINT { throw V4PoolFailure.conflict }
      guard result == SQLITE_DONE else { throw V4PoolFailure.storage }
    }
    private func scalar(_ sql: String) throws -> Int {
      let s = try statement(sql)
      defer { sqlite3_finalize(s) }
      guard sqlite3_step(s) == SQLITE_ROW, sqlite3_column_type(s, 0) == SQLITE_INTEGER else {
        throw V4PoolFailure.storage
      }
      let n = sqlite3_column_int64(s, 0)
      guard n >= 0, n <= Int.max, sqlite3_step(s) == SQLITE_DONE else {
        throw V4PoolFailure.storage
      }
      return Int(n)
    }
    private func blob(_ s: OpaquePointer, _ index: Int32) throws -> Data {
      let count = Int(sqlite3_column_bytes(s, index))
      guard sqlite3_column_type(s, index) == SQLITE_BLOB, (1...16384).contains(count),
        let bytes = sqlite3_column_blob(s, index)
      else { throw V4PoolFailure.storage }
      return Data(bytes: bytes, count: count)
    }
    private func check() throws {
      guard db != nil, descriptor >= 0 else { throw V4PoolFailure.closed }
      try runtime.check()
      try backing.check()
      try runtime.check()
      guard db != nil, descriptor >= 0 else { throw V4PoolFailure.closed }
      var info = stat()
      guard lstat(backing.path, &info) == 0, info.st_ino == fileIdentity.st_ino,
        info.st_dev == fileIdentity.st_dev, info.st_nlink == 1,
        info.st_size <= backing.maximumBytes
      else { throw V4PoolFailure.storage }
      guard lstat(backing.path + ".lock", &info) == 0, info.st_ino == lockIdentity.st_ino,
        info.st_dev == lockIdentity.st_dev, info.st_nlink == 1
      else { throw V4PoolFailure.storage }
    }
    private func validate() throws {
      let schema = try statement(
        "SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
      defer { sqlite3_finalize(schema) }
      for expected in [Self.manifest, Self.spend] {
        guard sqlite3_step(schema) == SQLITE_ROW, let sql = sqlite3_column_text(schema, 0),
          String(cString: sql) == expected
        else { throw V4PoolFailure.storage }
      }
      guard sqlite3_step(schema) == SQLITE_DONE else { throw V4PoolFailure.storage }
      let s = try statement("SELECT identity,rows,max_rows,max_bytes FROM manifest WHERE id=1")
      defer { sqlite3_finalize(s) }
      guard sqlite3_step(s) == SQLITE_ROW, try blob(s, 0) == backing.identity.bytes,
        sqlite3_column_int64(s, 2) == backing.maximumRows,
        sqlite3_column_int64(s, 3) == backing.maximumBytes,
        try scalar("SELECT count(*) FROM manifest") == 1,
        try scalar("SELECT count(*) FROM spend") == sqlite3_column_int64(s, 1),
        sqlite3_column_int64(s, 1) <= backing.maximumRows,
        sqlite3_step(s) == SQLITE_DONE
      else { throw V4PoolFailure.storage }
    }
    // The only continuation is created on the stack of the original successful
    // COMMIT. Every failure (including a post-COMMIT guard) is final. No query,
    // retry, existing row or reopened connection can mint this native handoff.
    func consume(_ claim: V4PreparedPoolClaim) throws -> V4ConsumedWebSocket {
      try backing.environment.gate.withLock {
        guard !busy, claim.environment === backing.environment else { throw V4PoolFailure.closed }
        busy = true
        defer { busy = false }
        do {
          try check()
          try claim.check()
          try backing.identity.check(claim.facts)
          let projection = V4Crypto.map([
            (0, V4Crypto.bytes(backing.identity.bytes)),
            (1, V4Crypto.bytes(claim.operationID)), (2, V4Crypto.bytes(claim.carrierID)),
            (3, V4Crypto.bytes(claim.facts.projection)),
          ])
          guard projection.count <= 16384 else { throw V4PoolFailure.capacity }
          try exec("BEGIN IMMEDIATE")
          try validate()
          guard try scalar("SELECT rows FROM manifest WHERE id=1") < backing.maximumRows else {
            throw V4PoolFailure.capacity
          }
          try execute("INSERT INTO spend VALUES(?1,1,?2)", blobs: [claim.facts.key, projection])
          try exec("UPDATE manifest SET rows=rows+1 WHERE id=1")
          try check()
          try claim.check()
          try exec("COMMIT")
          try check()
          try claim.check()
          return V4ConsumedWebSocket(claim)
        } catch {
          try? exec("ROLLBACK")
          claim.close()
          close()
          throw error
        }
      }
    }
    func close() {
      backing.environment.gate.withLock {
        if let db {
          sqlite3_close_v2(db)
          self.db = nil
        }
        if descriptor >= 0 {
          Darwin.close(descriptor)
          descriptor = -1
        }
        if lockDescriptor >= 0 {
          Darwin.close(lockDescriptor)
          lockDescriptor = -1
        }
        runtime.seal()
        if backing.active === self { backing.active = nil }
      }
    }
    deinit { close() }
  }

  // This is a consumed native connection, not an established Session. Its
  // original ten-second preparation deadline remains in force until actual
  // Hello/FSB/FSA/Noise/READY orchestration performs a separate handoff.
  final class V4ConsumedWebSocket: V4HandshakeWriter, V4RecordPublisher, @unchecked Sendable {
    private let claim: V4PreparedPoolClaim
    fileprivate init(_ claim: V4PreparedPoolClaim) { self.claim = claim }
    func check() throws { try claim.check() }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws { try publish(buffer) }
    func publish(_ buffer: V4CryptoBuffer) throws { try claim.publish(buffer) }
    func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws {
      try claim.publish(buffer, completion: completion)
    }
    func receive() async throws -> V4CryptoBuffer { try await claim.receive() }
    func flush() async throws { try await claim.flush() }
    func writable() throws -> Bool { try claim.writable() }
    func wakeup(_ action: (@Sendable () -> Void)?) { claim.wakeup(action) }
    func recordCompletion(_ action: (@Sendable () throws -> Void)?) {
      claim.recordCompletion(action)
    }
    func promote(_ admission: V4NativeSessionAdmission) throws {
      guard admission.socket === self else { throw V4CryptoFailure.phase }
      try claim.promote()
    }
    func close() { claim.close() }
    func waitClosed() async { await claim.waitClosed() }
    deinit { claim.close() }
  }
#endif
