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
  final class V4PoolStoreBacking: @unchecked Sendable {
    let environment: V4EnvironmentFoundation
    let identity: V4PoolStoreIdentity
    fileprivate(set) var parentWinner: ParentWinnerAuthorityConfiguration?
    fileprivate let path: String
    fileprivate let maximumBytes: Int
    fileprivate let maximumRows: Int
    fileprivate let continuity: (V4PoolStoreIdentity) throws -> Void
    private let disk: V4PersistentDiskCharge
    private var retired = false
    private var opening = false
    fileprivate var closing = false
    fileprivate var pendingCleanup: V4SQLiteCleanup?
    private var retiring = false
    fileprivate weak var active: V4SQLitePoolStore?

    init(
      environment: V4EnvironmentFoundation, directory: URL, identity: V4PoolStoreIdentity,
      maximumBytes: Int, maximumRows: Int, parentWinner: ParentWinnerAuthorityConfiguration? = nil,
      continuity: @escaping (V4PoolStoreIdentity) throws -> Void
    ) throws {
      let setup = try environment.poolStoreStorage()
      let tail = try setup.executionTail()
      defer { setup.seal(); tail.release() }
      guard directory.isFileURL,
        directory.standardizedFileURL.path == directory.resolvingSymlinksInPath().path,
        directory.path.utf8.count <= 2048, !directory.path.utf8.contains(0),
        identity.storeID.count == 16, identity.storeID.contains(where: { $0 != 0 }),
        identity.generation > 0, identity.issuer.count == 16,
        [identity.tenant, identity.spendAuthority, identity.winnerAuthority]
          .allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
        ((1 << 20)...(1 << 30)).contains(maximumBytes), maximumBytes % 4096 == 0,
        (1...65536).contains(maximumRows),
        parentWinner == nil || parentWinner?.authority == identity.winnerAuthority
      else { throw V4PoolFailure.configuration }
      var info = stat()
      guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
        info.st_uid == geteuid(), info.st_mode & 0o077 == 0
      else { throw V4PoolFailure.configuration }
      self.environment = environment
      self.identity = identity; self.parentWinner = parentWinner
      path = directory.appendingPathComponent("spend.sqlite3").path
      self.maximumBytes = maximumBytes
      self.maximumRows = maximumRows
      self.continuity = continuity
      try continuity(identity)
      try setup.check(); try Task.checkCancellation()
      disk = try environment.poolDiskStorage(diskBytes: UInt64(maximumBytes) * 3)
    }
    fileprivate func check() throws {
      try environment.gate.withLock {
        guard !retired else { throw V4PoolFailure.closed }
        try disk.check()
      }
      try continuity(identity)
      try environment.gate.withLock {
        guard !retired else { throw V4PoolFailure.closed }
        try disk.check()
      }
    }
    // The pool backing is fixed before any server claim can be consumed,
    // and a second authority cannot be swapped in.
    func installParentWinner(_ configuration: ParentWinnerAuthorityConfiguration) throws {
      let (setup, tail) = try environment.gate.withLock { () throws -> (V4CryptoReservation, V4ResourceReference) in
        guard !retired, active != nil, parentWinner == nil,
          configuration.authority == identity.winnerAuthority else { throw V4PoolFailure.configuration }
        let setup = try environment.poolStoreStorage()
        return (setup, try setup.executionTail())
      }
      defer { setup.seal(); tail.release() }
      try check()
      try environment.gate.withLock {
        try setup.check(); try Task.checkCancellation()
        guard !retired, active != nil, parentWinner == nil else { throw V4PoolFailure.closed }
        parentWinner = configuration
      }
    }
    func open(create: Bool) throws -> V4SQLitePoolStore {
      let (runtime, tail) = try environment.gate.withLock { () throws -> (V4CryptoReservation, V4ResourceReference) in
        guard active == nil, !opening, !closing, !retiring, !retired else { throw V4PoolFailure.conflict }
        let runtime = try environment.poolStoreStorage()
        let tail = try runtime.executionTail()
        opening = true
        return (runtime, tail)
      }
      defer { tail.release() }
      do {
        try check()
        let store = try V4SQLitePoolStore(backing: self, create: create, runtime: runtime)
        do {
          try environment.gate.withLock {
            try runtime.check(); try Task.checkCancellation()
            guard !retired, !retiring, active == nil else { throw V4PoolFailure.closed }
            try environment.registerNativeConnection(store)
            active = store; opening = false
          }
        } catch { store.close(); throw error }
        return store
      } catch {
        runtime.seal()
        if (error as? V4PoolFailure) == .storage || error is StorageFormatError { environment.root.diagnosticCounters.increment(.storeFailures) }
        environment.gate.withLock { opening = false }
        throw error
      }
    }
    func waitPhysicalCleanup() async {
      let cleanup = environment.gate.withLock { pendingCleanup }
      await cleanup?.waitPhysicalCleanup()
    }
    func retireRemovedFiles() throws {
      let tail = try environment.gate.withLock { () throws -> V4ResourceReference in
        guard !retired, !opening, !closing, active == nil, !retiring else { throw V4PoolFailure.closed }
        let tail = try disk.executionTail()
        retiring = true
        return tail
      }
      defer { tail.release() }
      do {
        for suffix in ["", ".lock", "-journal", "-wal", "-shm"] {
          var info = stat()
          guard lstat(path + suffix, &info) != 0, errno == ENOENT else {
            throw V4PoolFailure.storage
          }
        }
        try environment.gate.withLock {
          try disk.check(); try Task.checkCancellation()
          guard !opening, active == nil else { throw V4PoolFailure.conflict }
          retired = true; retiring = false; disk.retire()
        }
      } catch {
        if (error as? V4PoolFailure) == .storage { environment.root.diagnosticCounters.increment(.storeFailures) }
        environment.gate.withLock { retiring = false }
        throw error
      }
    }
  }

  final class V4SQLitePoolStore: V4NativeConnectionLifecycle, @unchecked Sendable {
    private static let format = V4SQLiteStorageFormat(group: .pool)
    private static let manifest =
      format.manifest(suffix: ", rows INTEGER NOT NULL CHECK(rows>=0), max_rows INTEGER NOT NULL, max_bytes INTEGER NOT NULL")
    private static let refusals =
      "CREATE TABLE refusals (lease BLOB PRIMARY KEY, original BLOB NOT NULL) STRICT, WITHOUT ROWID"
    private static let spend =
      "CREATE TABLE spend (lease BLOB PRIMARY KEY, source INTEGER NOT NULL CHECK(source=1), consumed BLOB NOT NULL) STRICT, WITHOUT ROWID"
    private let backing: V4PoolStoreBacking
    private let runtime: V4CryptoReservation
    private let cleanup: V4SQLiteCleanup
    private let directoryPath: String
    private var db: OpaquePointer?
    private var descriptor: Int32 = -1
    private var lockDescriptor: Int32 = -1
    private var fileIdentity = stat()
    private var lockIdentity = stat()
    private var directoryIdentity = stat()
    private var busy = false
    private var closed = false
    fileprivate init(backing: V4PoolStoreBacking, create: Bool, runtime: V4CryptoReservation) throws {
      self.backing = backing
      self.runtime = runtime
      directoryPath = URL(fileURLWithPath: backing.path).deletingLastPathComponent().path
      cleanup = try V4SQLiteCleanup(environment: backing.environment, storage: runtime)
      do {
        guard lstat(directoryPath, &directoryIdentity) == 0,
          V4LiveServerAdmissionLedger.safe(directoryIdentity, directory: true) else { throw V4PoolFailure.storage }
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
        if !create { try V4SQLiteAdmission.prepare(db!) }
        try configureReader()
        if !create {
          try admitCurrentFormat()
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
        if create { try exec("PRAGMA page_size=4096") }
        guard try scalar("PRAGMA page_size") == 4096,
          try scalar("PRAGMA max_page_count=\(backing.maximumBytes / 4096)")
            == backing.maximumBytes / 4096
        else { throw V4PoolFailure.storage }
        if create {
          try exec("BEGIN IMMEDIATE")
          try exec(Self.manifest)
          try exec(Self.refusals)
          try exec(Self.spend)
          try exec("PRAGMA user_version=\(Self.format.requiredRevision)")
          try execute(
            "INSERT INTO manifest(id,format,revision,identity,rows,max_rows,max_bytes) VALUES(1,'\(Self.format.group.rawValue)',\(Self.format.requiredRevision),?1,0,?2,?3)",
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
    private func configureReader() throws {
      guard let db else { throw V4PoolFailure.closed }
      sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 32768)
      sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 4096)
      sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 8)
      sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 8)
      sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0)
      try exec("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-256; PRAGMA mmap_size=0; PRAGMA busy_timeout=0")
    }
    private func admitCurrentFormat() throws {
      guard let db else { throw V4PoolFailure.closed }
      var observed = StorageRevision.unknown
      do {
        try checkFileIdentity()
        try exec("BEGIN")
        observed = try Self.format.inspect(db, identity: backing.identity.bytes)
        try validate()
        guard try scalar("PRAGMA page_size") == 4096,
          try scalar("PRAGMA page_count") <= backing.maximumBytes / 4096 else {
          throw Self.format.refusal(.backendConfiguration, observed: observed)
        }
        try validateRecords()
        try checkFileIdentity()
        try exec("ROLLBACK")
      } catch {
        let code = sqlite3_errcode(db)
        try? exec("ROLLBACK")
        if let format = error as? StorageFormatError { throw format }
        throw Self.format.refusal(.schemaOrStateInvalid,
          observed: code == SQLITE_CORRUPT || code == SQLITE_NOTADB ? .unknown : observed)
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
      try backing.environment.gate.withLock {
        guard !closed, db != nil, descriptor >= 0 else { throw V4PoolFailure.closed }
        try runtime.check(); try Task.checkCancellation()
      }
      try backing.check()
      try backing.environment.gate.withLock {
        guard !closed, db != nil, descriptor >= 0 else { throw V4PoolFailure.closed }
        try runtime.check(); try Task.checkCancellation()
      }
      try checkFileIdentity()
    }
    private func checkFileIdentity() throws {
      guard let db else { throw V4PoolFailure.closed }
      var info = stat(); var moved: Int32 = 0
      guard lstat(directoryPath, &info) == 0, V4LiveServerAdmissionLedger.safe(info, directory: true),
        info.st_dev == directoryIdentity.st_dev, info.st_ino == directoryIdentity.st_ino,
        fstat(descriptor, &info) == 0, info.st_dev == fileIdentity.st_dev, info.st_ino == fileIdentity.st_ino,
        lstat(backing.path, &info) == 0, V4LiveServerAdmissionLedger.safe(info),
        info.st_ino == fileIdentity.st_ino, info.st_dev == fileIdentity.st_dev,
        info.st_size >= 0, info.st_size <= backing.maximumBytes,
        fstat(lockDescriptor, &info) == 0, info.st_dev == lockIdentity.st_dev, info.st_ino == lockIdentity.st_ino,
        lstat(backing.path + ".lock", &info) == 0, V4LiveServerAdmissionLedger.safe(info),
        info.st_ino == lockIdentity.st_ino, info.st_dev == lockIdentity.st_dev, info.st_size == 0,
        sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else { throw V4PoolFailure.storage }
      for suffix in ["-journal", "-wal", "-shm"] {
        if lstat(backing.path + suffix, &info) == 0 {
          guard V4LiveServerAdmissionLedger.safe(info), info.st_size >= 0,
            info.st_size <= backing.maximumBytes else { throw V4PoolFailure.storage }
        } else if errno != ENOENT { throw V4PoolFailure.storage }
      }
    }
    private func validate() throws {
      let schema = try statement(
        "SELECT type,name,sql FROM sqlite_schema ORDER BY name LIMIT 4")
      defer { sqlite3_finalize(schema) }
      for (name, expected) in [("manifest", Self.manifest), ("refusals", Self.refusals), ("spend", Self.spend)] {
        guard sqlite3_step(schema) == SQLITE_ROW,
          sqlite3_column_type(schema, 0) == SQLITE_TEXT, let type = sqlite3_column_text(schema, 0), String(cString: type) == "table",
          sqlite3_column_type(schema, 1) == SQLITE_TEXT, let actualName = sqlite3_column_text(schema, 1), String(cString: actualName) == name,
          sqlite3_column_type(schema, 2) == SQLITE_TEXT, let sql = sqlite3_column_text(schema, 2), String(cString: sql) == expected
        else { throw V4PoolFailure.storage }
      }
      guard sqlite3_step(schema) == SQLITE_DONE else { throw V4PoolFailure.storage }
      let s = try statement("SELECT identity,rows,max_rows,max_bytes FROM manifest WHERE id=1")
      defer { sqlite3_finalize(s) }
      guard sqlite3_step(s) == SQLITE_ROW, try blob(s, 0) == backing.identity.bytes,
        sqlite3_column_type(s, 1) == SQLITE_INTEGER, sqlite3_column_int64(s, 1) >= 0,
        sqlite3_column_type(s, 2) == SQLITE_INTEGER, sqlite3_column_type(s, 3) == SQLITE_INTEGER,
        sqlite3_column_int64(s, 2) == backing.maximumRows,
        sqlite3_column_int64(s, 3) == backing.maximumBytes,
        try scalar("SELECT count(*) FROM manifest") == 1,
        try scalar("SELECT count(*) FROM spend") == sqlite3_column_int64(s, 1),
        try scalar("SELECT (SELECT count(*) FROM spend) + (SELECT count(*) FROM refusals)") <= backing.maximumRows,
        sqlite3_step(s) == SQLITE_DONE
      else { throw V4PoolFailure.storage }
    }
    private func validateRecords() throws {
      let integrity = try statement("PRAGMA quick_check(1)"); defer { sqlite3_finalize(integrity) }
      guard sqlite3_step(integrity) == SQLITE_ROW, sqlite3_column_type(integrity, 0) == SQLITE_TEXT,
        let result = sqlite3_column_text(integrity, 0), String(cString: result) == "ok",
        sqlite3_step(integrity) == SQLITE_DONE else { throw V4PoolFailure.storage }
      let registry = try V4NamespaceRegistry()
      // Refusal-only originals and client-side spend-only rows are valid.
      // When both facts exist, they must describe the same original call.
      let rows = try statement("SELECT refusals.lease,refusals.original,spend.consumed FROM refusals LEFT JOIN spend ON spend.lease=refusals.lease UNION ALL SELECT spend.lease,NULL,spend.consumed FROM spend WHERE NOT EXISTS(SELECT 1 FROM refusals WHERE refusals.lease=spend.lease) LIMIT \(backing.maximumRows + 1)")
      defer { sqlite3_finalize(rows) }
      var count = 0
      while true {
        let result = sqlite3_step(rows); if result == SQLITE_DONE { break }
        count += 1
        guard result == SQLITE_ROW, count <= backing.maximumRows else { throw V4PoolFailure.storage }
        let lease = try blob(rows, 0)
        let original: Data?, consumed: Data?
        if sqlite3_column_type(rows, 1) == SQLITE_NULL { original = nil } else { original = try blob(rows, 1) }
        if sqlite3_column_type(rows, 2) == SQLITE_NULL { consumed = nil } else { consumed = try blob(rows, 2) }
        guard let projection = original ?? consumed, original == nil || consumed == nil || original == consumed else { throw V4PoolFailure.storage }
        try validateProjection(projection, lease: lease, registry: registry)
      }
    }
    private func validateProjection(_ encoded: Data, lease key: Data, registry: V4NamespaceRegistry) throws {
      var lease = V4PoolWireCursor(key, maximum: 512)
      try lease.map(3); try lease.key(0); let tenant = try lease.text(maximum: 128)
      try lease.key(1); let issuer = try lease.bytes(maximum: 16)
      try lease.key(2); let leaseID = try lease.bytes(maximum: 16); try lease.end()
      guard tenant == backing.identity.tenant, issuer == backing.identity.issuer, leaseID.count == 16 else { throw V4PoolFailure.storage }
      var original = V4PoolWireCursor(encoded, maximum: 16_384)
      try original.map(4); try original.key(0)
      guard try original.bytes(maximum: 2048) == backing.identity.bytes else { throw V4PoolFailure.storage }
      try original.key(1); let operation = try original.bytes(maximum: 16)
      try original.key(2); let carrier = try original.bytes(maximum: 16)
      try original.key(3); let projection = try original.bytes(maximum: 8192); try original.end()
      guard operation.count == 16, carrier.count == 16 else { throw V4PoolFailure.storage }
      var facts = V4PoolWireCursor(projection, maximum: 8192)
      try facts.map(8); try facts.key(0)
      guard try facts.text(maximum: 64) == "flowersec/swift/pool-consume/1" else { throw V4PoolFailure.storage }
      try facts.key(1); let artifact = try facts.bytes(maximum: 32)
      try facts.key(2); let activation = try facts.bytes(maximum: 32)
      try facts.key(3); let nonce = try facts.bytes(maximum: 32)
      try facts.key(4); let candidate = try facts.bytes(maximum: 16)
      try facts.key(5); let route = try facts.bytes(maximum: 32)
      try facts.key(6); let candidateIndex = try facts.uint()
      try facts.key(7); let authorizationWire = try facts.bytes(maximum: 4096); try facts.end()
      guard artifact.count == 32, activation.count == 32, nonce.count == 32, nonce.contains(where: { $0 != 0 }),
        candidate.count == 16, route.count == 32, candidateIndex < 16 else { throw V4PoolFailure.storage }
      let authorization = try V4NamespaceDocument(authorizationWire, schema: "ActivationAuthorization", bytes: 4096,
        nodes: 512, registry: registry, context: ["activation_source_profile": V4ActivationSource.preauthorizedPool.rawValue]).root
      let selected = try authorization.field("candidate_selection"), once = try selected.field("once_authority_ref")
      guard try authorization.digest("activation_digest") == activation, try authorization.t("tenant_id") == tenant,
        try authorization.b("artifact_issuer_key_id") == issuer, try authorization.b("lease_id") == leaseID,
        try authorization.b("artifact_digest") == artifact, try selected.b("artifact_digest") == artifact,
        try selected.field("candidate_indices").children.contains(where: { try $0.uint() == candidateIndex }),
        try once.t("tenant_id") == tenant, try once.b("artifact_issuer_key_id") == issuer,
        try once.t("spend_authority_id") == backing.identity.spendAuthority,
        try once.t("winner_authority_id") == backing.identity.winnerAuthority else { throw V4PoolFailure.storage }
    }
    // The only continuation is created on the stack of the original successful
    // COMMIT. Every failure (including a post-COMMIT guard) is final. No query,
    // retry, existing row or reopened connection can mint this native handoff.
    func consume(_ claim: V4PreparedPoolClaim) throws -> V4ConsumedWebSocket {
      guard let facts = claim.facts else { throw V4PoolFailure.closed }
      let (tail, parentWinner) = try backing.environment.gate.withLock { () throws -> (V4ResourceReference, ParentWinnerAuthorityConfiguration?) in
        guard !closed, !busy, claim.environment === backing.environment else { throw V4PoolFailure.closed }
        try claim.check(); try Task.checkCancellation()
        let tail = try runtime.executionTail()
        busy = true
        return (tail, backing.parentWinner)
      }
      defer {
        let closing = backing.environment.gate.withLock { () -> Bool in
          if !closed { busy = false }
          return closed
        }
        if closing {
          closeStorage()
          backing.environment.gate.withLock { busy = false }
        }
        tail.release()
      }
      // The original operation exclusively owns these handles until its tail
      // exits. Close fences access immediately without interrupting COMMIT.
      var commitDispatched = false
      do {
          try check()
          try claim.check()
          try backing.identity.check(facts)
          let projection = V4Crypto.map([
            (0, V4Crypto.bytes(backing.identity.bytes)),
            (1, V4Crypto.bytes(claim.operationID)), (2, V4Crypto.bytes(claim.carrierID)),
            (3, V4Crypto.bytes(facts.projection)),
          ])
          guard projection.count <= 16384 else { throw V4PoolFailure.capacity }
          if claim.localRole == .server {
            guard let configured = parentWinner else { throw V4PoolFailure.configuration }
            _ = try facts.credential.parentWinnerSelection(authority: configured.authority)
            // This refusal is not admission. It binds the original native
            // claim before the independent CAS can become uncertain. No read
            // of this row can continue or reconstruct that original claim.
            try exec("BEGIN IMMEDIATE"); try validate()
            guard try scalar("SELECT (SELECT count(*) FROM spend) + (SELECT count(*) FROM refusals)") <= backing.maximumRows - 2 else { throw V4PoolFailure.capacity }
            try execute("INSERT INTO refusals VALUES(?1,?2)", blobs: [facts.key, projection])
            try check(); try claim.check(); try exec("COMMIT"); try check(); try claim.check()
            let winner = try V4OriginalParentWinner.select(configuration: parentWinner,
              claim: claim,
              willDispatch: { facts.credential.connectionFacts.spendDispatched() },
              didCommit: { facts.credential.connectionFacts.spent() }) { try self.check(); try claim.check() }
            try winner.consume(owner: claim, admission: facts.credential)
          }
          try exec("BEGIN IMMEDIATE")
          try validate()
          guard try scalar("SELECT (SELECT count(*) FROM spend) + (SELECT count(*) FROM refusals)") < backing.maximumRows else {
            throw V4PoolFailure.capacity
          }
          try execute("INSERT INTO spend VALUES(?1,1,?2)", blobs: [facts.key, projection])
          try exec("UPDATE manifest SET rows=rows+1 WHERE id=1")
          try check()
          try claim.check()
          facts.credential.connectionFacts.spendDispatched()
          if claim.localRole == .server { facts.credential.connectionFacts.admissionDispatched() }
          commitDispatched = true
          try exec("COMMIT")
          facts.credential.connectionFacts.spent()
          if claim.localRole == .server { facts.credential.connectionFacts.admitted() }
          try check()
          try claim.check()
          return V4ConsumedWebSocket(claim)
        } catch {
          if let failure = error as? V4PoolFailure {
            switch failure {
            case .storage: backing.environment.root.diagnosticCounters.increment(.storeFailures)
            case .conflict: backing.environment.root.diagnosticCounters.increment(.reservationConflicts)
            case .capacity: backing.environment.root.diagnosticCounters.increment(.resourceRefusals)
            case .configuration, .closed: break
            }
          }
          if (try? exec("ROLLBACK")) != nil, !commitDispatched {
            facts.credential.connectionFacts.spendConfirmedAbsent()
            if claim.localRole == .server { facts.credential.connectionFacts.admissionRejected() }
          }
          claim.close()
          close()
          throw error
        }
    }
    func close() {
      backing.environment.gate.withLock {
        closed = true
        cleanup.beginClose()
        runtime.seal()
        if !busy { closeStorage() }
      }
    }
    private func closeStorage() {
      backing.environment.gate.withLock {
        guard !cleanup.started else { return }
        backing.closing = true
        backing.pendingCleanup = cleanup
        cleanup.start(database: db, file: descriptor, lockFile: lockDescriptor) { [backing] in
          backing.active = nil; backing.closing = false; backing.pendingCleanup = nil
        }
        db = nil; descriptor = -1; lockDescriptor = -1
      }
    }
    func waitPhysicalCleanup() async { await cleanup.waitPhysicalCleanup() }
    deinit { close() }
  }

  // This is a consumed native connection, not an established Session. Its
  // original ten-second preparation deadline remains in force until actual
  // Hello/FSB/FSA/Noise/READY orchestration performs a separate handoff.
  final class V4ConsumedWebSocket: V4HandshakeWriter, V4RecordPublisher, V4TunnelAuthenticationCarrier, @unchecked Sendable {
    private let claim: V4PreparedPoolClaim
    fileprivate init(_ claim: V4PreparedPoolClaim) { self.claim = claim }
    static func live(_ claim: V4PreparedPoolClaim) throws -> V4ConsumedWebSocket {
      guard claim.facts == nil, claim.localRole == .client else { throw V4CryptoFailure.phase }
      try claim.check()
      return V4ConsumedWebSocket(claim)
    }
    static func liveServer(_ admission: V4OriginalLiveServerAdmission) throws -> V4ConsumedWebSocket {
      let claim = try admission.takeClaim()
      guard claim.facts == nil, claim.localRole == .server else { throw V4CryptoFailure.phase }
      return V4ConsumedWebSocket(claim)
    }
    func check() throws { try claim.check() }
    var tunnelCarrierIdentity: AnyObject { claim.tunnelCarrierIdentity }
    func claimTunnelChallenge(credential: V4CredentialAdmission) throws -> (Data, Data) {
      try claim.claimTunnelChallenge(credential: credential)
    }
    func checkHop(_ hop: V4TunnelHop) throws { try hop.checkCarrier(tunnelCarrierIdentity) }
    func submit(_ flight: V4HandshakeFlight, buffer: V4CryptoBuffer) throws { try publish(buffer) }
    func publish(_ buffer: V4CryptoBuffer) throws { try claim.publish(buffer) }
    func publish(_ buffer: V4CryptoBuffer, admissionCheck: () throws -> Void) throws {
      try claim.publish(buffer, admissionCheck: admissionCheck)
    }
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
