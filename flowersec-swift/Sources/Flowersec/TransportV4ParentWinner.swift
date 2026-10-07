#if os(macOS) || os(iOS)
import Darwin
import Foundation
import SQLite3

/// Public immutable selection evidence. This value carries no carrier,
/// admission or forwarding capability and cannot activate a stored selection.
public struct ParentWinnerSelection: Sendable, Equatable, CustomStringConvertible {
  public let authority: String
  public let parent: Data
  public let projection: Data
  init(authority: String, parent: Data, projection: Data) {
    self.authority = authority; self.parent = parent; self.projection = projection
  }
  public var description: String { "Flowersec.ParentWinnerSelection(<redacted>)" }
}

/// Independently installed common authority shared by every direct and tunnel
/// admission for a parent. The qualified adapter must durably compare and set
/// unselected to the exact projection, return that same fact for an exact
/// retry, and fail on conflict or uncertain COMMIT. It must never retry an
/// uncertain write or redirect to a different authority or candidate.
public struct ParentWinnerAuthorityConfiguration: Sendable {
  public let authority: String
  public let compareAndSelect: @Sendable (ParentWinnerSelection) throws -> ParentWinnerSelection
  fileprivate let selectOriginal: @Sendable (ParentWinnerSelection) throws -> ParentWinnerSelection
  public init(authority: String,
    compareAndSelect: @escaping @Sendable (ParentWinnerSelection) throws -> ParentWinnerSelection) {
    self.authority = authority; self.compareAndSelect = compareAndSelect
    selectOriginal = compareAndSelect
  }
  fileprivate init(authority: String,
    selectOriginal: @escaping @Sendable (ParentWinnerSelection) throws -> ParentWinnerSelection) {
    self.authority = authority; self.selectOriginal = selectOriginal
    compareAndSelect = { selection in
      do { return try selectOriginal(selection) }
      catch let committed as V4ParentWinnerCommittedFailure { throw committed.failure }
    }
  }
}

/// An independently fixed, bounded SQLite authority. All consumers of the
/// same parent must use this common store or one qualified common service.
public struct ParentWinnerStoreConfiguration: Sendable {
  public let directory: URL
  public let backingIdentity: Data
  public let authority: String
  public let create: Bool
  public let maximumRows: Int
  public let maximumBytes: Int
  public let checkContinuity: @Sendable (Data) throws -> Void
  public init(directory: URL, backingIdentity: Data, authority: String, create: Bool,
    maximumRows: Int = 4096, maximumBytes: Int = 16 << 20,
    checkContinuity: @escaping @Sendable (Data) throws -> Void) {
    self.directory = directory; self.backingIdentity = backingIdentity; self.authority = authority; self.create = create
    self.maximumRows = maximumRows; self.maximumBytes = maximumBytes; self.checkContinuity = checkContinuity
  }
}

private struct V4ParentWinnerCommittedFailure: Error {
  let failure: any Error
}

/// Current storage facts only. Parsing cannot verify fresh authority or mint
/// an original admission, possession or winner dispatch confirmation.
struct V4StoredParentWinnerProjection {
  let tenant: String
  let issuer: Data
  let lease: Data
  let source: UInt64
  let authority: String
  let artifact: Data
  let activation: Data
  let candidateSet: Data
  let candidate: Data
  let route: Data
  let attempt: Data
  let clientCertificate: Data
  let serverCertificate: Data
  let audience: String
  let revocationAuthority: String
  let activationWire: Data
  let initiation: UInt64
  let sessionEnd: UInt64

  static func capture(parent: Data, projection: Data, authority expected: String? = nil,
    registry: V4NamespaceRegistry) throws -> Self {
    var key = V4PoolWireCursor(parent, maximum: 512)
    try key.map(3); try key.key(0); let tenant = try key.text(maximum: 128)
    try key.key(1); let issuer = try key.bytes(maximum: 16)
    try key.key(2); let lease = try key.bytes(maximum: 16); try key.end()
    var value = V4PoolWireCursor(projection, maximum: 16_384)
    try value.map(16); try value.key(0)
    guard try value.text(maximum: 64) == "flowersec/swift/parent-winner/1" else { throw V4PoolFailure.storage }
    try value.key(1); let source = try value.uint()
    try value.key(2); let authority = try value.text(maximum: 128)
    try value.key(3); let artifact = try value.bytes(maximum: 32)
    try value.key(4); let activation = try value.bytes(maximum: 32)
    try value.key(5); let candidateSet = try value.bytes(maximum: 32)
    try value.key(6); let candidate = try value.bytes(maximum: 16)
    try value.key(7); let route = try value.bytes(maximum: 32)
    try value.key(8); let attempt = try value.bytes(maximum: 16)
    try value.key(9); let clientCertificate = try value.bytes(maximum: 32)
    try value.key(10); let serverCertificate = try value.bytes(maximum: 32)
    try value.key(11); let audience = try value.text(maximum: 128)
    try value.key(12); let revocationAuthority = try value.text(maximum: 128)
    try value.key(13); let activationWire = try value.bytes(maximum: 4096)
    try value.key(14); let initiation = try value.uint()
    try value.key(15); let sessionEnd = try value.uint(); try value.end()
    guard source <= 1, expected == nil || authority == expected,
      [tenant, authority, audience, revocationAuthority].allSatisfy({ V4NamespaceRegistry.securityID($0.utf8) }),
      [issuer, lease, candidate, attempt].allSatisfy({ $0.count == 16 }),
      [artifact, activation, candidateSet, route, clientCertificate, serverCertificate].allSatisfy({ $0.count == 32 }),
      initiation > 0, sessionEnd >= initiation else { throw V4PoolFailure.storage }
    let authorization = try V4NamespaceDocument(activationWire, schema: "ActivationAuthorization", bytes: 4096,
      nodes: 512, registry: registry,
      context: ["activation_source_profile": source == 0 ? "live_authority" : "preauthorized_pool"]).root
    guard try authorization.digest("activation_digest") == activation,
      try authorization.t("tenant_id") == tenant, try authorization.b("artifact_issuer_key_id") == issuer,
      try authorization.b("lease_id") == lease, try authorization.b("artifact_digest") == artifact,
      try authorization.b("attempt_id") == attempt, try authorization.b("client_identity_digest") == clientCertificate,
      try authorization.b("server_identity_digest") == serverCertificate, try authorization.t("audience") == audience,
      try authorization.u("activation_not_after_ms") <= initiation,
      try authorization.u("session_not_after_ms") <= sessionEnd else { throw V4PoolFailure.storage }
    if source == 0 {
      guard try authorization.b("candidate_selection") == candidate, try authorization.b("route_selection") == route,
        V4Crypto.hash(V4Crypto.bytes(candidate) + V4Crypto.bytes(route)) == candidateSet else { throw V4PoolFailure.storage }
    } else {
      let selected = try authorization.field("candidate_selection")
      let once = try selected.field("once_authority_ref")
      guard try selected.b("candidate_set_digest") == candidateSet, try selected.b("artifact_digest") == artifact,
        try once.t("winner_authority_id") == authority, try once.t("tenant_id") == tenant,
        try once.b("artifact_issuer_key_id") == issuer else { throw V4PoolFailure.storage }
    }
    return Self(tenant: tenant, issuer: issuer, lease: lease, source: source, authority: authority,
      artifact: artifact, activation: activation, candidateSet: candidateSet, candidate: candidate, route: route,
      attempt: attempt, clientCertificate: clientCertificate, serverCertificate: serverCertificate,
      audience: audience, revocationAuthority: revocationAuthority, activationWire: activationWire,
      initiation: initiation, sessionEnd: sessionEnd)
  }
}

// Only the synchronous original CAS call can mint this confirmation. It is
// bound to the still-current native claim and is consumed before its local
// irreversible transaction. A public selection or a history read cannot mint
// the confirmation or reconstruct that physical owner's dispatch rights.
final class V4OriginalParentWinner {
  private let owner: AnyObject
  private let selection: ParentWinnerSelection
  private let checkOwner: () throws -> Void
  private var used = false
  private init(owner: AnyObject, selection: ParentWinnerSelection, check: @escaping () throws -> Void) {
    self.owner = owner; self.selection = selection; checkOwner = check
  }
  static func select(configuration: ParentWinnerAuthorityConfiguration?, claim: V4PreparedPoolClaim,
    willDispatch: () -> Void = {}, didCommit: () -> Void = {}, check: @escaping () throws -> Void) throws -> V4OriginalParentWinner {
    guard claim.localRole == .server else { throw V4CryptoFailure.authentication }
    try claim.check()
    return try selectOriginal(configuration: configuration, admission: claim.originalCredential, owner: claim,
      willDispatch: willDispatch, didCommit: didCommit) {
      try claim.check(); try check()
    }
  }
  static func select(configuration: ParentWinnerAuthorityConfiguration?, possession: V4RelayPossession,
    willDispatch: () -> Void = {}, didCommit: () -> Void = {}, check: @escaping () throws -> Void) throws -> V4OriginalParentWinner {
    // The possession constructor is restricted to the original four-flight
    // HOP verifier. A decoded Grant, stored projection or public fact cannot
    // satisfy this entrance.
    try check()
    return try selectOriginal(configuration: configuration, admission: possession.admission, owner: possession,
      willDispatch: willDispatch, didCommit: didCommit, check: check)
  }
  private static func selectOriginal(configuration: ParentWinnerAuthorityConfiguration?, admission: V4CredentialAdmission,
    owner: AnyObject, willDispatch: () -> Void = {}, didCommit: () -> Void = {}, check: @escaping () throws -> Void) throws -> V4OriginalParentWinner {
    guard let configuration, V4NamespaceRegistry.securityID(configuration.authority.utf8) else { throw V4PoolFailure.configuration }
    try check()
    let selection = try admission.parentWinnerSelection(authority: configuration.authority)
    willDispatch()
    let result: ParentWinnerSelection
    do { result = try configuration.selectOriginal(selection) }
    catch let committed as V4ParentWinnerCommittedFailure {
      didCommit()
      throw committed.failure
    }
    guard result == selection else { throw V4PoolFailure.conflict }
    didCommit()
    try check()
    guard try admission.parentWinnerSelection(authority: configuration.authority) == selection else { throw V4PoolFailure.conflict }
    return V4OriginalParentWinner(owner: owner, selection: selection, check: check)
  }
  func consume(owner: AnyObject, admission: V4CredentialAdmission) throws {
    guard !used, self.owner === owner else { throw V4PoolFailure.conflict }
    try checkOwner()
    guard try admission.parentWinnerSelection(authority: selection.authority) == selection else { throw V4PoolFailure.conflict }
    used = true
  }
}

/// A shared CAS owner. Closing it fences future selection, while committed
/// refusal facts remain on disk. There is no history-to-admission API.
public final class ParentWinnerAuthority: V4NativeConnectionLifecycle, @unchecked Sendable {
  private static let format = V4SQLiteStorageFormat(group: .parentWinner)
  private static let manifestSchema = format.manifest()
  private static let winnerSchema = "CREATE TABLE winners (parent BLOB PRIMARY KEY, projection BLOB NOT NULL) WITHOUT ROWID, STRICT"
  private let environment: V4EnvironmentFoundation
  private let settings: ParentWinnerStoreConfiguration
  private let path: String
  private let binding: Data
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
  private var selecting = false
  public var configuration: ParentWinnerAuthorityConfiguration {
    ParentWinnerAuthorityConfiguration(authority: settings.authority,
      selectOriginal: { [self] selection in try compareAndSelect(selection) })
  }
  init(environment: V4EnvironmentFoundation, configuration: ParentWinnerStoreConfiguration) throws {
    let setup = try environment.poolStoreStorage()
    let tail = try setup.executionTail()
    defer { tail.release() }
    let c = configuration
    guard c.directory.isFileURL, c.directory.standardizedFileURL.path == c.directory.resolvingSymlinksInPath().path,
      c.directory.path.utf8.count <= 2048, !c.directory.path.utf8.contains(0),
      c.backingIdentity.count == 16, c.backingIdentity.contains(where: { $0 != 0 }),
      V4NamespaceRegistry.securityID(c.authority.utf8), (1...65_536).contains(c.maximumRows),
      ((1 << 20)...(1 << 30)).contains(c.maximumBytes), c.maximumBytes % 4096 == 0,
      lstat(c.directory.path, &directoryIdentity) == 0, V4LiveServerAdmissionLedger.safe(directoryIdentity, directory: true)
    else { throw V4PoolFailure.configuration }
    self.environment = environment; settings = c
    path = c.directory.appendingPathComponent("parent-winner.sqlite3").path
    binding = V4Crypto.map([(0, V4Crypto.text("flowersec/swift/parent-winner-store/1")),
      (1, V4Crypto.text(c.authority)), (2, V4Crypto.bytes(c.backingIdentity)),
      (3, V4NamespaceValue.head(0, UInt64(c.maximumRows))), (4, V4NamespaceValue.head(0, UInt64(c.maximumBytes)))])
    storage = setup; disk = try environment.poolDiskStorage(diskBytes: UInt64(c.maximumBytes) * 3)
    cleanup = try V4SQLiteCleanup(environment: environment, storage: setup)
    try c.checkContinuity(c.backingIdentity)
    do {
      lockFile = Darwin.open(path + ".lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard lockFile >= 0, fstat(lockFile, &lockIdentity) == 0, V4LiveServerAdmissionLedger.safe(lockIdentity),
        flock(lockFile, LOCK_EX | LOCK_NB) == 0 else { throw V4PoolFailure.storage }
      file = Darwin.open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC | (c.create ? O_CREAT | O_EXCL : 0), 0o600)
      guard file >= 0, fstat(file, &fileIdentity) == 0, V4LiveServerAdmissionLedger.safe(fileIdentity),
        fileIdentity.st_size >= 0, fileIdentity.st_size <= c.maximumBytes,
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nil) == SQLITE_OK
      else { throw V4PoolFailure.storage }
      if !c.create { try V4SQLiteAdmission.prepare(db!) }
      sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 65_536); sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 4096); sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 0)
      try execute("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-256")
      if !c.create {
        try admitCurrentFormat()
          try V4SQLiteAdmission.allowWrites(db!)
          try V4SQLiteAdmission.restoreCloseCheckpoint(db!)
      }
      for pragma in ["journal_mode=DELETE", "synchronous=FULL", "fullfsync=ON", "trusted_schema=OFF", "mmap_size=0", "temp_store=MEMORY", "cache_size=-256"] {
        try execute("PRAGMA " + pragma)
      }
      if c.create { try execute("PRAGMA page_size=4096") }
      guard try scalar("PRAGMA page_size") == 4096,
        try scalar("PRAGMA max_page_count=\(c.maximumBytes / 4096)") == c.maximumBytes / 4096 else { throw V4PoolFailure.storage }
      if c.create {
        try execute("BEGIN IMMEDIATE")
        try execute(Self.manifestSchema)
        try execute(Self.winnerSchema)
        try write("INSERT INTO manifest VALUES(1,'\(Self.format.group.rawValue)',\(Self.format.requiredRevision),?1)", blobs: [binding])
        try execute("PRAGMA user_version=\(Self.format.requiredRevision)"); try execute("COMMIT")
        guard fsync(file) == 0 else { throw V4PoolFailure.storage }
        let directory = Darwin.open(c.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else { throw V4PoolFailure.storage }
        defer { Darwin.close(directory) }; guard fsync(directory) == 0 else { throw V4PoolFailure.storage }
      }
      try check()
      try environment.gate.withLock {
        try setup.check(); try Task.checkCancellation()
        try environment.registerNativeConnection(self)
      }
    } catch {
      if error is StorageFormatError || (error as? V4PoolFailure) == .storage { environment.root.diagnosticCounters.increment(.storeFailures) }
      close(); throw error
    }
  }
  private func admitCurrentFormat() throws {
    guard let db else { throw V4PoolFailure.closed }
    var observed = StorageRevision.unknown
    do {
      try checkFileIdentity()
      try execute("BEGIN")
      observed = try Self.format.inspect(db, identity: binding)
      try checkCurrentState()
      try checkFileIdentity()
      try execute("ROLLBACK")
    } catch {
      let code = sqlite3_errcode(db)
      try? execute("ROLLBACK")
      if let format = error as? StorageFormatError { throw format }
      throw Self.format.refusal(.schemaOrStateInvalid,
        observed: code == SQLITE_CORRUPT || code == SQLITE_NOTADB ? .unknown : observed)
    }
  }
  private func check() throws {
    let db = try environment.gate.withLock { () throws -> OpaquePointer in
      guard !closed, let value = self.db else { throw V4PoolFailure.closed }
      try storage.check(); try disk.check(); return value
    }
    try settings.checkContinuity(settings.backingIdentity)
    try environment.gate.withLock {
      guard !closed else { throw V4PoolFailure.closed }
      try storage.check(); try disk.check()
    }
    try checkFileIdentity()
    guard sqlite3_db_readonly(db, "main") == 0 else { throw V4PoolFailure.storage }
    _ = try Self.format.inspect(db, identity: binding)
    guard try scalar("SELECT count(*) FROM sqlite_schema") == 2,
      try scalar("SELECT count(*) FROM winners") <= settings.maximumRows,
      try schema("manifest") == Self.manifestSchema, try schema("winners") == Self.winnerSchema else { throw V4PoolFailure.storage }
  }
  private func checkFileIdentity() throws {
    guard let db else { throw V4PoolFailure.closed }
    var current = stat(); var directory = stat(); var lock = stat(); var moved: Int32 = 0
    guard lstat(settings.directory.path, &directory) == 0, V4LiveServerAdmissionLedger.safe(directory, directory: true),
      directory.st_dev == directoryIdentity.st_dev, directory.st_ino == directoryIdentity.st_ino,
      lstat(path, &current) == 0, V4LiveServerAdmissionLedger.safe(current), current.st_dev == fileIdentity.st_dev, current.st_ino == fileIdentity.st_ino,
      current.st_size >= 0, current.st_size <= settings.maximumBytes,
      lstat(path + ".lock", &lock) == 0, V4LiveServerAdmissionLedger.safe(lock), lock.st_dev == lockIdentity.st_dev, lock.st_ino == lockIdentity.st_ino,
      sqlite3_file_control(db, "main", SQLITE_FCNTL_HAS_MOVED, &moved) == SQLITE_OK, moved == 0 else { throw V4PoolFailure.storage }
    for suffix in ["-journal", "-wal", "-shm"] {
      var sidecar = stat()
      if lstat(path + suffix, &sidecar) == 0 {
        guard V4LiveServerAdmissionLedger.safe(sidecar), sidecar.st_size >= 0, sidecar.st_size <= settings.maximumBytes else { throw V4PoolFailure.storage }
      } else if errno != ENOENT { throw V4PoolFailure.storage }
    }
  }
  private func checkCurrentState() throws {
    guard try scalar("PRAGMA page_size") == 4096,
      try scalar("PRAGMA page_count") <= settings.maximumBytes / 4096,
      try scalar("SELECT count(*) FROM sqlite_schema") == 2,
      try schema("manifest") == Self.manifestSchema, try schema("winners") == Self.winnerSchema,
      try scalar("SELECT count(*) FROM winners") <= settings.maximumRows else { throw V4PoolFailure.storage }
    let integrity = try statement("PRAGMA quick_check"); defer { sqlite3_finalize(integrity) }
    guard sqlite3_step(integrity) == SQLITE_ROW, sqlite3_column_type(integrity, 0) == SQLITE_TEXT,
      let text = sqlite3_column_text(integrity, 0), String(cString: text) == "ok",
      sqlite3_step(integrity) == SQLITE_DONE else { throw V4PoolFailure.storage }
    let registry = try V4NamespaceRegistry()
    let rows = try statement("SELECT parent,projection FROM winners LIMIT \(settings.maximumRows + 1)")
    defer { sqlite3_finalize(rows) }
    var count = 0
    while true {
      let result = sqlite3_step(rows); if result == SQLITE_DONE { break }
      count += 1
      guard result == SQLITE_ROW, count <= settings.maximumRows,
        sqlite3_column_type(rows, 0) == SQLITE_BLOB, (1...512).contains(sqlite3_column_bytes(rows, 0)),
        sqlite3_column_type(rows, 1) == SQLITE_BLOB, (1...16_384).contains(sqlite3_column_bytes(rows, 1)),
        let parent = sqlite3_column_blob(rows, 0), let projection = sqlite3_column_blob(rows, 1) else { throw V4PoolFailure.storage }
      _ = try V4StoredParentWinnerProjection.capture(parent: Data(bytes: parent, count: Int(sqlite3_column_bytes(rows, 0))),
        projection: Data(bytes: projection, count: Int(sqlite3_column_bytes(rows, 1))), authority: settings.authority, registry: registry)
    }
  }
  private func compareAndSelect(_ selection: ParentWinnerSelection) throws -> ParentWinnerSelection {
    let tail = try environment.gate.withLock { () throws -> V4ResourceReference in
      guard !closed else { throw V4PoolFailure.closed }
      guard !selecting, selection.authority == settings.authority,
        (1...512).contains(selection.parent.count), (1...16_384).contains(selection.projection.count) else { throw V4PoolFailure.configuration }
      let tail = try storage.executionTail()
      selecting = true
      return tail
    }
    defer {
      let closing = environment.gate.withLock { () -> Bool in
        if !closed { selecting = false }
        return closed
      }
      if closing {
        closeStorage()
        environment.gate.withLock { selecting = false }
      }
      tail.release()
    }
      do {
        try check(); try execute("BEGIN IMMEDIATE")
        if let previous = try blob("SELECT projection FROM winners WHERE parent=?1", key: selection.parent) {
          guard previous == selection.projection else { throw V4PoolFailure.conflict }
        } else {
          guard try scalar("SELECT count(*) FROM winners") < settings.maximumRows else { throw V4PoolFailure.capacity }
          try write("INSERT INTO winners VALUES(?1,?2)", blobs: [selection.parent, selection.projection])
        }
        try check(); try execute("COMMIT")
        // Preserve the physical commit fact if the original authority loses
        // its guard after COMMIT. The caller records spend before failing.
        do { try check() } catch { throw V4ParentWinnerCommittedFailure(failure: error) }
        return selection
      } catch {
        try? execute("ROLLBACK")
        // COMMIT uncertainty permanently fences this original authority owner.
        // Reopening requires independently established host continuity.
        let failure = error as? V4PoolFailure
        if failure != .conflict && failure != .capacity { close() }
        throw error
      }
  }
  private func schema(_ name: String) throws -> String {
    let value = try statement("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1"); defer { sqlite3_finalize(value) }
    guard sqlite3_bind_text(value, 1, name, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self)) == SQLITE_OK,
      sqlite3_step(value) == SQLITE_ROW, let sql = sqlite3_column_text(value, 0) else { throw V4PoolFailure.storage }
    let result = String(cString: sql)
    guard sqlite3_step(value) == SQLITE_DONE else { throw V4PoolFailure.storage }; return result
  }
  private func statement(_ sql: String) throws -> OpaquePointer {
    guard let db else { throw V4PoolFailure.closed }; var value: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &value, nil) == SQLITE_OK, let value else { throw V4PoolFailure.storage }; return value
  }
  private func execute(_ sql: String) throws {
    guard let db, sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw V4PoolFailure.storage }
  }
  private func scalar(_ sql: String) throws -> Int {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    guard sqlite3_step(value) == SQLITE_ROW, sqlite3_column_type(value, 0) == SQLITE_INTEGER else { throw V4PoolFailure.storage }
    let result = sqlite3_column_int64(value, 0)
    guard result >= 0, result <= Int.max, sqlite3_step(value) == SQLITE_DONE else { throw V4PoolFailure.storage }; return Int(result)
  }
  private func bind(_ bytes: Data, to statement: OpaquePointer, index: Int32) throws {
    guard bytes.withUnsafeBytes({ sqlite3_bind_blob(statement, index, $0.baseAddress, Int32($0.count), unsafeBitCast(-1, to: sqlite3_destructor_type.self)) }) == SQLITE_OK else { throw V4PoolFailure.storage }
  }
  private func write(_ sql: String, blobs: [Data]) throws {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    for (offset, blob) in blobs.enumerated() { try bind(blob, to: value, index: Int32(offset + 1)) }
    guard sqlite3_step(value) == SQLITE_DONE else { throw V4PoolFailure.storage }
  }
  private func blob(_ sql: String, key: Data?) throws -> Data? {
    let value = try statement(sql); defer { sqlite3_finalize(value) }
    if let key { try bind(key, to: value, index: 1) }
    let step = sqlite3_step(value); if step == SQLITE_DONE { return nil }
    guard step == SQLITE_ROW, let bytes = sqlite3_column_blob(value, 0) else { throw V4PoolFailure.storage }
    let count = Int(sqlite3_column_bytes(value, 0)); guard (1...16_384).contains(count) else { throw V4PoolFailure.storage }
    let result = Data(bytes: bytes, count: count)
    guard sqlite3_step(value) == SQLITE_DONE else { throw V4PoolFailure.storage }; return result
  }
  public func close() {
    environment.gate.withLock {
      guard !closed else { return }; closed = true
      cleanup.beginClose()
      storage.seal()
      if !selecting { closeStorage() }
    }
  }
  private func closeStorage() {
    environment.gate.withLock {
      guard !cleanup.started else { return }
      cleanup.start(database: db, file: file, lockFile: lockFile)
      db = nil; file = -1; lockFile = -1
    }
  }
  func waitPhysicalCleanup() async { await cleanup.waitPhysicalCleanup() }
  deinit { close() }
}
#endif
