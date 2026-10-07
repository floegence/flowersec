#if os(macOS) || os(iOS)
  import Darwin
  import Foundation
  import SQLite3
  import XCTest

  @testable import Flowersec

  @MainActor
  final class TransportPoolTests: XCTestCase {
    private func route(
      _ fixture: CredentialFixture, port: Int, lease: UInt8 = 30,
      attempt: UInt8 = 33
    ) throws -> V4WebSocketRoute {
      fixture.candidateLeg = NamespaceFixture.map([
        0: .uint(0), 1: .bytes(Data(repeating: 50, count: 16)), 2: .uint(1),
        3: .uint(0), 4: .uint(1), 5: .uint(1), 6: .text("localhost"), 7: .uint(UInt64(port)),
        8: .text("/flowersec/v4/direct"), 9: .text("http/1.1"), 10: .text("flowersec.direct.v4"),
        11: NamespaceFixture.map([0: .uint(0), 1: .bool(true)]),
      ])
      let input = try fixture.input(
        source: .preauthorizedPool, indices: [0],
        artifact: [6: .bytes(Data(repeating: lease, count: 16))],
        activation: [
          5: .bytes(Data(repeating: lease, count: 16)),
          9: .bytes(Data(repeating: attempt, count: 16)),
        ])
      return try fixture.verify(input).webSocketRoute(in: fixture.base.environment)
    }
    private func prepare(_ route: V4WebSocketRoute) async throws -> V4PreparedWebSocket {
      let ca = try Data(
        contentsOf: Bundle.module.url(
          forResource: "self_signed_ca",
          withExtension: "pem", subdirectory: "Fixtures")!)
      return try await .prepare(route: route, numericAddress: "127.0.0.1", trustRootsPEM: [ca])
    }
    private func directory() throws -> URL {
      let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      let directory = root.appendingPathComponent(".flowersec/swift-pool-\(UUID().uuidString)")
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      return directory
    }
    private func backing(
      _ fixture: CredentialFixture, directory: URL, maximumRows: Int = 8,
      spend: String = "spend", continuity: @escaping (V4PoolStoreIdentity) throws -> Void = { _ in }
    ) throws
      -> V4PoolStoreBacking
    {
      try V4PoolStoreBacking(
        environment: fixture.base.environment, directory: directory,
        identity: V4PoolStoreIdentity(
          storeID: Data(repeating: 7, count: 16), generation: 1,
          tenant: "tenant", issuer: Data(repeating: 5, count: 16),
          spendAuthority: spend, winnerAuthority: "winner"),
        maximumBytes: 1 << 20, maximumRows: maximumRows, continuity: continuity)
    }
    private func rows(_ directory: URL) throws -> Int {
      var db: OpaquePointer?
      guard
        sqlite3_open_v2(
          directory.appendingPathComponent("spend.sqlite3").path,
          &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK
      else {
        if let db { sqlite3_close(db) }
        throw V4PoolFailure.storage
      }
      defer { sqlite3_close(db) }
      var statement: OpaquePointer?
      guard sqlite3_prepare_v2(db, "SELECT count(*) FROM spend", -1, &statement, nil) == SQLITE_OK
      else {
        throw V4PoolFailure.storage
      }
      defer { sqlite3_finalize(statement) }
      guard sqlite3_step(statement) == SQLITE_ROW else { throw V4PoolFailure.storage }
      return Int(sqlite3_column_int64(statement, 0))
    }
    func testDefiniteConsumeTransfersActualSocketAndReopenNeverRegrantsLease() async throws {
      let directory = try directory()
      defer { try? FileManager.default.removeItem(at: directory) }
      let server = try V4WebSocketTestServer()
      defer { server.stop() }
      let fixture = try CredentialFixture()
      let backing = try backing(fixture, directory: directory)
      let store = try backing.open(create: true)
      XCTAssertThrowsError(try backing.open(create: false))
      var prepared: V4PreparedWebSocket? = try await prepare(route(fixture, port: server.port))
      let consumed = try prepared!.consumePool(using: store)
      prepared = nil
      XCTAssertEqual(try rows(directory), 1)
      let output = try fixture.base.environment.cryptoBuffer(capacity: 3)
      try output.store(Data([1, 2, 3]))
      try consumed.publish(output)
      let input = try await consumed.receive()
      XCTAssertEqual(try input.withBytes { $0 }, Data([1, 2, 3]))
      consumed.close()
      await consumed.waitClosed()
      store.close()
      await store.waitPhysicalCleanup()
      XCTAssertEqual(fixture.base.root.snapshot().used.diskBytes, 3 << 20)
      XCTAssertThrowsError(try backing.retireRemovedFiles())
      let reopened = try backing.open(create: false)
      let replay = try await prepare(route(fixture, port: server.port, attempt: 34))
      XCTAssertThrowsError(try replay.consumePool(using: reopened))
      await replay.waitClosed()
      XCTAssertEqual(try rows(directory), 1)
      let bytes = try Data(contentsOf: directory.appendingPathComponent("spend.sqlite3"))
      XCTAssertNil(bytes.range(of: Data(repeating: 32, count: 32)), "PSK persisted")
      XCTAssertNotNil(bytes.range(of: Data("flowersec/swift/pool-consume/1".utf8)))
      reopened.close()
      await reopened.waitPhysicalCleanup()
      try FileManager.default.removeItem(at: directory)
      try backing.retireRemovedFiles()
      XCTAssertEqual(fixture.base.root.snapshot().used.diskBytes, 0)
    }
    func testOriginalPreparationAliasCannotPublishAfterConsumption() async throws {
      let directory = try directory()
      defer { try? FileManager.default.removeItem(at: directory) }
      let server = try V4WebSocketTestServer()
      defer { server.stop() }
      let fixture = try CredentialFixture()
      let backing = try backing(fixture, directory: directory)
      let store = try backing.open(create: true)
      let prepared = try await prepare(route(fixture, port: server.port))
      let consumed = try prepared.consumePool(using: store)
      let output = try fixture.base.environment.cryptoBuffer(capacity: 0)
      try output.store(Data())
      XCTAssertThrowsError(try prepared.publish(output))
      XCTAssertThrowsError(try consumed.publish(output))
      await consumed.waitClosed()
      XCTAssertEqual(try rows(directory), 1)
      store.close()
      await store.waitPhysicalCleanup()
      try FileManager.default.removeItem(at: directory)
      try backing.retireRemovedFiles()
    }
    func testAuthorityMismatchAndFiniteHistoryRefuseBeforeSecondConsume() async throws {
      for wrongAuthority in [true, false] {
        let directory = try directory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let server = try V4WebSocketTestServer()
        defer { server.stop() }
        let fixture = try CredentialFixture()
        let backing = try backing(
          fixture, directory: directory, maximumRows: 1,
          spend: wrongAuthority ? "other" : "spend")
        let store = try backing.open(create: true)
        let prepared = try await prepare(route(fixture, port: server.port))
        if wrongAuthority {
          XCTAssertThrowsError(try prepared.consumePool(using: store))
          XCTAssertEqual(try rows(directory), 0)
        } else {
          let consumed = try prepared.consumePool(using: store)
          consumed.close()
          await consumed.waitClosed()
          let second = try await prepare(route(fixture, port: server.port, lease: 35))
          XCTAssertThrowsError(try second.consumePool(using: store))
          await second.waitClosed()
          XCTAssertEqual(try rows(directory), 1)
        }
        await prepared.waitClosed()
        store.close()
        await store.waitPhysicalCleanup()
        try FileManager.default.removeItem(at: directory)
        try backing.retireRemovedFiles()
      }
    }
    func testPostCommitExpirationLeavesConsumedHistoryWithoutNativeHandoff() async throws {
      let directory = try directory()
      defer { try? FileManager.default.removeItem(at: directory) }
      let server = try V4WebSocketTestServer()
      defer { server.stop() }
      let fixture = try CredentialFixture()
      var expired = false
      let backing = try backing(fixture, directory: directory) { _ in
        // A separate reader sees the row only after the real SQLite COMMIT.
        if !expired, (try? self.rows(directory)) == 1 {
          expired = true
          fixture.base.source.advance(700)
        }
      }
      let store = try backing.open(create: true)
      let prepared = try await prepare(route(fixture, port: server.port))
      XCTAssertThrowsError(try prepared.consumePool(using: store))
      XCTAssertTrue(expired)
      XCTAssertEqual(try rows(directory), 1)
      await prepared.waitClosed()
      XCTAssertThrowsError(try prepared.consumePool(using: store))
      await store.waitPhysicalCleanup()
      try FileManager.default.removeItem(at: directory)
      try backing.retireRemovedFiles()
    }
    func testRestoreRequiresExactIndependentStoreIdentityAndOriginalFormat() async throws {
      let directory = try directory()
      defer { try? FileManager.default.removeItem(at: directory) }
      let fixture = try CredentialFixture()
      let backing = try backing(fixture, directory: directory)
      let store = try backing.open(create: true)
      store.close()
      await store.waitPhysicalCleanup()
      let wrong = try self.backing(fixture, directory: directory, spend: "other")
      XCTAssertThrowsError(try wrong.open(create: false))
      await wrong.waitPhysicalCleanup()
      let restored = try backing.open(create: false)
      fixture.base.environment.beginClose()
      await restored.waitPhysicalCleanup()
      XCTAssertEqual(fixture.base.root.snapshot().used.diskBytes, 6 << 20)
      XCTAssertEqual(try fixture.base.environment.account.snapshot().used.diskBytes, 0)
      let lock = Darwin.open(directory.appendingPathComponent("spend.sqlite3.lock").path, O_RDWR)
      XCTAssertGreaterThanOrEqual(lock, 0)
      if lock >= 0 {
        XCTAssertEqual(
          flock(lock, LOCK_EX | LOCK_NB), 0, "TransportEnvironment kept the physical store lock")
        Darwin.close(lock)
      }
      restored.close()
      try FileManager.default.removeItem(at: directory)
      try backing.retireRemovedFiles()
      try wrong.retireRemovedFiles()
    }
  }
#endif
