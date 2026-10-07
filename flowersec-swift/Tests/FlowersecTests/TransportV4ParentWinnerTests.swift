#if os(macOS) || os(iOS)
import Foundation
import XCTest
@testable import Flowersec

/// These tests exercise real durable CAS facts. Public facts are never used to
/// fabricate a possession, consumed socket, admission or Session capability.
final class TransportParentWinnerTests: XCTestCase {
  func testCommonParentExactRetryAndDifferentCandidateConflict() throws {
    let fixture = try CredentialFixture(nativeResources: true)
    defer { fixture.base.environment.beginClose() }
    let directory = try winnerDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let authority = try ParentWinnerAuthority(environment: fixture.base.environment,
      configuration: winnerSettings(directory: directory, create: true))
    defer { authority.close() }
    let original = try fixture.input()
    let admission = try fixture.base.environment.verifyDirectCredentials(configuration: fixture.configuration(), input: original)
    defer { admission.close() }
    let selected = try admission.parentWinnerSelection(authority: "winner")
    let shared = authority.configuration
    XCTAssertEqual(try shared.compareAndSelect(selected), selected)
    XCTAssertEqual(try shared.compareAndSelect(selected), selected)
    // Both route domains share a parent key. Their changed public selection
    // cannot create another winner even when using another local authority.
    let changed = ParentWinnerSelection(authority: selected.authority, parent: selected.parent,
      projection: V4Crypto.map([(0, V4Crypto.text("another candidate and route"))]))
    XCTAssertThrowsError(try shared.compareAndSelect(changed)) { error in XCTAssertEqual(error as? V4PoolFailure, .conflict) }
    XCTAssertEqual(try shared.compareAndSelect(selected), selected,
      "a losing contender does not stop the common authority")
    XCTAssertEqual(try v4CommittedRowCount(path: directory.appendingPathComponent("parent-winner.sqlite3").path, table: "winners"), 1)
  }

  func testVerifiedMixedDirectAndTunnelCandidatesUseOneParentCAS() throws {
    let fixture = try V4TunnelCredentialFixture(profile: .x25519, nativeResources: true, mixedDirectCandidate: true)
    let directory = try winnerDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let authority = try ParentWinnerAuthority(environment: fixture.credentials.base.environment,
      configuration: winnerSettings(directory: directory, create: true))
    defer { authority.close() }
    let original = fixture.original
    func input(index: Int, role: V4CryptoRole, grant: Data = Data()) -> V4CredentialInput {
      V4CredentialInput(artifact: original.artifact, clientCertificate: original.clientCertificate,
        serverCertificate: original.serverCertificate, activation: original.activation, source: .preauthorizedPool,
        candidateIndex: index, grant: grant, relayCertificate: index == 1 ? fixture.relay : Data(), localRole: role)
    }
    let direct = try fixture.credentials.verify(input(index: 0, role: .server))
    let tunnelClient = try fixture.credentials.verify(input(index: 1, role: .client, grant: fixture.grant(candidateIndex: 1)))
    let tunnelServer = try fixture.credentials.verify(input(index: 1, role: .server,
      grant: fixture.grant(candidateIndex: 1, overrides: [13: fixture.namespace(role: 6)])))
    defer { direct.close(); tunnelClient.close(); tunnelServer.close() }
    XCTAssertEqual(direct.pathKind, 0); XCTAssertEqual(tunnelClient.pathKind, 1)
    let directSelection = try direct.parentWinnerSelection(authority: "winner")
    let tunnelSelection = try tunnelClient.parentWinnerSelection(authority: "winner")
    XCTAssertEqual(tunnelSelection, try tunnelServer.parentWinnerSelection(authority: "winner"),
      "both tunnel legs must present the identical public parent fact")
    XCTAssertEqual(directSelection.parent, tunnelSelection.parent)
    XCTAssertNotEqual(directSelection.projection, tunnelSelection.projection)
    XCTAssertEqual(try authority.configuration.compareAndSelect(directSelection), directSelection)
    for selection in [tunnelSelection, try tunnelServer.parentWinnerSelection(authority: "winner")] {
      XCTAssertThrowsError(try authority.configuration.compareAndSelect(selection)) { error in XCTAssertEqual(error as? V4PoolFailure, .conflict) }
    }
    XCTAssertEqual(try v4CommittedRowCount(path: directory.appendingPathComponent("parent-winner.sqlite3").path, table: "winners"), 1)
  }

  func testSelectionResultLossFencesOwnerAndPreservesRefusal() async throws {
    let fixture = try CredentialFixture(nativeResources: true)
    defer { fixture.base.environment.beginClose() }
    let directory = try winnerDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("parent-winner.sqlite3").path
    let observer = V4WinnerResultLoss(path: path)
    let settings = ParentWinnerStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 111, count: 16),
      authority: "winner", create: true, maximumRows: 16, maximumBytes: 1 << 20,
      checkContinuity: { _ in try observer.check() })
    let authority = try ParentWinnerAuthority(environment: fixture.base.environment, configuration: settings)
    defer { authority.close() }
    let admission = try fixture.base.environment.verifyDirectCredentials(configuration: fixture.configuration(), input: fixture.input())
    defer { admission.close() }
    let selection = try admission.parentWinnerSelection(authority: "winner")
    XCTAssertThrowsError(try authority.configuration.compareAndSelect(selection)) { error in XCTAssertEqual(error as? V4PoolFailure, .storage) }
    XCTAssertTrue(observer.observed)
    XCTAssertEqual(try v4CommittedRowCount(path: path, table: "winners"), 1)
    XCTAssertThrowsError(try authority.configuration.compareAndSelect(selection)) { error in XCTAssertEqual(error as? V4PoolFailure, .closed) }
    await authority.waitPhysicalCleanup()
    let reopened = try ParentWinnerAuthority(environment: fixture.base.environment,
      configuration: winnerSettings(directory: directory, create: false))
    defer { reopened.close() }
    // Exact CAS readback is public evidence only. There is no API here to
    // reconstruct the original native claim or its dispatch confirmation.
    XCTAssertEqual(try reopened.configuration.compareAndSelect(selection), selection)
  }

  private func winnerSettings(directory: URL, create: Bool) -> ParentWinnerStoreConfiguration {
    ParentWinnerStoreConfiguration(directory: directory, backingIdentity: Data(repeating: 111, count: 16),
      authority: "winner", create: create, maximumRows: 16, maximumBytes: 1 << 20, checkContinuity: { _ in })
  }
  private func winnerDirectory() throws -> URL {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
    let directory = root.appendingPathComponent(".flowersec/swift-parent-winner-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory
  }
}

private final class V4WinnerResultLoss: @unchecked Sendable {
  private let gate = NSLock()
  private let path: String
  private var lost = false
  var observed: Bool { gate.withLock { lost } }
  init(path: String) { self.path = path }
  func check() throws {
    if try v4CommittedRowCount(path: path, table: "winners") > 0 {
      gate.withLock { lost = true }; throw V4PoolFailure.storage
    }
  }
}
#endif
