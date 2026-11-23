#if os(macOS)
import Darwin
import Foundation

struct CapacityGeneration: Sendable {
  static let marker = Data("flowersec/5\n".utf8)
  let clientKey, serverKey: String
  let tunnel: Bool
  let store, records: URL

  var keys: [String] { [clientKey, serverKey] }

  private func contains(_ url: URL) throws -> Bool {
    var info = stat()
    if lstat(url.path, &info) != 0 {
      if errno == ENOENT { return false }
      throw CapacityRoleError.invalidMaterial
    }
    guard info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o777 == 0o600,
          try privateCapacityFile(url, maximum: 64) == Self.marker else { throw CapacityRoleError.invalidMaterial }
    return true
  }

  func releasedLegs() throws -> Int {
    let admissions = tunnel ? keys.map { records.appendingPathComponent("admitted-" + $0) }
      + keys.map { store.appendingPathComponent("spent-" + $0) }
      : [store.appendingPathComponent("spent-" + clientKey), store.appendingPathComponent("admitted-" + serverKey)]
    guard try admissions.allSatisfy(contains) else { throw CapacityRoleError.incomplete }
    let releases = tunnel ? keys.map { records.appendingPathComponent("released-" + $0) }
      : [store.appendingPathComponent("released-client-" + clientKey), store.appendingPathComponent("released-" + serverKey)]
    return try releases.filter(contains).count
  }

  func requireHeld() throws {
    guard try releasedLegs() == 0 else { throw CapacityRoleError.incomplete }
  }

  func joinReleases() async throws {
    while try releasedLegs() != 2 { try await Task.sleep(for: .milliseconds(20)) }
  }
}
#endif
