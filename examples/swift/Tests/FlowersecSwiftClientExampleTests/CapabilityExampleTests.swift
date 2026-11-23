import Testing
import Foundation

@testable import FlowersecSwiftClientExample

@Test func exampleDescribesTheOpaqueV5Contract() {
  #expect(
    renderPublicContractV5() == """
      transport=v5
      session_api=opaque

      """)
}

@Test func spendReceiptIsDurableAndSingleUse() throws {
  let temporaryRoot = ProcessInfo.processInfo.environment["TMPDIR"].map {
    URL(fileURLWithPath: $0, isDirectory: true)
  } ?? FileManager.default.temporaryDirectory
  let directory = temporaryRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: directory) }
  let receipt = directory.appendingPathComponent("artifact.spent")

  try commitSpendReceipt(at: receipt.path)

  #expect(try Data(contentsOf: receipt) == Data("flowersec-v5-artifact-spent\n".utf8))
  let attributes = try FileManager.default.attributesOfItem(atPath: receipt.path)
  #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
  #expect(throws: (any Error).self) {
    try commitSpendReceipt(at: receipt.path)
  }
}
