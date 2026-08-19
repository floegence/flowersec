import Testing
import Foundation

@testable import FlowersecSwiftClientExample

@Test func exampleDescribesTheOpaqueV3Contract() {
  #expect(
    renderPublicContractV3() == """
      transport=v3
      session_api=opaque

      """)
}

@Test func spendReceiptIsDurableAndSingleUse() throws {
  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: directory) }
  let receipt = directory.appendingPathComponent("artifact.spent")

  try commitSpendReceipt(at: receipt.path)

  #expect(try Data(contentsOf: receipt) == Data("flowersec-v3-artifact-spent\n".utf8))
  let attributes = try FileManager.default.attributesOfItem(atPath: receipt.path)
  #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
  #expect(throws: (any Error).self) {
    try commitSpendReceipt(at: receipt.path)
  }
}
