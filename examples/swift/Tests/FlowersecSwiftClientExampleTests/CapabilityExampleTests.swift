import Testing
import Foundation

@testable import FlowersecSwiftClientExample

@Test func exampleDescribesTheCurrentConnectionAndServiceContract() {
  #expect(
    renderPublicContract() == """
      transport=v4
      connection_api=environment+source
      service_api=named

      """)
}

@Test func spendReceiptIsDurableAndSingleUse() throws {
  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: directory) }
  let receipt = directory.appendingPathComponent("artifact.spent")

  try commitSpendReceipt(at: receipt.path)

  #expect(try Data(contentsOf: receipt) == Data("flowersec-v4-material-spent\n".utf8))
  let attributes = try FileManager.default.attributesOfItem(atPath: receipt.path)
  #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
  #expect(throws: (any Error).self) {
    try commitSpendReceipt(at: receipt.path)
  }
}

@Test func localFixtureMapsRejectAmbiguousEncoding() throws {
  let value = try FixtureCBOR.decode(Data([0xa1, 0x00, 0x01]))
  #expect(try value.field(0).uint == 1)
  for invalid in [
    Data([0xa1, 0x18, 0x00, 0x01]),
    Data([0xa2, 0x00, 0x01, 0x00, 0x02]),
    Data([0xa0, 0x00]),
    Data([0xbf, 0xff]),
  ] {
    #expect(throws: EngineeringMaterialError.self) { try FixtureCBOR.decode(invalid) }
  }
}

@Test func oneShotHistoryCannotBeRecreatedOrReplaced() throws {
  let directory = FileManager.default.temporaryDirectory
    .appendingPathComponent(UUID().uuidString, isDirectory: true)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: directory) }
  let receipt = directory.appendingPathComponent("material.spent")
  let history = try EngineeringHistory(receiptPath: receipt.path)
  try history.checkContinuity()
  #expect(history.storeID.count == 16)
  #expect(throws: (any Error).self) { try EngineeringHistory(receiptPath: receipt.path) }
  let moved = directory.appendingPathComponent("original-history")
  try FileManager.default.moveItem(at: history.directory, to: moved)
  try FileManager.default.createDirectory(at: history.directory, withIntermediateDirectories: false,
    attributes: [.posixPermissions: 0o700])
  #expect(throws: EngineeringMaterialError.self) { try history.checkContinuity() }
  try FileManager.default.removeItem(at: history.directory)
  let unrelated = directory.appendingPathComponent("unrelated-history", isDirectory: true)
  try FileManager.default.createSymbolicLink(at: history.directory, withDestinationURL: unrelated)
  #expect(throws: (any Error).self) { try EngineeringHistory(receiptPath: receipt.path) }
  #expect(!FileManager.default.fileExists(atPath: unrelated.path))
}
