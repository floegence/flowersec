import Flowersec
import Foundation

func renderPublicContractV2() -> String {
  return """
    transport=v2
    session_api=opaque

    """
}

func commitSpendReceipt(at path: String) throws {
  let receiptURL = URL(fileURLWithPath: path)
  try Data("flowersec-v2-artifact-spent\n".utf8).write(
    to: receiptURL,
    options: .withoutOverwriting
  )
  do {
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600],
      ofItemAtPath: receiptURL.path
    )
    let receipt = try FileHandle(forWritingTo: receiptURL)
    defer { try? receipt.close() }
    try receipt.synchronize()
  } catch {
    // An uncertain durable write remains spent; never remove and reuse it.
    throw error
  }
}

private enum ExampleConfigurationError: Error {
  case missingSpendReceiptPath
}

@main
private enum FlowersecSwiftClientExample {
  static func main() async throws {
    print(renderPublicContractV2(), terminator: "")
    guard let artifactPath = ProcessInfo.processInfo.environment["FSEC_ARTIFACT_V2_PATH"] else {
      return
    }
    guard let receiptPath = ProcessInfo.processInfo.environment["FSEC_SPEND_RECEIPT_V2_PATH"] else {
      throw ExampleConfigurationError.missingSpendReceiptPath
    }
    let artifact = try parseArtifactV2(Data(contentsOf: URL(fileURLWithPath: artifactPath)))
    let lease = ArtifactLeaseV2(artifact: artifact) {
      try commitSpendReceipt(at: receiptPath)
    }
    let session = try await ConnectorV2(lease: lease).connect()
    await session.close()
  }
}
