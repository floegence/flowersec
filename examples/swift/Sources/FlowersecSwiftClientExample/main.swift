import Flowersec
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

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
    try syncDirectory(at: receiptURL.deletingLastPathComponent())
  } catch {
    // An uncertain durable write remains spent; never remove and reuse it.
    throw error
  }
}

func syncDirectory(at directoryURL: URL) throws {
  let directory = directoryURL.withUnsafeFileSystemRepresentation {
    path -> UnsafeMutablePointer<DIR>? in
    guard let path else { return nil }
    return opendir(path)
  }
  guard let directory else {
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
  defer { _ = closedir(directory) }
  let descriptor = dirfd(directory)
  guard fsync(descriptor) == 0 else {
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
}

func recoveryActionV2(for error: any Error) -> RetryAction? {
  if let connectError = error as? ConnectError {
    return classifyConnectError(connectError).action
  }
  if let sessionError = error as? SessionError {
    return classifySessionError(sessionError).action
  }
  return nil
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
    let artifact = try parseArtifact(Data(contentsOf: URL(fileURLWithPath: artifactPath)))
    let lease = ArtifactLease(artifact: artifact) {
      try commitSpendReceipt(at: receiptPath)
    }
    let session: any Session
    do {
      session = try await connect(lease: lease)
    } catch {
      if let action = recoveryActionV2(for: error) {
        print("recovery=\(action.rawValue)")
      }
      throw error
    }
    do {
      _ = try await session.probeLiveness()
    } catch {
      if let action = recoveryActionV2(for: error) {
        print("recovery=\(action.rawValue)")
      }
      await session.close()
      throw error
    }
    await session.close()
  }
}
