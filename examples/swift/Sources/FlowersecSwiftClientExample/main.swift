import Flowersec
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

func renderPublicContractV3() -> String {
  return """
    transport=v3
    session_api=opaque

    """
}

func commitSpendReceipt(at path: String) throws {
  let receiptURL = URL(fileURLWithPath: path)
  try Data("flowersec-v3-artifact-spent\n".utf8).write(
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

func retryDisposition(for error: any Error) -> RetryDispositionV3? {
  if let connectError = error as? ConnectError {
    return connectError.retryDisposition
  }
  if let sessionError = error as? SessionError {
    return sessionError.retryDispositionV3
  }
  return nil
}

private enum ExampleConfigurationError: Error {
  case missingSpendReceiptPath
  case invalidRPCResponse
  case invalidNotification
  case invalidStreamResponse
  case stalledStreamWrite
}

private let echoRPCTypeID: UInt32 = 7_001
private let notificationTypeID: UInt32 = 7_002
private let echoStreamKind = "parity.echo"

private struct ValuePayload: Codable, Equatable, Sendable {
  let value: String
}

private func runApplicationWorkflow(session: any Session) async throws {
  let (notifications, notificationContinuation) = AsyncStream<
    Result<ValuePayload, RPCNotificationError>
  >.makeStream(bufferingPolicy: .bufferingNewest(1))
  let subscription = try await session.rpc.subscribeNotification(
    notificationTypeID,
    as: ValuePayload.self
  ) { result in
    notificationContinuation.yield(result)
  }
  do {
    let request = ValuePayload(value: "ping")
    let response = try await session.rpc.call(
      echoRPCTypeID,
      request,
      as: ValuePayload.self,
      timeout: .seconds(10)
    )
    guard response == request else { throw ExampleConfigurationError.invalidRPCResponse }

    try await session.rpc.notify(notificationTypeID, ValuePayload(value: "notify"))
    var notificationIterator = notifications.makeAsyncIterator()
    guard let notification = await notificationIterator.next() else {
      throw ExampleConfigurationError.invalidNotification
    }
    guard try notification.get().value == "notify" else {
      throw ExampleConfigurationError.invalidNotification
    }

    let streamCell = ProcessInfo.processInfo.environment["FSEC_EXAMPLE_STREAM_CELL"] ?? "direct"
    let metadata = try StreamMetadata(["cell": .string(streamCell)])
    let stream = try await session.openStream(kind: echoStreamKind, metadata: metadata)
    try await writeAll(Data("hello".utf8), to: stream)
    try await stream.closeWrite()
    guard try await readAll(from: stream) == Data("world".utf8) else {
      throw ExampleConfigurationError.invalidStreamResponse
    }

    _ = try await session.probeLiveness()
    await subscription.cancel()
    notificationContinuation.finish()
  } catch {
    await subscription.cancel()
    notificationContinuation.finish()
    throw error
  }
}

private func writeAll(_ data: Data, to stream: any ByteStream) async throws {
  var offset = 0
  while offset < data.count {
    let written = try await stream.write(data.subdata(in: offset..<data.count))
    guard written > 0 else { throw ExampleConfigurationError.stalledStreamWrite }
    offset += written
  }
}

private func readAll(from stream: any ByteStream) async throws -> Data {
  var output = Data()
  while let chunk = try await stream.read(maxBytes: 64 * 1_024) {
    output.append(chunk)
  }
  return output
}

@main
private enum FlowersecSwiftClientExample {
  static func main() async throws {
    print(renderPublicContractV3(), terminator: "")
    guard let artifactPath = ProcessInfo.processInfo.environment["FSEC_ARTIFACT_V3_PATH"] else {
      return
    }
    guard let receiptPath = ProcessInfo.processInfo.environment["FSEC_SPEND_RECEIPT_V3_PATH"] else {
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
      if let disposition = retryDisposition(for: error) {
        print("recovery=\(String(describing: disposition))")
      }
      throw error
    }
    do {
      try await runApplicationWorkflow(session: session)
    } catch {
      if let disposition = retryDisposition(for: error) {
        print("recovery=\(String(describing: disposition))")
      }
      try? await session.close()
      throw error
    }
    try await session.close()
  }
}
