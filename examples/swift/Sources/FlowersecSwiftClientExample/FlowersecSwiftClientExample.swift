import Flowersec
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

func renderPublicContract() -> String {
  // Shared parity contract: typed RPC 7001, notification 7002, stream parity.echo.
  return """
    transport=v4
    connection_api=environment+source
    service_api=named

    """
}

func commitSpendReceipt(at path: String) throws {
  let receiptURL = URL(fileURLWithPath: path)
  try Data("flowersec-v4-material-spent\n".utf8).write(
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

func retryDisposition(for error: any Error) -> RetryDisposition? {
  if let connectError = error as? ConnectError {
    return connectError.retryDisposition
  }
  if let sessionError = error as? SessionError {
    return sessionError.retryDisposition
  }
  return nil
}

private enum ExampleConfigurationError: Error {
  case missingSpendReceiptPath
  case invalidRPCResponse
  case invalidStreamResponse
  case stalledStreamWrite
  case invalidNativeTCPDestination
  case nativeBridgeIncomplete
}

private let echoStreamKind = "parity.echo"

private func runApplicationWorkflow(session: any Session, environment: TransportEnvironment,
  material: EngineeringMaterial) async throws
{
  let application = try ParityApplication()
  let client = try await application.bind(session: session, environment: environment,
    target: material.serviceTarget())
  defer { client.close() }
  let deadlineAtMS = UInt64(Date().timeIntervalSince1970 * 1000) + 10_000
  let request = ValuePayload(value: "ping")
  let response = try await client.call(application.echo, request: request,
    requestCodec: application.codec, responseCodec: application.codec,
    options: ServiceCallOptions(deadlineAtMS: deadlineAtMS, responseLimitBytes: 4096))
  guard response.value == request else { throw ExampleConfigurationError.invalidRPCResponse }
  try await client.notify(application.notification, request: ValuePayload(value: "notify"),
    codec: application.codec, options: ServiceCallOptions(deadlineAtMS: deadlineAtMS))

  let streamCell = ProcessInfo.processInfo.environment["FSEC_EXAMPLE_STREAM_CELL"] ?? "direct"
  let metadata = try StreamMetadata(["cell": .string(streamCell)])
  let stream = try await session.openStream(kind: echoStreamKind, metadata: metadata)
  try await writeAll(Data("hello".utf8), to: stream)
  try await stream.closeWrite()
  guard try await readAll(from: stream) == Data("world".utf8) else {
    throw ExampleConfigurationError.invalidStreamResponse
  }
  if let address = ProcessInfo.processInfo.environment["FSEC_EXAMPLE_TCP_ADDRESS"] {
    guard let value = ProcessInfo.processInfo.environment["FSEC_EXAMPLE_TCP_PORT"],
      let port = Int(value), (1...65535).contains(port) else {
      throw ExampleConfigurationError.invalidNativeTCPDestination
    }
    let kind = ProcessInfo.processInfo.environment["FSEC_EXAMPLE_TCP_STREAM_KIND"] ?? "example.tcp"
    let raw = try await session.openStream(kind: kind)
    let result = try await runNativeDuplexWorkflow(stream: raw, environment: environment,
      numericAddress: address, port: port)
    guard result.outcome == .normal, result.cleanupStatus.complete else {
      throw ExampleConfigurationError.nativeBridgeIncomplete
    }
  }
  _ = try await session.probeLiveness()
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
    guard output.count + chunk.count <= 5 else { throw ExampleConfigurationError.invalidStreamResponse }
    output.append(chunk)
  }
  return output
}

@main
private enum FlowersecSwiftClientExample {
  static func main() async throws {
    print(renderPublicContract(), terminator: "")
    guard let materialPath = ProcessInfo.processInfo.environment["FSEC_MATERIAL_PATH"] else {
      return
    }
    guard let receiptPath = ProcessInfo.processInfo.environment["FSEC_SPEND_RECEIPT_V3_PATH"] ?? ProcessInfo.processInfo.environment["FSEC_SPEND_RECEIPT_PATH"] else {
      throw ExampleConfigurationError.missingSpendReceiptPath
    }
    let material = try EngineeringMaterial.load(materialPath)
    let trustRootsPEM = try ProcessInfo.processInfo.environment["FSEC_TRUST_ROOT_PEM_PATH"]
      .map { [try readBoundedFile($0, maximumBytes: 262_144)] } ?? []
    guard !FileManager.default.fileExists(atPath: receiptPath) else {
      throw EngineeringMaterialError.alreadyAcquired
    }
    let history = try EngineeringHistory(receiptPath: receiptPath)
    let environment = try await TransportEnvironment(configuration:
      material.configuration(history: history, roots: trustRootsPEM))
    let source: ConnectionMaterialSource
    let session: any Session
    do {
      source = try await material.makeSource(environment: environment)
      session = try await connect(environment: environment, source: source,
        requirements: ConnectionRequirements(localConsumerTLS13Verification: true, applicationProfile: "services"))
    } catch {
      if let disposition = retryDisposition(for: error) {
        print("recovery=\(String(describing: disposition))")
      }
      try? await environment.close()
      throw error
    }
    defer { source.close() }
    do {
      // READY proves the original native SQLite spend completed. This marker
      // is a human-readable receipt; the retained history is authoritative.
      try commitSpendReceipt(at: receiptPath)
      try await runApplicationWorkflow(session: session, environment: environment, material: material)
    } catch {
      if let disposition = retryDisposition(for: error) {
        print("recovery=\(String(describing: disposition))")
      }
      try? await environment.close()
      try? await session.close()
      throw error
    }
    do {
      try await session.close()
    } catch {
      try? await environment.close()
      throw error
    }
    do {
      try await environment.close()
    } catch {
      try? await environment.close()
      throw error
    }
  }
}
