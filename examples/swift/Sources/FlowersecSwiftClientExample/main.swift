import Flowersec
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

func renderPublicContractV5() -> String {
  return """
    transport=v5
    session_api=opaque

    """
}

func commitSpendReceipt(at path: String) throws {
  try commitCapacityFile(Data("flowersec-v5-artifact-spent\n".utf8), at: URL(fileURLWithPath: path))
}

func durableConnectionLease(releaseAt path: String) -> ConnectionLease {
  ConnectionLease {
    try commitCapacityFile(Data("flowersec/5\n".utf8), at: URL(fileURLWithPath: path))
  }
}

func commitCapacityFile(_ bytes: Data, at url: URL) throws {
  let directory = url.deletingLastPathComponent()
  let pending = directory.appendingPathComponent(".pending-\(UUID().uuidString)")
  let descriptor = open(pending.path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
  guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  defer { _ = unlink(pending.path) }
  let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
  try file.write(contentsOf: bytes); try file.synchronize(); try file.close()
  guard link(pending.path, url.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  try syncDirectory(at: directory)
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

enum ExampleConfigurationError: Error {
  case missingSpendReceiptPath
  case missingOrigin
  case invalidRPCResponse
  case invalidStreamResponse
  case stalledStreamWrite
  case invalidConfiguration
}

private let echoRPCTypeID: UInt32 = 7_001
private let notificationTypeID: UInt32 = 7_002
private let echoStreamKind = "parity.echo"

struct ValuePayload: Codable, Equatable, Sendable {
  let value: String
}

func runApplicationWorkflow(session: any Session, app: ParityApplication,
                            beforeNotify: @Sendable () async throws -> Void = {}) async throws {
  do {
    let request = ValuePayload(value: "ping")
    let response = try await session.rpc.call(
      echoRPCTypeID,
      request,
      as: ValuePayload.self,
      timeout: .seconds(10)
    )
    guard response == request else { throw ExampleConfigurationError.invalidRPCResponse }
    try await app.checkOptionalCalls(on: session)

    try await beforeNotify()
    try await session.rpc.notify(notificationTypeID, ValuePayload(value: "notify"))

    let streamCell = ProcessInfo.processInfo.environment["FSEC_EXAMPLE_STREAM_CELL"] ?? "direct"
    let metadata = try StreamMetadata(["cell": .string(streamCell)])
    let stream = try await session.openStream(kind: echoStreamKind, metadata: metadata)
    try await writeAll(Data("hello".utf8), to: stream)
    try await stream.closeWrite()
    guard try await readAll(from: stream, maximum: 5) == Data("world".utf8) else {
      throw ExampleConfigurationError.invalidStreamResponse
    }

    _ = try await session.probeLiveness()
  } catch {
    throw error
  }
}

func writeAll(_ data: Data, to stream: any ByteStream) async throws {
  var offset = 0
  while offset < data.count {
    let written = try await stream.write(data.subdata(in: offset..<data.count))
    guard written > 0 else { throw ExampleConfigurationError.stalledStreamWrite }
    offset += written
  }
}

func readAll(from stream: any ByteStream, maximum: Int) async throws -> Data {
  var output = Data()
  while let chunk = try await stream.read(maxBytes: min(64 * 1_024, maximum - output.count + 1)) {
    guard !chunk.isEmpty, chunk.count <= maximum - output.count else { throw ExampleConfigurationError.invalidStreamResponse }
    output.append(chunk)
  }
  return output
}

private enum FlowersecSwiftClientExample {
  static func main() async throws {
    let env = ProcessInfo.processInfo.environment
    #if os(macOS)
      if let role = env["FLOWERSEC_CAPACITY_ROLE"] { try await runCapacityRole(role, env); return }
    #endif
    print(renderPublicContractV5(), terminator: "")
    #if os(macOS) || os(iOS)
      if env["FSEC_EXAMPLE_LISTEN"] == "1" { try await runDirectListener(env); return }
    #endif
    guard let artifactPath = ProcessInfo.processInfo.environment["FSEC_ARTIFACT_V5_PATH"] else {
      if let mode = env["FSEC_EXAMPLE_LARGE_RPC"], mode != "0" { throw ExampleConfigurationError.invalidConfiguration }
      return
    }
    guard let receiptPath = ProcessInfo.processInfo.environment["FSEC_SPEND_RECEIPT_V5_PATH"] else {
      throw ExampleConfigurationError.missingSpendReceiptPath
    }
    let artifact = try parseArtifact(Data(contentsOf: URL(fileURLWithPath: artifactPath)))
    let lease = ArtifactLease(reservingFor: artifact) {
      try commitSpendReceipt(at: receiptPath)
      return durableConnectionLease(releaseAt: receiptPath + ".released")
    }
    let trustRootsPEM = try ProcessInfo.processInfo.environment["FSEC_TRUST_ROOT_PEM_PATH"]
      .map { [try Data(contentsOf: URL(fileURLWithPath: $0))] } ?? []
    guard let origin = ProcessInfo.processInfo.environment["FSEC_ORIGIN"] else {
      throw ExampleConfigurationError.missingOrigin
    }
    let app = try ParityApplication(env)
    let options = ConnectorOptions(
      origin: origin,
      connectTimeout: .seconds(15),
      trustRootsPEM: trustRootsPEM, rpcFrameLimits: app.frameLimits, rpcHandlers: app.handlers,
      tunnelIngress: env["FSEC_TUNNEL_INGRESS"], maxConcurrentRPCRequests: try exampleConcurrency(env)
    )
    let session: any Session
    do {
      session = try await connect(lease: lease, options: options)
    } catch {
      if let disposition = retryDisposition(for: error) {
        print("recovery=\(String(describing: disposition))")
      }
      throw error
    }
    do {
      try await runEndpoint(session: session, app: app, env: env, serving: env["FSEC_EXAMPLE_SERVE"] == "1")
    } catch {
      if let disposition = retryDisposition(for: error) {
        print("recovery=\(String(describing: disposition))")
      }
      try? await session.close()
      throw error
    }
    try await session.close()
    if app.largeMode != .disabled {
      let end = await session.waitTermination()
      guard end.error == .closed else { throw end.error }
      let served = env["FSEC_EXAMPLE_BIDIRECTIONAL"] != "1" && (env["FSEC_EXAMPLE_SERVE"] == "1" || app.largeMode == .serve)
      print("binary_echo=\(served ? "accepted" : "verified")")
    }
  }
}

do {
  try await FlowersecSwiftClientExample.main()
} catch {
  let reason: String
  switch error {
  case let problem as ExampleConfigurationError: reason = String(describing: problem)
  case let problem as ConnectError: reason = String(describing: problem)
  case let problem as SessionError: reason = String(describing: problem)
  case let problem as RPCError: reason = "RPC rejected (code \(problem.code))"
  default: reason = "operation failed"
  }
  FileHandle.standardError.write(Data("Flowersec example: \(reason)\n".utf8))
  exit(EXIT_FAILURE)
}
