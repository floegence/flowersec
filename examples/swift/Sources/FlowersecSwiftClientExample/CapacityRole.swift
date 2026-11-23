#if os(macOS)
import Darwin
import Foundation
import Flowersec

struct CapacityOptions: Decodable, Sendable {
  let nativeSDK, carrier: String
  let serverCarrier: String?
  let directReplacement, tunnelReplacement: Bool?
  let overlapSuccessors: Int?
  let sessions, streamsPerSession, operationTimeoutMS: Int
  let materialPath, storeDirectory: String
}

struct CapacityCommand: Decodable, Sendable {
  let id, cancel: UInt64?
  let op: String?
  let timeoutMS, index, count, generation: Int?
  let session, expectedSession: String?
  let operation: String?, bytes: Int?
  let options: CapacityOptions?
}

struct CapacityResult: Encodable, Sendable {
  var endpointAddress: String?, endpointAddresses: [String]?, id: String?, generation: Int?
  var clientResponsive: Bool?, serverResponsive: Bool?
  var activeSessions: Int?, activeStreams: Int?, residualStreams: Int?, closed: Bool?
  var ingressURLs: [String]?, registered: Int?, releasedLegs: Int?
  var lookupKey: String?, legKeys: [String]?, admissionProfile: String?, verifiedContractsPerEndpoint: Int?
  var liveEnds: [Int]?, responsiveLegs: Int?, heldLegs: Int?, path: String?
  var operation: String?, requestBytes: Int?, responseBytes: Int?, verified: Bool?
}

enum CapacityRoleError: String, Error {
  case invalidCommand, deploymentUnavailable, invalidMaterial, positionUnavailable, operationExpired, incomplete, incompatibleDeployment, configuration
}

private struct CapacityAnswer: Encodable { let id: UInt64; let result: CapacityResult?; let error: String? }
private struct CapacityTermination: Encodable { let event = "terminated"; let session: String }

final class CapacityWriter: @unchecked Sendable {
  let file: FileHandle
  private let lock = NSLock()
  init(_ file: FileHandle) { self.file = file }
  func write<T: Encodable>(_ value: T) throws {
    var bytes = try JSONEncoder().encode(value)
    guard bytes.count <= 8192 else { throw CapacityRoleError.invalidCommand }; bytes.append(10)
    try lock.withLock { try file.write(contentsOf: bytes) }
  }
  func terminated(_ id: String) throws { try write(CapacityTermination(session: id)) }
}

private actor CapacityCommands {
  let product: CapacityRuntime, writer: CapacityWriter
  var last: UInt64 = 0, sealed = false, closed = false
  var tasks: [UInt64: Task<Void, Never>] = [:]
  var ioError = false
  init(product: CapacityRuntime, writer: CapacityWriter) { self.product = product; self.writer = writer }
  func submit(_ data: Data) async throws {
    let c = try JSONDecoder().decode(CapacityCommand.self, from: data)
    if let cancel = c.cancel {
      guard c.id == nil, c.op == nil, cancel > 0, cancel <= last else { throw CapacityRoleError.invalidCommand }
      tasks[cancel]?.cancel(); return
    }
    guard !closed, !ioError, let id = c.id, id > last, id <= 9_007_199_254_740_991,
          let op = c.op, (last == 0) == (op == "initialize"),
          let ms = c.timeoutMS, (1...86_400_000).contains(ms), tasks.count < 1016,
          !sealed || op == "snapshot" || op == "close" else { throw CapacityRoleError.invalidCommand }
    last = id
    let deadline = ContinuousClock.now.advanced(by: .milliseconds(ms))
    if op == "quiesce" || op == "close" { sealed = true; closed = op == "close"; await drain(cancel: true) }
    let work = Task {
      let attempt = Task { try await product.perform(c) }
      let timer = Task { try await Task.sleep(until: deadline, clock: .continuous); attempt.cancel() }
      let reply: CapacityAnswer
      do {
        let result = try await withTaskCancellationHandler { try await attempt.value } onCancel: { attempt.cancel() }
        guard ContinuousClock.now < deadline else { throw CapacityRoleError.operationExpired }
        try Task.checkCancellation()
        reply = CapacityAnswer(id: id, result: result, error: nil)
      } catch {
        let code = (error as? CapacityRoleError)?.rawValue ?? (error as? ConnectError)?.code.rawValue
          ?? (error as? SessionError)?.rawValue ?? (error is CancellationError ? "canceled" : "operation_failed")
        reply = CapacityAnswer(id: id, result: nil, error: code)
      }
      timer.cancel()
      do { try writer.write(reply) } catch { ioError = true; _ = shutdown(writer.file.fileDescriptor, SHUT_RDWR) }
      tasks[id] = nil
    }
    tasks[id] = work
    if op == "close" { await work.value }
  }
  func drain(cancel: Bool) async {
    let pending = Array(tasks.values)
    if cancel { for t in pending { t.cancel() } }
    for t in pending { await t.value }
  }
  func finish() async throws {
    await drain(cancel: !closed)
    try await product.stop()
    guard closed, !ioError else { throw CapacityRoleError.incomplete }
  }
}

private func roleSocket() throws -> FileHandle {
  var kind: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size), addr = sockaddr_storage(), n = socklen_t(MemoryLayout<sockaddr_storage>.size)
  var yes: Int32 = 1
  guard getsockopt(3, SOL_SOCKET, SO_TYPE, &kind, &size) == 0, kind == SOCK_STREAM,
        withUnsafeMutablePointer(to: &addr, { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(3, $0, &n) } }) == 0,
        addr.ss_family == sa_family_t(AF_UNIX), fcntl(3, F_SETFD, FD_CLOEXEC) == 0,
        setsockopt(3, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size)) == 0
  else { throw CapacityRoleError.invalidCommand }
  return FileHandle(fileDescriptor: 3, closeOnDealloc: true)
}

// Commands and events are forwarded unchanged. The original launcher owns deadlines, ramp, hold and sampling.
private func readChunk(_ file: FileHandle) throws -> Data {
  var bytes = [UInt8](repeating: 0, count: 8192)
  while true {
    let n = bytes.withUnsafeMutableBytes { Darwin.read(file.fileDescriptor, $0.baseAddress, $0.count) }
    if n >= 0 { return Data(bytes.prefix(n)) }
    if errno != EINTR { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  }
}

private func bridge(_ input: FileHandle, _ output: FileHandle, halfClose: Bool) async throws {
  try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
    DispatchQueue.global().async {
      do {
        while true { let bytes = try readChunk(input); if bytes.isEmpty { break }; try output.write(contentsOf: bytes) }
        if halfClose { _ = shutdown(output.fileDescriptor, SHUT_WR) }; c.resume()
      } catch { c.resume(throwing: error) }
    }
  }
}

func runCapacityRole(_ role: String, _ env: [String: String]) async throws {
  let socket = try roleSocket()
  defer { try? socket.close() }
  if role == "coordinator" {
    async let requests: Void = bridge(.standardInput, socket, halfClose: true)
    async let replies: Void = bridge(socket, .standardOutput, halfClose: false)
    _ = try await (requests, replies); return
  }
  guard role == "product", env["FLOWERSEC_SERVER_PARITY_PEER"] == "1" else { throw CapacityRoleError.invalidCommand }
  let writer = CapacityWriter(socket), runtime = CapacityRuntime(env: env, output: writer)
  let commands = CapacityCommands(product: runtime, writer: writer)
  do {
    // Keep blocking descriptor IO off the Swift cooperative executor.
    let reader = DispatchQueue(label: "flowersec.capacity.commands")
    var pending = Data()
    while true {
      let bytes: Data = try await withCheckedThrowingContinuation { c in reader.async { c.resume(with: Result { try readChunk(socket) }) } }
      if bytes.isEmpty { break }
      for byte in bytes {
        if byte == 10 { guard !pending.isEmpty else { throw CapacityRoleError.invalidCommand }; try await commands.submit(pending); pending.removeAll(keepingCapacity: true) }
        else { guard pending.count < 8192 else { throw CapacityRoleError.invalidCommand }; pending.append(byte) }
      }
    }
    guard pending.isEmpty else { throw CapacityRoleError.invalidCommand }
    try await commands.finish()
  } catch { await commands.drain(cancel: true); try? await runtime.stop(); throw error }
}
#endif
