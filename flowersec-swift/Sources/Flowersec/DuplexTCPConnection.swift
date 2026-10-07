import Foundation

public enum DuplexTCPOperation: String, Sendable {
  case configure, connect, read, write, halfClose = "half_close", close
}

/// Actual native failure, detached from socket ownership and payload data.
public struct DuplexTCPError: Error, Sendable, Equatable {
  public let operation: DuplexTCPOperation
  public let systemCode: Int32
  init(_ operation: DuplexTCPOperation, _ systemCode: Int32) {
    self.operation = operation; self.systemCode = systemCode
  }
}

#if os(macOS) || os(iOS)
import Darwin

/// A dedicated native TCP socket owned exclusively by the SDK. It exposes no
/// descriptor, Channel, ByteStream I/O, TLS claim, or authenticated drain claim.
/// A bridge must pair it with an original Flowersec raw Stream from the same
/// Environment. Close is refused after transfer; Abort belongs to the bridge.
public final class DuplexTCPConnection: @unchecked Sendable {
  let owner: V4DuplexTCPOwner
  init(_ owner: V4DuplexTCPOwner) { self.owner = owner }
  public func close() throws { try owner.closeUnclaimed() }
  public func cleanupStatus() -> CleanupStatus { owner.nativeCleanupStatus() }
  deinit { owner.closeIfUnclaimed() }
}

public extension TransportEnvironment {
  /// Opens a fresh, fully owned socket to an application-selected numeric
  /// IPv4/IPv6 address. No DNS lookup or external socket adoption is performed.
  func connectDuplexTCP(numericAddress: String, port: Int,
    chunkBytes: Int = 16_384, kernelBufferBytes: Int = 65_536,
    timeout: Duration = .seconds(10)) async throws -> DuplexTCPConnection {
    let environment = try notificationFoundation()
    let address = try V4DuplexTCPAddress(numericAddress, port: port)
    guard timeout > .zero, timeout <= .seconds(90) else { throw DuplexBridgeFailure.configurationCapacity }
    let owner = try V4DuplexTCPOwner(environment: environment, address: address,
      chunkBytes: chunkBytes, kernelBufferBytes: kernelBufferBytes)
    let deadline = ContinuousClock.now.advanced(by: timeout)
    do {
      try await owner.connect(before: deadline)
      return try owner.connectionForPublication(before: deadline)
    } catch { owner.close(); throw error }
  }
}

fileprivate struct V4DuplexTCPAddress: Sendable {
  let bytes: Data
  let family: Int32
  init(_ value: String, port: Int) throws {
    guard (1...65535).contains(port), !value.isEmpty, value.utf8.count <= 64,
      !value.utf8.contains(0) else { throw DuplexBridgeFailure.configurationCapacity }
    var ipv4 = sockaddr_in()
    ipv4.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    ipv4.sin_family = sa_family_t(AF_INET)
    ipv4.sin_port = UInt16(port).bigEndian
    let v4 = value.withCString { Darwin.inet_pton(AF_INET, $0, &ipv4.sin_addr) }
    if v4 == 1 {
      bytes = withUnsafeBytes(of: ipv4) { Data($0) }; family = AF_INET
      return
    }
    var ipv6 = sockaddr_in6()
    ipv6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
    ipv6.sin6_family = sa_family_t(AF_INET6)
    ipv6.sin6_port = UInt16(port).bigEndian
    let v6 = value.withCString { Darwin.inet_pton(AF_INET6, $0, &ipv6.sin6_addr) }
    guard v6 == 1 else { throw DuplexBridgeFailure.configurationCapacity }
    bytes = withUnsafeBytes(of: ipv6) { Data($0) }; family = AF_INET6
  }
}

final class V4DuplexTCPOwner: V4DuplexBridgeEndpoint, V4NativeConnectionLifecycle, @unchecked Sendable {
  let bridgeEnvironment: V4EnvironmentFoundation
  var bridgeKind: DuplexBridgeEndpointKind { .nativeTCP }
  private var gate: NSRecursiveLock { bridgeEnvironment.gate }
  private let address: V4DuplexTCPAddress
  private let maximumChunk: Int
  private var chunkLimit: Int
  private var descriptor: Int32 = -1
  private var storage: V4CryptoReservation?
  private var physicalTail: V4ResourceReference?
  private var scratch: Data
  private var token: V4DuplexBridgeToken?
  private var connecting = false
  private var connected = false
  private var closed = false
  private var reading = false
  private var writing = false
  private var inputEOF = false
  private var outputShutdown = false
  private var closeError: DuplexTCPError?

  fileprivate init(environment: V4EnvironmentFoundation, address: V4DuplexTCPAddress,
    chunkBytes: Int, kernelBufferBytes: Int) throws {
    bridgeEnvironment = environment; self.address = address
    maximumChunk = chunkBytes; chunkLimit = chunkBytes
    scratch = Data()
    let storage = try environment.duplexNativeTCPStorage(chunkBytes: chunkBytes,
      kernelBufferBytes: kernelBufferBytes)
    self.storage = storage
    physicalTail = try storage.executionTail()
    do {
      try environment.gate.withLock {
        try storage.check()
        try environment.registerNativeConnection(self)
        descriptor = Darwin.socket(address.family, SOCK_STREAM, Int32(IPPROTO_TCP))
        guard descriptor >= 0 else { throw DuplexTCPError(.configure, errno) }
        guard Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
          Darwin.fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
          throw DuplexTCPError(.configure, errno)
        }
        var noSignal: Int32 = 1
        guard Darwin.setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
          socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw DuplexTCPError(.configure, errno) }
        var buffer = Int32(kernelBufferBytes)
        guard Darwin.setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &buffer,
          socklen_t(MemoryLayout<Int32>.size)) == 0,
          Darwin.setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &buffer,
          socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw DuplexTCPError(.configure, errno) }
        // The kernel may clamp or round buffer sizes. The provider reservation
        // includes both buffers and bounded OS bookkeeping; a larger-than-
        // admitted effective buffer is refused before connect or payload I/O.
        for option in [SO_RCVBUF, SO_SNDBUF] {
          var actual: Int32 = 0
          var length = socklen_t(MemoryLayout<Int32>.size)
          guard Darwin.getsockopt(descriptor, SOL_SOCKET, option, &actual, &length) == 0 else {
            throw DuplexTCPError(.configure, errno)
          }
          guard actual > 0, actual <= buffer * 2 else { throw DuplexBridgeFailure.configurationCapacity }
        }
        scratch = Data(count: chunkBytes)
      }
    } catch { close(); throw error }
  }

  fileprivate func connect(before deadline: ContinuousClock.Instant) async throws {
    try gate.withLock {
      try check()
      try Task.checkCancellation()
      guard ContinuousClock.now < deadline else { throw DuplexBridgeFailure.deadlineExceeded }
      guard !connected, !connecting, token == nil else { throw DuplexBridgeFailure.streamOwned }
      connecting = true
    }
    defer { gate.withLock { connecting = false; releaseIfExited() } }
    var requested = false
    while true {
      try Task.checkCancellation()
      guard ContinuousClock.now < deadline else { throw DuplexBridgeFailure.deadlineExceeded }
      let ready = try gate.withLock { () throws -> Bool in
        try check()
        // The connect syscall must be admitted under the same original gate
        // as Close and environment shutdown. The outer check can become stale
        // while waiting for that gate.
        try Task.checkCancellation()
        guard ContinuousClock.now < deadline else { throw DuplexBridgeFailure.deadlineExceeded }
        if !requested {
          var target = sockaddr_storage()
          withUnsafeMutableBytes(of: &target) { $0.copyBytes(from: address.bytes) }
          let result = withUnsafePointer(to: &target) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
              Darwin.connect(descriptor, $0, socklen_t(address.bytes.count))
            }
          }
          let code = errno
          requested = true
          if result == 0 { connected = true; return true }
          guard code == EINPROGRESS || code == EALREADY || code == EINTR else { throw DuplexTCPError(.connect, code) }
        }
        var event = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
        let polled = Darwin.poll(&event, 1, 0)
        guard polled >= 0 || errno == EINTR else { throw DuplexTCPError(.connect, errno) }
        if polled <= 0 { return false }
        var code: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard Darwin.getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &code, &length) == 0 else { throw DuplexTCPError(.connect, errno) }
        guard code == 0 else { throw DuplexTCPError(.connect, code) }
        connected = true
        return true
      }
      if ready { return }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }

  private func check() throws {
    guard !closed, descriptor >= 0, let storage else { throw SessionError.closed }
    try storage.check()
  }
  func connectionForPublication(before deadline: ContinuousClock.Instant) throws -> DuplexTCPConnection {
    try gate.withLock {
      try check()
      try Task.checkCancellation()
      guard ContinuousClock.now < deadline else { throw DuplexBridgeFailure.deadlineExceeded }
      guard connected, !connecting else { throw DuplexBridgeFailure.ownerUnavailable }
      // Mint the public alias inside the original lifecycle gate, so Close
      // cannot win between the final admission and ownership publication.
      return DuplexTCPConnection(self)
    }
  }
  func checkBridgeCandidate(chunkBytes: Int) throws {
    try gate.withLock {
      try check()
      guard connected, !connecting, token == nil, !reading, !writing,
        !inputEOF, !outputShutdown else { throw DuplexBridgeFailure.streamOwned }
      guard chunkBytes <= maximumChunk else { throw DuplexBridgeFailure.configurationCapacity }
    }
  }
  func claimBridge(token: V4DuplexBridgeToken, chunkBytes: Int) throws {
    try gate.withLock {
      try checkBridgeCandidate(chunkBytes: chunkBytes)
      self.token = token; chunkLimit = chunkBytes
    }
  }
  private func checkToken(_ token: V4DuplexBridgeToken) throws {
    try check()
    guard self.token === token else { throw DuplexBridgeFailure.streamOwned }
  }

  func bridgeRead(token: V4DuplexBridgeToken, maxBytes: Int,
    beforeRead: @escaping @Sendable () throws -> Void,
    delivered: @escaping @Sendable (Data) -> Void) async throws -> Data? {
    try gate.withLock {
      try checkToken(token)
      guard !reading, (1...chunkLimit).contains(maxBytes) else { throw DuplexBridgeFailure.resourceExhausted }
      reading = true
    }
    defer { gate.withLock { reading = false; releaseIfExited() } }
    while true {
      try Task.checkCancellation()
      let input = try gate.withLock { () throws -> Data?? in
        try checkToken(token); try beforeRead()
        if inputEOF { return .some(nil) }
        let count = scratch.withUnsafeMutableBytes { raw in Darwin.recv(descriptor, raw.baseAddress, maxBytes, 0) }
        let code = errno
        if count > 0 {
          let bytes = scratch.subdata(in: 0..<count)
          // Consumption and progress/tail transfer occur synchronously under
          // the same original gate as Abort and destination acceptance.
          delivered(bytes)
          return .some(bytes)
        }
        if count == 0 { inputEOF = true; return .some(nil) }
        if code == EAGAIN || code == EWOULDBLOCK || code == EINTR { return nil }
        throw DuplexTCPError(.read, code)
      }
      if let input { return input }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }

  func bridgeWrite(token: V4DuplexBridgeToken, _ data: Data,
    beforeAccept: @escaping @Sendable () throws -> Void,
    accepted: @escaping @Sendable (Int) -> Void) async throws -> Int {
    try gate.withLock {
      try checkToken(token)
      guard !writing, !outputShutdown, !data.isEmpty, data.count <= chunkLimit else { throw DuplexBridgeFailure.streamOwned }
      writing = true
    }
    defer { gate.withLock { writing = false; releaseIfExited() } }
    while true {
      try Task.checkCancellation()
      let count = try gate.withLock { () throws -> Int? in
        try checkToken(token); try beforeAccept()
        let count = data.withUnsafeBytes { raw in Darwin.send(descriptor, raw.baseAddress, raw.count, 0) }
        let code = errno
        if count > 0 { accepted(count); return count }
        if count < 0 && (code == EAGAIN || code == EWOULDBLOCK || code == EINTR) { return nil }
        throw DuplexTCPError(.write, count == 0 ? EIO : code)
      }
      if let count { return count }
      try await ContinuousClock().sleep(for: .milliseconds(5))
    }
  }

  func bridgeCloseWrite(token: V4DuplexBridgeToken,
    beforeFinish: @escaping @Sendable () throws -> Void) async throws {
    try gate.withLock {
      try checkToken(token); try beforeFinish()
      if outputShutdown { return }
      guard !writing else { throw DuplexBridgeFailure.streamOwned }
      guard Darwin.shutdown(descriptor, SHUT_WR) == 0 else { throw DuplexTCPError(.halfClose, errno) }
      outputShutdown = true
    }
  }
  func bridgeFinish(token: V4DuplexBridgeToken,
    beforeFinish: @escaping @Sendable () throws -> Void) async throws {
    try gate.withLock {
      try checkToken(token); try beforeFinish()
      guard outputShutdown, inputEOF, !reading, !writing else { throw DuplexBridgeFailure.finishFailed }
      // Each send was admitted by the real kernel send queue; SHUT_WR placed
      // FIN after that prefix. This does not prove peer drain or business work.
      closeDescriptor(aborting: false)
      releaseIfExited()
      if let closeError { throw closeError }
    }
  }
  func bridgeReset(token: V4DuplexBridgeToken) {
    gate.withLock { if self.token === token { closeDescriptor(); releaseIfExited() } }
  }
  func bridgeCleanupComplete(token: V4DuplexBridgeToken) -> Bool {
    gate.withLock { self.token === token && closed && !connecting && !reading && !writing && storage == nil }
  }

  func closeUnclaimed() throws {
    try gate.withLock {
      guard token == nil else { throw DuplexBridgeFailure.streamOwned }
      closeDescriptor(); releaseIfExited()
      if let closeError { throw closeError }
    }
  }
  func closeIfUnclaimed() { gate.withLock { if token == nil { closeDescriptor(); releaseIfExited() } } }
  // Environment close is authoritative and may abort a transferred endpoint.
  func close() { gate.withLock { closeDescriptor(); releaseIfExited() } }
  private func closeDescriptor(aborting: Bool = true) {
    guard !closed else { return }
    closed = true
    if descriptor >= 0 {
      if aborting { _ = Darwin.shutdown(descriptor, SHUT_RDWR) }
      if Darwin.close(descriptor) != 0 { closeError = DuplexTCPError(.close, errno) }
      // Never retry an ambiguous close on a descriptor the OS may have reused.
      descriptor = -1
    }
  }
  private func releaseIfExited() {
    guard closed, closeError == nil, !connecting, !reading, !writing else { return }
    scratch = Data()
    physicalTail?.release(); physicalTail = nil; storage = nil
  }
  func nativeCleanupStatus() -> CleanupStatus {
    gate.withLock { CleanupStatus(complete: closed && storage == nil, cleanupIncomplete: closeError != nil,
      pendingCallbacks: UInt64((connecting ? 1 : 0) + (reading ? 1 : 0) + (writing ? 1 : 0))) }
  }
  deinit {
    gate.withLock {
      closeDescriptor()
      // An ambiguous close has no physical exit proof. Leave its original
      // execution-tail slot charged in the root instead of releasing it when
      // the last public alias disappears. Cleanup stays incomplete and this
      // capacity cannot be reused during that root's remaining lifetime.
      releaseIfExited()
    }
  }
}
#endif
