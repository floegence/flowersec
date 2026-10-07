import Foundation
#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

// Only concrete SDK codecs may select this input path. Protocol conformance,
// application wrappers and caller-provided safety labels grant no capability.
enum V4ControlledMessageInput: Sendable {
  case bytes(Data)
  case utf8(String)

  func boundedSize(maximum: Int) throws -> Int {
    switch self {
    case .bytes(let bytes):
      guard bytes.count <= maximum else { throw MessageCodecFailure.encodeFailed }
      return bytes.count
    case .utf8(let text):
      let size = text.utf8.prefix(maximum + 1).count
      guard size <= maximum else { throw MessageCodecFailure.encodeFailed }
      return size
    }
  }

  // Called only after the complete input/copy vector is acquired. These
  // snapshots do not retain a slice of a larger caller-owned backing.
  func ownedCopy() -> Self {
    switch self {
    case .bytes(let bytes):
      return .bytes(bytes.withUnsafeBytes {
        guard let address = $0.baseAddress, !$0.isEmpty else { return Data() }
        return Data(bytes: address, count: $0.count)
      })
    case .utf8(let text):
      return .utf8(String(decoding: text.utf8, as: UTF8.self))
    }
  }

  func encode(into writer: V4MessageSegments) throws {
    switch self {
    case .bytes(let bytes): try writer.tryAppend(bytes)
    case .utf8(let text):
      // Primitive String.UTF8View invokes no application getter or hook and
      // needs no intermediate complete encoded array.
      for byte in text.utf8 { try writer.tryAppend(byte) }
    }
  }
}

// Mutable bytes remain private to their original writer until Finalize. The
// publisher sees bounded copies; no writable alias crosses the adapter API.
final class V4MessageSegment: @unchecked Sendable {
  private var bytes: Data
  let capacity: Int
  private(set) var used = 0

  init(capacity: Int, allocation: Int, storage: V4CryptoReservation) throws {
    guard let pointer = malloc(allocation) else { throw MessageStreamFailure.resourceExhausted }
    self.capacity = capacity
    bytes = Data(bytesNoCopy: pointer, count: capacity, deallocator: .custom { pointer, _ in
      free(pointer)
      withExtendedLifetime(storage) {}
    })
  }

  func append(_ source: UnsafeRawBufferPointer) {
    precondition(source.count <= capacity - used)
    if !source.isEmpty {
      bytes.withUnsafeMutableBytes { destination in
        destination.baseAddress!.advanced(by: used).copyMemory(
          from: source.baseAddress!, byteCount: source.count)
      }
      used += source.count
    }
  }

  func copyChunk(offset: Int, maximum: Int) -> Data {
    precondition(offset >= 0 && offset <= used)
    return bytes.subdata(in: offset..<min(used, offset + maximum))
  }
}

// The resource and FIFO owner execute each growth under the original gate.
// One append reserves all new blocks at once before allocation or copying.
final class V4MessageSegments {
  private let maximum: Int
  private let gate: NSRecursiveLock
  private let reserve: (Int, Int) throws -> V4CryptoReservation
  private let check: () throws -> Void
  private var blocks: [V4MessageSegment] = []
  private var capacity = 0
  private var length = 0
  private var index = 0
  private var sealed = false
  private var failure: Error?

  init(
    maximum: Int, gate: NSRecursiveLock,
    reserve: @escaping (Int, Int) throws -> V4CryptoReservation,
    check: @escaping () throws -> Void
  ) {
    self.maximum = maximum; self.gate = gate; self.reserve = reserve; self.check = check
    blocks.reserveCapacity(65)
  }

  // Darwin's allocator size is known before allocation. Platforms without
  // that native size contract retain the arbitrary codec's conservative path.
  static var available: Bool {
    #if canImport(Darwin)
      return true
    #else
      return false
    #endif
  }

  private static func allocationSize(_ requested: Int) throws -> Int {
    #if canImport(Darwin)
      return malloc_good_size(requested)
    #else
      throw V4ResourceFailure.configuration
    #endif
  }

  private func prepare(_ count: Int) throws {
    if let failure { throw failure }
    guard !sealed, count >= 0, count <= maximum - length else {
      throw MessageCodecFailure.encodeFailed
    }
    try check()
    guard count > capacity - length else { return }
    var requested = capacity
    var physical = 0
    var additions: [(Int, Int)] = []
    additions.reserveCapacity(65)
    while count > requested - length {
      let next = min(requested == 0 ? 256 : 16_384, maximum - requested)
      guard next > 0, blocks.count + additions.count < 65 else {
        throw MessageCodecFailure.encodeFailed
      }
      let actual = try Self.allocationSize(next)
      guard actual >= next, actual <= 32_768 else { throw MessageCodecFailure.encodeFailed }
      requested += next
      physical += actual
      additions.append((next, actual))
    }
    let storage = try reserve(physical, additions.count)
    for (requested, actual) in additions {
      blocks.append(try V4MessageSegment(capacity: requested, allocation: actual, storage: storage))
    }
    capacity = requested
  }

  func tryAppend(_ bytes: Data) throws {
    try gate.withLock {
      do {
        try prepare(bytes.count)
        bytes.withUnsafeBytes { source in
          var offset = 0
          while offset < source.count {
            let block = blocks[index]
            let count = min(source.count - offset, block.capacity - block.used)
            block.append(UnsafeRawBufferPointer(rebasing: source[offset..<offset + count]))
            offset += count
            if block.used == block.capacity { index += 1 }
          }
        }
        length += bytes.count
      } catch { failure = failure ?? error; throw failure! }
    }
  }

  func tryAppend(_ byte: UInt8) throws {
    try gate.withLock {
      do {
        try prepare(1)
        var value = byte
        withUnsafeBytes(of: &value) { blocks[index].append($0) }
        if blocks[index].used == blocks[index].capacity { index += 1 }
        length += 1
      } catch { failure = failure ?? error; throw failure! }
    }
  }

  func finalize() throws -> (segments: [V4MessageSegment], length: Int) {
    try gate.withLock {
      if let failure { throw failure }
      guard !sealed else { throw MessageCodecFailure.encodeFailed }
      do {
        try check()
        sealed = true
        let candidate = blocks
        blocks = []
        return (candidate, length)
      } catch { failure = error; sealed = true; throw error }
    }
  }
}
