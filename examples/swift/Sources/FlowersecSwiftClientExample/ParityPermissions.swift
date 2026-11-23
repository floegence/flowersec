import Flowersec
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct ParityPermissions: Sendable {
  private struct Grants: Decodable {
    let execute: Set<UInt32>
    let disclose: Set<UInt32>
  }

  let file: String?
  let excluded: Set<UInt32>

  func execute(_ method: UInt32) throws {
    guard !excluded.contains(method) else { throw denied }
    if let file, try !read(file).execute.contains(method) { throw denied }
  }

  func disclose(_ methods: [UInt32]) throws {
    guard excluded.isDisjoint(with: methods) else { throw denied }
    if let file, try !read(file).disclose.isSuperset(of: methods) { throw denied }
  }

  private var denied: RPCError { RPCError(code: 403, message: "parity permission denied") }

  private func read(_ path: String) throws -> Grants {
    let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
    guard descriptor >= 0 else { throw denied }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer { try? handle.close() }
    var info = stat()
    guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_size > 0, info.st_size <= 4096,
          let data = try? handle.read(upToCount: 4097), data.count == info.st_size,
          let fields = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          Set(fields.keys) == ["execute", "disclose"],
          let grants = try? JSONDecoder().decode(Grants.self, from: data) else { throw denied }
    return grants
  }
}
