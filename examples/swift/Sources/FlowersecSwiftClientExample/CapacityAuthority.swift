#if os(macOS)
import CryptoKit
import Darwin
import Foundation

func privateCapacityFile(_ url: URL, maximum: Int) throws -> Data {
  let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
  guard descriptor >= 0 else { throw CapacityRoleError.invalidMaterial }
  let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
  defer { try? handle.close() }
  var info = stat()
  guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
        info.st_mode & 0o077 == 0, info.st_size > 0, info.st_size <= maximum,
        let bytes = try handle.read(upToCount: maximum + 1), bytes.count == info.st_size
  else { throw CapacityRoleError.invalidMaterial }
  return bytes
}

func capacityBase64URL(_ bytes: Data) -> String {
  bytes.base64EncodedString().replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "=", with: "")
}

struct CapacityAuthority: Sendable {
  private struct Record: Decodable { let schema_version: Int; let lookup_key, artifact_base64url: String }
  private let file: URL, digest: SHA256.Digest

  init(directory: URL, key: String, artifact: Data) throws {
    file = directory.appendingPathComponent(key + ".json")
    let bytes = try privateCapacityFile(file, maximum: 96 * 1024)
    let record = try JSONDecoder().decode(Record.self, from: bytes)
    guard record.schema_version == 1, record.lookup_key == key, record.artifact_base64url == capacityBase64URL(artifact)
    else { throw CapacityRoleError.invalidMaterial }
    digest = SHA256.hash(data: bytes)
  }

  func check() throws {
    guard let bytes = try? privateCapacityFile(file, maximum: 96 * 1024), SHA256.hash(data: bytes) == digest
    else { throw CapacityRoleError.invalidMaterial }
  }
}
#endif
