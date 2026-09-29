import Foundation

struct V4StreamMetadataProjection: Equatable, Sendable {
  let namespace: String
  let version: UInt16
  let values: [String: Data]
}

enum V4StreamMetadataCodec {
  static func encode(namespace: String, version: UInt16, values: [String: Data]) throws -> Data {
    guard namespace.utf8.count <= 64, values.count <= 64 else {
      throw StreamMetadataError.invalidValue
    }
    var entries: [(Data, Data)] = []
    var size = 0
    for (key, value) in values {
      guard (1...64).contains(key.utf8.count), value.count <= 1024 else {
        throw StreamMetadataError.invalidValue
      }
      let name = V4Crypto.text(key)
      let bytes = V4Crypto.bytes(value)
      size += name.count + bytes.count
      guard size <= 4096 else { throw StreamMetadataError.invalidValue }
      entries.append((name, bytes))
    }
    entries.sort {
      $0.0.count == $1.0.count ? $0.0.lexicographicallyPrecedes($1.0) : $0.0.count < $1.0.count
    }
    var map = V4NamespaceValue.head(5, UInt64(entries.count))
    for (key, value) in entries {
      map.append(key)
      map.append(value)
    }
    let result = V4Crypto.map([
      (0, V4Crypto.text(namespace)), (1, V4NamespaceValue.head(0, UInt64(version))), (2, map),
    ])
    _ = try decode(result)
    return result
  }

  static func decode(_ encoded: Data) throws -> V4StreamMetadataProjection {
    do {
      let document = try V4NamespaceDocument(
        encoded, schema: "StreamMetadata", bytes: 4096,
        nodes: 136, registry: V4NamespaceRegistry())
      let root = document.root
      var pairs = try root.field("values").children.makeIterator()
      var values: [String: Data] = [:]
      while let key = pairs.next() {
        guard let value = pairs.next() else { throw StreamMetadataError.invalidValue }
        values[try key.text()] = try value.bytes()
      }
      return try V4StreamMetadataProjection(
        namespace: root.t("namespace"),
        version: UInt16(root.u("version")), values: values)
    } catch { throw StreamMetadataError.invalidValue }
  }
}
