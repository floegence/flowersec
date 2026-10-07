import Foundation

// Application kinds use frozen canonical text and namespace rules.
// The reserved Flowersec namespace belongs only to authenticated SDK services.
enum V4ApplicationStreamKind {
  static func valid(_ kind: String) -> Bool {
    guard (1...128).contains(kind.utf8.count),
      !kind.hasPrefix("flowersec."), !kind.hasPrefix("flowersec/"),
      kind.utf8.elementsEqual(kind.precomposedStringWithCanonicalMapping.utf8),
      let first = kind.unicodeScalars.first, let last = kind.unicodeScalars.last,
      !first.properties.isWhitespace, !last.properties.isWhitespace else { return false }
    return kind.unicodeScalars.allSatisfy {
      !($0.value <= 0x1F || (0x7F...0x9F).contains($0.value)) && Unicode151Generated.assigned($0)
    }
  }
}

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

  static func typed(definition: Data, application: StreamMetadata) throws -> StreamMetadata {
    let encodedApplication = try application.encoded()
    guard definition.count == 32, encodedApplication.count <= 4006,
      application.namespace?.hasPrefix("flowersec/") != true else {
      throw StreamMetadataError.invalidValue
    }
    // Canonical text-map ordering places the ten-byte name before the
    // eleven-byte name; neither entry uses the ordinary 1024-byte value cap.
    let values = V4NamespaceValue.head(5, 2)
      + V4Crypto.text("definition") + V4Crypto.bytes(definition)
      + V4Crypto.text("application") + V4Crypto.bytes(encodedApplication)
    let encoded = V4Crypto.map([
      (0, V4Crypto.text("flowersec/typed-message")),
      (1, V4NamespaceValue.head(0, 1)), (2, values),
    ])
    guard encoded.count <= 4096 else { throw StreamMetadataError.invalidValue }
    return try StreamMetadata(encoded: encoded)
  }

  static func typedApplication(_ metadata: StreamMetadata, definition: Data) throws -> StreamMetadata {
    guard metadata.namespace == "flowersec/typed-message", metadata.version == 1,
      let values = metadata.byteValues, values.count == 2,
      values["definition"] == definition, let application = values["application"] else {
      throw StreamMetadataError.invalidValue
    }
    let result = try StreamMetadata(encoded: application)
    guard result.namespace?.hasPrefix("flowersec/") != true else {
      throw StreamMetadataError.invalidValue
    }
    return result
  }

  static func decode(_ encoded: Data) throws -> V4StreamMetadataProjection {
    do {
      let registry = try V4NamespaceRegistry()
      let document: V4NamespaceDocument
      do {
        document = try V4NamespaceDocument(
          encoded, schema: "TypedMessageMetadata", bytes: 4096, nodes: 160, registry: registry)
      } catch {
        document = try V4NamespaceDocument(
          encoded, schema: "StreamMetadata", bytes: 4096, nodes: 136, registry: registry)
      }
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
