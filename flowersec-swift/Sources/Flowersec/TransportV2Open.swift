import CoreFoundation
import Foundation

enum OpenPayloadErrorV2: Error, Equatable, Sendable {
  case invalidPayload
}

struct OpenPayloadV2: Equatable, Sendable {
  public static let fixedPayloadBytes = 46
  public static let maxPayloadBytes = 8_192
  public static let maxKindBytes = 128
  public static let maxMetadataBytes = 4_096

  public let logicalStreamID: UInt64
  public let fss2Hash: Data
  public let kind: String
  public let metadata: Data

  public init(logicalStreamID: UInt64, fss2Hash: Data, kind: String, metadata: Data) {
    self.logicalStreamID = logicalStreamID
    self.fss2Hash = fss2Hash
    self.kind = kind
    self.metadata = metadata
  }

  public func encoded() throws -> Data {
    guard logicalStreamID != 0, fss2Hash.count == 32, Self.validKind(kind) else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    let canonicalMetadata = try OpenMetadataCanonicalizerV2.canonicalize(
      metadata,
      allowEmpty: true
    )
    let total = Self.fixedPayloadBytes + kind.utf8.count + canonicalMetadata.count
    guard total <= Self.maxPayloadBytes else {
      throw OpenPayloadErrorV2.invalidPayload
    }

    var output = Data()
    output.reserveCapacity(total)
    output.appendUInt64BE(logicalStreamID)
    output.append(fss2Hash)
    output.appendUInt16BE(UInt16(kind.utf8.count))
    output.appendUInt32BE(UInt32(canonicalMetadata.count))
    output.append(Data(kind.utf8))
    output.append(canonicalMetadata)
    return output
  }

  public static func decode(_ raw: Data) throws -> OpenPayloadV2 {
    guard raw.count >= fixedPayloadBytes, raw.count <= maxPayloadBytes else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    let bytes = [UInt8](raw)
    let logicalStreamID = readUInt64BE(bytes, offset: 0)
    let kindLength = Int(readUInt16BE(bytes, offset: 40))
    let metadataLength = Int(readUInt32BE(bytes, offset: 42))
    guard
      logicalStreamID != 0,
      fixedPayloadBytes + kindLength + metadataLength == bytes.count
    else {
      throw OpenPayloadErrorV2.invalidPayload
    }

    let kindEnd = fixedPayloadBytes + kindLength
    guard
      let kind = String(bytes: bytes[fixedPayloadBytes..<kindEnd], encoding: .utf8),
      validKind(kind)
    else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    let metadata = try OpenMetadataCanonicalizerV2.canonicalize(
      Data(bytes[kindEnd...]),
      allowEmpty: false
    )
    return OpenPayloadV2(
      logicalStreamID: logicalStreamID,
      fss2Hash: Data(bytes[8..<40]),
      kind: kind,
      metadata: metadata
    )
  }

  private static func validKind(_ value: String) -> Bool {
    guard OpenUnicodeV2.valid(value, maxBytes: maxKindBytes, allowEmpty: false) else {
      return false
    }
    guard let first = value.unicodeScalars.first, let last = value.unicodeScalars.last else {
      return false
    }
    return !first.properties.isWhitespace && !last.properties.isWhitespace
  }

  private static func readUInt16BE(_ bytes: [UInt8], offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
  }

  private static func readUInt32BE(_ bytes: [UInt8], offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24 | UInt32(bytes[offset + 1]) << 16
      | UInt32(bytes[offset + 2]) << 8 | UInt32(bytes[offset + 3])
  }

  private static func readUInt64BE(_ bytes: [UInt8], offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for byte in bytes[offset..<(offset + 8)] {
      value = value << 8 | UInt64(byte)
    }
    return value
  }
}

private enum OpenMetadataCanonicalizerV2 {
  private static let maxDepth = 4
  private static let maxNodes = 64
  private static let maxObjectKeys = 64
  private static let maxArrayItems = 32
  private static let maxKeyBytes = 64
  private static let maxStringBytes = 512
  private static let maxSafeInteger: Int64 = 9_007_199_254_740_991

  static func canonicalize(_ raw: Data, allowEmpty: Bool) throws -> Data {
    if raw.isEmpty, allowEmpty {
      return Data("{}".utf8)
    }
    guard !raw.isEmpty, raw.count <= OpenPayloadV2.maxMetadataBytes else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: raw, options: [.fragmentsAllowed])
    } catch {
      throw OpenPayloadErrorV2.invalidPayload
    }
    guard value is [String: Any] else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    var nodes = -1
    try validate(value, depth: 1, nodes: &nodes)
    var canonical = Data()
    try appendCanonical(value, to: &canonical)
    guard canonical.count <= OpenPayloadV2.maxMetadataBytes, canonical == raw else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    return canonical
  }

  private static func validate(_ value: Any, depth: Int, nodes: inout Int) throws {
    guard depth <= maxDepth else { throw OpenPayloadErrorV2.invalidPayload }
    nodes += 1
    guard nodes <= maxNodes else { throw OpenPayloadErrorV2.invalidPayload }

    if value is NSNull { return }
    if let number = value as? NSNumber {
      if CFGetTypeID(number) == CFBooleanGetTypeID() { return }
      let double = number.doubleValue
      guard
        double.isFinite,
        double.rounded(.towardZero) == double,
        double >= -Double(maxSafeInteger),
        double <= Double(maxSafeInteger)
      else {
        throw OpenPayloadErrorV2.invalidPayload
      }
      return
    }
    if let string = value as? String {
      guard OpenUnicodeV2.valid(string, maxBytes: maxStringBytes, allowEmpty: true) else {
        throw OpenPayloadErrorV2.invalidPayload
      }
      return
    }
    if let array = value as? [Any] {
      guard array.count <= maxArrayItems else { throw OpenPayloadErrorV2.invalidPayload }
      for item in array {
        try validate(item, depth: depth + 1, nodes: &nodes)
      }
      return
    }
    guard let object = value as? [String: Any], object.count <= maxObjectKeys else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    for (key, child) in object {
      guard OpenUnicodeV2.valid(key, maxBytes: maxKeyBytes, allowEmpty: false) else {
        throw OpenPayloadErrorV2.invalidPayload
      }
      try validate(child, depth: depth + 1, nodes: &nodes)
    }
  }

  private static func appendCanonical(_ value: Any, to output: inout Data) throws {
    if value is NSNull {
      output.append(Data("null".utf8))
      return
    }
    if let number = value as? NSNumber {
      if CFGetTypeID(number) == CFBooleanGetTypeID() {
        output.append(Data(number.boolValue ? "true".utf8 : "false".utf8))
      } else {
        output.append(Data(String(number.int64Value).utf8))
      }
      return
    }
    if let string = value as? String {
      appendCanonicalString(string, to: &output)
      return
    }
    if let array = value as? [Any] {
      output.append(0x5B)
      for (index, item) in array.enumerated() {
        if index != 0 { output.append(0x2C) }
        try appendCanonical(item, to: &output)
      }
      output.append(0x5D)
      return
    }
    guard let object = value as? [String: Any] else {
      throw OpenPayloadErrorV2.invalidPayload
    }
    let keys = object.keys.sorted(by: utf16Less)
    output.append(0x7B)
    for (index, key) in keys.enumerated() {
      if index != 0 { output.append(0x2C) }
      appendCanonicalString(key, to: &output)
      output.append(0x3A)
      guard let child = object[key] else { throw OpenPayloadErrorV2.invalidPayload }
      try appendCanonical(child, to: &output)
    }
    output.append(0x7D)
  }

  private static func appendCanonicalString(_ value: String, to output: inout Data) {
    output.append(0x22)
    for byte in value.utf8 {
      if byte == 0x22 || byte == 0x5C { output.append(0x5C) }
      output.append(byte)
    }
    output.append(0x22)
  }

  private static func utf16Less(_ left: String, _ right: String) -> Bool {
    Array(left.utf16).lexicographicallyPrecedes(Array(right.utf16))
  }
}

private enum OpenUnicodeV2 {
  static func valid(_ value: String, maxBytes: Int, allowEmpty: Bool) -> Bool {
    let normalized = value.precomposedStringWithCanonicalMapping
    guard
      value.utf8.count <= maxBytes,
      allowEmpty || !value.isEmpty,
      value.utf8.elementsEqual(normalized.utf8)
    else {
      return false
    }
    for scalar in value.unicodeScalars {
      let codePoint = scalar.value
      guard
        !(codePoint <= 0x1F || (codePoint >= 0x7F && codePoint <= 0x9F)),
        let age = scalar.properties.age,
        age.major < 15 || (age.major == 15 && age.minor <= 1)
      else {
        return false
      }
    }
    return true
  }
}
