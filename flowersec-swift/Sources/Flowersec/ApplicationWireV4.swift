import Foundation

/// The grammar is intentionally separate from authenticated service authority.
/// Parsed headers cannot register a method or authorize an application entry.
final class V4ApplicationWireRegistry: @unchecked Sendable {
  struct Variant: Sendable {
    let code: UInt64
    let fields: [Int]
    let constants: [Int: UInt64]
    let request: String?
    let sdkError: Bool
    let applicationError: Bool
  }
  let variants: [String: Variant]
  init() throws {
    guard let document = try JSONSerialization.jsonObject(with: Data(TransportV4Registry.applicationHeaderRegistryJSON.utf8)) as? [String: Any],
      let kinds = document["kinds"] as? [String: [String: Any]] else { throw ServiceFailure.protocolFailure }
    var result: [String: Variant] = [:]
    for (name, value) in kinds {
      guard let code = V4NamespaceRegistry.number(value["code"]), let fields = value["fields"] as? [Int] else {
        throw ServiceFailure.protocolFailure
      }
      var constants: [Int: UInt64] = [:]
      for (key, constant) in value["constants"] as? [String: Any] ?? [:] {
        guard let field = Int(key), let number = V4NamespaceRegistry.number(constant) else { throw ServiceFailure.protocolFailure }
        constants[field] = number
      }
      result[name] = Variant(code: code, fields: fields, constants: constants, request: value["request"] as? String,
        sdkError: value["sdk_error"] as? Bool == true, applicationError: value["application_error"] as? Bool == true)
    }
    variants = result
  }
}

struct V4ApplicationHeader: Sendable, Equatable {
  enum Scalar: Sendable, Equatable { case uint(UInt64), bytes(Data) }
  let kind: String
  let fields: [Int: Scalar]
  func uint(_ id: Int) throws -> UInt64 {
    guard case .uint(let value) = fields[id] else { throw ServiceFailure.protocolFailure }
    return value
  }
  func bytes(_ id: Int) throws -> Data {
    guard case .bytes(let value) = fields[id] else { throw ServiceFailure.protocolFailure }
    return value
  }
  var payloadBytes: Int { get throws { try Int(uint(3)) } }
  var typeID: UInt32 { get throws { try UInt32(uint(2)) } }
  init(kind: String, fields: [Int: Scalar], registry: V4ApplicationWireRegistry) throws {
    guard let variant = registry.variants[kind] else { throw ServiceFailure.protocolFailure }
    var complete = fields
    complete[0] = .uint(variant.code)
    guard complete.keys.sorted() == variant.fields else { throw ServiceFailure.protocolFailure }
    for (id, scalar) in complete {
      if [1, 4, 6].contains(id) {
        guard case .bytes(let value) = scalar, value.count == 32 else { throw ServiceFailure.protocolFailure }
      } else {
        guard case .uint(let value) = scalar else { throw ServiceFailure.protocolFailure }
        switch id {
        case 0: guard value == variant.code else { throw ServiceFailure.protocolFailure }
        case 2, 10: guard value > 0, value <= UInt64(UInt32.max) else { throw ServiceFailure.protocolFailure }
        case 3, 8: guard value <= 1_048_576 else { throw ServiceFailure.protocolFailure }
        case 7: guard value <= 1 else { throw ServiceFailure.protocolFailure }
        case 9: guard value > 0 else { throw ServiceFailure.protocolFailure }
        default: break
        }
        if let constant = variant.constants[id], constant != value { throw ServiceFailure.protocolFailure }
      }
    }
    self.kind = kind; self.fields = complete
  }
  init(encoded: Data, registry: V4ApplicationWireRegistry) throws {
    guard (1...512).contains(encoded.count) else { throw ServiceFailure.protocolFailure }
    var decoder = V4ApplicationCBOR(encoded)
    let (major, count) = try decoder.head()
    guard major == 5, count <= 11 else { throw ServiceFailure.protocolFailure }
    var fields: [Int: Scalar] = [:]
    var previous = -1
    for _ in 0..<Int(count) {
      let (keyMajor, id) = try decoder.head()
      guard keyMajor == 0, id <= 10, Int(id) > previous else { throw ServiceFailure.protocolFailure }
      previous = Int(id)
      let (valueMajor, value) = try decoder.head()
      if valueMajor == 0 { fields[previous] = .uint(value) }
      else if valueMajor == 2, value == 32 { fields[previous] = .bytes(try decoder.take(32)) }
      else { throw ServiceFailure.protocolFailure }
    }
    guard decoder.finished, case .uint(let code) = fields[0],
      let kind = registry.variants.first(where: { $0.value.code == code })?.key else { throw ServiceFailure.protocolFailure }
    try self.init(kind: kind, fields: fields, registry: registry)
  }
  func encoded() -> Data {
    V4Crypto.map(fields.keys.sorted().map { id in
      let encoded: Data
      switch fields[id]! {
      case .uint(let value): encoded = V4NamespaceValue.head(0, value)
      case .bytes(let value): encoded = V4Crypto.bytes(value)
      }
      return (UInt64(id), encoded)
    })
  }
  func checkResponse(to original: Self, registry: V4ApplicationWireRegistry) throws {
    guard let variant = registry.variants[kind], variant.request == original.kind else { throw ServiceFailure.protocolFailure }
    for id in [1, 2, 4, 6, 9] { guard fields[id] == original.fields[id] else { throw ServiceFailure.protocolFailure } }
    if original.fields[8] != nil, !variant.sdkError, try uint(3) > original.uint(8) { throw ServiceFailure.protocolFailure }
    if variant.sdkError, try uint(3) > 1024 { throw ServiceFailure.protocolFailure }
  }
}

struct V4ApplicationCBOR {
  private let input: Data
  private var offset = 0
  init(_ input: Data) { self.input = input }
  var finished: Bool { offset == input.count }
  mutating func take(_ count: Int) throws -> Data {
    guard count >= 0, count <= input.count - offset else { throw ServiceFailure.protocolFailure }
    defer { offset += count }
    return Data(input[offset..<offset + count])
  }
  mutating func head() throws -> (UInt8, UInt64) {
    let initial = try take(1)[0]
    let additional = initial & 31
    if additional < 24 { return (initial >> 5, UInt64(additional)) }
    let width: Int
    switch additional { case 24: width = 1; case 25: width = 2; case 26: width = 4; case 27: width = 8; default: throw ServiceFailure.protocolFailure }
    let value = try take(width).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    let minimum: UInt64 = width == 1 ? 24 : width == 2 ? 256 : width == 4 ? 65536 : 0x1_0000_0000
    guard value >= minimum else { throw ServiceFailure.protocolFailure }
    return (initial >> 5, value)
  }
}

struct V4RPCFragment: Sendable {
  enum Kind: UInt8, Sendable { case begin = 0, data = 1, abort = 2, stopOutput = 3 }
  let kind: Kind
  let serial: UInt64
  let replyTo: UInt64
  let offset: UInt32
  let payload: Data
  init(kind: Kind, serial: UInt64, replyTo: UInt64 = 0, offset: UInt32 = 0, payload: Data = Data()) throws {
    guard serial > 0 else { throw ServiceFailure.protocolFailure }
    switch kind {
    case .begin: guard (1...512).contains(payload.count), offset == 0 else { throw ServiceFailure.protocolFailure }
    case .data: guard (1...16_367).contains(payload.count), replyTo == 0 else { throw ServiceFailure.protocolFailure }
    case .abort: guard payload.isEmpty, replyTo == 0 else { throw ServiceFailure.protocolFailure }
    case .stopOutput: guard payload.isEmpty, replyTo == 0, offset == 0 else { throw ServiceFailure.protocolFailure }
    }
    self.kind = kind; self.serial = serial; self.replyTo = replyTo; self.offset = offset; self.payload = payload
  }
  init(encoded: Data) throws {
    func integer(_ start: Int, _ width: Int) throws -> UInt64 {
      guard start >= 0, start + width <= encoded.count else { throw ServiceFailure.protocolFailure }
      return encoded[start..<start + width].reduce(0) { $0 << 8 | UInt64($1) }
    }
    guard (13...16_384).contains(encoded.count), try integer(0, 4) == UInt64(encoded.count - 4),
      let kind = Kind(rawValue: encoded[4]) else { throw ServiceFailure.protocolFailure }
    let serial = try integer(5, 8)
    switch kind {
    case .begin:
      let length = try integer(21, 2)
      guard encoded.count == 23 + Int(length) else { throw ServiceFailure.protocolFailure }
      try self.init(kind: kind, serial: serial, replyTo: integer(13, 8), payload: Data(encoded.dropFirst(23)))
    case .data, .abort:
      guard encoded.count >= 17 else { throw ServiceFailure.protocolFailure }
      try self.init(kind: kind, serial: serial, offset: UInt32(integer(13, 4)), payload: Data(encoded.dropFirst(17)))
    case .stopOutput:
      guard encoded.count == 13 else { throw ServiceFailure.protocolFailure }
      try self.init(kind: kind, serial: serial)
    }
  }
  func encoded() -> Data {
    var body = Data([kind.rawValue]) + V4Crypto.integer(serial, width: 8)
    switch kind {
    case .begin: body += V4Crypto.integer(replyTo, width: 8) + V4Crypto.integer(UInt64(payload.count), width: 2)
    case .data, .abort: body += V4Crypto.integer(UInt64(offset), width: 4)
    case .stopOutput: break
    }
    body += payload
    return V4Crypto.integer(UInt64(body.count), width: 4) + body
  }
}
