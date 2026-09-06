import Foundation

enum JSONPreflightV3 {
  enum ValidationError: Error { case invalid }
  private static let maximumDepth = 128

  static func validate(_ data: Data) throws {
    var parser = Parser(bytes: Array(data))
    try parser.document(context: .ordinary)
  }

  static func validateArtifact(_ data: Data) throws {
    var parser = Parser(bytes: Array(data))
    try parser.document(context: .artifactRoot)
  }

  static func scopedPayloads(_ data: Data) throws -> [Data] {
    var parser = Parser(bytes: Array(data))
    try parser.document(context: .artifactRoot)
    return parser.payloads
  }

  // Foundation dictionaries use Swift String equality and therefore collapse
  // canonically equivalent but byte-distinct member names. Keep a raw-byte
  // structural check available for canonical documents that contain both.
  static func validateCanonicalStructure(_ data: Data) throws -> Bool {
    var parser = CanonicalParser(bytes: Array(data))
    let collision = try parser.document()
    return collision
  }

  private enum Context {
    case ordinary
    case artifactRoot
    case artifactScopes
    case artifactScope
  }

  private struct ScopedBudget { var nodes = 0 }

  private struct Parser {
    let bytes: [UInt8]
    var index = 0
    var payloads = [Data]()

    mutating func document(context: Context) throws {
      try value(context: context, depth: 0)
      space()
      guard index == bytes.count else { throw ValidationError.invalid }
    }

    mutating func value(context: Context, depth: Int) throws {
      guard depth <= JSONPreflightV3.maximumDepth else { throw ValidationError.invalid }
      space()
      guard index < bytes.count else { throw ValidationError.invalid }
      switch bytes[index] {
      case 123: try object(context: context, depth: depth)
      case 91: try array(context: context, depth: depth)
      case 34: _ = try string()
      default: _ = try scalar()
      }
    }

    mutating func object(context: Context, depth: Int) throws {
      guard take(123) else { throw ValidationError.invalid }
      space()
      var keys = Set<String>()
      if take(125) { return }
      while true {
        space()
        let key = try string()
        guard keys.insert(key).inserted else { throw ValidationError.invalid }
        space()
        guard take(58) else { throw ValidationError.invalid }
        if context == .artifactRoot && key == "scoped" {
          try value(context: .artifactScopes, depth: depth + 1)
        } else if context == .artifactScope && key == "payload" {
          var budget = ScopedBudget()
          space()
          let start = index
          try scopedValue(depth: 1, root: true, budget: &budget)
          payloads.append(Data(bytes[start..<index]))
        } else {
          try value(context: .ordinary, depth: depth + 1)
        }
        space()
        if take(125) { return }
        guard take(44) else { throw ValidationError.invalid }
      }
    }

    mutating func array(context: Context, depth: Int) throws {
      guard take(91) else { throw ValidationError.invalid }
      space()
      if take(93) { return }
      while true {
        try value(context: context == .artifactScopes ? .artifactScope : .ordinary, depth: depth + 1)
        space()
        if take(93) { return }
        guard take(44) else { throw ValidationError.invalid }
      }
    }

    mutating func scopedValue(depth: Int, root: Bool, budget: inout ScopedBudget) throws {
      space()
      guard depth <= 16, budget.nodes < 256, index < bytes.count else {
        throw ValidationError.invalid
      }
      budget.nodes += 1
      if root && bytes[index] != 123 { throw ValidationError.invalid }
      switch bytes[index] {
      case 123: try scopedObject(depth: depth, budget: &budget)
      case 91: try scopedArray(depth: depth, budget: &budget)
      case 34: _ = try string(maximumUTF8Bytes: 1_024)
      default:
        let scalar = try scalar()
        if case .number(let raw) = scalar {
          guard safeInteger(raw) else { throw ValidationError.invalid }
        }
      }
    }

    mutating func scopedObject(depth: Int, budget: inout ScopedBudget) throws {
      guard take(123) else { throw ValidationError.invalid }
      space()
      var keys = Set<[UInt8]>()
      var members = 0
      if take(125) { return }
      while true {
        space()
        let key = try string(maximumUTF8Bytes: 128)
        members += 1
        guard members <= 64, keys.insert(Array(key.utf8)).inserted else { throw ValidationError.invalid }
        space()
        guard take(58) else { throw ValidationError.invalid }
        try scopedValue(depth: depth + 1, root: false, budget: &budget)
        space()
        if take(125) { return }
        guard take(44) else { throw ValidationError.invalid }
      }
    }

    mutating func scopedArray(depth: Int, budget: inout ScopedBudget) throws {
      guard take(91) else { throw ValidationError.invalid }
      space()
      var elements = 0
      if take(93) { return }
      while true {
        elements += 1
        guard elements <= 64 else { throw ValidationError.invalid }
        try scopedValue(depth: depth + 1, root: false, budget: &budget)
        space()
        if take(93) { return }
        guard take(44) else { throw ValidationError.invalid }
      }
    }

    mutating func string(maximumUTF8Bytes: Int? = nil) throws -> String {
      guard take(34) else { throw ValidationError.invalid }
      let contentStart = index
      while index < bytes.count {
        let byte = bytes[index]
        if byte == 34 {
          let contentLength = index - contentStart
          if let maximumUTF8Bytes, contentLength > maximumUTF8Bytes * 6 {
            throw ValidationError.invalid
          }
          let quotedStart = contentStart - 1
          index += 1
          let quoted = Data(bytes[quotedStart..<index])
          guard let decoded = try? JSONDecoder().decode(String.self, from: quoted),
            maximumUTF8Bytes.map({ decoded.utf8.count <= $0 }) ?? true
          else { throw ValidationError.invalid }
          return decoded
        }
        if byte < 0x20 { throw ValidationError.invalid }
        if byte == 92 {
          guard index + 1 < bytes.count else { throw ValidationError.invalid }
          if bytes[index + 1] == 117 {
            guard index + 5 < bytes.count,
              bytes[(index + 2)...(index + 5)].allSatisfy(isHexDigit)
            else { throw ValidationError.invalid }
            index += 6
          } else {
            guard [34, 47, 92, 98, 102, 110, 114, 116].contains(bytes[index + 1]) else {
              throw ValidationError.invalid
            }
            index += 2
          }
        } else {
          index += 1
        }
      }
      throw ValidationError.invalid
    }

    private enum Scalar {
      case literal
      case number(String)
    }

    private mutating func scalar() throws -> Scalar {
      for literal in [Array("true".utf8), Array("false".utf8), Array("null".utf8)] {
        if bytes[index...].starts(with: literal) {
          index += literal.count
          return .literal
        }
      }
      let start = index
      _ = take(45)
      guard index < bytes.count else { throw ValidationError.invalid }
      if take(48) {
        if index < bytes.count, isDigit(bytes[index]) { throw ValidationError.invalid }
      } else {
        guard index < bytes.count, (49...57).contains(bytes[index]) else {
          throw ValidationError.invalid
        }
        index += 1
        while index < bytes.count, isDigit(bytes[index]) { index += 1 }
      }
      if take(46) {
        guard index < bytes.count, isDigit(bytes[index]) else { throw ValidationError.invalid }
        while index < bytes.count, isDigit(bytes[index]) { index += 1 }
      }
      if index < bytes.count, bytes[index] == 101 || bytes[index] == 69 {
        index += 1
        if index < bytes.count, bytes[index] == 43 || bytes[index] == 45 { index += 1 }
        guard index < bytes.count, isDigit(bytes[index]) else { throw ValidationError.invalid }
        while index < bytes.count, isDigit(bytes[index]) { index += 1 }
      }
      guard let raw = String(bytes: bytes[start..<index], encoding: .utf8) else {
        throw ValidationError.invalid
      }
      return .number(raw)
    }

    mutating func space() {
      while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
    }

    mutating func take(_ byte: UInt8) -> Bool {
      guard index < bytes.count, bytes[index] == byte else { return false }
      index += 1
      return true
    }

    private func safeInteger(_ raw: String) -> Bool {
      guard !raw.contains("."), !raw.contains("e"), !raw.contains("E") else { return false }
      if raw.first == "-" {
      return raw != "-0" && Int64(raw).map({ $0 >= -9_007_199_254_740_991 }) ?? false
    }
      return UInt64(raw).map({ $0 <= 9_007_199_254_740_991 }) ?? false
    }

    private func isDigit(_ byte: UInt8) -> Bool { (48...57).contains(byte) }
    private func isHexDigit(_ byte: UInt8) -> Bool {
      isDigit(byte) || (65...70).contains(byte) || (97...102).contains(byte)
    }
  }

  private struct CanonicalParser {
    let bytes: [UInt8]
    var index = 0
    var equivalentKeyCollision = false

    mutating func document() throws -> Bool {
      try value()
      guard index == bytes.count else { throw ValidationError.invalid }
      return equivalentKeyCollision
    }

    mutating func value() throws {
      guard index < bytes.count else { throw ValidationError.invalid }
      switch bytes[index] {
      case 123: try object()
      case 91: try array()
      case 34: _ = try string()
      case 116: try literal("true")
      case 102: try literal("false")
      case 110: try literal("null")
      default: try number()
      }
    }

    mutating func object() throws {
      guard take(123) else { throw ValidationError.invalid }
      var keys = [String]()
      if take(125) { return }
      while true {
        let key = try string()
        if keys.contains(where: { $0 == key }) { equivalentKeyCollision = true }
        if let previous = keys.last,
          !Array(previous.utf16).lexicographicallyPrecedes(Array(key.utf16)) {
          throw ValidationError.invalid
        }
        keys.append(key)
        guard take(58) else { throw ValidationError.invalid }
        try value()
        if take(125) { return }
        guard take(44) else { throw ValidationError.invalid }
      }
    }

    mutating func array() throws {
      guard take(91) else { throw ValidationError.invalid }
      if take(93) { return }
      while true {
        try value()
        if take(93) { return }
        guard take(44) else { throw ValidationError.invalid }
      }
    }

    mutating func string() throws -> String {
      let start = index
      guard take(34) else { throw ValidationError.invalid }
      while index < bytes.count {
        switch bytes[index] {
        case 34:
          index += 1
          let quoted = Data(bytes[start..<index])
          guard let value = try? JSONDecoder().decode(String.self, from: quoted) else {
            throw ValidationError.invalid
          }
          return value
        case 92:
          guard index + 1 < bytes.count else { throw ValidationError.invalid }
          if bytes[index + 1] == 117 {
            guard index + 5 < bytes.count,
              bytes[(index + 2)...(index + 5)].allSatisfy({
                ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102)
              }) else { throw ValidationError.invalid }
            index += 6
          } else {
            guard [34, 47, 92, 98, 102, 110, 114, 116].contains(bytes[index + 1])
            else { throw ValidationError.invalid }
            index += 2
          }
        default:
          guard bytes[index] >= 0x20 else { throw ValidationError.invalid }
          index += 1
        }
      }
      throw ValidationError.invalid
    }

    mutating func literal(_ value: String) throws {
      let bytes = Array(value.utf8)
      guard self.bytes[index...].starts(with: bytes) else { throw ValidationError.invalid }
      index += bytes.count
    }

    mutating func number() throws {
      let start = index
      if take(45) {}
      guard index < bytes.count else { throw ValidationError.invalid }
      if take(48) {
        if index < bytes.count && (48...57).contains(bytes[index]) { throw ValidationError.invalid }
      } else {
        guard index < bytes.count && (49...57).contains(bytes[index]) else {
          throw ValidationError.invalid
        }
        index += 1
        while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
      }
      if take(46) {
        guard index < bytes.count && (48...57).contains(bytes[index]) else { throw ValidationError.invalid }
        while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
      }
      if index < bytes.count && [101, 69].contains(bytes[index]) {
        index += 1
        if index < bytes.count && [43, 45].contains(bytes[index]) { index += 1 }
        guard index < bytes.count && (48...57).contains(bytes[index]) else { throw ValidationError.invalid }
        while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
      }
      guard index > start else { throw ValidationError.invalid }
      let raw = String(decoding: bytes[start..<index], as: UTF8.self)
      guard let number = Double(raw), number.isFinite,
        let encoded = try? JSONSerialization.data(withJSONObject: [number]),
        encoded.count >= 2,
        String(decoding: encoded.dropFirst().dropLast(), as: UTF8.self) == raw
      else { throw ValidationError.invalid }
    }

    mutating func take(_ byte: UInt8) -> Bool {
      guard index < bytes.count, bytes[index] == byte else { return false }
      index += 1
      return true
    }
  }
}
