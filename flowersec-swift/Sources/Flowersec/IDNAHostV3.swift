import CFlowersecIDNA
import Foundation

enum IDNAHostErrorV3: Error, Equatable, Sendable {
  case invalidHost
}

/// Frozen host normalization shared by Flowersec v3 artifacts and Origin policies.
enum IDNAHostV3 {
  static let unicodeVersion = Unicode151Generated.version

  /// Returns a lowercase A-label host under the Flowersec v3 IDNA profile.
  ///
  /// ICU performs UTS #46 non-transitional processing with STD3, Bidi, and
  /// ContextJ checks. The explicit scalar-age checks reject unassigned input and
  /// every character introduced after Unicode 15.1, including characters hidden
  /// inside an A-label, so newer host Unicode tables cannot widen this contract.
  static func lookupASCII(_ host: String) throws -> String {
    guard !host.isEmpty, !host.hasSuffix("."), host.utf8.count <= Int(Int32.max) else {
      throw IDNAHostErrorV3.invalidHost
    }
    try requireUnicode151(host)

    var errorCode: Int32 = 0
    guard let processor = FSECIDNAOpen(profileOptions, &errorCode), errorCode <= 0 else {
      throw IDNAHostErrorV3.invalidHost
    }
    defer { FSECIDNAClose(processor) }

    do {
      let ascii = try transform(
        host,
        processor: processor,
        maximumOutputBytes: 253,
        operation: FSECIDNAToASCII
      )
      let unicode = try transform(
        ascii,
        processor: processor,
        maximumOutputBytes: 1_024,
        operation: FSECIDNAToUnicode
      )
      try requireUnicode151(unicode)
      return try validateASCII(ascii)
    } catch {
      return try lookupUnicode151DeltaASCII(host, processor: processor)
    }
  }

  static func lookupUnicode151DeltaASCII(_ host: String) throws -> String {
    guard !host.isEmpty, !host.hasSuffix("."), host.utf8.count <= Int(Int32.max) else {
      throw IDNAHostErrorV3.invalidHost
    }
    try requireUnicode151(host)

    var errorCode: Int32 = 0
    guard let processor = FSECIDNAOpen(profileOptions, &errorCode), errorCode <= 0 else {
      throw IDNAHostErrorV3.invalidHost
    }
    defer { FSECIDNAClose(processor) }

    return try lookupUnicode151DeltaASCII(host, processor: processor)
  }

  private static func lookupUnicode151DeltaASCII(
    _ host: String,
    processor: OpaquePointer
  ) throws -> String {
    var decodedLabels =
      host
      .split(separator: ".", omittingEmptySubsequences: false)
      .map(String.init)
    var originalALabels: [Int: String] = [:]
    var deltaCount = 0

    for index in decodedLabels.indices {
      let lowercased = decodedLabels[index].lowercased()
      if lowercased.hasPrefix("xn--") {
        let payload = String(lowercased.dropFirst(4))
        guard !payload.isEmpty, payload.utf8.allSatisfy({ $0 < 0x80 }) else {
          throw IDNAHostErrorV3.invalidHost
        }
        decodedLabels[index] = try punycodeDecode(payload)
        originalALabels[index] = lowercased
      }
      deltaCount += decodedLabels[index].unicodeScalars.filter(isUnicode151Delta).count
    }
    guard deltaCount > 0 else {
      throw IDNAHostErrorV3.invalidHost
    }

    let decoded = decodedLabels.joined(separator: ".")
    guard let placeholder = choosePlaceholder(decoded) else {
      throw IDNAHostErrorV3.invalidHost
    }
    var originalDelta: [Unicode.Scalar] = []
    var substituted = ""
    for scalar in decoded.unicodeScalars {
      if isUnicode151Delta(scalar) {
        originalDelta.append(scalar)
        substituted.unicodeScalars.append(placeholder)
      } else {
        substituted.unicodeScalars.append(scalar)
      }
    }

    let mapped = try transform(
      substituted,
      processor: processor,
      maximumOutputBytes: 1_024,
      operation: FSECIDNAToUnicode
    )
    guard mapped.unicodeScalars.filter({ $0 == placeholder }).count == originalDelta.count else {
      throw IDNAHostErrorV3.invalidHost
    }

    var restored = ""
    var deltaIndex = 0
    for scalar in mapped.unicodeScalars {
      if scalar == placeholder {
        restored.unicodeScalars.append(originalDelta[deltaIndex])
        deltaIndex += 1
      } else {
        restored.unicodeScalars.append(scalar)
      }
    }
    guard deltaIndex == originalDelta.count else {
      throw IDNAHostErrorV3.invalidHost
    }
    try requireUnicode151(restored)

    let labels = restored.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    guard labels.count == decodedLabels.count else {
      throw IDNAHostErrorV3.invalidHost
    }
    var asciiLabels: [String] = []
    asciiLabels.reserveCapacity(labels.count)
    for (index, label) in labels.enumerated() {
      guard !label.isEmpty else {
        throw IDNAHostErrorV3.invalidHost
      }
      let asciiLabel: String
      if label.utf8.allSatisfy({ $0 < 0x80 }) {
        asciiLabel = label.lowercased()
      } else {
        let payload = try punycodeEncode(label).lowercased()
        guard !payload.isEmpty, payload.utf8.allSatisfy({ $0 < 0x80 }) else {
          throw IDNAHostErrorV3.invalidHost
        }
        asciiLabel = "xn--" + payload
      }
      guard !asciiLabel.isEmpty, asciiLabel.utf8.count <= 63 else {
        throw IDNAHostErrorV3.invalidHost
      }
      if let original = originalALabels[index], original != asciiLabel {
        throw IDNAHostErrorV3.invalidHost
      }
      asciiLabels.append(asciiLabel)
    }
    return try validateASCII(asciiLabels.joined(separator: "."))
  }

  private static func validateASCII(_ ascii: String) throws -> String {
    let bytes = Array(ascii.utf8)
    guard
      !bytes.isEmpty,
      bytes.count <= 253,
      bytes.allSatisfy({ $0 < 0x80 }),
      bytes.last != 0x2E,
      ascii.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({
        !$0.isEmpty && $0.utf8.count <= 63
      })
    else {
      throw IDNAHostErrorV3.invalidHost
    }
    return String(decoding: bytes.map(asciiLowercase), as: UTF8.self)
  }

  private static let profileOptions: UInt32 =
    0x02  // UIDNA_USE_STD3_RULES
    | 0x04  // UIDNA_CHECK_BIDI
    | 0x08  // UIDNA_CHECK_CONTEXTJ
    | 0x10  // UIDNA_NONTRANSITIONAL_TO_ASCII
    | 0x20  // UIDNA_NONTRANSITIONAL_TO_UNICODE

  private static func isUnicode151Delta(_ scalar: Unicode.Scalar) -> Bool {
    scalar.value >= 0x2EBF0 && scalar.value <= 0x2EE5D
  }

  private static func choosePlaceholder(_ value: String) -> Unicode.Scalar? {
    let existing = Set(value.unicodeScalars.map(\.value))
    for rawValue in UInt32(0x4E00)...UInt32(0x9FFF) where !existing.contains(rawValue) {
      if let scalar = Unicode.Scalar(rawValue) {
        return scalar
      }
    }
    return nil
  }

  private static func requireUnicode151(_ value: String) throws {
    for scalar in value.unicodeScalars {
      guard Unicode151Generated.assigned(scalar) else {
        throw IDNAHostErrorV3.invalidHost
      }
    }
  }

  private static func asciiLowercase(_ byte: UInt8) -> UInt8 {
    (0x41...0x5A).contains(byte) ? byte + 0x20 : byte
  }

  private static func transform(
    _ input: String,
    processor: OpaquePointer,
    maximumOutputBytes: Int32,
    operation: FlowersecUIDNATransform
  ) throws -> String {
    let source = input.utf8CString
    let sourceLength = Int32(source.count - 1)

    var preflightErrors: UInt32 = 0
    var preflightError: Int32 = 0
    let required = withUnsafeMutablePointer(to: &preflightErrors) { infoPointer in
      source.withUnsafeBufferPointer { sourceBuffer in
        operation(
          processor,
          sourceBuffer.baseAddress,
          sourceLength,
          nil,
          0,
          infoPointer,
          &preflightError
        )
      }
    }
    guard
      required >= 0,
      required <= maximumOutputBytes,
      preflightError <= 0 || preflightError == 15
    else {
      throw IDNAHostErrorV3.invalidHost
    }

    var destination = [CChar](repeating: 0, count: Int(required) + 1)
    var errors: UInt32 = 0
    var errorCode: Int32 = 0
    let written = withUnsafeMutablePointer(to: &errors) { infoPointer in
      source.withUnsafeBufferPointer { sourceBuffer in
        destination.withUnsafeMutableBufferPointer { destinationBuffer in
          operation(
            processor,
            sourceBuffer.baseAddress,
            sourceLength,
            destinationBuffer.baseAddress,
            Int32(destinationBuffer.count),
            infoPointer,
            &errorCode
          )
        }
      }
    }
    guard errorCode <= 0, errors == 0, written == required else {
      throw IDNAHostErrorV3.invalidHost
    }
    return String(
      decoding: destination.prefix(Int(written)).map(UInt8.init(bitPattern:)), as: UTF8.self)
  }

  // RFC 3492 bootstring implementation. Keeping it in the package avoids
  // reaching ICU's internal u_strToPunycode/u_strFromPunycode symbols.
  static func punycodeDecode(_ input: String) throws -> String {
    guard input.utf8.count <= 1_024 else { throw IDNAHostErrorV3.invalidHost }
    let bytes = Array(input.utf8)
    guard bytes.allSatisfy({ $0 < 128 }) else { throw IDNAHostErrorV3.invalidHost }
    var output: [UInt32] = []
    var index = 0
    if let dash = bytes.lastIndex(of: 45), dash > 0 {
      output = bytes[..<dash].map(UInt32.init)
      index = dash + 1
    }
    var n: UInt64 = 128
    var i: UInt64 = 0
    var bias: UInt64 = 72
    while index < bytes.count {
      let old = i
      var weight: UInt64 = 1
      var k: UInt64 = 36
      while true {
        guard index < bytes.count else { throw IDNAHostErrorV3.invalidHost }
        let byte = bytes[index]
        index += 1
        let digit: UInt64
        switch byte {
        case 97...122: digit = UInt64(byte - 97)
        case 65...90: digit = UInt64(byte - 65)
        case 48...57: digit = UInt64(byte - 48 + 26)
        default: throw IDNAHostErrorV3.invalidHost
        }
        guard digit <= (0x7fff_ffff - i) / weight else { throw IDNAHostErrorV3.invalidHost }
        i += digit * weight
        let threshold = punycodeThreshold(k, bias)
        if digit < threshold { break }
        guard weight <= 0x7fff_ffff / (36 - threshold) else {
          throw IDNAHostErrorV3.invalidHost
        }
        weight *= 36 - threshold
        k += 36
      }
      let count = UInt64(output.count) + 1
      bias = punycodeAdapt(i - old, count, old == 0)
      guard i / count <= 0x7fff_ffff - n else { throw IDNAHostErrorV3.invalidHost }
      n += i / count
      i %= count
      guard n <= 0x10ffff, let scalar = UnicodeScalar(UInt32(n)) else {
        throw IDNAHostErrorV3.invalidHost
      }
      output.insert(scalar.value, at: Int(i))
      i += 1
    }
    guard output.allSatisfy({ UnicodeScalar($0) != nil }) else {
      throw IDNAHostErrorV3.invalidHost
    }
    let result = String(String.UnicodeScalarView(output.compactMap(UnicodeScalar.init)))
    guard result.utf16.count <= 1_024 else { throw IDNAHostErrorV3.invalidHost }
    return result
  }

  static func punycodeEncode(_ input: String) throws -> String {
    guard input.utf16.count <= 1_024 else { throw IDNAHostErrorV3.invalidHost }
    let scalars = input.unicodeScalars.map(\.value)
    guard scalars.allSatisfy({ UnicodeScalar($0) != nil }) else {
      throw IDNAHostErrorV3.invalidHost
    }
    var output = scalars.filter { $0 < 128 }.map(UInt8.init)
    let basic = UInt64(output.count)
    var handled = basic
    var n: UInt64 = 128
    var delta: UInt64 = 0
    var bias: UInt64 = 72
    if basic > 0 { output.append(45) }
    while handled < UInt64(scalars.count) {
      guard let next = scalars.map(UInt64.init).filter({ $0 >= n }).min(),
        next - n <= (0x7fff_ffff - delta) / (handled + 1)
      else { throw IDNAHostErrorV3.invalidHost }
      delta += (next - n) * (handled + 1)
      n = next
      for scalar in scalars {
        let value = UInt64(scalar)
        if value < n {
          guard delta < 0x7fff_ffff else { throw IDNAHostErrorV3.invalidHost }
          delta += 1
        }
        guard value == n else { continue }
        var q = delta
        var k: UInt64 = 36
        while true {
          let threshold = punycodeThreshold(k, bias)
          if q < threshold { break }
          output.append(punycodeDigit(threshold + (q - threshold) % (36 - threshold)))
          q = (q - threshold) / (36 - threshold)
          k += 36
        }
        output.append(punycodeDigit(q))
        bias = punycodeAdapt(delta, handled + 1, handled == basic)
        delta = 0
        handled += 1
      }
      guard delta < 0x7fff_ffff else { throw IDNAHostErrorV3.invalidHost }
      delta += 1
      n += 1
    }
    guard output.count <= 1_024 else { throw IDNAHostErrorV3.invalidHost }
    return String(decoding: output, as: UTF8.self)
  }

  private static func punycodeThreshold(_ k: UInt64, _ bias: UInt64) -> UInt64 {
    min(26, max(1, k > bias ? k - bias : 0))
  }

  private static func punycodeAdapt(_ original: UInt64, _ count: UInt64, _ first: Bool) -> UInt64 {
    var delta = original / (first ? 700 : 2)
    delta += delta / count
    var k: UInt64 = 0
    while delta > 455 {
      delta /= 35
      k += 36
    }
    return k + 36 * delta / (delta + 38)
  }

  private static func punycodeDigit(_ value: UInt64) -> UInt8 {
    UInt8(value < 26 ? value + 97 : value - 26 + 48)
  }
}

private typealias FlowersecUIDNATransform =
  @convention(c) (
    OpaquePointer?, UnsafePointer<CChar>?, Int32,
    UnsafeMutablePointer<CChar>?, Int32,
    UnsafeMutablePointer<UInt32>?, UnsafeMutablePointer<Int32>?
  ) -> Int32
