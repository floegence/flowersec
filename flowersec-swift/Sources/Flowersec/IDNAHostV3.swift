import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

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

    guard let icu = FlowersecICU.load() else {
      throw IDNAHostErrorV3.invalidHost
    }
    defer { icu.unload() }

    var errorCode: Int32 = 0
    guard let processor = icu.open(profileOptions, &errorCode), errorCode <= 0 else {
      throw IDNAHostErrorV3.invalidHost
    }
    defer { icu.close(processor) }

    do {
      let ascii = try transform(
        host,
        processor: processor,
        maximumOutputBytes: 253,
        operation: icu.toASCII
      )
      let unicode = try transform(
        ascii,
        processor: processor,
        maximumOutputBytes: 1_024,
        operation: icu.toUnicode
      )
      try requireUnicode151(unicode)
      return try validateASCII(ascii)
    } catch {
      return try lookupUnicode151DeltaASCII(host, icu: icu, processor: processor)
    }
  }

  static func lookupUnicode151DeltaASCII(_ host: String) throws -> String {
    guard !host.isEmpty, !host.hasSuffix("."), host.utf8.count <= Int(Int32.max) else {
      throw IDNAHostErrorV3.invalidHost
    }
    try requireUnicode151(host)

    guard let icu = FlowersecICU.load() else {
      throw IDNAHostErrorV3.invalidHost
    }
    defer { icu.unload() }

    var errorCode: Int32 = 0
    guard let processor = icu.open(profileOptions, &errorCode), errorCode <= 0 else {
      throw IDNAHostErrorV3.invalidHost
    }
    defer { icu.close(processor) }

    return try lookupUnicode151DeltaASCII(host, icu: icu, processor: processor)
  }

  private static func lookupUnicode151DeltaASCII(
    _ host: String,
    icu: FlowersecICU,
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
        decodedLabels[index] = try punycodeTransform(payload, operation: icu.fromPunycode)
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
      operation: icu.toUnicode
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
        let payload = try punycodeTransform(label, operation: icu.toPunycode).lowercased()
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

    var preflightInfo = FlowersecUIDNAInfo()
    var preflightError: Int32 = 0
    let required = withUnsafeMutablePointer(to: &preflightInfo) { infoPointer in
      source.withUnsafeBufferPointer { sourceBuffer in
        operation(
          processor,
          sourceBuffer.baseAddress,
          sourceLength,
          nil,
          0,
          UnsafeMutableRawPointer(infoPointer),
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
    var info = FlowersecUIDNAInfo()
    var errorCode: Int32 = 0
    let written = withUnsafeMutablePointer(to: &info) { infoPointer in
      source.withUnsafeBufferPointer { sourceBuffer in
        destination.withUnsafeMutableBufferPointer { destinationBuffer in
          operation(
            processor,
            sourceBuffer.baseAddress,
            sourceLength,
            destinationBuffer.baseAddress,
            Int32(destinationBuffer.count),
            UnsafeMutableRawPointer(infoPointer),
            &errorCode
          )
        }
      }
    }
    guard errorCode <= 0, info.errors == 0, written == required else {
      throw IDNAHostErrorV3.invalidHost
    }
    return String(
      decoding: destination.prefix(Int(written)).map(UInt8.init(bitPattern:)), as: UTF8.self)
  }

  private static func punycodeTransform(
    _ input: String,
    operation: FlowersecPunycodeTransform
  ) throws -> String {
    let source = Array(input.utf16)
    var preflightError: Int32 = 0
    let required = source.withUnsafeBufferPointer { sourceBuffer in
      operation(
        sourceBuffer.baseAddress,
        Int32(sourceBuffer.count),
        nil,
        0,
        nil,
        &preflightError
      )
    }
    guard required >= 0, required <= 1_024, preflightError <= 0 || preflightError == 15 else {
      throw IDNAHostErrorV3.invalidHost
    }

    var destination = [UInt16](repeating: 0, count: Int(required) + 1)
    var errorCode: Int32 = 0
    let written = source.withUnsafeBufferPointer { sourceBuffer in
      destination.withUnsafeMutableBufferPointer { destinationBuffer in
        operation(
          sourceBuffer.baseAddress,
          Int32(sourceBuffer.count),
          destinationBuffer.baseAddress,
          Int32(destinationBuffer.count),
          nil,
          &errorCode
        )
      }
    }
    guard errorCode <= 0, written == required else {
      throw IDNAHostErrorV3.invalidHost
    }
    return String(decoding: destination.prefix(Int(written)), as: UTF16.self)
  }
}

private struct FlowersecUIDNAInfo {
  var size = Int16(MemoryLayout<FlowersecUIDNAInfo>.size)
  var isTransitionalDifferent: Int8 = 0
  var reservedB3: Int8 = 0
  var errors: UInt32 = 0
  var reservedI2: Int32 = 0
  var reservedI3: Int32 = 0
}

private typealias FlowersecUIDNAOpen =
  @convention(c) (
    UInt32,
    UnsafeMutablePointer<Int32>?
  ) -> OpaquePointer?

private typealias FlowersecUIDNAClose = @convention(c) (OpaquePointer?) -> Void

private typealias FlowersecUIDNATransform =
  @convention(c) (
    OpaquePointer?,
    UnsafePointer<CChar>?,
    Int32,
    UnsafeMutablePointer<CChar>?,
    Int32,
    UnsafeMutableRawPointer?,
    UnsafeMutablePointer<Int32>?
  ) -> Int32

private typealias FlowersecPunycodeTransform =
  @convention(c) (
    UnsafePointer<UInt16>?,
    Int32,
    UnsafeMutablePointer<UInt16>?,
    Int32,
    UnsafePointer<Int8>?,
    UnsafeMutablePointer<Int32>?
  ) -> Int32

private struct FlowersecICU {
  let handle: UnsafeMutableRawPointer
  let open: FlowersecUIDNAOpen
  let close: FlowersecUIDNAClose
  let toASCII: FlowersecUIDNATransform
  let toUnicode: FlowersecUIDNATransform
  let toPunycode: FlowersecPunycodeTransform
  let fromPunycode: FlowersecPunycodeTransform

  static func load() -> FlowersecICU? {
    for libraryName in libraryNames {
      guard let handle = dlopen(libraryName, RTLD_LAZY | RTLD_LOCAL) else {
        continue
      }
      if let icu = loadSymbols(handle: handle) {
        return icu
      }
      dlclose(handle)
    }
    return nil
  }

  private static func loadSymbols(handle: UnsafeMutableRawPointer) -> FlowersecICU? {
    for suffix in symbolSuffixes {
      guard
        let openSymbol = dlsym(handle, "uidna_openUTS46\(suffix)"),
        let closeSymbol = dlsym(handle, "uidna_close\(suffix)"),
        let toASCIISymbol = dlsym(handle, "uidna_nameToASCII_UTF8\(suffix)"),
        let toUnicodeSymbol = dlsym(handle, "uidna_nameToUnicodeUTF8\(suffix)"),
        let toPunycodeSymbol = dlsym(handle, "u_strToPunycode\(suffix)"),
        let fromPunycodeSymbol = dlsym(handle, "u_strFromPunycode\(suffix)")
      else {
        continue
      }
      return FlowersecICU(
        handle: handle,
        open: unsafeBitCast(openSymbol, to: FlowersecUIDNAOpen.self),
        close: unsafeBitCast(closeSymbol, to: FlowersecUIDNAClose.self),
        toASCII: unsafeBitCast(toASCIISymbol, to: FlowersecUIDNATransform.self),
        toUnicode: unsafeBitCast(toUnicodeSymbol, to: FlowersecUIDNATransform.self),
        toPunycode: unsafeBitCast(toPunycodeSymbol, to: FlowersecPunycodeTransform.self),
        fromPunycode: unsafeBitCast(fromPunycodeSymbol, to: FlowersecPunycodeTransform.self)
      )
    }
    return nil
  }

  private static var libraryNames: [String] {
    #if canImport(Darwin)
      ["/usr/lib/libicucore.dylib"]
    #elseif canImport(Glibc)
      ["libicuuc.so"] + (40...199).reversed().map { "libicuuc.so.\($0)" }
    #else
      []
    #endif
  }

  private static var symbolSuffixes: [String] {
    #if canImport(Darwin)
      [""]
    #elseif canImport(Glibc)
      [""] + (40...199).reversed().map { "_\($0)" }
    #else
      []
    #endif
  }

  func unload() {
    dlclose(handle)
  }
}
