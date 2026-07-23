import Foundation

#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#endif

enum IDNAHostErrorV2: Error, Equatable, Sendable {
  case invalidHost
}

/// Frozen host normalization shared by Flowersec v2 artifacts and Origin policies.
enum IDNAHostV2 {
  static let unicodeVersion = "15.1.0"

  /// Returns a lowercase A-label host under the Flowersec v2 IDNA profile.
  ///
  /// ICU performs UTS #46 non-transitional processing with STD3, Bidi, and
  /// ContextJ checks. The explicit scalar-age checks reject unassigned input and
  /// every character introduced after Unicode 15.1, including characters hidden
  /// inside an A-label, so newer host Unicode tables cannot widen this contract.
  static func lookupASCII(_ host: String) throws -> String {
    guard !host.isEmpty, !host.hasSuffix("."), host.utf8.count <= Int(Int32.max) else {
      throw IDNAHostErrorV2.invalidHost
    }
    try requireUnicode151(host)

    guard let icu = FlowersecICU.load() else {
      throw IDNAHostErrorV2.invalidHost
    }
    defer { icu.unload() }

    var errorCode: Int32 = 0
    guard let processor = icu.open(profileOptions, &errorCode), errorCode <= 0 else {
      throw IDNAHostErrorV2.invalidHost
    }
    defer { icu.close(processor) }

    let ascii = try transform(
      host,
      processor: processor,
      maximumOutputBytes: 253,
      operation: icu.toASCII
    )

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
      throw IDNAHostErrorV2.invalidHost
    }

    let unicode = try transform(
      ascii,
      processor: processor,
      maximumOutputBytes: 1_024,
      operation: icu.toUnicode
    )
    try requireUnicode151(unicode)
    return String(decoding: bytes.map(asciiLowercase), as: UTF8.self)
  }

  private static let profileOptions: UInt32 =
    0x02  // UIDNA_USE_STD3_RULES
    | 0x04  // UIDNA_CHECK_BIDI
    | 0x08  // UIDNA_CHECK_CONTEXTJ
    | 0x10  // UIDNA_NONTRANSITIONAL_TO_ASCII
    | 0x20  // UIDNA_NONTRANSITIONAL_TO_UNICODE

  private static func requireUnicode151(_ value: String) throws {
    for scalar in value.unicodeScalars {
      guard let age = scalar.properties.age else {
        throw IDNAHostErrorV2.invalidHost
      }
      guard age.major < 15 || (age.major == 15 && age.minor <= 1) else {
        throw IDNAHostErrorV2.invalidHost
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
      throw IDNAHostErrorV2.invalidHost
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
      throw IDNAHostErrorV2.invalidHost
    }
    return String(
      decoding: destination.prefix(Int(written)).map(UInt8.init(bitPattern:)), as: UTF8.self)
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

private struct FlowersecICU {
  let handle: UnsafeMutableRawPointer
  let open: FlowersecUIDNAOpen
  let close: FlowersecUIDNAClose
  let toASCII: FlowersecUIDNATransform
  let toUnicode: FlowersecUIDNATransform

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
        let toUnicodeSymbol = dlsym(handle, "uidna_nameToUnicodeUTF8\(suffix)")
      else {
        continue
      }
      return FlowersecICU(
        handle: handle,
        open: unsafeBitCast(openSymbol, to: FlowersecUIDNAOpen.self),
        close: unsafeBitCast(closeSymbol, to: FlowersecUIDNAClose.self),
        toASCII: unsafeBitCast(toASCIISymbol, to: FlowersecUIDNATransform.self),
        toUnicode: unsafeBitCast(toUnicodeSymbol, to: FlowersecUIDNATransform.self)
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
