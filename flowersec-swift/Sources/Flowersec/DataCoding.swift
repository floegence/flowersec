import Crypto
import Foundation

extension Data {
  static func secureRandom(count: Int) throws -> Data {
    guard count >= 0 else {
      throw FlowersecError(
        path: .direct,
        stage: .validate,
        code: .invalidInput,
        message: "Secure random byte count must not be negative."
      )
    }
    guard count > 0 else { return Data() }
    var bytes = Data()
    bytes.reserveCapacity(count)
    while bytes.count < count {
      let chunk = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      bytes.append(chunk)
    }
    return Data(bytes.prefix(count))
  }

  init?(base64URLEncoded rawValue: String) {
    var value =
      rawValue
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = value.count % 4
    if remainder > 0 {
      value.append(String(repeating: "=", count: 4 - remainder))
    }
    self.init(base64Encoded: value)
  }

  func base64URLEncodedString() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  mutating func appendUInt16BE(_ value: UInt16) {
    append(UInt8((value >> 8) & 0xff))
    append(UInt8(value & 0xff))
  }

  mutating func appendUInt32BE(_ value: UInt32) {
    append(UInt8((value >> 24) & 0xff))
    append(UInt8((value >> 16) & 0xff))
    append(UInt8((value >> 8) & 0xff))
    append(UInt8(value & 0xff))
  }

  mutating func appendUInt64BE(_ value: UInt64) {
    append(UInt8((value >> 56) & 0xff))
    append(UInt8((value >> 48) & 0xff))
    append(UInt8((value >> 40) & 0xff))
    append(UInt8((value >> 32) & 0xff))
    append(UInt8((value >> 24) & 0xff))
    append(UInt8((value >> 16) & 0xff))
    append(UInt8((value >> 8) & 0xff))
    append(UInt8(value & 0xff))
  }

  func readUInt16BE(at offset: Int) -> UInt16 {
    (UInt16(self[offset]) << 8) | UInt16(self[offset + 1])
  }

  func readUInt32BE(at offset: Int) -> UInt32 {
    (UInt32(self[offset]) << 24)
      | (UInt32(self[offset + 1]) << 16)
      | (UInt32(self[offset + 2]) << 8)
      | UInt32(self[offset + 3])
  }

  func readUInt64BE(at offset: Int) -> UInt64 {
    var value: UInt64 = 0
    for index in 0..<8 {
      value = (value << 8) | UInt64(self[offset + index])
    }
    return value
  }
}
