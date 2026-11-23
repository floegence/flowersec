import Crypto
import Foundation

enum FlowersecHKDF {
  static func extractSHA256(salt: Data, inputKeyMaterial: Data) -> Data {
    let code = HMAC<SHA256>.authenticationCode(
      for: inputKeyMaterial,
      using: SymmetricKey(data: salt)
    )
    return Data(code)
  }

  static func expandSHA256(
    pseudoRandomKey: Data,
    info: Data,
    outputByteCount: Int
  ) -> Data {
    guard outputByteCount > 0 else { return Data() }
    var output = Data()
    var previous = Data()
    var counter: UInt8 = 1
    while output.count < outputByteCount {
      previous = expandBlock(previous: previous, info: info, counter: counter, key: pseudoRandomKey)
      output.append(previous)
      counter &+= 1
    }
    return Data(output.prefix(outputByteCount))
  }

  private static func expandBlock(
    previous: Data,
    info: Data,
    counter: UInt8,
    key: Data
  ) -> Data {
    var message = Data(previous)
    message.append(info)
    message.append(counter)
    let code = HMAC<SHA256>.authenticationCode(
      for: message,
      using: SymmetricKey(data: key)
    )
    return Data(code)
  }
}
