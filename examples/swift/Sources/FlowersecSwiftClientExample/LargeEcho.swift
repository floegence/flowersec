import Flowersec
import Foundation

enum LargeEchoMode: String {
  case disabled = "0", call = "1", serve
}

actor LargeEcho {
  private static let size = 32 * 1024 * 1024
  private static let encodedSize = (size + 2) / 3 * 4
  static let minimumFrame = encodedSize + #"{"type_id":7010,"request_id":9007199254740991,"response_to":0,"payload":""}"#.utf8.count
  private(set) var accepted = false

  func echo(_ text: String, permissions: ParityPermissions) throws -> String {
    try permissions.execute(7010)
    let encoded = text.utf8
    guard encoded.count == Self.encodedSize else { throw RPCError(code: 400, message: "invalid binary payload") }
    var position = encoded.startIndex
    var remaining = Self.size
    while position != encoded.endIndex {
      try Task.checkCancellation()
      let end = encoded.index(position, offsetBy: 64 * 1024, limitedBy: encoded.endIndex) ?? encoded.endIndex
      let chunk = encoded[position..<end]
      guard let bytes = Data(base64Encoded: Data(chunk)), bytes.count == min(48 * 1024, remaining),
            bytes.base64EncodedData().elementsEqual(chunk) else { throw RPCError(code: 400, message: "invalid binary payload") }
      remaining -= bytes.count
      position = end
    }
    try Task.checkCancellation()
    try permissions.execute(7010)
    accepted = true
    return text
  }

  static func call(on session: any Session) async throws {
    let expected = try makePayload()
    let response = try await session.rpc.call(7010, expected, as: String.self, timeout: .seconds(120))
    guard response.utf8.elementsEqual(expected.utf8) else { throw ExampleConfigurationError.invalidRPCResponse }
  }

  private static func makePayload() throws -> String {
    var bytes = Data(count: size)
    try bytes.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) in
      for start in stride(from: 0, to: size, by: 64 * 1024) {
        try Task.checkCancellation()
        for index in start..<min(size, start + 64 * 1024) {
          buffer[index] = UInt8(truncatingIfNeeded: index ^ (index >> 8) ^ (index >> 16))
        }
      }
    }
    return bytes.base64EncodedString()
  }
}
