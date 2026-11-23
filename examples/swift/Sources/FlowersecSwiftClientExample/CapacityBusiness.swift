#if os(macOS)
import Flowersec
import Foundation

struct CapacityEcho: Codable, Equatable, Sendable {
  let value: String?, payload: String?
  init(value: String? = nil, payload: String? = nil) { self.value = value; self.payload = payload }
}

enum CapacityBusiness {
  static let large = 1 << 20
  static func valid(_ size: Int) -> Bool { size == 256 || size == large }

  static func roundTrip(from client: any Session, to server: any Session, operation: String, bytes: Int) async throws -> (Int, Int) {
    guard valid(bytes) else { throw CapacityRoleError.invalidCommand }
    try Task.checkCancellation()
    if operation == "echo" {
      let text = String(repeating: "Z", count: bytes)
      let reply = try await client.rpc.call(7001, CapacityEcho(payload: text), as: CapacityEcho.self, timeout: .seconds(30))
      guard reply.value == nil, let echoed = reply.payload, echoed == text else { throw CapacityRoleError.incomplete }
      return (text.utf8.count, echoed.utf8.count)
    }
    guard operation == "raw" else { throw CapacityRoleError.invalidCommand }
    let kind = "public-release-roundtrip", metadata = try StreamMetadata(["direction": .string("client-to-server")])
    let request = Data(repeating: 0x5a, count: bytes), reply = Data(repeating: 0x37, count: bytes)
    return try await withThrowingTaskGroup(of: (Bool, Int).self) { group in
      group.addTask {
        let incoming = try await server.acceptStream()
        do {
          guard incoming.kind == kind, incoming.metadata == metadata else { throw CapacityRoleError.incomplete }
          let received = try await readAll(from: incoming.stream, maximum: bytes)
          guard received == request else { throw CapacityRoleError.incomplete }
          try await writeAll(reply, to: incoming.stream); try await incoming.stream.closeWrite()
          return (true, received.count)
        } catch { try? await incoming.stream.reset(); throw error }
      }
      group.addTask {
        let stream = try await client.openStream(kind: kind, metadata: metadata)
        do {
          try await writeAll(request, to: stream); try await stream.closeWrite()
          let received = try await readAll(from: stream, maximum: bytes)
          guard received == reply else { throw CapacityRoleError.incomplete }
          return (false, received.count)
        } catch { try? await stream.reset(); throw error }
      }
      var receivedRequest: Int?, receivedReply: Int?
      for try await (serverSide, count) in group {
        if serverSide { receivedRequest = count } else { receivedReply = count }
      }
      guard let receivedRequest, let receivedReply else { throw CapacityRoleError.incomplete }
      return (receivedRequest, receivedReply)
    }
  }
}
#endif
