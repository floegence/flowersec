import Flowersec
import Foundation
import Testing

struct PublicAPISurfaceTests {
  @Test func opaqueApplicationSurfaceCompilesWithoutTestableImport() async throws {
    let metadata = try StreamMetadata([
      "operation": .string("health"),
      "attempt": .integer(1),
    ])
    let stream = PublicContractByteStream(kind: "health")
    let rpc = PublicContractRPCPeer()
    let session = PublicContractSession(rpc: rpc, stream: stream)

    let opened = try await session.openStream(kind: "health", metadata: metadata)
    #expect(opened.kind == "health")
    #expect(try await opened.write(Data("ok".utf8)) == 2)
    let accepted = try await session.acceptStream()
    #expect(accepted.kind == "health")
    #expect(accepted.metadata == .empty)
    #expect(await stream.terminalError() == nil)
    #expect(await session.waitTermination() == SessionTermination(error: .closed))
    try await stream.reset()
    try await stream.close()
    try await session.close()
    #expect(SessionError.operationFailed.rawValue == "operation_failed")
    #expect(RPCError(code: 404, message: "not found").code == 404)
  }
}

private actor PublicContractByteStream: ByteStream {
  nonisolated let kind: String

  init(kind: String) { self.kind = kind }

  func read(maxBytes: Int) async throws -> Data? {
    _ = maxBytes
    return nil
  }

  func write(_ data: Data) async throws -> Int { data.count }
  func closeWrite() async throws {}
  func reset() async throws {}
  func close() async throws {}
  func terminalError() async -> SessionError? { nil }
}

private actor PublicContractRPCPeer: RPCPeer {
  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response {
    _ = typeID
    _ = request
    _ = responseType
    _ = timeout
    throw SessionError.operationFailed
  }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    _ = typeID
    _ = payload
  }

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription {
    _ = typeID
    _ = payloadType
    _ = handler
    return PublicContractNotificationSubscription()
  }
}

private struct PublicContractNotificationSubscription: RPCNotificationSubscription {
  func cancel() async {}
}

private struct PublicContractSession: Session {
  let rpc: any RPCPeer
  let stream: any ByteStream

  func openStream(
    kind: String,
    metadata: StreamMetadata
  ) async throws -> any ByteStream {
    _ = kind
    _ = metadata
    return stream
  }

  func acceptStream() async throws -> IncomingStream {
    IncomingStream(kind: stream.kind, metadata: .empty, stream: stream)
  }

  func rekey() async throws {}
  func probeLiveness() async throws -> Duration { .zero }
  func waitTermination() async -> SessionTermination { SessionTermination(error: .closed) }
  func close() async throws {}
}
