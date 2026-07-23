import Flowersec
import Foundation
import Testing

struct PublicAPISurfaceTests {
  @Test func opaqueApplicationSurfaceCompilesWithoutTestableImport() async throws {
    let metadata = try StreamMetadataV2([
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
    #expect(await session.waitClosed() == .closed)
    #expect(SessionErrorV2.operationFailed.rawValue == "operation_failed")
    #expect(RPCErrorV2(code: 404, message: "not found").code == 404)
  }
}

private actor PublicContractByteStream: ByteStreamV2 {
  nonisolated let kind: String

  init(kind: String) { self.kind = kind }

  func read(maxBytes: Int) async throws -> Data? {
    _ = maxBytes
    return nil
  }

  func write(_ data: Data) async throws -> Int { data.count }
  func closeWrite() async throws {}
  func reset() async {}
  func close() async {}
  func terminalError() async -> SessionErrorV2? { nil }
}

private actor PublicContractRPCPeer: RPCPeerV2 {
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
    throw SessionErrorV2.operationFailed
  }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    _ = typeID
    _ = payload
  }
}

private struct PublicContractSession: SessionV2 {
  let rpc: any RPCPeerV2
  let stream: any ByteStreamV2

  func openStream(
    kind: String,
    metadata: StreamMetadataV2
  ) async throws -> any ByteStreamV2 {
    _ = kind
    _ = metadata
    return stream
  }

  func acceptStream() async throws -> IncomingStreamV2 {
    IncomingStreamV2(kind: stream.kind, metadata: .empty, stream: stream)
  }

  func rekey() async throws {}
  func probeLiveness() async throws -> Duration { .zero }
  func waitClosed() async -> SessionErrorV2 { .closed }
  func close() async {}
}
