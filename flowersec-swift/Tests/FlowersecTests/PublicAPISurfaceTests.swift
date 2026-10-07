import Flowersec
import Foundation
import Testing

struct PublicAPISurfaceTests {
  @Test func opaqueApplicationSurfaceCompilesWithoutTestableImport() async throws {
    let streamHandlers = try StreamHandlers()
    try streamHandlers.handleStream(kind: "health") { _ in }
    let metadata = try StreamMetadata([
      "operation": .string("health"),
      "attempt": .integer(1),
    ])
    let stream = PublicContractByteStream(kind: "health")
    let session = PublicContractSession(stream: stream)

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

private struct PublicContractSession: Session {
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
