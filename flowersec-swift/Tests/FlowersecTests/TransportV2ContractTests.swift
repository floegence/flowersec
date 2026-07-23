import Foundation
import Testing

@testable import Flowersec

struct TransportV2ContractTests {
  @Test func macOSCapabilityAdvertisesOnlyVerifiedWSSDialTuples() throws {
    let descriptor = RuntimeCapabilitiesV2.macOS
    try descriptor.validate()
    #expect(descriptor.tuples.map(\.carrier) == [.webSocket, .webSocket, .webSocket])
    #expect(descriptor.tuples.map(\.path) == [.direct, .tunnel, .tunnel])
    #expect(descriptor.tuples.map(\.sessionRole) == [.client, .client, .server])
    #expect(descriptor.unsupported.map(\.carrier) == [.rawQUIC, .webTransport])
  }

  @Test func carrierRegistryValuesMatchPortableContract() {
    #expect(CarrierKind.webSocket.rawValue == "websocket")
    #expect(CarrierKind.rawQUIC.rawValue == "raw_quic")
    #expect(CarrierKind.webTransport.rawValue == "webtransport")
  }

  @Test func appleCapabilityDoesNotAdvertiseUnwiredCarriers() {
    #expect(
      RuntimeCapabilitiesV2.apple
        == RuntimeCapabilityDescriptorV2(
          schemaVersion: 2,
          language: "swift",
          runtime: "apple",
          tuples: [],
          unsupported: [
            UnsupportedRuntimeCarrierV2(
              carrier: .rawQUIC,
              reason: "network_framework_quic_contract_incomplete_on_supported_targets"
            ),
            UnsupportedRuntimeCarrierV2(
              carrier: .webSocket,
              reason: "transport_v2_websocket_adapter_not_committed"
            ),
            UnsupportedRuntimeCarrierV2(
              carrier: .webTransport,
              reason: "network_framework_quic_contract_incomplete_on_supported_targets"
            ),
          ]
        )
    )
  }

  @Test func appleCapabilityMatchesSharedStrictCodecVector() throws {
    let workingDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    let relativePath = "testdata/transport_v2/capability_vectors.json"
    let candidates = [
      workingDirectory.appendingPathComponent(relativePath),
      workingDirectory.deletingLastPathComponent().appendingPathComponent(relativePath),
    ]
    let url = try #require(candidates.first { FileManager.default.fileExists(atPath: $0.path) })
    let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
    let vectors = try #require(fixture?["vectors"] as? [[String: Any]])
    let vector = try #require(vectors.first { $0["name"] as? String == "swift-apple" })
    let canonical = try RuntimeCapabilitiesV2.apple.canonicalJSON()
    #expect(String(decoding: canonical, as: UTF8.self) == vector["canonical_json"] as? String)
    #expect(try RuntimeCapabilitiesV2.apple.digestHex() == vector["digest_hex"] as? String)
    #expect(
      try RuntimeCapabilityDescriptorV2.decodeCanonicalJSON(canonical)
        == RuntimeCapabilitiesV2.apple)
    #expect(throws: (any Error).self) {
      try RuntimeCapabilityDescriptorV2.decodeCanonicalJSON(Data([0x20]) + canonical)
    }
  }

  @Test func metadataAcceptsBoundedPortableJSON() throws {
    let metadata = try StreamMetadataV2([
      "request": .string("hello"),
      "nested": .object([
        "items": .array([.integer(1), .bool(true), .null])
      ]),
    ])

    #expect(metadata.values["request"] == .string("hello"))
    #expect(metadata.encodedByteCount <= StreamMetadataV2.maxEncodedBytes)
  }

  @Test func metadataRejectsUnsafeIntegersAndOversizedStrings() {
    #expect(throws: StreamMetadataErrorV2.unsafeInteger) {
      try StreamMetadataV2(["value": .integer(9_007_199_254_740_992)])
    }
    #expect(throws: StreamMetadataErrorV2.stringTooLong) {
      try StreamMetadataV2(["value": .string(String(repeating: "a", count: 513))])
    }
  }

  @Test func metadataRejectsDepthNodeAndArrayLimitViolations() {
    let tooDeep: JSONValueV2 = .array([.array([.array([.array([.array([.null])])])])])
    #expect(throws: StreamMetadataErrorV2.depthExceeded) {
      try StreamMetadataV2(["value": tooDeep])
    }
    #expect(throws: StreamMetadataErrorV2.arrayTooLong) {
      try StreamMetadataV2(["value": .array(Array(repeating: .null, count: 33))])
    }
    #expect(throws: StreamMetadataErrorV2.nodeLimitExceeded) {
      try StreamMetadataV2([
        "a": .array(Array(repeating: .null, count: 32)),
        "b": .array(Array(repeating: .null, count: 32)),
      ])
    }
  }

  @Test func carrierNeutralProtocolsSupportAsyncSessionAndStreamOperations() async throws {
    let rpc = ContractRPCPeerV2()
    let stream = ContractByteStreamV2(id: 7, kind: "rpc")
    let session = ContractSessionV2(rpc: rpc, stream: stream)

    let opened = try await session.openStream(kind: "rpc", metadata: .empty)
    let accepted = try await session.acceptStream()
    #expect(opened.kind == "rpc")
    #expect(accepted.kind == "rpc")
    #expect(accepted.metadata == .empty)
    #expect(try await opened.write(Data([1, 2])) == 2)
    try await opened.closeWrite()
    await opened.reset()
    await opened.close()
    try await session.rekey()
    #expect(try await session.probeLiveness() == .milliseconds(1))
    await session.close()
  }
}

private actor ContractRPCPeerV2: RPCPeerV2 {
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
    throw CancellationError()
  }

  func notify<Payload: Encodable & Sendable>(_ typeID: UInt32, _ payload: Payload) async throws {
    _ = typeID
    _ = payload
  }
}

private actor ContractByteStreamV2: ByteStreamV2 {
  nonisolated let id: UInt64
  nonisolated let kind: String

  init(id: UInt64, kind: String) {
    self.id = id
    self.kind = kind
  }

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

private final class ContractSessionV2: SessionV2, @unchecked Sendable {
  let path: PathKind = .direct
  let chosenCarrier: CarrierKind = .webSocket
  let endpointInstanceID: String? = nil
  let rpc: any RPCPeerV2
  private let stream: any ByteStreamV2

  init(rpc: any RPCPeerV2, stream: any ByteStreamV2) {
    self.rpc = rpc
    self.stream = stream
  }

  func openStream(kind: String, metadata: StreamMetadataV2) async throws -> any ByteStreamV2 {
    _ = kind
    _ = metadata
    return stream
  }

  func acceptStream() async throws -> IncomingStreamV2 {
    IncomingStreamV2(kind: stream.kind, metadata: .empty, stream: stream)
  }

  func rekey() async throws {}
  func probeLiveness() async throws -> Duration { .milliseconds(1) }
  func waitClosed() async -> SessionErrorV2 { .closed }
  func close() async {}
}
