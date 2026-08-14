import Foundation
import Testing

@testable import Flowersec

struct TransportV2ContractTests {
  @Test func appleCapabilitiesAdvertiseOnlyProductionWSSDialTuples() throws {
    for descriptor in [RuntimeCapabilitiesV2.macOS, RuntimeCapabilitiesV2.iOS] {
      try descriptor.validate()
      #expect(descriptor.tuples.map(\.carrier) == [.webSocket, .webSocket, .webSocket])
      #expect(descriptor.tuples.map(\.path) == [.direct, .tunnel, .tunnel])
      #expect(descriptor.tuples.map(\.sessionRole) == [.client, .client, .server])
      #expect(descriptor.unsupported.map(\.carrier) == [.rawQUIC, .webTransport])
    }
  }

  @Test func carrierRegistryValuesMatchPortableContract() {
    #expect(CarrierKind.webSocket.rawValue == "websocket")
    #expect(CarrierKind.rawQUIC.rawValue == "raw_quic")
    #expect(CarrierKind.webTransport.rawValue == "webtransport")
  }

  @Test func appleCapabilitiesMatchSharedStrictCodecVectors() throws {
    let url = packageRoot().appendingPathComponent("testdata/transport_v2/capability_vectors.json")
    let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
    let vectors = try #require(fixture?["vectors"] as? [[String: Any]])
    for (name, descriptor) in [
      ("swift-ios", RuntimeCapabilitiesV2.iOS),
      ("swift-macos", RuntimeCapabilitiesV2.macOS),
    ] {
      let vector = try #require(vectors.first { $0["name"] as? String == name })
      let canonical = try descriptor.canonicalJSON()
      #expect(String(decoding: canonical, as: UTF8.self) == vector["canonical_json"] as? String)
      #expect(try descriptor.digestHex() == vector["digest_hex"] as? String)
      #expect(try RuntimeCapabilityDescriptorV2.decodeCanonicalJSON(canonical) == descriptor)
      #expect(throws: (any Error).self) {
        try RuntimeCapabilityDescriptorV2.decodeCanonicalJSON(Data([0x20]) + canonical)
      }
    }
  }

  @Test func metadataAcceptsBoundedPortableJSON() throws {
    let metadata = try StreamMetadata([
      "request": .string("hello"),
      "nested": .object([
        "items": .array([.integer(1), .bool(true), .null])
      ]),
    ])

    #expect(metadata.values["request"] == .string("hello"))
    #expect(metadata.values["nested"] != nil)
  }

  @Test func metadataRejectsUnsafeIntegersAndOversizedStrings() {
    #expect(throws: StreamMetadataError.invalidValue) {
      try StreamMetadata(["value": .integer(9_007_199_254_740_992)])
    }
    #expect(throws: StreamMetadataError.invalidValue) {
      try StreamMetadata(["value": .string(String(repeating: "a", count: 513))])
    }
  }

  @Test func metadataRejectsDepthNodeAndArrayLimitViolations() {
    let tooDeep: JSONValue = .array([.array([.array([.array([.array([.null])])])])])
    #expect(throws: StreamMetadataError.invalidValue) {
      try StreamMetadata(["value": tooDeep])
    }
    #expect(throws: StreamMetadataError.invalidValue) {
      try StreamMetadata(["value": .array(Array(repeating: .null, count: 33))])
    }
    #expect(throws: StreamMetadataError.invalidValue) {
      try StreamMetadata([
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
    try await opened.reset()
    try await opened.close()
    try await session.rekey()
    #expect(try await session.probeLiveness() == .milliseconds(1))
    try await session.close()
  }
}

private actor ContractRPCPeerV2: RPCPeer {
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

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription {
    _ = typeID
    _ = payloadType
    _ = handler
    return ContractNotificationSubscriptionV2()
  }
}

private struct ContractNotificationSubscriptionV2: RPCNotificationSubscription {
  func cancel() async {}
}

private actor ContractByteStreamV2: ByteStream {
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
  func reset() async throws {}
  func close() async throws {}
  func terminalError() async -> SessionError? { nil }
}

private final class ContractSessionV2: Session, @unchecked Sendable {
  let path: PathKind = .direct
  let chosenCarrier: CarrierKind = .webSocket
  let endpointInstanceID: String? = nil
  let rpc: any RPCPeer
  private let stream: any ByteStream

  init(rpc: any RPCPeer, stream: any ByteStream) {
    self.rpc = rpc
    self.stream = stream
  }

  func openStream(kind: String, metadata: StreamMetadata) async throws -> any ByteStream {
    _ = kind
    _ = metadata
    return stream
  }

  func acceptStream() async throws -> IncomingStream {
    IncomingStream(kind: stream.kind, metadata: .empty, stream: stream)
  }

  func rekey() async throws {}
  func probeLiveness() async throws -> Duration { .milliseconds(1) }
  func waitTermination() async -> SessionTermination { SessionTermination(error: .closed) }
  func close() async throws {}
}
