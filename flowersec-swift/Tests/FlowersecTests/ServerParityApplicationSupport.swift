#if os(macOS)
import Crypto
@testable import Flowersec
import Foundation

struct PeerParityValue: Codable, Equatable, Sendable { let value: String }

struct PeerParityCodec: MessageCodec {
  let definition: MessageDefinition
  func encode(_ value: PeerParityValue, into destination: inout Data) throws -> Int {
    guard value.value.utf8.count <= 4096 else { throw MessageCodecFailure.encodeFailed }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let encoded = try encoder.encode(value)
    guard encoded.count <= definition.maxMessageBytes else { throw MessageCodecFailure.encodeFailed }
    destination = encoded
    return encoded.count
  }
  func decode(_ source: Data) throws -> PeerParityValue {
    guard source.count <= definition.maxMessageBytes,
      let fields = try JSONSerialization.jsonObject(with: source) as? [String: Any],
      fields.count == 1, let value = fields["value"] as? String,
      value.utf8.count <= 4096 else { throw MessageCodecFailure.decodeFailed }
    return PeerParityValue(value: value)
  }
}

// The parity fixture and this example share this explicit local application
// declaration. A peer cannot choose a namespace, type, codec or dispatch route.
struct PeerParityApplication: Sendable {
  let definition: ServiceDefinition
  let echo: MethodDefinition
  let completion: MethodDefinition
  let datagramReady: MethodDefinition
  let notification: MethodDefinition
  let codec: PeerParityCodec
  init() throws {
    let schema = Data(#"{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"type":"object"}"#.utf8)
    let payload = try MessageDefinition(schemaDigest: Data(SHA256.hash(data: schema)),
      revision: "1", maxMessageBytes: 4096)
    codec = PeerParityCodec(definition: payload)
    echo = try MethodDefinition(.init(typeID: 7001, shape: .unary, semantics: .transient,
      request: payload, response: payload, responseRevision: "1", requestMaxBytes: 4096,
      minResponseLimitBytes: 0, maxResponseBytes: 4096))
    notification = try MethodDefinition(.init(typeID: 7002, shape: .notify, semantics: .observation,
      request: payload, responseRevision: "1", requestMaxBytes: 4096))
    completion = try MethodDefinition(.init(typeID: 7003, shape: .unary, semantics: .transient,
      request: payload, response: payload, responseRevision: "1", requestMaxBytes: 4096,
      minResponseLimitBytes: 0, maxResponseBytes: 4096))
    datagramReady = try MethodDefinition(.init(typeID: 7005, shape: .unary, semantics: .transient,
      request: payload, response: payload, responseRevision: "1", requestMaxBytes: 4096,
      minResponseLimitBytes: 0, maxResponseBytes: 4096))
    definition = try ServiceDefinition(namespace: "flowersec.parity", methods: [
      .init(name: "echo", method: echo), .init(name: "publish", method: notification),
      .init(name: "complete", method: completion), .init(name: "datagramReady", method: datagramReady),
    ])
  }
  func bind(session: any Session, environment: TransportEnvironment, target: ServiceBindingTarget)
    async throws -> ServiceClient
  {
    let methods = [echo, notification, completion, datagramReady]
    var contracts: [ServiceContract] = []
    for method in methods {
      contracts.append(try await environment.captureServiceContract(Self.contract(typeID: method.typeID, notify: method.shape == .notify)))
    }
    let queryBinding = try ServiceContractQueryBinding(typeID: 7,
      contractDigest: Data([9]) + Data(repeating: 0, count: 31), maximumLifetimeMS: 30_000)
    let deadline = UInt64(Date().timeIntervalSince1970 * 1000) + 10_000
    let requests = try methods.enumerated().map { index, method in
      try ServiceContractQueryTarget(namespace: definition.namespace, typeID: method.typeID,
        wantedDigest: contracts[index].digest, known: .init(contract: contracts[index]), maximumOfferWindowMS: 30_000)
    }
    let results = try await session.queryContracts(requests, target: target, binding: queryBinding, deadlineAtMS: deadline)
    guard results.count == methods.count else { throw ServiceFailure.contractMismatch }
    let snapshots = try results.enumerated().map { index, result in
      guard let snapshot = result.snapshot, snapshot.contract.digest == contracts[index].digest else { throw ServiceFailure.contractMismatch }
      return snapshot
    }
    return try session.bindService(definition, target: target, contracts: snapshots)
  }

  static func contract(typeID: UInt32, notify: Bool) -> Data {
    var fields: [(UInt64, Data)] = [
      (0, text("flowersec.parity")), (1, uint(UInt64(typeID))), (2, uint(notify ? 2 : 0)),
      (notify ? 5 : 3, uint(0)), (6, text("1")), (7, text("1")),
      (8, uint(notify ? 0 : 1)), (9, uint(0)), (10, uint(notify ? 0 : 4096)),
      (11, uint(30_000)), (21, Data([0xf4])), (23, uint(4096)), (27, Data([0x80])),
    ]
    if !notify { fields.append((12, uint(30_000))) }
    fields.sort { $0.0 < $1.0 }
    return head(major: 5, value: UInt64(fields.count))
      + fields.reduce(into: Data()) { $0.append(uint($1.0)); $0.append($1.1) }
  }
  private static func uint(_ value: UInt64) -> Data { head(major: 0, value: value) }
  private static func text(_ value: String) -> Data {
    head(major: 3, value: UInt64(value.utf8.count)) + Data(value.utf8)
  }
  private static func head(major: UInt8, value: UInt64) -> Data {
    if value < 24 { return Data([(major << 5) | UInt8(value)]) }
    let size: Int = value <= 255 ? 1 : value <= 65_535 ? 2 : value <= 4_294_967_295 ? 4 : 8
    var bytes = Data([(major << 5) | (size == 1 ? 24 : size == 2 ? 25 : size == 4 ? 26 : 27)])
    for shift in stride(from: (size - 1) * 8, through: 0, by: -8) {
      bytes.append(UInt8(truncatingIfNeeded: value >> shift))
    }
    return bytes
  }
}

#endif
