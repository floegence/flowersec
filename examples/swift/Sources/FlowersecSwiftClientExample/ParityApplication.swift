import CryptoKit
import Flowersec
import Foundation

struct ValuePayload: Codable, Equatable, Sendable { let value: String }

struct ValuePayloadCodec: MessageCodec {
  let definition: MessageDefinition
  func encode(_ value: ValuePayload, into destination: inout Data) throws -> Int {
    guard value.value.utf8.count <= 4096 else { throw MessageCodecFailure.encodeFailed }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let encoded = try encoder.encode(value)
    guard encoded.count <= definition.maxMessageBytes else { throw MessageCodecFailure.encodeFailed }
    destination = encoded
    return encoded.count
  }
  func decode(_ source: Data) throws -> ValuePayload {
    guard source.count <= definition.maxMessageBytes,
      let fields = try JSONSerialization.jsonObject(with: source) as? [String: Any],
      fields.count == 1, let value = fields["value"] as? String,
      value.utf8.count <= 4096 else { throw MessageCodecFailure.decodeFailed }
    return ValuePayload(value: value)
  }
}

// The parity fixture and this example share this explicit local application
// declaration. A peer cannot choose a namespace, type, codec or dispatch route.
struct ParityApplication: Sendable {
  let definition: ServiceDefinition
  let echo: MethodDefinition
  let notification: MethodDefinition
  let codec: ValuePayloadCodec
  init() throws {
    let schema = Data(#"{"additionalProperties":false,"properties":{"value":{"type":"string"}},"required":["value"],"type":"object"}"#.utf8)
    let payload = try MessageDefinition(schemaDigest: Data(SHA256.hash(data: schema)),
      revision: "1", maxMessageBytes: 4096)
    codec = ValuePayloadCodec(definition: payload)
    echo = try MethodDefinition(.init(typeID: 7001, shape: .unary, semantics: .transient,
      request: payload, response: payload, responseRevision: "1", requestMaxBytes: 4096,
      minResponseLimitBytes: 0, maxResponseBytes: 4096))
    notification = try MethodDefinition(.init(typeID: 7002, shape: .notify, semantics: .observation,
      request: payload, responseRevision: "1", requestMaxBytes: 4096))
    definition = try ServiceDefinition(namespace: "flowersec.parity", methods: [
      .init(name: "echo", method: echo), .init(name: "publish", method: notification),
    ])
  }
  func bind(session: any Session, environment: TransportEnvironment, target: ServiceBindingTarget)
    async throws -> ServiceClient
  {
    let echoContract = try await environment.captureServiceContract(Self.contract(typeID: 7001, notify: false))
    let notificationContract = try await environment.captureServiceContract(Self.contract(typeID: 7002, notify: true))
    // Fixed query coordinates are independently configured by this fixture.
    // Known/wanted digests pin the exact local contracts before any peer result.
    let queryBinding = try ServiceContractQueryBinding(typeID: 7,
      contractDigest: Data([9]) + Data(repeating: 0, count: 31), maximumLifetimeMS: 30_000)
    let deadline = UInt64(Date().timeIntervalSince1970 * 1000) + 10_000
    let results = try await session.queryContracts([
      .init(namespace: definition.namespace, typeID: 7001, wantedDigest: echoContract.digest,
        known: .init(contract: echoContract), maximumOfferWindowMS: 30_000),
      .init(namespace: definition.namespace, typeID: 7002, wantedDigest: notificationContract.digest,
        known: .init(contract: notificationContract), maximumOfferWindowMS: 30_000),
    ], target: target, binding: queryBinding, deadlineAtMS: deadline)
    guard results.count == 2, let echo = results[0].snapshot, let notify = results[1].snapshot,
      echo.contract.digest == echoContract.digest, notify.contract.digest == notificationContract.digest else {
      throw ServiceFailure.contractMismatch
    }
    return try session.bindService(definition, target: target, contracts: [echo, notify])
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
