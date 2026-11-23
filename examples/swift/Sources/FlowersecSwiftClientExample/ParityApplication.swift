import Flowersec
import Foundation

private struct ContractFile: Decodable {
  let namespace: String
  let query_type_id: UInt32
  let contracts: [String: Data]
}

private struct Query: Codable { let namespace: String; let type_ids: [UInt32] }
private struct Reply: Codable { let contracts: [String] }

struct ParityApplication: Sendable {
  private static let types: [UInt32] = [7001, 7002, 7003, 7005]
  private let expected: [Data]
  private let query: Bool
  private let queryOverlap: Int
  let largeMode: LargeEchoMode
  let largeEcho: LargeEcho?
  private let extraMethods: UInt32
  private let rounds: Int
  let frameLimits: RPCFrameLimits
  let handlers: RPCHandlers
  let permissions: ParityPermissions
  var checkedContractCount: Int { query ? expected.count : 0 }

  init(_ env: [String: String], authorized: Set<UInt32> = [7001, 7002, 7003, 7005], capacityBusiness: Bool = false) throws {
    #if os(macOS)
    let capacityProduct = env["FLOWERSEC_CAPACITY_ROLE"] == "product"
    #else
    let capacityProduct = false
    #endif
    let permissions = ParityPermissions(file: capacityProduct ? nil : env["FLOWERSEC_PARITY_POLICY_FILE"],
                                        excluded: Set(Self.types).subtracting(authorized))
    self.permissions = permissions
    query = env["FSEC_EXAMPLE_QUERY"] == "1"
    guard let overlap = Int(env["FSEC_EXAMPLE_QUERY_OVERLAP"] ?? "1"), overlap > 0 else {
      throw ExampleConfigurationError.invalidConfiguration
    }
    queryOverlap = overlap
    guard let largeMode = LargeEchoMode(rawValue: env["FSEC_EXAMPLE_LARGE_RPC"] ?? "0"),
          !(largeMode == .serve && env["FSEC_EXAMPLE_BIDIRECTIONAL"] == "1") else {
      throw ExampleConfigurationError.invalidConfiguration
    }
    self.largeMode = largeMode
    let largeEcho = largeMode == .disabled ? nil : LargeEcho()
    self.largeEcho = largeEcho
    guard let count = UInt32(env["FSEC_EXAMPLE_METHOD_COUNT"] ?? "0"), count <= UInt32.max - 10_000,
          let repetitions = Int(env["FSEC_EXAMPLE_METHOD_ROUNDS"] ?? "1"), repetitions > 0
    else { throw ExampleConfigurationError.invalidConfiguration }
    extraMethods = count
    rounds = repetitions
    let common = env["FSEC_RPC_FRAME_BYTES"]
    let send = env["FSEC_RPC_SEND_BYTES"], receive = env["FSEC_RPC_RECEIVE_BYTES"]
    if common != nil || send != nil || receive != nil || largeEcho != nil {
      guard common == nil || (send == nil && receive == nil),
            let sendBytes = (send ?? common).flatMap(Int.init), let receiveBytes = (receive ?? common).flatMap(Int.init),
            largeEcho == nil || min(sendBytes, receiveBytes) >= LargeEcho.minimumFrame else {
        throw ExampleConfigurationError.invalidConfiguration
      }
      frameLimits = try RPCFrameLimits(send: sendBytes, receive: receiveBytes)
    } else { frameLimits = .standard }

    var routes = RPCHandlers()
    var declarations: [UInt32: Data] = [:]
    let file = try env["FSEC_PARITY_CONTRACTS_PATH"].map {
      try JSONDecoder().decode(ContractFile.self, from: Data(contentsOf: URL(fileURLWithPath: $0)))
    }
    guard !query || file != nil else { throw ExampleConfigurationError.invalidConfiguration }
    if let file, file.namespace != "flowersec.parity" || file.query_type_id != 7004 {
      throw ExampleConfigurationError.invalidConfiguration
    }
    expected = try file.map { f in try Self.types.map { id in
      guard let bytes = f.contracts[String(id)], !bytes.isEmpty else { throw ExampleConfigurationError.invalidConfiguration }
      return bytes
    } } ?? []

    // Only methods installed for this grant have visible declarations.
    for id in Self.types where authorized.contains(id) {
      #if os(macOS)
      if capacityProduct {
        if id == 7001 && capacityBusiness {
          try routes.register(id, context: CapacityPeer.self) { (state: CapacityPeer, request: CapacityEcho) in try await state.echo(request) }
        } else if id != 7002 {
          try routes.register(id, context: CapacityPeer.self) { state, payload in try await state.handle(id, payload) }
        }
        if let file { declarations[id] = file.contracts[String(id)] }
        continue
      }
      #endif
      if id == 7002 {
        try routes.registerNotification(id) { (payload: ValuePayload) in
          try permissions.execute(id)
          guard payload.value == "notify" else { throw RPCError(code: 400, message: "invalid value") }
        }
        if let file { declarations[id] = file.contracts[String(id)] }
        continue
      }
      try routes.register(id) { (payload: ValuePayload) -> ValuePayload in
        try permissions.execute(id)
        let allowed: Bool
        switch id {
        case 7001: allowed = ["ping", "notifications-observed"].contains(payload.value)
        case 7003: allowed = payload.value == "complete"
        case 7005: allowed = payload.value == "datagram-ready"
        default: allowed = false
        }
        guard allowed else { throw RPCError(code: 400, message: "invalid value") }
        return payload
      }
      if let file { declarations[id] = file.contracts[String(id)] }
    }
    if file != nil {
      let visible = declarations
      let lookup: @Sendable (Query) throws -> Reply = { q in
        guard q.namespace == "flowersec.parity", !q.type_ids.isEmpty, q.type_ids.count <= Self.types.count else { throw RPCError(code: 404, message: "unavailable") }
        try permissions.disclose(q.type_ids)
        return try Reply(contracts: q.type_ids.map { id in
          guard let bytes = visible[id] else { throw RPCError(code: 404, message: "unavailable") }
          return bytes.base64EncodedString()
        })
      }
      #if os(macOS)
      if capacityProduct {
        try routes.register(7004, context: CapacityPeer.self) { (state: CapacityPeer, q: Query) in
          try await state.authorizeQuery(includingNotification: q.type_ids.contains(7002)); return try lookup(q)
        }
      } else { try routes.register(7004, handler: lookup) }
      #else
      try routes.register(7004, handler: lookup)
      #endif
    }
    if let largeEcho {
      try routes.register(7010, acceptsNotifications: false) { (text: String) -> String in
        try await largeEcho.echo(text, permissions: permissions)
      }
    }
    for offset in 0..<extraMethods {
      let id = 10_000 + offset
      try routes.register(id) { (value: ValuePayload) -> ValuePayload in
        try permissions.execute(id)
        return ValuePayload(value: "\(id):\(value.value)")
      }
    }
    handlers = routes
  }

  func checkOptionalCalls(on session: any Session, callLarge: Bool = true) async throws {
    if query {
      try await withThrowingTaskGroup(of: Void.self) { group in
        for _ in 0..<queryOverlap {
          group.addTask {
            let reply = try await session.rpc.call(7004, Query(namespace: "flowersec.parity", type_ids: Self.types),
                                                   as: Reply.self, timeout: .seconds(10))
            guard reply.contracts.count == expected.count else { throw ExampleConfigurationError.invalidRPCResponse }
            for (encoded, bytes) in zip(reply.contracts, expected) {
              guard let decoded = Data(base64Encoded: encoded), decoded == bytes,
                    decoded.base64EncodedString() == encoded else { throw ExampleConfigurationError.invalidRPCResponse }
            }
          }
        }
        while try await group.next() != nil {}
      }
    }
    if largeMode == .call && callLarge { try await LargeEcho.call(on: session) }
    for round in 0..<rounds {
      for offset in 0..<extraMethods {
        let id = 10_000 + offset
        let reply = try await session.rpc.call(id, ValuePayload(value: String(round)), as: ValuePayload.self,
                                               timeout: .seconds(10))
        guard reply.value == "\(id):\(round)" else { throw ExampleConfigurationError.invalidRPCResponse }
      }
    }
  }
}
