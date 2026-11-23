#if os(macOS)
import Flowersec
import Foundation
import Darwin

actor CapacityPeer {
  private let authority: CapacityAuthority
  private let business: Bool
  private var released = false
  private var session: (any Session)?, subscription: (any RPCNotificationSubscription)?
  private var notifications = 0, invalid = false
  private let observed = AsyncStream.makeStream(of: Bool.self, bufferingPolicy: .bufferingOldest(1))

  init(authority: CapacityAuthority, business: Bool) { self.authority = authority; self.business = business }

  func authorize() throws {
    guard !released, (try? authority.check()) != nil else { throw RPCError(code: 403, message: "unavailable") }
  }

  func bind(_ session: any Session) async throws {
    self.session = session
    try authorize()
    subscription = try await session.rpc.subscribeNotification(7002, as: ValuePayload.self) { [weak self] event in
      await self?.observe((try? event.get().value) == "notify")
    }
  }

  func authorizeQuery(includingNotification: Bool) throws {
    try authorize()
    if includingNotification && subscription == nil { throw RPCError(code: 404, message: "unavailable") }
  }

  private func observe(_ valid: Bool) {
    if !valid || (try? authorize()) == nil { invalid = true; observed.continuation.finish(); return }
    notifications += 1
    if notifications == 2 { observed.continuation.yield(true); observed.continuation.finish() }
  }

  func handle(_ id: UInt32, _ request: ValuePayload) async throws -> ValuePayload {
    try authorize()
    switch (id, request.value) {
    case (7001, "ping"): break
    case (7001, "notifications-observed"):
      if notifications < 2 {
        var iterator = observed.stream.makeAsyncIterator()
        guard await iterator.next() == true else { throw CapacityRoleError.incomplete }
      }
      guard notifications >= 2, !invalid else { throw CapacityRoleError.incomplete }
    case (7003, "complete"):
      guard let session else { throw CapacityRoleError.incomplete }
      try await session.rekey(); _ = try await session.probeLiveness()
    case (7005, "datagram-ready"): break
    default: throw RPCError(code: 400, message: "invalid value")
    }
    return request
  }

  func echo(_ request: CapacityEcho) async throws -> CapacityEcho {
    if let value = request.value, request.payload == nil {
      return CapacityEcho(value: try await handle(7001, ValuePayload(value: value)).value)
    }
    try authorize(); try Task.checkCancellation()
    guard business, request.value == nil, let text = request.payload, CapacityBusiness.valid(text.utf8.count),
          text.utf8.allSatisfy({ $0 == 0x5a }) else { throw RPCError(code: 400, message: "invalid value") }
    return request
  }

  func ready() -> Bool { session != nil && subscription != nil && notifications >= 2 && !invalid }

  func release() async {
    released = true; observed.continuation.finish()
    await subscription?.cancel(); subscription = nil; session = nil
  }
}

actor CapacityPair {
  let id: String, generation: Int
  let tunnelKeys: [String]
  let proof: CapacityGeneration
  private let client, server: any Session
  private let local, remote: CapacityPeer
  private var watches: [Task<Void, Never>] = [], retained: [any ByteStream] = []
  private var terminated = false, eventFailed = false, closing = false
  private let output: CapacityWriter

  init(id: String, generation: Int, proof: CapacityGeneration, client: any Session, server: any Session,
       local: CapacityPeer, remote: CapacityPeer, output: CapacityWriter) {
    self.id = id; self.generation = generation; self.proof = proof; self.tunnelKeys = proof.tunnel ? proof.keys : []
    self.client = client; self.server = server
    self.local = local; self.remote = remote; self.output = output
  }

  func establish(_ app: ParityApplication) async throws {
    async let a: Void = local.bind(client)
    async let b: Void = remote.bind(server)
    _ = try await (a, b)
    async let clientQuery: Void = app.checkOptionalCalls(on: client)
    async let serverQuery: Void = app.checkOptionalCalls(on: server)
    _ = try await (clientQuery, serverQuery)
    // Both subscriptions and contract checks are live before either peer starts its workload.
    try await withThrowingTaskGroup(of: Void.self) { group in
      for end in [client, server] {
        group.addTask { try await Self.serveEcho(end) }
        group.addTask { try await Self.exercise(end) }
      }
      do { while try await group.next() != nil {} }
      catch { group.cancelAll(); try? await client.close(); try? await server.close(); throw error }
    }
    // Rekey once in each direction, sequentially, using the peer's real completion handler.
    for end in [client, server] { try await Self.call(end, 7003, "complete") }
    try await checkLive()
  }

  func watch() {
    for end in [client, server] { watches.append(Task { _ = await end.waitTermination(); self.ended() }) }
  }

  private func ended() {
    guard !terminated else { return }; terminated = true
    do { try output.terminated(id) } catch { eventFailed = true; _ = Darwin.shutdown(output.file.fileDescriptor, SHUT_RDWR) }
  }

  private static func call(_ end: any Session, _ id: UInt32, _ value: String) async throws {
    let req = ValuePayload(value: value)
    guard try await end.rpc.call(id, req, as: ValuePayload.self, timeout: .seconds(30)) == req else {
      throw CapacityRoleError.incomplete
    }
  }

  private static func serveEcho(_ end: any Session) async throws {
    let incoming = try await end.acceptStream()
    guard incoming.kind == "parity.echo", try await readAll(from: incoming.stream, maximum: 5) == Data("hello".utf8)
    else { throw CapacityRoleError.incomplete }
    try await writeAll(Data("world".utf8), to: incoming.stream); try await incoming.stream.closeWrite()
  }

  private static func exercise(_ end: any Session) async throws {
    try await call(end, 7001, "ping")
    for _ in 0..<2 { try await end.rpc.notify(7002, ValuePayload(value: "notify")) }
    try await call(end, 7001, "notifications-observed")
    let stream = try await end.openStream(kind: "parity.echo")
    try await writeAll(Data("hello".utf8), to: stream); try await stream.closeWrite()
    guard try await readAll(from: stream, maximum: 5) == Data("world".utf8) else { throw CapacityRoleError.incomplete }
  }

  func checkLive() async throws {
    guard !closing, !terminated, await local.ready(), await remote.ready(), try await sessionActivity(client).open,
          try await sessionActivity(server).open else { throw CapacityRoleError.incomplete }
  }

  func snapshot() async throws -> (Int, Int, Int) {
    let a = try await sessionActivity(client), b = try await sessionActivity(server)
    return (a.open && b.open ? 1 : 0, a.activeStreams + b.activeStreams, a.retainedStreams + b.retainedStreams)
  }

  func business(_ operation: String, bytes: Int) async throws -> CapacityResult {
    try await checkLive()
    let (sent, received) = try await CapacityBusiness.roundTrip(from: client, to: server, operation: operation, bytes: bytes)
    try Task.checkCancellation(); try await checkLive()
    return CapacityResult(id: id, generation: generation, operation: operation, requestBytes: sent, responseBytes: received, verified: true)
  }

  func probe(overlap: Bool) async throws -> CapacityResult {
    try await checkLive()
    _ = try await client.probeLiveness()
    guard generation > 1, overlap || tunnelKeys.isEmpty else { return CapacityResult() }
    _ = try await server.probeLiveness()
    try await checkLive()
    if !tunnelKeys.isEmpty { return CapacityResult(id: id, generation: generation, responsiveLegs: 2) }
    return CapacityResult(id: id, generation: generation, clientResponsive: true, serverResponsive: true)
  }

  func openStream() async throws {
    try await checkLive()
    let a = try await client.openStream(kind: "parity.hold")
    do {
      let incoming = try await server.acceptStream()
      guard !closing, incoming.kind == "parity.hold" else { try await incoming.stream.reset(); throw CapacityRoleError.incomplete }
      retained.append(a); retained.append(incoming.stream)
    } catch { try? await a.reset(); throw error }
  }

  func close() async throws {
    closing = true
    await local.release(); await remote.release()
    async let a: Void = client.close(), b: Void = server.close()
    _ = try await (a, b)
    for task in watches { await task.value }; watches.removeAll(); retained.removeAll()
    let first = try await sessionActivity(client), second = try await sessionActivity(server)
    guard !first.open, !second.open, first.activeStreams == 0, second.activeStreams == 0,
          first.retainedStreams == 0, second.retainedStreams == 0, !eventFailed else { throw CapacityRoleError.incomplete }
  }
}
#endif
