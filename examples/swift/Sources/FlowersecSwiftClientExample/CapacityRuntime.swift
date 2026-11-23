#if os(macOS)
import CryptoKit
import Flowersec
import Foundation

private struct CapacityMaterial: Sendable {
  private struct Projection: Decodable {
    struct Session: Decodable { let channel_id: String; let init_expire_at_unix_s: UInt64 }
    struct Path: Decodable {
      struct Candidate: Decodable { let carrier, url: String }
      let kind: String; let role: Int?; let token, routing_token: String?
      let candidates: [Candidate]
    }
    let session: Session, path: Path
  }
  let artifact: Artifact, id: String, authority: CapacityAuthority, credentialDigest: String
  private let file: URL, original: Data, expiry: UInt64, artifactIsDirect: Bool, overlap: Bool

  init(_ url: URL, channel: String, records: URL, tunnelRole: Int? = nil, ingress: String? = nil, overlap: Bool = false) throws {
    let raw = try privateCapacityFile(url, maximum: 65_536)
    artifact = try parseArtifact(raw)
    let p = try JSONDecoder().decode(Projection.self, from: raw)
    guard p.session.channel_id == channel, p.path.kind == (tunnelRole == nil ? "direct" : "tunnel"), p.path.role == tunnelRole,
          ingress.map({ selected in p.path.candidates.contains { $0.carrier == "websocket" && $0.url == selected } }) ?? true,
          let credential = p.path.token ?? p.path.routing_token else { throw CapacityRoleError.invalidMaterial }
    id = p.session.channel_id; expiry = p.session.init_expire_at_unix_s; artifactIsDirect = tunnelRole == nil
    credentialDigest = capacityBase64URL(Data(SHA256.hash(data: Data(credential.utf8))))
    authority = try CapacityAuthority(directory: records, key: credentialDigest, artifact: raw)
    file = url; original = raw; self.overlap = overlap
  }

  func registerServer(at directory: URL) throws {
    struct Registration: Encodable { let channel_id, lookup_key, artifact_sha256: String }
    try Task.checkCancellation()
    let reply = Registration(channel_id: id, lookup_key: credentialDigest, artifact_sha256: capacityBase64URL(Data(SHA256.hash(data: original))))
    try commitCapacityFile(try JSONEncoder().encode(reply), at: directory.appendingPathComponent(id + ".json"))
  }

  func spend(in store: URL, role: String) throws {
    try Task.checkCancellation()
    try authority.check()
    guard expiry > UInt64(max(0, Date().timeIntervalSince1970)), try privateCapacityFile(file, maximum: 65_536) == original else {
      throw CapacityRoleError.invalidMaterial
    }
    let prefix = role == "direct-acceptor" ? "admitted-" : "spent-"
    let receipt = store.appendingPathComponent(prefix + credentialDigest)
    if overlap { try commitCapacityFile(CapacityGeneration.marker, at: receipt) }
    else { try commitSpendReceipt(at: receipt.path) }
  }

  func lease(_ store: URL, _ role: String) -> ArtifactLease {
    if artifactIsDirect {
      return ArtifactLease(reservingFor: artifact) { try self.acquireDirect(in: store, role: role) }
    }
    return ArtifactLease(artifact: artifact, commitSpend: { try self.spend(in: store, role: role) })
  }

  func acquireDirect(in store: URL, role: String) throws -> ConnectionLease {
    try spend(in: store, role: role)
    let prefix = role == "direct-acceptor" ? "released-" : "released-client-"
    return durableConnectionLease(releaseAt: store.appendingPathComponent(prefix + credentialDigest).path)
  }
}

private struct PendingDirect: Sendable {
  let material: CapacityMaterial, handlers: RPCHandlers, store: URL
  let accept: AsyncStream<any Session>.Continuation
}

actor CapacityRuntime {
  private let env: [String: String], output: CapacityWriter
  private var options: CapacityOptions?, app: ParityApplication?, listener: DirectWebSocketListener?
  private var store: URL?, materials: URL?, records: URL?, approvals: URL?, roots: [Data] = [], origin = "", ingress: [String] = []
  private var installedB: [String: CapacityMaterial] = [:]
  private var serverPreparationStarted = false
  private var prepared = false, stopped = false
  private var pairs: [Int: CapacityPair] = [:], byID: [String: Int] = [:], busy = Set<Int>(), seen = Set<String>()
  private struct Retired { let id: String, generation: Int, tunnelKeys: [String] }
  private var retired: [Int: Retired] = [:], pending: [String: PendingDirect] = [:]
  private var successors: [Int: CapacityPair] = [:], claimed = Set<Int>(), responsive = Set<String>(), usedKeys = Set<String>()
  private var closedOwners: [String: (index: Int, generation: Int, proof: CapacityGeneration)] = [:]
  private var retiring: String?, retirements = 0, operating = Set<String>(), closing = Set<String>()
  private var overlap: Bool { options?.overlapSuccessors == 4 }
  private var liveOwners: [CapacityPair] { Array(pairs.values) + Array(successors.values) }

  init(env: [String: String], output: CapacityWriter) { self.env = env; self.output = output }

  private func initialize(_ o: CapacityOptions) async throws -> CapacityResult {
    guard options == nil, !stopped, o.nativeSDK == "swift", o.carrier == "websocket",
          o.serverCarrier == nil || o.serverCarrier == "websocket", (1...1000).contains(o.sessions),
          (0...128).contains(o.streamsPerSession), (1...86_400_000).contains(o.operationTimeoutMS),
          o.overlapSuccessors == nil || (o.overlapSuccessors == 4 && o.sessions >= 4 && (o.serverCarrier == nil ? o.directReplacement : o.tunnelReplacement) == true),
          o.materialPath.hasPrefix("/"), o.storeDirectory.hasPrefix("/")
    else { throw CapacityRoleError.incompatibleDeployment }
    options = o; origin = env["FSEC_ORIGIN"] ?? "https://parity.example"
    let base = URL(fileURLWithPath: o.materialPath).deletingLastPathComponent()
    func roleDirectory(_ role: String, _ name: String) throws -> URL {
      let path = env["FSEC_CAPACITY_\(role)_DIR"] ?? base.appendingPathComponent(name).path
      guard path.hasPrefix("/") else { throw CapacityRoleError.invalidMaterial }
      return URL(fileURLWithPath: path, isDirectory: true)
    }
    materials = try roleDirectory("INVITATION", "invitations"); records = try roleDirectory("RECORD", "records")
    approvals = try roleDirectory("APPROVAL", "approvals"); store = URL(fileURLWithPath: o.storeDirectory, isDirectory: true)
    var settings = env; settings["FSEC_EXAMPLE_QUERY"] = "1"
    if overlap, settings["FSEC_RPC_FRAME_BYTES"] == nil && settings["FSEC_RPC_SEND_BYTES"] == nil && settings["FSEC_RPC_RECEIVE_BYTES"] == nil {
      settings["FSEC_RPC_FRAME_BYTES"] = String(CapacityBusiness.large + 256)
    }
    if settings["FSEC_PARITY_CONTRACTS_PATH"] == nil { settings["FSEC_PARITY_CONTRACTS_PATH"] = "examples/parity-contracts.json" }
    let app = try ParityApplication(settings, capacityBusiness: overlap); self.app = app
    guard !overlap || min(app.frameLimits.send, app.frameLimits.receive) >= CapacityBusiness.large + 256 else { throw CapacityRoleError.incompatibleDeployment }
    let rootsPath = env["FSEC_TRUST_ROOT_PEM_PATH"] ?? env["FSEC_CAPACITY_ROOTS"] ?? (o.serverCarrier == nil ? nil : base.appendingPathComponent("ca.pem").path)
    roots = try rootsPath.map { [try Data(contentsOf: URL(fileURLWithPath: $0))] } ?? []
    if o.serverCarrier != nil {
      guard let a = env["FSEC_CAPACITY_INGRESS_A"], let b = env["FSEC_CAPACITY_INGRESS_B"]
      else { throw CapacityRoleError.deploymentUnavailable }
      ingress = [a, b]
      guard !overlap || a == b else { throw CapacityRoleError.incompatibleDeployment }
      let addresses = try ingress.map { url in
        guard let u = URLComponents(string: url), u.scheme == "wss", let host = u.host, u.path == "/flowersec/v5/tunnel",
              u.user == nil, u.password == nil, u.query == nil, u.fragment == nil, (1...65535).contains(u.port ?? 443)
        else { throw CapacityRoleError.incompatibleDeployment }
        return "\(host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host):\(u.port ?? 443)"
      }
      return CapacityResult(endpointAddresses: addresses, ingressURLs: ingress)
    }
    guard let cert = env["FSEC_LISTEN_CERT_PEM_PATH"], let key = env["FSEC_LISTEN_KEY_PEM_PATH"],
          let port = Int(env["FSEC_LISTEN_PORT"] ?? "0") else { throw CapacityRoleError.deploymentUnavailable }
    let ip = env["FSEC_LISTEN_ADDRESS"] ?? "127.0.0.1"
    let bound = try await DirectWebSocketListener.listen(bindAddress: ip, port: port, endpoint: env["FSEC_LISTEN_ENDPOINT"],
      allowedOrigins: [origin], certificateChainPEM: Data(contentsOf: URL(fileURLWithPath: cert)),
      privateKeyPEM: Data(contentsOf: URL(fileURLWithPath: key)), maxConnections: o.sessions + (o.overlapSuccessors ?? 0),
      admissionTimeout: .milliseconds(min(o.operationTimeoutMS, 3_600_000)), rpcFrameLimits: app.frameLimits,
      maxConcurrentRPCRequests: try exampleConcurrency(env), authorize: { [weak self] r in await self?.authorize(r) },
      onSession: { [weak self] end, request in
        guard await self?.deliver(end, id: request.channelID) == true else { return }
        _ = await end.waitTermination()
      })
    listener = bound
    return CapacityResult(endpointAddress: "\(ip.contains(":") ? "[\(ip)]" : ip):\(bound.port)")
  }

  private func authorize(_ r: DirectAdmissionRequest) -> DirectAdmissionGrant? {
    guard let p = pending[r.channelID] else { return nil }
    return DirectAdmissionGrant(reservingFor: p.material.artifact, handlers: p.handlers) {
      try p.material.acquireDirect(in: p.store, role: "direct-acceptor")
    }
  }

  private func deliver(_ end: any Session, id: String) -> Bool {
    guard let p = pending[id] else { return false }
    if case .enqueued = p.accept.yield(end) { p.accept.finish(); return true }; return false
  }

  private func acquire(_ c: CapacityCommand, replacement: Bool) async throws -> CapacityResult {
    guard let o = options, prepared, let app, let store, let materials, let records, let approvals, let i = c.index, (0..<o.sessions).contains(i),
          !busy.contains(i) else { throw CapacityRoleError.positionUnavailable }
    busy.insert(i); defer { busy.remove(i) }
    let concurrent = c.op == "connect_successor", direct = ingress.isEmpty
    let g: Int
    if concurrent {
      let old = try predecessor(c, index: i)
      if direct { try claim(i) }
      else { guard claimed.contains(i), let next = c.expectedSession, installedB[next] != nil else { throw CapacityRoleError.positionUnavailable } }
      try await old.checkLive(); try old.proof.requireHeld(); g = 2
    } else if replacement {
      guard !overlap, pairs[i] == nil, (direct ? o.directReplacement : o.tunnelReplacement) == true,
            let old = retired[i], old.id == c.session, let n = c.generation, n == old.generation + 1,
            let expected = c.expectedSession, expected != old.id, c.op == (ingress.isEmpty ? "replace_direct" : "replace_tunnel")
      else { throw CapacityRoleError.positionUnavailable }; g = n
    } else {
      guard pairs[i] == nil, retired[i] == nil, c.generation == nil || c.generation == 1 else { throw CapacityRoleError.positionUnavailable }; g = 1
    }
    let id = g == 1 ? "p\(i)" : "p\(i)-g\(g)"
    let dir = materials.appendingPathComponent(id, isDirectory: true)
    let material = try CapacityMaterial(direct ? materials.appendingPathComponent(id + ".json") : dir.appendingPathComponent("first.json"),
      channel: id, records: records, tunnelRole: direct ? nil : 1, ingress: direct ? nil : ingress[0], overlap: overlap)
    guard (!replacement || c.expectedSession == id), !seen.contains(id) else { throw CapacityRoleError.invalidMaterial }
    seen.insert(id)
    let other: CapacityMaterial
    if direct { other = try CapacityMaterial(approvals.appendingPathComponent(id + ".json"), channel: id, records: records, overlap: overlap) }
    else if let installed = installedB.removeValue(forKey: id) { other = installed }
    else {
      guard !replacement, !overlap else { throw CapacityRoleError.positionUnavailable }
      other = try CapacityMaterial(dir.appendingPathComponent("second.json"), channel: id, records: records, tunnelRole: 2, ingress: ingress[1])
    }
    guard direct || material.credentialDigest != other.credentialDigest else { throw CapacityRoleError.invalidMaterial }
    let proof = CapacityGeneration(clientKey: material.credentialDigest, serverKey: other.credentialDigest, tunnel: !direct, store: store, records: records)
    if overlap {
      guard !direct || proof.clientKey == proof.serverKey, usedKeys.isDisjoint(with: proof.keys) else { throw CapacityRoleError.invalidMaterial }
      usedKeys.formUnion(proof.keys)
    }
    let local = CapacityPeer(authority: material.authority, business: overlap), remote = CapacityPeer(authority: other.authority, business: overlap), concurrency = try exampleConcurrency(env)
    func config(_ state: CapacityPeer, _ entry: String?) -> ConnectorOptions {
      ConnectorOptions(origin: origin, connectTimeout: .milliseconds(min(o.operationTimeoutMS, 30_000)), trustRootsPEM: roots,
        rpcFrameLimits: app.frameLimits, rpcHandlers: app.handlers.bound(to: state), tunnelIngress: entry, maxConcurrentRPCRequests: concurrency)
    }
    let clientOptions = config(local, direct ? nil : ingress[0]), lease = material.lease(store, "client")
    var ends: [Int: any Session] = [:]
    let peerConnect: @Sendable () async throws -> any Session
    if direct {
      let accepted = AsyncStream<any Session>.makeStream(bufferingPolicy: .bufferingOldest(1))
      pending[id] = PendingDirect(material: other, handlers: app.handlers.bound(to: remote), store: store, accept: accepted.continuation)
      peerConnect = {
        var it = accepted.stream.makeAsyncIterator()
        guard let end = await it.next() else { throw CapacityRoleError.incomplete }; return end
      }
    } else {
      let options = config(remote, ingress[1]), lease = other.lease(store, "server")
      peerConnect = { try await connect(lease: lease, options: options) }
    }
    defer { pending.removeValue(forKey: id)?.accept.finish() }
    do {
      // Collect successful legs even when the sibling fails, so a partial handshake cannot leak a session.
      try await withThrowingTaskGroup(of: (Int, Result<any Session, Error>).self) { group in
        group.addTask { do { return (0, .success(try await connect(lease: lease, options: clientOptions))) } catch { return (0, .failure(error)) } }
        group.addTask { do { return (1, .success(try await peerConnect())) } catch { return (1, .failure(error)) } }
        var failure: Error?
        while let (side, result) = try await group.next() {
          switch result { case .success(let end): ends[side] = end
          case .failure(let error): failure = failure ?? error; group.cancelAll(); pending[id]?.accept.finish() }
        }
        if let failure { throw failure }
      }
      guard let a = ends[0], let b = ends[1] else { throw CapacityRoleError.incomplete }
      let pair = CapacityPair(id: id, generation: g, proof: proof,
        client: a, server: b, local: local, remote: remote, output: output)
      try await pair.establish(app); try Task.checkCancellation()
      if overlap { try proof.requireHeld() }
      if concurrent {
        let old = try predecessor(c, index: i); try await old.checkLive(); try old.proof.requireHeld()
        successors[i] = pair
      } else { pairs[i] = pair; retired[i] = nil }
      byID[id] = i
      await pair.watch()
      if concurrent {
        return CapacityResult(id: id, generation: g, lookupKey: proof.clientKey, legKeys: direct ? nil : proof.keys,
          admissionProfile: "flowersec/5", verifiedContractsPerEndpoint: app.checkedContractCount)
      }
      return CapacityResult(id: id, generation: g)
    } catch {
      let openingError = error
      await local.release(); await remote.release()
      var closeError: Error?
      for end in ends.values { do { try await end.close() } catch { closeError = closeError ?? error } }
      throw closeError ?? openingError
    }
  }

  private func position(_ c: CapacityCommand) throws -> (Int, CapacityPair) {
    guard let id = c.session, !closing.contains(id), let i = byID[id], c.index == nil || c.index == i, overlap || !busy.contains(i),
          let p = pairs[i]?.id == id ? pairs[i] : successors[i], p.id == id, c.generation == nil || c.generation == p.generation
    else { throw CapacityRoleError.configuration }; return (i, p)
  }

  private func predecessor(_ c: CapacityCommand, index: Int) throws -> CapacityPair {
    guard overlap, prepared, retirements == 0, retiring == nil, pairs.count == options?.sessions,
          let old = pairs[index], old.id == c.session, old.generation == 1, c.generation == nil || c.generation == 2,
          c.expectedSession == "p\(index)-g2", successors[index] == nil else { throw CapacityRoleError.positionUnavailable }
    return old
  }

  private func claim(_ index: Int) throws {
    guard claimed.count < 4, claimed.insert(index).inserted else { throw CapacityRoleError.positionUnavailable }
  }

  private func installServer(_ channel: String) throws {
    guard ingress.count == 2, let materials, let approvals, let records, installedB[channel] == nil else { throw CapacityRoleError.configuration }
    let file = materials.appendingPathComponent(channel).appendingPathComponent("second.json")
    let leg = try CapacityMaterial(file, channel: channel, records: records, tunnelRole: 2, ingress: ingress[1], overlap: overlap)
    try leg.registerServer(at: approvals); installedB[channel] = leg
  }

  private func joinTunnelReleases(_ old: Retired) async throws {
    guard let records, old.tunnelKeys.count == 2 else { throw CapacityRoleError.configuration }
    let expected = Data("flowersec/5\n".utf8)
    for key in old.tunnelKeys {
      let admitted = records.appendingPathComponent("admitted-" + key)
      guard try privateCapacityFile(admitted, maximum: 64) == expected else { throw CapacityRoleError.incomplete }
      let released = records.appendingPathComponent("released-" + key)
      while !FileManager.default.fileExists(atPath: released.path) { try await Task.sleep(for: .milliseconds(20)) }
      guard try privateCapacityFile(released, maximum: 64) == expected else { throw CapacityRoleError.incomplete }
    }
  }

  private func beginRetirement(_ old: CapacityPair, index: Int) async throws {
    guard retiring == nil, let next = successors[index], old.generation == 1, responsive.contains(next.id),
          claimed.count == 4, successors.count + retirements == 4, pairs.count == options?.sessions else { throw CapacityRoleError.configuration }
    retiring = old.id
    do {
      for claimedIndex in claimed {
        guard let pair = successors[claimedIndex] ?? pairs[claimedIndex], pair.generation == 2,
              responsive.contains(pair.id) else { throw CapacityRoleError.incomplete }
        try await pair.checkLive(); try pair.proof.requireHeld()
      }
      try await old.checkLive(); try old.proof.requireHeld(); try Task.checkCancellation()
    } catch { retiring = nil; throw error }
  }

  private func promote(after id: String, index: Int) async throws {
    guard retiring == id, let next = successors[index], pairs[index] == nil, let previous = closedOwners[id],
          previous.index == index, try previous.proof.releasedLegs() == 2 else { throw CapacityRoleError.configuration }
    try await next.checkLive(); try next.proof.requireHeld()
    pairs[index] = next; successors[index] = nil; retirements += 1; retiring = nil
  }

  private func generationState(_ c: CapacityCommand) async throws -> CapacityResult {
    guard overlap, let id = c.session else { throw CapacityRoleError.configuration }
    if let old = closedOwners[id] {
      guard c.index == nil || c.index == old.index, c.generation == nil || c.generation == old.generation else { throw CapacityRoleError.configuration }
      let released = try old.proof.releasedLegs()
      return CapacityResult(id: id, generation: old.generation, closed: true, releasedLegs: released, liveEnds: [0, 0],
        heldLegs: 2 - released, path: old.proof.tunnel ? "tunnel" : "direct")
    }
    let (_, pair) = try position(c)
    try await pair.checkLive(); try pair.proof.requireHeld()
    return CapacityResult(id: id, generation: pair.generation, closed: false, releasedLegs: 0, liveEnds: [1, 1],
      heldLegs: 2, path: pair.proof.tunnel ? "tunnel" : "direct")
  }

  func perform(_ c: CapacityCommand) async throws -> CapacityResult {
    try Task.checkCancellation()
    switch c.op {
    case "initialize": guard let o = c.options else { throw CapacityRoleError.invalidCommand }; return try await initialize(o)
    case "prepare_server":
      guard !prepared, !serverPreparationStarted, let o = options, c.count == o.sessions else { throw CapacityRoleError.configuration }
      serverPreparationStarted = true
      for index in 0..<o.sessions { try Task.checkCancellation(); try installServer("p\(index)") }
      return CapacityResult(registered: installedB.count)
    case "install_tunnel_server":
      guard !serverPreparationStarted, let index = c.index, let o = options, (0..<o.sessions).contains(index),
            pairs[index] == nil, retired[index] == nil, !busy.contains(index), !seen.contains("p\(index)") else { throw CapacityRoleError.configuration }
      try installServer("p\(index)"); return CapacityResult(id: "p\(index)", generation: 1, registered: 1)
    case "replace_tunnel_server":
      if overlap {
        guard options?.tunnelReplacement == true, !ingress.isEmpty, let i = c.index, !busy.contains(i), let next = c.expectedSession else { throw CapacityRoleError.configuration }
        let old = try predecessor(c, index: i); busy.insert(i); defer { busy.remove(i) }
        try claim(i); try await old.checkLive(); try old.proof.requireHeld()
        try installServer(next); return CapacityResult(id: next, generation: 2, registered: 1)
      }
      guard options?.tunnelReplacement == true, let index = c.index, let old = retired[index],
            let generation = c.generation, generation == old.generation + 1, old.id == c.session,
            let next = c.expectedSession, next == "p\(index)-g\(generation)", !busy.contains(index) else { throw CapacityRoleError.configuration }
      busy.insert(index); defer { busy.remove(index) }
      try await joinTunnelReleases(old)
      try installServer(next); return CapacityResult(id: next, generation: generation, registered: 1)
    case "confirm_tunnel_releases":
      if overlap {
        guard !ingress.isEmpty, let id = c.session, let old = closedOwners[id], old.index == c.index, old.generation == c.generation,
              !busy.contains(old.index) else { throw CapacityRoleError.configuration }
        busy.insert(old.index); defer { busy.remove(old.index) }
        try await old.proof.joinReleases()
        if retiring == id { try await promote(after: id, index: old.index) }
        return CapacityResult(id: id, generation: old.generation, closed: true, releasedLegs: 2)
      }
      guard options?.tunnelReplacement == true, let index = c.index, let old = retired[index], old.id == c.session,
            old.generation == c.generation, !busy.contains(index) else { throw CapacityRoleError.configuration }
      busy.insert(index); defer { busy.remove(index) }
      try await joinTunnelReleases(old)
      return CapacityResult(id: old.id, generation: old.generation, closed: true, releasedLegs: old.tunnelKeys.count)
    case "prepare":
      guard let o = options, c.count == o.sessions, !prepared, !serverPreparationStarted || installedB.count == o.sessions,
            !overlap || ingress.isEmpty || installedB.count == o.sessions else { throw CapacityRoleError.invalidCommand }
      prepared = true
    case "connect": return try await acquire(c, replacement: false)
    case "replace_direct", "replace_tunnel", "connect_successor": return try await acquire(c, replacement: true)
    case "business", "probe":
      let (i, p) = try position(c)
      guard operating.insert(p.id).inserted else { throw CapacityRoleError.positionUnavailable }
      if !overlap { busy.insert(i) }; defer { operating.remove(p.id); if !overlap { busy.remove(i) } }
      if c.op == "business" {
        guard overlap, let operation = c.operation, let bytes = c.bytes else { throw CapacityRoleError.configuration }
        return try await p.business(operation, bytes: bytes)
      }
      let reply = try await p.probe(overlap: overlap)
      if overlap, p.generation > 1 { responsive.insert(p.id) }; return reply
    case "generation_state": return try await generationState(c)
    case "check_live", "check_tunnel_id":
      guard c.op != "check_tunnel_id" || (overlap && !ingress.isEmpty && c.session != nil) else { throw CapacityRoleError.configuration }
      if c.session != nil {
        let (_, p) = try position(c); try await p.checkLive()
        if overlap { return CapacityResult(id: p.id, generation: p.generation, liveEnds: [1, 1]) }
      } else {
        let selected = liveOwners
        guard let n = c.count, n > 0, selected.count == n else { throw CapacityRoleError.incomplete }
        for p in selected { try await p.checkLive() }
        guard selected.count == byID.count, selected.allSatisfy({ byID[$0.id] != nil }) else { throw CapacityRoleError.incomplete }
      }
    case "snapshot":
      let selected = c.session == nil && c.index == nil ? liveOwners : [try position(c).1]
      var active = 0, streams = 0, residual = 0
      for p in selected { let (a, s, r) = try await p.snapshot(); active += a; streams += s; residual += r }
      return CapacityResult(activeSessions: active, activeStreams: streams, residualStreams: residual, closed: stopped)
    case "open_streams":
      guard let n = c.count, n > 0, let o = options, n == o.streamsPerSession, pairs.count == o.sessions else { throw CapacityRoleError.invalidCommand }
      let selected = liveOwners
      try await withThrowingTaskGroup(of: Void.self) { group in
        for p in selected { group.addTask { for _ in 0..<n { try await p.openStream() } } }
        try await group.waitForAll()
      }
    case "close_session":
      let (i, p) = try position(c)
      guard !operating.contains(p.id), busy.insert(i).inserted else { throw CapacityRoleError.positionUnavailable }
      closing.insert(p.id); defer { busy.remove(i); closing.remove(p.id) }
      if overlap, retirements < 4 { try await beginRetirement(p, index: i) }
      try await p.close(); pairs[i] = nil; byID[p.id] = nil
      if overlap {
        closedOwners[p.id] = (i, p.generation, p.proof)
        if !p.proof.tunnel {
          guard try p.proof.releasedLegs() == 2 else { throw CapacityRoleError.incomplete }
          if retiring == p.id { try await promote(after: p.id, index: i) }
        }
        return CapacityResult(id: p.id, generation: p.generation, closed: true, releasedLegs: p.proof.tunnel ? nil : 2)
      }
      retired[i] = Retired(id: p.id, generation: p.generation, tunnelKeys: p.tunnelKeys)
      return CapacityResult(id: p.id, generation: p.generation, closed: true)
    case "quiesce": break // CapacityCommands has canceled and joined all outstanding commands.
    case "close": try await stop(verifyReleases: overlap); return CapacityResult(closed: true)
    default: throw CapacityRoleError.invalidCommand
    }
    return CapacityResult()
  }

  func stop(verifyReleases: Bool = false) async throws {
    if stopped { return }; stopped = true
    for p in pending.values { p.accept.finish() }; pending.removeAll()
    var failure: Error?
    let remaining = liveOwners
    await withTaskGroup(of: (any Error)?.self) { group in
      for p in remaining { group.addTask { do { try await p.close(); return nil } catch { return error } } }
      for await error in group { if let error { failure = failure ?? error } }
    }
    await listener?.close()
    try await listener?.waitClosedAndCheckReleases()
    listener = nil; pairs.removeAll(); successors.removeAll(); byID.removeAll(); installedB.removeAll()
    if let failure { throw failure }
    if verifyReleases {
      for proof in remaining.map(\.proof) + closedOwners.values.map(\.proof) { try await proof.joinReleases() }
    }
  }
}
#endif
