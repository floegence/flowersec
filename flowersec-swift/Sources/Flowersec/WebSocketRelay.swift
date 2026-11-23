#if os(macOS) || os(iOS)
import Crypto
import Foundation
import NIOCore
import NIOWebSocket

/// Create this projection at the trusted issuer. It can be persisted or sent to a relay
/// without sending the invitation, its bearer token, or its endpoint session secret.
public struct RelayAdmissionRecord: Codable, Sendable {
  public let lookupKey: String
  let authorityScope: String
  let expectedPeerID: String
  let expires: UInt64
  let bindings: [String: Data]

  public init(artifact: Artifact, authorityScope: String) throws {
    let path = artifact.value.path
    guard path.kind == "tunnel", let token = path.token, let peer = path.expectedPeerEndpointInstanceID,
          AdmissionCodecV3.registryID(authorityScope, maximum: 128) else { throw ConnectError.invalidOptions }
    self.authorityScope = authorityScope
    lookupKey = Data(SHA256.hash(data: Data(token.utf8))).base64URLEncodedStringV3()
    expectedPeerID = peer
    expires = artifact.value.session.initExpireAtUnixSeconds
    bindings = try Dictionary(uniqueKeysWithValues: artifact.canonicalCandidates.map { candidate in
      (candidate.id, try AdmissionCodecV3.encodeFSB5(artifact: artifact, chosenCandidateID: candidate.id).admissionBinding)
    })
  }
}

public struct RelayAdmissionRequest: Sendable {
  public let lookupKey: String
  public let origin: String
  public let remoteAddress: String
  public let ingressEndpoint: String
}

public struct RelayAdmissionGrant: Sendable {
  let record: RelayAdmissionRecord
  let consume: @Sendable () async throws -> ConnectionLease?

  public init(record: RelayAdmissionRecord, consume: @escaping @Sendable () async throws -> Void) {
    self.record = record
    self.consume = { try await consume(); return nil }
  }

  public init(reservingFor record: RelayAdmissionRecord, acquireConnectionLease: @escaping @Sendable () async throws -> ConnectionLease) {
    self.record = record
    self.consume = acquireConnectionLease
  }
}

/// A host transaction can distinguish a confirmed replay from a generic or uncertain denial.
public enum RelayAdmissionError: Error, Sendable {
  case credentialReplay
}

public struct WebSocketRelayIngress: Sendable {
  let bindAddress: String
  let port: Int
  let endpoint: String?
  let allowedOrigins: Set<String>
  let certificate: Data
  let key: Data

  public init(bindAddress: String, port: Int, endpoint: String? = nil, allowedOrigins: Set<String>,
              certificateChainPEM: Data, privateKeyPEM: Data) {
    self.bindAddress = bindAddress; self.port = port; self.endpoint = endpoint
    self.allowedOrigins = allowedOrigins; certificate = certificateChainPEM; key = privateKeyPEM
  }
}

public final class WebSocketRelay: Sendable {
  public typealias Authorize = @Sendable (RelayAdmissionRequest) async throws -> RelayAdmissionGrant?
  /// Actual bound TCP ports in ingress configuration order.
  public let ports: [Int]
  private let servers: [any Channel]
  private let children: DirectChildrenV3

  private init(ports: [Int], servers: [any Channel], children: DirectChildrenV3) {
    self.ports = ports; self.servers = servers; self.children = children
  }

  public static func listen(ingresses: [WebSocketRelayIngress], maxConnections: Int = 4096,
                            maxPendingLegs: Int = 1024, maxActivePairs: Int = 1024,
                            admissionTimeout: Duration = .seconds(10), pairTimeout: Duration = .seconds(10),
                            authorize: @escaping Authorize) async throws -> WebSocketRelay {
    guard !ingresses.isEmpty, maxConnections >= 2, maxPendingLegs > 0, maxActivePairs > 0,
          pairTimeout > .zero, pairTimeout <= .seconds(3600) else { throw ConnectError.invalidOptions }
    let children = DirectChildrenV3(maximum: maxConnections)
    let pairs = WebSocketRelayPairs(maxPending: maxPendingLegs, maxActive: maxActivePairs, timeout: pairTimeout)
    var servers: [any Channel] = [], ports: [Int] = []
    do {
      for ingress in ingresses {
        try Task.checkCancellation()
        let server = try await BoundWebSocketIngressV3.bind(kind: "tunnel", bindAddress: ingress.bindAddress,
          port: ingress.port, endpoint: ingress.endpoint, allowedOrigins: ingress.allowedOrigins,
          certificateChainPEM: ingress.certificate, privateKeyPEM: ingress.key, admissionTimeout: admissionTimeout,
          children: children) { leg in try await serve(leg, authorize: authorize, pairs: pairs) }
        servers.append(server)
        guard let port = server.localAddress?.port else { throw ConnectError.connectionFailed }
        ports.append(port)
      }
      try Task.checkCancellation()
      return WebSocketRelay(ports: ports, servers: servers, children: children)
    } catch {
      let drain = children.shutdown()
      for server in servers { try? await server.close().get() }
      await drain.value
      throw error
    }
  }

  public func close() async {
    let drain = children.shutdown()
    for server in servers { server.close(promise: nil) }
    for server in servers { try? await server.closeFuture.get() }
    await drain.value
  }

  public func waitClosedAndCheckReleases() async throws {
    for server in servers { try? await server.closeFuture.get() }
    await children.shutdown().value
    try children.checkReleases()
  }

  private static func serve(_ leg: BoundWebSocketLegV3, authorize: Authorize, pairs: WebSocketRelayPairs) async throws {
    let transport = NIOWebSocketBinaryTransportV3(socket: leg.socket)
    let admission = try AdmissionCodecV3.decodeFSB5(try await transport.readBinary())
    var lease: ConnectionLease?
    var group: RelayPairGroup?
    do {
      try Task.checkCancellation()
      guard let claim = admission.tunnel, claim.candidate.carrier == "websocket", claim.candidate.normalizedURL == leg.endpoint,
            ContinuousClock.now < leg.deadline else { throw RelayRejection.invalid }
      try checkIngress(claim, leg)
      let request = RelayAdmissionRequest(lookupKey: claim.lookupKey, origin: leg.origin, remoteAddress: leg.address, ingressEndpoint: leg.endpoint)
      guard let grant = try await authorize(request) else { throw RelayRejection.invalid }
      let record = grant.record
      guard record.lookupKey == claim.lookupKey, record.bindings[admission.chosenCandidateID] == admission.admissionBinding,
            AdmissionCodecV3.registryID(record.authorityScope, maximum: 128), AdmissionCodecV3.registryID(record.expectedPeerID, maximum: 128),
            record.expectedPeerID != claim.localID else { throw RelayRejection.invalid }
      let participant = RelayParticipant(leg: leg, transport: transport, claim: claim, record: record, channelID: admission.channelID)
      try participant.checkAdmission()
      lease = try await grant.consume()
      let registered = try await pairs.join(participant)
      group = registered
      await withTaskCancellationHandler {
        try? await registered.done.futureResult.get()
      } onCancel: { Task { await pairs.legStopped(registered) } }
    } catch {
      let reason = error is RelayAdmissionError ? RelayRejection.replay : ((error as? RelayRejection) ?? .invalid)
      if !Task.isCancelled { try? await transport.writeBinary(reason.response) }
    }
    leg.channel.close(promise: nil)
    try? await leg.channel.closeFuture.get()
    let released = await Task { try await lease?.finish() }.result
    if let group { await pairs.released(group) }
    try released.get()
  }

  fileprivate static func checkIngress(_ claim: TunnelAdmissionV3, _ leg: BoundWebSocketLegV3) throws {
    let now = UInt64(max(0, Date().timeIntervalSince1970))
    try BoundWebSocketIngressV3.verify(claim.candidate, endpoint: leg.endpoint, leaf: leg.leaf, now: now)
  }
}

private enum RelayRejection: String, Error {
  case invalid = "invalid_credential", expired = "expired_artifact", timeout = "pair_timeout", mismatch = "pair_mismatch", replay = "credential_replay", capacity
  var response: Data {
    let reason = Data(rawValue.utf8)
    return Data("FSA5".utf8) + Data([5, self == .expired || self == .timeout || self == .capacity ? 2 : 1, 0, UInt8(reason.count)]) + reason
  }
}

private struct RelayPairKey: Hashable {
  let scope: String, audience: String, group: String, channel: String, contract: String
}

private struct RelayParticipant: Sendable {
  let leg: BoundWebSocketLegV3
  let transport: NIOWebSocketBinaryTransportV3
  let claim: TunnelAdmissionV3
  let record: RelayAdmissionRecord
  let channelID: String
  var key: RelayPairKey { .init(scope: record.authorityScope, audience: claim.audience, group: claim.group, channel: channelID, contract: claim.contract) }

  var admissionDeadline: ContinuousClock.Instant {
    let expiresIn = max(0, Double(record.expires) - Date().timeIntervalSince1970)
    return min(.now.advanced(by: .seconds(min(3600, expiresIn))), leg.deadline)
  }

  func checkAdmission() throws {
    try Task.checkCancellation()
    guard leg.channel.isActive, ContinuousClock.now < leg.deadline else { throw RelayRejection.timeout }
    guard Double(record.expires) > Date().timeIntervalSince1970 else { throw RelayRejection.expired }
    try WebSocketRelay.checkIngress(claim, leg)
  }
}

private final class RelayPairGroup: @unchecked Sendable {
  let first: RelayParticipant
  let done: EventLoopPromise<Void>
  var deadline: ContinuousClock.Instant
  var second: RelayParticipant?
  var work: Task<Void, Never>?
  var timer: Task<Void, Never>?
  var closing = false
  var remaining = 1

  init(_ first: RelayParticipant, deadline: ContinuousClock.Instant) {
    self.first = first; self.deadline = deadline; done = first.leg.channel.eventLoop.makePromise(of: Void.self)
  }
}

private actor WebSocketRelayPairs {
  let maxPending: Int, maxActive: Int, timeout: Duration
  var pending = 0, active = 0
  var groups: [RelayPairKey: RelayPairGroup] = [:]

  init(maxPending: Int, maxActive: Int, timeout: Duration) {
    self.maxPending = maxPending; self.maxActive = maxActive; self.timeout = timeout
  }

  func join(_ participant: RelayParticipant) throws -> RelayPairGroup {
    try participant.checkAdmission()
    let key = participant.key
    if let group = groups[key] {
      let first = group.first
      guard !group.closing, group.second == nil, first.claim.role != participant.claim.role,
            first.claim.localID == participant.record.expectedPeerID, participant.claim.localID == first.record.expectedPeerID
      else { throw RelayRejection.mismatch }
      try first.checkAdmission()
      guard .now < group.deadline else { throw RelayRejection.timeout }
      guard active < maxActive else { rejectPending(group, reason: .capacity); throw RelayRejection.capacity }
      pending -= 1; active += 1; group.second = participant; group.remaining = 2
      if participant.admissionDeadline < group.deadline {
        group.deadline = participant.admissionDeadline
        armTimer(group)
      }
      group.work = Task {
        do {
          try first.checkAdmission(); try participant.checkAdmission()
          guard .now < group.deadline else { throw RelayRejection.timeout }
          let success = Data("FSA5".utf8) + Data([5, 0, 0, 0])
          async let left: Void = first.transport.writeBinary(success)
          async let right: Void = participant.transport.writeBinary(success)
          _ = try await (left, right)
          try Task.checkCancellation()
          guard .now < group.deadline else { throw RelayRejection.timeout }
          group.timer?.cancel(); first.leg.established(); participant.leg.established()
          await Self.forward(first, participant)
        } catch { }
        group.closing = true
        first.leg.channel.close(promise: nil); participant.leg.channel.close(promise: nil)
        group.done.succeed(())
      }
      return group
    }
    guard pending < maxPending else { throw RelayRejection.capacity }
    let group = RelayPairGroup(participant, deadline: min(.now.advanced(by: timeout), participant.admissionDeadline))
    groups[key] = group; pending += 1
    armTimer(group)
    return group
  }

  private func armTimer(_ group: RelayPairGroup) {
    group.timer?.cancel()
    let participant = group.first, deadline = group.deadline
    group.timer = Task {
      do { try await Task.sleep(until: deadline, clock: .continuous) } catch { return }
      guard !Task.isCancelled, !group.closing else { return }
      if group.second == nil {
        let reason: RelayRejection = Double(participant.record.expires) <= Date().timeIntervalSince1970 ? .expired : .timeout
        rejectPending(group, reason: reason)
      } else { stop(group) }
    }
  }

  private func rejectPending(_ group: RelayPairGroup, reason: RelayRejection) {
    group.closing = true; group.timer?.cancel()
    group.work = Task {
      try? await group.first.transport.writeBinary(reason.response)
      group.first.leg.channel.close(promise: nil); group.done.succeed(())
    }
  }

  func stop(_ group: RelayPairGroup) {
    guard !group.closing else { return }
    group.closing = true
    group.timer?.cancel(); group.work?.cancel()
    group.first.leg.channel.close(promise: nil); group.second?.leg.channel.close(promise: nil)
    if group.second == nil { group.done.succeed(()) }
  }

  func legStopped(_ group: RelayPairGroup) {
    if group.second == nil { stop(group) }
  }

  func released(_ group: RelayPairGroup) {
    group.remaining -= 1
    guard group.remaining == 0 else { return }
    group.timer?.cancel(); group.timer = nil; group.work = nil
    groups.removeValue(forKey: group.first.key)
    if group.second == nil { pending -= 1 } else { active -= 1 }
  }

  private static func forward(_ first: RelayParticipant, _ second: RelayParticipant) async {
    let client = first.claim.role == 1 ? first : second
    let server = first.claim.role == 2 ? first : second
    let closeOrder = RelayFINOrderV3()
    func copy(_ source: RelayParticipant, to target: RelayParticipant) async throws {
      var framing = RelayControlFINV3()
      while true {
        let bytes = try await source.transport.readBinary()
        let fin = try framing.consume(bytes)
        if fin { try await closeOrder.observe(server: source.claim.role == 2) }
        try await target.transport.writeBinary(bytes)
        if fin { return }
      }
    }
    await withThrowingTaskGroup(of: Void.self) { copies in
      copies.addTask { try await copy(client, to: server) }
      copies.addTask { try await copy(server, to: client) }
      do {
        _ = try await copies.next()
        let timer = server.leg.channel.eventLoop.scheduleTask(in: .seconds(2)) {
          client.leg.channel.close(promise: nil); server.leg.channel.close(promise: nil)
        }
        defer { timer.cancel() }
        _ = try await copies.next()
        try await client.transport.sendSessionClose()
        await client.transport.close()
        try await server.leg.channel.closeFuture.get()
      } catch {
        copies.cancelAll()
        client.leg.channel.close(promise: nil); server.leg.channel.close(promise: nil)
      }
    }
  }
}

private actor RelayFINOrderV3 {
  private var serverFIN = false

  func observe(server: Bool) throws {
    if server { serverFIN = true }
    else if !serverFIN { throw TransportV3CarrierError.streamReset }
  }
}

private struct RelayControlFINV3 {
  private var header = Data()
  private var remaining = 0
  private var finAtEnd = false

  mutating func consume(_ bytes: Data) throws -> Bool {
    var offset = bytes.startIndex
    var fin = false
    while offset < bytes.endIndex {
      if remaining == 0 {
        let count = min(FlowersecYamuxConstants.headerSize - header.count, bytes.endIndex - offset)
        header.append(bytes[offset..<(offset + count)])
        offset += count
        if header.count < FlowersecYamuxConstants.headerSize { break }
        let frame = try FlowersecYamuxFrame(header: header)
        header.removeAll(keepingCapacity: true)
        let data = frame.type == FlowersecYamuxConstants.typeData
        if data, frame.length > FlowersecSDKDefaults.Yamux.maxFrameBytes { throw TransportV3CarrierError.streamReset }
        remaining = data ? Int(frame.length) : 0
        let control = frame.streamID == 1 && (data || frame.type == FlowersecYamuxConstants.typeWindowUpdate)
        if control, frame.flags & ~(FlowersecYamuxConstants.flagSYN | FlowersecYamuxConstants.flagACK | FlowersecYamuxConstants.flagFIN) != 0 || (fin && (data || frame.flags != 0)) {
          throw TransportV3CarrierError.streamReset
        }
        finAtEnd = control && frame.flags & FlowersecYamuxConstants.flagFIN != 0
      }
      let count = min(remaining, bytes.endIndex - offset)
      offset += count
      remaining -= count
      if remaining == 0, finAtEnd { fin = true }
    }
    return fin
  }
}

/// Enforce the pre-admission message boundary on the event loop, including fragments
/// already in a TCP read. Ping and close remain local to this WSS connection.
final class RelayAdmissionFrameGate: ChannelDuplexHandler, @unchecked Sendable {
  typealias InboundIn = WebSocketFrame
  typealias OutboundIn = WebSocketFrame
  typealias OutboundOut = WebSocketFrame
  private var remaining = 32_768 + 12
  private var waiting = false
  private var admitted = false
  private var invalid = false

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    guard !invalid else { return }
    switch frame.opcode {
    case .ping:
      context.writeAndFlush(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)), promise: nil)
    case .pong: break
    case .connectionClose: invalid = true; context.close(promise: nil)
    case .binary, .continuation:
      if !admitted {
        guard !waiting, frame.data.readableBytes <= remaining else { invalid = true; context.close(promise: nil); return }
        remaining -= frame.data.readableBytes
        if frame.fin { waiting = true }
      }
      context.fireChannelRead(data)
    default: invalid = true; context.close(promise: nil)
    }
  }

  func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
    guard !invalid else { promise?.fail(TransportV3CarrierError.closed); return }
    let frame = unwrapOutboundIn(data)
    if waiting, !admitted, frame.opcode == .binary, frame.data.readableBytesView.elementsEqual([70, 83, 65, 53, 5, 0, 0, 0]) {
      admitted = true
    }
    context.write(data, promise: promise)
  }
}
#endif
