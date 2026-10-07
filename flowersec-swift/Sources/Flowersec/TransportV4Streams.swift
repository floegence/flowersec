import Foundation

// Handles identify their original Session; no caller can construct a frontier,
// acceptance, drain proof, or retirement capability through this API.
struct V4StreamHandle: Sendable {
  fileprivate let owner: V4ReliableSession
  fileprivate let view: V4StreamView
  let number: UInt64
}
private final class V4StreamView: @unchecked Sendable {
  var end: UInt8 = 0
  var sendEnd: UInt8 = 0
  var finSubmitted = false
  var applicationUsed = false
  var bridge: V4DuplexBridgeToken?
}
enum V4StreamRejection: UInt64, Sendable {
  case resource = 1
  case metadata, kind, application, draining
}
enum V4StreamDecision: Equatable, Sendable {
  case accept(receiveWindow: UInt64)
  case reject(V4StreamRejection)
}
enum V4StreamRead {
  case data(V4CryptoBuffer)
  case pending, eof, aborted
}
enum V4StreamPhase: Sendable { case opening, pending, accepted, recent, stable }

struct V4StreamTuple: Equatable, Sendable {
  let epoch: UInt32
  let next: UInt64
  let offset: UInt64
  func precedes(_ other: Self) -> Bool {
    epoch == other.epoch && next <= other.next && offset <= other.offset
  }
  var encoded: Data {
    V4Crypto.map([(0, u(UInt64(epoch))), (1, u(next)), (2, u(offset))])
  }
  init(epoch: UInt32 = 0, next: UInt64 = 0, offset: UInt64 = 0) {
    self.epoch = epoch
    self.next = next
    self.offset = offset
  }
  init(_ value: V4NamespaceValue) throws {
    epoch = try UInt32(value.u("epoch"))
    next = try value.u("next_sequence")
    offset = try value.u("offset")
  }
}
private func u(_ value: UInt64) -> Data { V4NamespaceValue.head(0, value) }

// A fixed, charged ring backs every published receive window. Reading releases
// logical promise; growing allocates replacement storage before publishing CREDIT.
private final class V4StreamRing {
  private var bytes: [UInt8]
  private var head = 0
  private(set) var count = 0
  var capacity: Int { bytes.count }
  init(capacity: Int) { bytes = [UInt8](repeating: 0, count: capacity) }
  func append(_ input: Data) throws {
    guard input.count <= capacity - count else { throw V4CryptoFailure.capacity }
    for byte in input {
      bytes[(head + count) % capacity] = byte
      count += 1
    }
  }
  func copyPrefix(_ maximum: Int) -> Data {
    var result = Data(count: min(maximum, count))
    for i in result.indices { result[i] = bytes[(head + i) % capacity] }
    return result
  }
  func consume(_ amount: Int) {
    for _ in 0..<amount {
      bytes[head] = 0
      head = (head + 1) % capacity
      count -= 1
    }
  }
  func grow(_ capacity: Int) throws {
    guard capacity > self.capacity else { return }
    var next = [UInt8](repeating: 0, count: capacity)
    for i in 0..<count { next[i] = bytes[(head + i) % bytes.count] }
    _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    bytes = next
    head = 0
  }
  deinit { _ = bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
}

final class V4ReliableSession: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
  private struct Proof: Equatable {
    let terminal: V4StreamTuple
    let observed: V4StreamTuple
    let aborted: Bool
  }
  private final class Direction {
    var current = V4StreamTuple()
    var last = V4StreamTuple()
    var terminal: V4StreamTuple?
    var proof: Proof?
    var limit: UInt64 = 0
    var committed: UInt64 = 0
    var released: UInt64 = 0
    var ack: UInt64 = 0
    var stop = false
    var fin = false
    var finRequested = false
    var stopSent = false
    var stoppedRequested = false
    var stoppedSent = false
    var drainSent = false
    var disabled = false
    var begun: V4ClockMark?
    var quarantined: V4ClockMark?
    var complete: Bool { terminal != nil && proof != nil }
  }
  private enum Kind: Int { case business, rpc, notify, management }
  private enum Token { case none, positive, rejection }
  private final class Slot {
    let scope: V4RecordScope
    let opener: V4CryptoRole
    let kind: String
    let streamClass: Kind
    let view = V4StreamView()
    let directions = [Direction(), Direction()]
    let opened: V4ClockMark
    var metadata: Data
    var ring = V4StreamRing(capacity: 0)
    var phase: V4StreamPhase
    var token: Token = .none
    var claimed = false
    var bootstrap = false
    var prefix = false
    var canceled = false
    var forced: V4StreamRejection?
    var openEpoch: UInt32 = 0
    var digest = Data()
    var outcome: V4StreamDecision?
    var creditDirty = false
    var recentAt: V4ClockMark?
    var batchRefs = 0
    var barrierRefs = 0
    var unpublished = 0
    var keysRetired = false
    init(
      scope: V4RecordScope, opener: V4CryptoRole, kind: String, streamClass: Kind,
      metadata: Data, phase: V4StreamPhase, opened: V4ClockMark
    ) {
      self.scope = scope
      self.opener = opener
      self.kind = kind
      self.streamClass = streamClass
      self.metadata = metadata
      self.phase = phase
      self.opened = opened
    }
  }
  private struct Batch {
    let sequence: UInt64
    let digest: Data
    let ids: [UInt64]
    let started: V4ClockMark
  }
  private let access: V4ReliableSessionAdmission
  private let storage: V4CryptoReservation
  private let registry: V4NamespaceRegistry
  private let maxTokens: Int
  private let maxSlots: Int
  private var slots: [Slot] = []
  private var lifetime = [[UInt64](repeating: 0, count: 3), [UInt64](repeating: 0, count: 3)]
  private var ordinal: UInt64 = 1
  private var promised: UInt64 = 0
  private var backing = 0
  private var metadataBytes = 0
  private var outgoing: Batch?
  private var incoming: Batch?
  private var lastOut: UInt64 = 0
  private var lastOutDigest = Data()
  private var lastIn: UInt64 = 0
  private var lastInDigest = Data()
  private var repeatACK = false
  private var draining = false
  private var acceptedPeerCeiling: UInt64 = 0
  private var localGoAway: UInt64?
  private var goAwaySent = false
  var observationDraining: Bool { access.environment.gate.withLock { draining } }
  private var busy = false
  private var closed = false
  private var rekey: V4RekeyCoordinator?
  private var pendingPong: Data?
  private let liveness: V4LivenessState
  private var authenticatedInput: (@Sendable () throws -> Void)?
  func observeAuthenticatedInput(_ action: (@Sendable () throws -> Void)?) {
    access.environment.gate.withLock { authenticatedInput = action }
  }
  private var peerCeiling: UInt64?
  private var peerGoAwayReason: UInt64?
  private var me: Int { Int(access.role.rawValue) }
  private var peer: Int { 1 - me }
  private var clock: V4TrustedClock { access.environment.clock }
  var description: String { "Flowersec.ReliableSession(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }

  init(_ admission: V4ReliableSessionAdmission) throws {
    try admission.claim()
    access = admission
    maxTokens = min(2 * admission.maxStreams + 128, 4096)
    maxSlots = maxTokens + 128
    storage =
      try admission.streamStorage
      ?? admission.environment.reliableSessionStorage(
        maxCredit: admission.maxCredit, slots: maxSlots)
    liveness = try V4LivenessState(
      clock: admission.environment.clock, storage: storage,
      policy: admission.environment.automaticLiveness)
    registry = try V4NamespaceRegistry()
    slots.reserveCapacity(maxSlots)
    if admission.applicationProfile != 0 {
      guard admission.maxStreams >= 1, admission.maxCredit >= 16_384 else {
        throw V4CryptoFailure.capacity
      }
      let s = Slot(
        scope: try admission.channel.admitReliableScope(1, access: access), opener: .client,
        kind: "flowersec.rpc.v4", streamClass: .rpc, metadata: Data(), phase: .accepted,
        opened: try clock.mark())
      s.bootstrap = true
      s.token = .positive
      try growWindow(s, limit: 16_384)
      s.directions[peer].committed = 16_384
      s.directions[me].limit = 16_384
      s.directions[me].committed = 16_384
      slots.append(s)
      if admission.role == .server { acceptedPeerCeiling = 1 }
      lifetime[0][1] = 1
      if admission.role == .client { ordinal = 2 }
    }
    rekey = try V4RekeyCoordinator(access, registry: registry, liveness: liveness)
    try check()
  }
  private func check() throws {
    guard !closed else { throw V4CryptoFailure.closed }
    try storage.check()
    try access.channel.checkSession(access)
    try rekey?.check()
    try liveness.check()
  }
  private func run<T>(_ body: () throws -> T) throws -> T {
    try access.environment.gate.withLock {
      guard !busy else { throw V4CryptoFailure.phase }
      busy = true
      defer { busy = false }
      do {
        try check()
        try deadlines()
      } catch {
        if let time = error as? V4TimeFailure, time != .expired, time != .canceled {
          liveness.clockUnavailable()
        }
        close()
        throw error
      }
      do { return try body() } catch {
        if error is V4ResourceFailure || error as? V4CryptoFailure == .capacity {
          liveness.localStall()
        }
        throw error
      }
    }
  }
  private func elapsed(_ start: V4ClockMark) throws -> UInt64 {
    let now = try clock.mark()
    guard now.sameEra(as: start), now.milliseconds >= start.milliseconds else {
      throw V4TimeFailure.continuity
    }
    return try clock.profile.elapsed(now.milliseconds - start.milliseconds).upperMS
  }
  private func find(_ number: UInt64) -> Slot? { slots.first { $0.scope.number == number } }
  private func resolve(_ handle: V4StreamHandle) throws -> Slot {
    guard handle.owner === self, let slot = find(handle.number), slot.view === handle.view else {
      throw V4CryptoFailure.phase
    }
    return slot
  }
  private func handle(_ s: Slot) -> V4StreamHandle {
    V4StreamHandle(owner: self, view: s.view, number: s.scope.number)
  }
  func internalCleanupComplete(_ stream: V4StreamHandle) -> Bool {
    access.environment.gate.withLock {
      guard stream.owner === self else { return false }
      return find(stream.number) == nil || closed
    }
  }
  func sameEndpoint(_ a: V4StreamHandle, _ b: V4StreamHandle) -> Bool {
    a.owner === b.owner && a.number == b.number && a.view === b.view
  }
  func checkBridgeCandidate(_ stream: V4StreamHandle) throws {
    try run {
      let slot = try resolve(stream)
      guard slot.phase == .accepted, slot.streamClass == .business,
        !slot.canceled, !slot.bootstrap, !slot.view.applicationUsed, slot.view.bridge == nil,
        slot.directions.allSatisfy({ !$0.stop && $0.terminal == nil })
      else { throw DuplexBridgeFailure.streamOwned }
    }
  }
  func claimBridge(_ stream: V4StreamHandle, token: V4DuplexBridgeToken) throws {
    try checkBridgeCandidate(stream)
    stream.view.bridge = token
  }
  func rollbackBridge(_ stream: V4StreamHandle, token: V4DuplexBridgeToken) {
    access.environment.gate.withLock {
      if stream.owner === self, stream.view.bridge === token { stream.view.bridge = nil }
    }
  }
  func checkApplicationOwner(_ stream: V4StreamHandle, bridge: V4DuplexBridgeToken? = nil) throws {
    try access.environment.gate.withLock {
      guard stream.owner === self else { throw SessionError.closed }
      if let bridge {
        guard stream.view.bridge === bridge else { throw SessionError.closed }
      } else {
        guard stream.view.bridge == nil else { throw SessionError.closed }
        stream.view.applicationUsed = true
      }
    }
  }
  func canDispose(_ stream: V4StreamHandle, bridge: V4DuplexBridgeToken?) -> Bool {
    access.environment.gate.withLock {
      guard stream.owner === self else { return false }
      if let bridge { return stream.view.bridge === bridge }
      return stream.view.bridge == nil
    }
  }
  func bridgeCleanupComplete(_ stream: V4StreamHandle, token: V4DuplexBridgeToken) -> Bool {
    access.environment.gate.withLock {
      guard stream.owner === self, stream.view.bridge === token else { return false }
      // Stream retirement remains owned by the original Session. The bridge
      // cannot report its physical backing released before that owner does.
      return find(stream.number) == nil || closed
    }
  }
  static func valid(_ number: UInt64) -> Bool {
    number > 0 && number <= 4_194_335 && (number & 1 != 0 || number / 2 <= 2_097_152)
  }
  private func classify(_ kind: String, opener: V4CryptoRole) throws -> Kind {
    guard (1...128).contains(kind.utf8.count) else { throw V4CryptoFailure.configuration }
    switch kind {
    case "flowersec.rpc.v4": return .rpc
    case "flowersec.notify.v4": return .notify
    case "flowersec.execution-management.v4":
      guard opener == .client else { throw V4CryptoFailure.configuration }
      return .management
    default:
      guard !kind.hasPrefix("flowersec."), !kind.hasPrefix("flowersec/") else {
        throw V4CryptoFailure.configuration
      }
      return .business
    }
  }
  private func room(_ kind: Kind, opener: V4CryptoRole) -> Bool {
    let active = slots.filter { [.opening, .accepted].contains($0.phase) }
    guard active.count < access.maxStreams else { return false }
    // Retired RPC scopes retain the opener quota through quarantine and
    // actual native cleanup. Logical close cannot manufacture a free carrier.
    let counted = kind == .rpc ? slots : active
    let count = counted.filter {
      $0.streamClass == kind && (kind == .business || $0.opener == opener)
    }.count
    return count < (kind == .business ? 1024 : kind == .rpc ? 4 : 1)
  }
  private func countLifetime(_ kind: Kind, opener: V4CryptoRole) throws {
    let group = kind == .business ? 0 : kind == .management ? 2 : 1
    let cap: UInt64 = group == 2 ? 16 : 1 << 20
    let role = Int(opener.rawValue)
    guard lifetime[role][group] < cap else { throw V4CryptoFailure.capacity }
    lifetime[role][group] += 1
  }
  private func takeToken(reject: Bool) throws -> Token {
    if slots.filter({ $0.token == .positive }).count < maxTokens { return .positive }
    if reject, slots.filter({ $0.token == .rejection }).count < 128 { return .rejection }
    throw V4CryptoFailure.capacity
  }
  private func growWindow(_ s: Slot, limit: UInt64) throws {
    let d = s.directions[peer]
    guard limit >= d.limit, limit >= d.released else { throw V4CryptoFailure.phase }
    let delta = limit - d.limit
    let required = limit - d.released
    guard delta <= access.maxCredit - promised, required <= access.maxCredit else {
      throw V4CryptoFailure.capacity
    }
    let growth = max(0, Int(required) - s.ring.capacity)
    guard growth <= Int(access.maxCredit) - backing else { throw V4CryptoFailure.capacity }
    try s.ring.grow(Int(required))
    promised += delta
    backing += growth
    d.limit = limit
  }
  private func releaseQueue(_ s: Slot) {
    let count = s.ring.count
    s.ring.consume(count)
    s.directions[peer].released += UInt64(count)
    promised -= UInt64(count)
  }
  private func trimPromise(_ s: Slot, limit: UInt64) throws {
    let d = s.directions[peer]
    guard limit >= d.current.offset, limit >= d.released, limit <= d.limit else {
      throw V4CryptoFailure.authentication
    }
    promised -= d.limit - limit
    d.limit = limit
  }
  private func discardBacking(_ s: Slot) {
    guard s.ring.count == 0 else { return }
    backing -= s.ring.capacity
    s.ring = V4StreamRing(capacity: 0)
  }
  private func decode(_ bytes: Data, _ schema: String) throws -> V4NamespaceValue {
    try V4NamespaceDocument(
      bytes, schema: schema, bytes: access.maxFrame, nodes: 4096,
      registry: registry, limits: ["max_data_payload_bytes": UInt64(access.maxFrame - 36)]
    ).root
  }
  private func validateMetadata(_ bytes: Data) throws {
    guard bytes.count <= 4096 else { throw V4CryptoFailure.capacity }
    if !bytes.isEmpty {
      do { _ = try decode(bytes, "TypedMessageMetadata") }
      catch { _ = try decode(bytes, "StreamMetadata") }
    }
  }
  private func send(
    _ scope: V4RecordScope, type: UInt8, body: Data,
    to publisher: any V4RecordPublisher, publication: (any V4RecordPublication)? = nil,
    accepted: (@Sendable () -> Void)? = nil
  ) throws {
    do {
      if type != 14 { liveness.localStall() }
      try access.channel.publish(
        scope: scope, frameType: type, plaintext: body,
        to: publisher, access: access,
        critical: type == 9
          && (body.first == 0xa8 || body.first == 0xac
            || (body.count > 2 && (2...6).contains(body[body.startIndex + 2]))),
        publication: publication, accepted: accepted
      )
      try check()
    } catch {
      close()
      throw error
    }
  }
  private func control(
    _ variant: UInt64, _ s: Slot, _ direction: Int,
    _ extra: [(UInt64, Data)] = []
  ) -> Data {
    V4Crypto.map([(0, u(variant)), (1, u(s.scope.number)), (2, u(UInt64(direction)))] + extra)
  }
  private func sendControl(_ body: Data, to publisher: any V4RecordPublisher) throws {
    try send(access.channel.maintenance, type: 9, body: body, to: publisher)
  }
  private func openBody(_ s: Slot, window: UInt64) throws -> Data {
    let frontier = try access.channel.frontier(s.scope, sending: true, access: access)
    guard frontier.next == 0 else { throw V4CryptoFailure.sequence }
    s.openEpoch = frontier.epoch
    var fields: [(UInt64, Data)] = [
      (0, u(s.scope.number)), (1, u(UInt64(s.opener.rawValue))),
      (2, u(s.scope.number)), (3, u(UInt64(frontier.epoch))), (4, u(0)),
      (5, V4Crypto.text(s.kind)), (6, V4Crypto.bytes(s.metadata)), (7, u(window)),
    ]
    s.digest = V4Crypto.hash(V4Crypto.domain("open", [V4Crypto.map(fields)]))
    fields.append((8, V4Crypto.bytes(s.digest)))
    return V4Crypto.map(fields)
  }
  func open(
    kind: String, metadata: Data = Data(), receiveWindow: UInt64,
    to publisher: any V4RecordPublisher, service: Bool = false
  ) throws -> V4StreamHandle {
    try run {
      let streamClass = try classify(kind, opener: access.role)
      guard streamClass == .business || service && access.applicationProfile != 0
        && (streamClass != .management || access.applicationProfile == 2),
        streamClass == .business || metadata.isEmpty,
        streamClass == .business || receiveWindow == 16_384 else { throw V4CryptoFailure.configuration }
      guard !draining else { throw SessionError.goingAway }
      guard !draining, rekey?.frozen != true,
        room(streamClass, opener: access.role), slots.count < maxSlots,
        slots.filter({ $0.phase == .opening }).count < 128
      else { throw V4CryptoFailure.capacity }
      try validateMetadata(metadata)
      // Client business admission wins simultaneous capacity pressure.
      guard
        access.role != .server
          || !slots.contains(where: {
            $0.phase == .pending && $0.opener == .client && $0.streamClass == .business
          })
      else { throw V4CryptoFailure.capacity }
      let id = ordinal * 2 - (access.role == .client ? 1 : 0)
      guard peerCeiling == nil || id <= peerCeiling! else { throw SessionError.goingAway }
      guard Self.valid(id) else { throw V4CryptoFailure.capacity }
      // The original session allocator owns the management lifetime quota and
      // burns the client ordinal before ticket/scope admission. Refused,
      // pre-ticket, and failed OPEN attempts therefore consume the same finite
      // 16-entry lifetime as successful channels.
      if streamClass == .management {
        try countLifetime(streamClass, opener: access.role)
        ordinal += 1
      }
      let token = try takeToken(reject: false)
      guard receiveWindow <= access.maxCredit - promised else { throw V4CryptoFailure.capacity }
      // All fallible local validation precedes irreversible scope admission.
      let scope = try access.channel.admitReliableScope(id, access: access)
      do {
        let s = Slot(
          scope: scope, opener: access.role, kind: kind, streamClass: streamClass,
          metadata: metadata, phase: .opening, opened: try clock.mark())
        s.token = token
        try growWindow(s, limit: receiveWindow)
        let body = try openBody(s, window: receiveWindow)
        guard body.count + 36 <= access.maxFrame else { throw V4CryptoFailure.capacity }
        s.prefix = true
        s.directions[peer].current = V4StreamTuple(epoch: s.openEpoch)
        s.directions[peer].last = s.directions[peer].current
        s.directions[me].current = V4StreamTuple(epoch: s.openEpoch, next: 1)
        s.directions[me].last = s.directions[me].current
        if streamClass != .management {
          try countLifetime(streamClass, opener: access.role)
          ordinal += 1
        }
        slots.append(s)
        try send(scope, type: 7, body: body, to: publisher)
        s.directions[peer].committed = receiveWindow
        s.metadata = Data()
        return handle(s)
      } catch {
        close()
        throw error
      }
    }
  }
  func materializeBootstrap(to publisher: any V4RecordPublisher) throws -> V4StreamHandle {
    try run {
      guard rekey?.frozen != true, access.role == .client, let s = find(1), s.bootstrap, !s.prefix,
        s.directions.allSatisfy({ $0.terminal == nil })
      else { throw V4CryptoFailure.phase }
      let body = try openBody(s, window: 16_384)
      s.prefix = true
      s.directions[0].current = V4StreamTuple(epoch: s.openEpoch, next: 1)
      try send(s.scope, type: 7, body: body, to: publisher)
      return handle(s)
    }
  }
  var bootstrapMaterialized: Bool { find(1)?.prefix == true }
  func bootstrapStream() throws -> V4StreamHandle? {
    try run { find(1).flatMap { $0.bootstrap ? handle($0) : nil } }
  }
  func checkResumeIssuance() throws {
    try run {
      guard access.features & 2 != 0, access.applicationProfile == 2 else { throw V4CryptoFailure.phase }
    }
  }
  func resumeStreamFacts(_ stream: V4StreamHandle, capture: Bool = true) throws -> (Data, UInt64) {
    try run {
      let slot = try resolve(stream)
      guard access.features & 2 != 0, access.applicationProfile == 2, slot.streamClass == .business,
        slot.phase == .accepted, !slot.canceled, !slot.bootstrap, slot.view.bridge == nil,
        !capture || (slot.ring.count == 0 && slot.directions.allSatisfy({ $0.current.offset == 0 && $0.terminal == nil && !$0.stop })) else { throw V4CryptoFailure.phase }
      return (access.context, slot.scope.number)
    }
  }
  func pendingOpen(service: Bool = false, kinds: Set<String>? = nil, excluding: Set<String> = []) throws -> V4StreamHandle? {
    try run {
      let epoch = try access.channel.rekeyState(access).epoch
      guard
        let s = slots.first(where: {
          $0.phase == .pending && !$0.claimed && $0.forced == nil && $0.openEpoch <= epoch
            && (service ? $0.streamClass != .business : $0.streamClass == .business)
            && (kinds == nil || kinds!.contains($0.kind)) && !excluding.contains($0.kind)
        })
      else {
        return nil
      }
      if s.token == .none { s.token = try takeToken(reject: false) }
      s.claimed = true
      return handle(s)
    }
  }
  func typedClaimRole(_ stream: V4StreamHandle, kind: String) throws -> Bool {
    try run {
      let slot = try resolve(stream)
      // Already authenticated DATA may be buffered under the original credit.
      // Native raw-use guards prove application consumption has not occurred;
      // a wire receive frontier is not an application-read frontier.
      guard slot.phase == .accepted, !slot.canceled, slot.kind == kind, slot.view.bridge == nil else {
        throw ServiceFailure.contractMismatch
      }
      return slot.opener == access.role
    }
  }

  func applicationInputAvailable(_ stream: V4StreamHandle) throws -> Bool {
    try run {
      let slot = try resolve(stream)
      guard slot.phase == .accepted, !slot.canceled else { throw ServiceFailure.closed }
      return slot.ring.count > 0 || slot.directions[peer].fin || slot.directions[peer].stop || slot.directions[peer].terminal != nil
    }
  }

  func pendingOpenDeadline(_ stream: V4StreamHandle) throws -> ContinuousClock.Instant {
    try run {
      let slot = try resolve(stream)
      guard slot.phase == .pending else { throw V4CryptoFailure.phase }
      let elapsed = try elapsed(slot.opened)
      guard elapsed < 10_000, slot.forced == nil else { throw SessionError.timeout }
      return ContinuousClock.now.advanced(by: .milliseconds(Int64(10_000 - elapsed)))
    }
  }

  func pendingMetadata(_ stream: V4StreamHandle) throws -> (kind: String, metadata: V4CryptoBuffer)
  {
    try run {
      let s = try resolve(stream)
      guard s.phase == .pending, s.claimed, s.token != .none,
        s.openEpoch <= (try access.channel.rekeyState(access).epoch)
      else { throw V4CryptoFailure.phase }
      let buffer = try access.environment.cryptoBuffer(
        capacity: s.metadata.count, delivery: { try self.check() })
      try buffer.store(s.metadata)
      return (s.kind, buffer)
    }
  }
  private func outcomeBody(_ s: Slot, decision: V4StreamDecision) -> Data {
    let rejected: Bool
    let window: UInt64
    switch decision {
    case .accept(let value):
      rejected = false
      window = value
    case .reject:
      rejected = true
      window = 0
    }
    var fields: [(UInt64, Data)] = [
      (0, u(s.scope.number)), (1, u(UInt64(s.opener.rawValue))),
      (2, u(rejected ? 1 : 0)), (3, u(UInt64(s.openEpoch))), (4, u(0)),
      (5, V4Crypto.bytes(s.digest)), (6, u(window)),
    ]
    if rejected { fields += [(7, u(UInt64(s.openEpoch))), (8, u(1)), (9, u(0))] }
    fields.append((10, u(1)))
    if case .reject(let reason) = decision { fields.append((11, u(reason.rawValue))) }
    return V4Crypto.map(fields)
  }
  private func reject(_ s: Slot) throws {
    guard !s.bootstrap, s.directions.allSatisfy({ $0.current.offset == 0 }),
      s.directions[1 - Int(s.opener.rawValue)].current.next == 0
    else {
      throw V4CryptoFailure.authentication
    }
    releaseQueue(s)
    let receive = s.directions[peer]
    promised -= receive.limit - receive.released
    receive.limit = receive.released
    receive.committed = receive.released
    s.view.end = 2
    for i in 0..<2 {
      let d = s.directions[i]
      let tuple = V4StreamTuple(epoch: s.openEpoch, next: i == Int(s.opener.rawValue) ? 1 : 0)
      d.terminal = tuple
      d.proof = Proof(terminal: tuple, observed: tuple, aborted: false)
      d.drainSent = true
      d.stop = true
    }
    try recent(s)
    discardBacking(s)
  }
  private func decide(
    _ s: Slot, requested: V4StreamDecision,
    to publisher: any V4RecordPublisher
  ) throws {
    guard s.phase == .pending, !s.bootstrap,
      s.openEpoch <= (try access.channel.rekeyState(access).epoch)
    else { throw V4CryptoFailure.phase }
    var decision = requested
    if draining { decision = .reject(.draining) }
    if let forced = s.forced { decision = .reject(forced) }
    if (try? classify(s.kind, opener: s.opener)) == nil { decision = .reject(.kind) }
    if (try? validateMetadata(s.metadata)) == nil { decision = .reject(.metadata) }
    if case .accept = decision, !room(s.streamClass, opener: s.opener) {
      if access.role == .server, s.opener == .client,
        slots.contains(where: { $0.phase == .opening && $0.streamClass == .business })
      {
        throw V4CryptoFailure.capacity
      }
      decision = .reject(.resource)
    }
    if s.token == .none {
      if case .reject = decision {
        s.token = try takeToken(reject: true)
      } else {
        s.token = try takeToken(reject: false)
      }
    }
    if case .accept(let window) = decision { try growWindow(s, limit: window) }
    let body = outcomeBody(s, decision: decision)
    // Publication is the linearization point for the advertised receive limit.
    try sendControl(body, to: publisher)
    s.outcome = decision
    metadataBytes -= s.metadata.count
    s.metadata = Data()
    s.forced = nil
    if case .accept(let window) = decision {
      s.phase = .accepted
      acceptedPeerCeiling = max(acceptedPeerCeiling, s.scope.number)
      s.directions[peer].committed = window
    } else {
      try reject(s)
    }
  }
  func decideOpen(
    _ stream: V4StreamHandle, decision: V4StreamDecision,
    to publisher: any V4RecordPublisher
  ) throws {
    try run { try decide(resolve(stream), requested: decision, to: publisher) }
  }
  func phase(_ stream: V4StreamHandle) throws -> V4StreamPhase {
    try run {
      guard stream.owner === self else { throw V4CryptoFailure.phase }
      return find(stream.number)?.phase ?? .stable
    }
  }
  @discardableResult func write(
    _ stream: V4StreamHandle, data: Data, fin: Bool = false,
    to publisher: any V4RecordPublisher,
    accepted: (@Sendable (Int) -> Void)? = nil,
    publication: (any V4RecordPublication)? = nil
  ) throws -> Int {
    try run { try write(resolve(stream), data: data, fin: fin, to: publisher, accepted: accepted, publication: publication) }
  }
  private func write(
    _ s: Slot, data: Data, fin: Bool, to publisher: any V4RecordPublisher,
    accepted: (@Sendable (Int) -> Void)? = nil,
    publication: (any V4RecordPublication)? = nil
  ) throws
    -> Int
  {
    let d = s.directions[me]
    guard rekey?.frozen != true, s.phase == .accepted, s.prefix, !d.stop, d.terminal == nil,
      !d.finRequested || fin
    else {
      throw V4CryptoFailure.phase
    }
    let (end, overflow) = d.current.offset.addingReportingOverflow(UInt64(data.count))
    guard !overflow, end <= d.limit, data.count + 128 <= access.maxFrame else {
      throw V4CryptoFailure.capacity
    }
    let frontier = try access.channel.frontier(s.scope, sending: true, access: access)
    guard frontier.next < .max else { throw V4CryptoFailure.sequence }
    let body = V4Crypto.map([
      (0, u(s.scope.number)), (1, u(UInt64(me))),
      (2, u(UInt64(frontier.epoch))), (3, u(frontier.next)), (4, u(d.current.offset)),
      (5, Data([fin ? 0xf5 : 0xf4])), (6, V4Crypto.bytes(data)),
    ])
    try send(s.scope, type: 8, body: body, to: publisher, publication: publication, accepted: {
      accepted?(data.count)
    })
    if frontier.epoch != d.current.epoch { d.last = d.current }
    d.current = V4StreamTuple(epoch: frontier.epoch, next: frontier.next + 1, offset: end)
    if fin {
      d.terminal = d.current
      d.fin = true
      s.view.finSubmitted = true
      d.stop = true
      try begin(d)
    }
    return data.count
  }
  func requestCloseWrite(_ stream: V4StreamHandle) throws {
    try run {
      let d = try resolve(stream).directions[me]
      if d.fin { return }
      guard !d.stop, d.terminal == nil else { throw SessionError.streamReset }
      d.finRequested = true
      try begin(d)
    }
  }
  func finSubmitted(_ stream: V4StreamHandle) throws -> Bool {
    try access.environment.gate.withLock {
      guard stream.owner === self else { throw V4CryptoFailure.phase }
      return stream.view.finSubmitted
    }
  }
  func read(_ stream: V4StreamHandle, maximum: Int, delivered: (@Sendable (Data) -> Void)? = nil) throws -> V4StreamRead {
    try run {
      guard stream.owner === self, maximum > 0, maximum <= 1_048_576 else {
        throw V4CryptoFailure.configuration
      }
      guard let s = find(stream.number) else {
        return stream.view.end == 1 ? .eof : .aborted
      }
      guard s.view === stream.view else { throw V4CryptoFailure.phase }
      let d = s.directions[peer]
      if d.stop && !d.fin { return .aborted }
      guard [.accepted, .recent, .stable].contains(s.phase),
        d.current.epoch <= (try access.channel.rekeyState(access)).epoch
      else { return .pending }
      guard s.ring.count > 0 else { return d.fin && d.proof != nil ? .eof : .pending }
      let count = min(maximum, s.ring.count)
      let output = try access.environment.cryptoBuffer(
        capacity: count, delivery: { try self.check() })
      var bytes = s.ring.copyPrefix(count)
      defer { V4Crypto.wipe(&bytes) }
      try output.store(bytes)
      try check()
      s.ring.consume(count)
      delivered?(bytes)
      d.released += UInt64(count)
      promised -= UInt64(count)
      if d.complete {
        discardBacking(s)
        try collect()
      }
      return .data(output)
    }
  }
  func grant(_ stream: V4StreamHandle, receiveLimit: UInt64) throws {
    try run {
      let s = try resolve(stream)
      let d = s.directions[peer]
      guard s.phase == .accepted, !d.stop, d.terminal == nil else { throw V4CryptoFailure.phase }
      try growWindow(s, limit: receiveLimit)
      s.creditDirty = true
    }
  }
  private func begin(_ d: Direction) throws {
    if d.begun == nil { d.begun = try clock.mark() }
  }
  private func reset(_ s: Slot) throws {
    if s.phase == .recent || s.phase == .stable {
      // Completed directions have already retired their keys. Closing their
      // application view only releases unread data; it emits no new reset.
      releaseQueue(s)
      discardBacking(s)
      try collect()
      return
    }
    s.canceled = true
    if s.phase == .opening { return }
    guard s.phase == .accepted else { throw V4CryptoFailure.phase }
    let send = s.directions[me]
    let receive = s.directions[peer]
    send.stop = true
    if !send.complete { send.stoppedRequested = true }
    send.terminal = send.terminal ?? send.current
    try begin(send)
    receive.stop = true
    receive.fin = false
    try begin(receive)
    s.view.end = 2
    releaseQueue(s)
  }
  func reset(_ stream: V4StreamHandle) throws {
    try run {
      guard stream.owner === self else { throw V4CryptoFailure.phase }
      guard let slot = find(stream.number) else {
        guard stream.view.end != 0 else { throw V4CryptoFailure.phase }
        return
      }
      guard slot.view === stream.view else { throw V4CryptoFailure.phase }
      try reset(slot)
    }
  }
  func beginDrain() throws {
    try run {
      guard localGoAway == nil else { return }
      localGoAway = acceptedPeerCeiling
      draining = true
      for slot in slots where slot.phase == .pending { slot.forced = .draining }
    }
  }
  func drainBusinessComplete() throws -> Bool {
    try run { localGoAway != nil && goAwaySent && slots.allSatisfy { $0.streamClass != .business || [.recent, .stable].contains($0.phase) } }
  }
  func writeCapacity(_ stream: V4StreamHandle) throws -> Int {
    try run {
      let s = try resolve(stream)
      let d = s.directions[me]
      if d.stop || d.terminal != nil || d.finRequested { throw SessionError.streamReset }
      guard s.phase == .accepted, rekey?.frozen != true else { return 0 }
      return Int(min(d.limit - d.current.offset, UInt64(access.maxFrame - 128)))
    }
  }
  func replenish(_ stream: V4StreamHandle, window: UInt64) throws {
    try run {
      let s = try resolve(stream)
      let d = s.directions[peer]
      guard s.phase == .accepted, !d.stop, d.terminal == nil else { return }
      let (limit, overflow) = d.released.addingReportingOverflow(window)
      guard !overflow else { throw V4CryptoFailure.capacity }
      if limit > d.limit {
        try growWindow(s, limit: limit)
        s.creditDirty = true
      }
    }
  }
  func sendFinished(_ stream: V4StreamHandle) throws -> Bool {
    let observed = try access.environment.gate.withLock {
      guard stream.owner === self else { throw V4CryptoFailure.phase }
      return stream.view.sendEnd
    }
    if observed == 1 { return true }
    if observed == 2 { throw SessionError.streamReset }
    return try run {
      guard stream.owner === self else { throw V4CryptoFailure.phase }
      guard let s = find(stream.number) else {
        if stream.view.sendEnd == 2 { throw SessionError.streamReset }
        return stream.view.sendEnd == 1
      }
      let d = s.directions[me]
      if (d.stop && !d.fin) || d.proof?.aborted == true { throw SessionError.streamReset }
      return d.fin && d.proof != nil
    }
  }
  func canOpen() throws -> Bool { try run { rekey?.frozen != true } }
  func canReceive() throws -> Bool {
    try run {
      if pendingPong != nil { liveness.localStall() }
      return pendingPong == nil
    }
  }
  func streamError(_ stream: V4StreamHandle) throws -> SessionError? {
    try run {
      guard stream.owner === self else { throw V4CryptoFailure.phase }
      if stream.view.end == 2 || stream.view.sendEnd == 2 { return .streamReset }
      guard let slot = find(stream.number) else { return nil }
      return slot.directions.contains { ($0.stop && !$0.fin) || $0.proof?.aborted == true }
        ? .streamReset : nil
    }
  }
  func beginProbe() throws -> V4LivenessProbe { try run { try liveness.begin() } }
  private func publishProbe(_ probe: V4LivenessProbe, to publisher: any V4RecordPublisher) throws {
    guard let nonce = try liveness.preparePublication(probe) else { return }
    try send(
      access.channel.maintenance, type: 14,
      body: V4Crypto.map([(0, V4Crypto.bytes(nonce))]), to: publisher, publication: probe)
  }
  func submitProbe(_ probe: V4LivenessProbe, to publisher: any V4RecordPublisher) throws {
    try run { try publishProbe(probe, to: publisher) }
  }
  func probeResult(_ probe: V4LivenessProbe) throws -> TransportLivenessProgress? {
    try access.environment.gate.withLock { try liveness.snapshot(probe) }
  }
  func endProbe(_ probe: V4LivenessProbe, reason: TransportLivenessFailure) {
    access.environment.gate.withLock { liveness.end(probe, reason: reason) }
  }
  func releaseProbe(_ probe: V4LivenessProbe) {
    access.environment.gate.withLock { liveness.release(probe) }
  }
  func noteLivenessTimeUnavailable() {
    access.environment.gate.withLock { liveness.clockUnavailable() }
  }
  func noteLivenessStall() { access.environment.gate.withLock { liveness.localStall() } }
  func noteLivenessProviderBlocked() {
    access.environment.gate.withLock { liveness.providerBlocked() }
  }
  func beginRekeyIntent() throws { try run { try rekey!.rememberIntent() } }

  // An optional handle supplies the original bound-input association. A shared
  // input can provision only one bounded OPEN key; all effects follow AEAD.
  // Quarantined input is discarded only with its original handle, never by a
  // peer-controlled header claiming another stream's identity.
  func receive(_ input: Data, on stream: V4StreamHandle? = nil) throws {
    try run {
      var isolated = false
      do {
        guard input.count >= 44, input.count - 8 <= access.maxFrame else {
          throw V4CryptoFailure.authentication
        }
        let wire = Data(input)
        let id = V4Crypto.number(wire[12..<20])
        let scope: V4RecordScope
        if let stream {
          let s = try resolve(stream)
          guard id == stream.number else { throw V4CryptoFailure.authentication }
          if s.directions[peer].disabled { return }
          scope = s.scope
        } else if id == 0 {
          scope = access.channel.maintenance
        } else if let s = find(id) {
          guard !s.directions[peer].disabled else { throw V4CryptoFailure.authentication }
          scope = s.scope
        } else {
          let state = try access.channel.rekeyState(access)
          let candidateOpen = state.sent && V4Crypto.number(wire[8..<12]) == UInt64(state.epoch) + 1
          guard wire[4] == 7, Self.valid(id),
            rekey?.frozen != true || rekey?.awaiting(id) == true || candidateOpen,
            id & 1 == (access.role.peer == .client ? 1 : 0), slots.count < maxSlots
          else {
            throw V4CryptoFailure.authentication
          }
          scope = try access.channel.admitReliableScope(id, access: access)
        }
        let record: V4AuthenticatedRecord
        do {
          record = try access.channel.receive(
            scope: scope, wire: wire, access: access,
            isolateFailure: stream != nil,
            marker: wire[4] == 6 && (try rekey!.markerForInput(wire)))
        } catch {
          if stream != nil, let s = find(id), s.phase == .accepted {
            try isolate(s)
            isolated = true
          }
          throw error
        }
        defer { record.close() }
        var pong: Data?
        do {
          try record.withBytes { body in
            switch record.frameType {
            case 6:
              guard record.scope == 0 else { throw V4CryptoFailure.authentication }
              try rekey!.receive(record, body: body, owner: self)
            case 7: try receiveOpen(body, scope: scope, record: record)
            case 8: try receiveData(body, record: record)
            case 9:
              guard record.scope == 0 else { throw V4CryptoFailure.authentication }
              try receiveControl(body)
            case 14:
              guard record.scope == 0, pendingPong == nil else { throw V4CryptoFailure.capacity }
              pendingPong = try decode(body, "PING").b("nonce")
            case 15:
              guard record.scope == 0 else { throw V4CryptoFailure.authentication }
              pong = try decode(body, "PONG").b("nonce")
            case 12:
              guard record.scope == 0 else { throw V4CryptoFailure.authentication }
              let value = try decode(body, "CLOSE")
              if try value.u("target_scope") == 0 { throw SessionError.closed }
              guard let s = find(try value.u("target_scope")) else {
                throw V4CryptoFailure.authentication
              }
              try reset(s)
            case 13:
              guard record.scope == 0 else { throw V4CryptoFailure.authentication }
              let value = try decode(body, "GOAWAY")
              let ceiling = try value.u("accept_ceiling")
              let reason = try value.u("reason")
              guard ceiling == 0 || (Self.valid(ceiling) && (ceiling + 1) % 2 == UInt64(me)),
                peerCeiling == nil || (ceiling == peerCeiling && reason == peerGoAwayReason),
                !slots.contains(where: {
                  $0.opener == access.role && $0.phase == .accepted && $0.scope.number > ceiling
                })
              else { throw V4CryptoFailure.authentication }
              peerCeiling = ceiling
              peerGoAwayReason = reason
              draining = true
            case 11:
              guard record.scope == 0 else { throw V4CryptoFailure.authentication }
              let value = try decode(body, "ERROR")
              let code = try value.u("code")
              if code == 9 || code == 10 {
                guard let s = find(try value.u("target_scope")),
                  [.accepted, .recent].contains(s.phase)
                else {
                  throw V4CryptoFailure.authentication
                }
                if s.phase == .accepted { try reset(s) }
              } else if code != 0 {
                throw SessionError.operationFailed
              }
            default: throw V4CryptoFailure.authentication
            }
          }
        } catch {
          if record.frameType == 8, let s = find(id), s.phase == .accepted {
            try isolate(s)
            isolated = true
          }
          throw error
        }
        // Only a complete authenticated, sequence-checked and protocol-valid
        // record qualifies. Early discarded/quarantined input never reaches it.
        try authenticatedInput?()
        if let pong { liveness.match(nonce: pong, epoch: record.epoch) }
      } catch {
        if !isolated { close() }
        throw error
      }
    }
  }
  private func receiveOpen(_ body: Data, scope: V4RecordScope, record: V4AuthenticatedRecord) throws
  {
    let v = try decode(body, "OPEN_STREAM")
    let id = record.scope
    guard Self.valid(id), id & 1 == (access.role.peer == .client ? 1 : 0),
      record.sequence == 0, try v.u("stream_id") == id, try v.u("scope") == id,
      try v.u("direction") == UInt64(peer), try v.u("epoch") == UInt64(record.epoch),
      try v.u("sequence") == 0
    else { throw V4CryptoFailure.authentication }
    let kind = try v.t("kind")
    let metadata = try v.b("metadata")
    let limit = try v.u("initial_receive_limit")
    let digest = try v.b("open_digest")
    guard try digest == v.digest("open_digest") else { throw V4CryptoFailure.authentication }
    if let s = find(id) {
      guard s.bootstrap, !s.prefix, kind == "flowersec.rpc.v4", metadata.isEmpty,
        limit == 16_384
      else { throw V4CryptoFailure.authentication }
      s.prefix = true
      s.openEpoch = record.epoch
      s.digest = digest
      s.directions[peer].current = V4StreamTuple(epoch: record.epoch, next: 1)
      return
    }
    let classified = try? classify(kind, opener: access.role.peer)
    let kindClass = classified ?? .business
    try countLifetime(kindClass, opener: access.role.peer)
    let full =
      slots.filter({ $0.phase == .pending && $0.forced == nil }).count >= 128
      || metadata.count > 512 * 1024 - metadataBytes
    let s = Slot(
      scope: scope, opener: access.role.peer, kind: kind, streamClass: kindClass,
      metadata: full ? Data() : metadata, phase: .pending, opened: try clock.mark())
    if full {
      s.token = try takeToken(reject: true)
      s.forced = .resource
    }
    if classified == nil { s.forced = .kind }
    // Reserved channels remain under the SDK's original dispatch owners.
    // Management is opened only by the client in the execution profile.
    if kindClass != .business && !(kindClass == .notify && access.applicationProfile >= 1 && metadata.isEmpty)
      && !(kindClass == .rpc && access.applicationProfile >= 1 && metadata.isEmpty)
      && !(kindClass == .management && access.applicationProfile == 2 && metadata.isEmpty) { s.forced = .kind }
    s.prefix = true
    s.openEpoch = record.epoch
    s.digest = digest
    s.directions[peer].current = V4StreamTuple(epoch: record.epoch, next: 1)
    s.directions[me].limit = limit
    s.directions[me].committed = limit
    metadataBytes += s.metadata.count
    s.barrierRefs = rekey?.barrierReferences(id) ?? 0
    s.directions[me].current = V4StreamTuple(epoch: record.epoch)
    s.directions[me].last = s.directions[me].current
    s.directions[peer].last = s.directions[peer].current
    slots.append(s)
  }
  private func receiveData(_ body: Data, record: V4AuthenticatedRecord) throws {
    let v = try decode(body, "STREAM_DATA")
    guard let s = find(record.scope), s.prefix, [.opening, .accepted].contains(s.phase),
      try v.u("stream_id") == record.scope, try v.u("direction") == UInt64(peer),
      try v.u("epoch") == UInt64(record.epoch), try v.u("sequence") == record.sequence
    else {
      throw V4CryptoFailure.authentication
    }
    try rekey?.checkIncomingFrontier(
      scope: record.scope, epoch: record.epoch, next: record.sequence + 1)
    let d = s.directions[peer]
    let data = try v.b("data")
    let offset = try v.u("offset")
    let (end, overflow) = offset.addingReportingOverflow(UInt64(data.count))
    guard !overflow, !d.disabled, !d.fin, offset == d.current.offset,
      end <= d.committed, record.epoch >= d.current.epoch,
      record.epoch <= (try access.channel.rekeyState(access)).epoch + 1, record.sequence < .max
    else {
      throw V4CryptoFailure.authentication
    }
    let current = V4StreamTuple(epoch: record.epoch, next: record.sequence + 1, offset: end)
    if let terminal = d.terminal, !current.precedes(terminal) {
      throw V4CryptoFailure.authentication
    }
    let fin = try v.field("fin").raw.elementsEqual([0xf5])
    if fin, let terminal = d.terminal, terminal != current { throw V4CryptoFailure.authentication }
    if d.stop {
      d.released += UInt64(data.count)
      promised -= UInt64(data.count)
    } else {
      try s.ring.append(data)
    }
    if current.epoch != d.current.epoch { d.last = d.current }
    d.current = current
    d.ack = end
    s.creditDirty = true
    if fin {
      d.terminal = current
      d.fin = !d.stop
      s.view.end = d.fin ? 1 : 2
      try begin(d)
      try trimPromise(s, limit: end)
    }
  }
  private func controlSchema(_ body: Data) throws -> String {
    guard let first = body.first else { throw V4CryptoFailure.authentication }
    if first == 0xa8 || first == 0xac { return "OPEN_ACCEPT" }
    guard body.count >= 3, body[body.startIndex + 1] == 0 else {
      throw V4CryptoFailure.authentication
    }
    switch body[body.startIndex + 2] {
    case 0: return "STREAM_ACK_CREDIT"
    case 2: return "STREAM_ACK_STOP"
    case 3: return "STREAM_ACK_STOPPED"
    case 4: return "STREAM_ACK_DRAINED"
    case 5: return "STREAM_ACK_RETIRE_BATCH"
    case 6: return "STREAM_ACK_RETIRE_ACK"
    default: throw V4CryptoFailure.authentication
    }
  }
  private func receiveControl(_ body: Data) throws {
    let schema = try controlSchema(body)
    let v = try decode(body, schema)
    if schema == "STREAM_ACK_RETIRE_BATCH" || schema == "STREAM_ACK_RETIRE_ACK" {
      try receiveRetirement(v, body: body)
      return
    }
    let id = try v.u("stream_id")
    let direction = try v.u("direction")
    let expected = schema == "STREAM_ACK_STOPPED" ? peer : me
    guard Self.valid(id), direction == UInt64(expected) else {
      throw V4CryptoFailure.authentication
    }
    guard let s = find(id) else {
      guard try access.channel.wasUsed(id, access: access),
        !(schema == "OPEN_ACCEPT" && id == 1 && access.applicationProfile != 0)
      else {
        throw V4CryptoFailure.authentication
      }
      return
    }
    if s.phase == .stable { return }
    if schema == "OPEN_ACCEPT" {
      guard !s.bootstrap, s.opener == access.role, try v.u("open_epoch") == UInt64(s.openEpoch),
        try v.u("open_sequence") == 0, try v.b("open_digest") == s.digest
      else {
        throw V4CryptoFailure.authentication
      }
      let decision: V4StreamDecision
      if try v.u("result") == 0 {
        guard try v.optional("final_epoch") == nil, try v.optional("reason") == nil else {
          throw V4CryptoFailure.authentication
        }
        decision = .accept(receiveWindow: try v.u("initial_receive_limit"))
      } else {
        guard try v.u("initial_receive_limit") == 0, try v.u("final_epoch") == UInt64(s.openEpoch),
          try v.u("final_next_sequence") == 1, try v.u("final_offset") == 0,
          let reason = try V4StreamRejection(rawValue: v.u("reason"))
        else {
          throw V4CryptoFailure.authentication
        }
        decision = .reject(reason)
      }
      if s.phase != .opening {
        guard decision == s.outcome else { throw V4CryptoFailure.authentication }
        return
      }
      s.outcome = decision
      switch decision {
      case .accept(let limit):
        s.phase = .accepted
        s.directions[me].limit = limit
        s.directions[me].committed = limit
        if s.canceled { try reset(s) }
      case .reject: try reject(s)
      }
      return
    }
    guard [.accepted, .recent].contains(s.phase) else { throw V4CryptoFailure.authentication }
    let d = s.directions[expected]
    switch schema {
    case "STREAM_ACK_CREDIT":
      let ack = try v.u("ack_offset")
      let limit = try v.u("receive_limit")
      guard ack <= d.current.offset, limit >= ack,
        (ack >= d.ack && limit >= d.limit) || (ack <= d.ack && limit <= d.limit)
      else {
        throw V4CryptoFailure.authentication
      }
      if ack <= d.ack && limit <= d.limit { return }
      d.ack = ack
      if !d.stop, d.terminal == nil {
        d.limit = limit
        d.committed = limit
      }
    case "STREAM_ACK_STOP":
      d.stop = true
      d.stoppedRequested = true
      d.stoppedSent = false
      d.terminal = d.terminal ?? d.current
      try begin(d)
    case "STREAM_ACK_STOPPED":
      let terminal = try V4StreamTuple(
        epoch: UInt32(v.u("final_epoch")),
        next: v.u("final_next_sequence"), offset: v.u("final_offset"))
      guard d.terminal == nil || d.terminal == terminal,
        try observed(d, epoch: terminal.epoch).precedes(terminal), terminal.offset <= d.committed
      else {
        throw V4CryptoFailure.authentication
      }
      d.terminal = terminal
      if !d.stop || d.fin {
        d.stop = true
        d.fin = false
        s.view.end = 2
        try begin(d)
        releaseQueue(s)
      }
      try trimPromise(s, limit: terminal.offset)
    case "STREAM_ACK_DRAINED":
      let terminal = try V4StreamTuple(v.field("terminal_tuple"))
      let observed = try V4StreamTuple(v.field("observed_tuple"))
      let aborted = try v.u("outcome") == 1
      let proof = Proof(terminal: terminal, observed: observed, aborted: aborted)
      guard d.terminal == terminal, observed.precedes(terminal), aborted || observed == terminal,
        d.proof == nil || d.proof == proof
      else { throw V4CryptoFailure.authentication }
      d.proof = proof
      s.view.sendEnd = aborted || !d.fin ? 2 : 1
      if !aborted { d.ack = max(d.ack, terminal.offset) }
      try recent(s)
    default: throw V4CryptoFailure.authentication
    }
  }
  private func recent(_ s: Slot) throws {
    guard s.directions.allSatisfy({ $0.complete }) else { return }
    if s.phase != .recent && s.phase != .stable {
      s.phase = .recent
      s.recentAt = try clock.mark()
    }
    if !s.keysRetired {
      try access.channel.retire(s.scope, access: access)
      s.keysRetired = true
    }
  }
  private func collect() throws {
    slots.removeAll { s in
      guard s.phase == .stable, s.batchRefs == 0, s.barrierRefs == 0, s.unpublished == 0,
        s.ring.count == 0
      else { return false }
      discardBacking(s)
      return true
    }
  }
  private func stable(_ ids: [UInt64]) throws {
    for id in ids {
      guard let s = find(id), s.batchRefs > 0 else { throw V4CryptoFailure.phase }
      s.batchRefs -= 1
      s.phase = .stable
    }
    try collect()
  }
  private func retirementDigest(_ body: Data, proposer: V4CryptoRole) -> Data {
    V4Crypto.hash(
      Data("flowersec/v4/retire-batch\0".utf8) + V4Crypto.lp(access.hash)
        + V4Crypto.lp(Data(access.profile.rawValue.utf8)) + Data([proposer.rawValue])
        + V4Crypto.lp(body))
  }
  private func receiveRetirement(_ v: V4NamespaceValue, body: Data) throws {
    let sequence = try v.u("batch_seq")
    if v.schema == "STREAM_ACK_RETIRE_ACK" {
      let digest = try v.b("batch_digest")
      if sequence < lastOut { return }
      if sequence == lastOut {
        guard digest == lastOutDigest else { throw V4CryptoFailure.authentication }
        return
      }
      guard let batch = outgoing, batch.sequence == sequence, batch.digest == digest else {
        throw V4CryptoFailure.authentication
      }
      lastOut = sequence
      lastOutDigest = digest
      outgoing = nil
      try stable(batch.ids)
      return
    }
    let digest = retirementDigest(body, proposer: access.role.peer)
    if sequence < lastIn { return }
    if sequence == lastIn {
      guard digest == lastInDigest else { throw V4CryptoFailure.authentication }
      repeatACK = true
      return
    }
    if let incoming {
      guard sequence == incoming.sequence, digest == incoming.digest else {
        throw V4CryptoFailure.authentication
      }
      return
    }
    guard lastIn < .max, sequence == lastIn + 1 else { throw V4CryptoFailure.authentication }
    var ids: [UInt64] = []
    for item in try v.field("scope_ids").children {
      let id = try item.uint()
      guard Self.valid(id), (ids.last ?? 0) < id, let s = find(id), s.phase == .recent,
        s.opener == access.role.peer, s.directions.allSatisfy({ $0.complete }), s.batchRefs == 0
      else {
        throw V4CryptoFailure.authentication
      }
      ids.append(id)
    }
    guard !ids.isEmpty, ids.count <= 1024 else { throw V4CryptoFailure.authentication }
    for id in ids { find(id)!.batchRefs += 1 }
    incoming = Batch(sequence: sequence, digest: digest, ids: ids, started: try clock.mark())
  }
  private func isolate(_ s: Slot) throws {
    try reset(s)
    let d = s.directions[peer]
    d.disabled = true
    d.quarantined = try clock.mark()
    releaseQueue(s)
    guard
      slots.filter({ $0.directions[peer].disabled && !$0.directions[peer].complete }).count <= 32
    else {
      close()
      throw V4CryptoFailure.capacity
    }
  }
  private func deadlines() throws {
    for batch in [incoming, outgoing].compactMap({ $0 }) {
      guard try elapsed(batch.started) < 90_000 else { throw V4TimeFailure.expired }
    }
    for s in slots {
      if s.phase == .opening, try elapsed(s.opened) >= 10_000 { throw V4TimeFailure.expired }
      if s.phase == .pending, try elapsed(s.opened) >= 10_000 { s.forced = .application }
      for i in 0..<2 {
        let d = s.directions[i]
        guard !d.complete, let begun = d.begun else { continue }
        let age = try elapsed(begun)
        guard age < 15_000 else { throw V4TimeFailure.expired }
        if let quarantined = d.quarantined {
          guard try elapsed(quarantined) < 10_000 else { throw V4TimeFailure.expired }
        } else if age >= 5000 {
          d.quarantined = try clock.mark()
          if i == peer {
            d.disabled = true
            d.stop = true
            d.fin = false
            s.view.end = 2
            releaseQueue(s)
          }
        }
      }
    }
    guard
      slots.reduce(0, { $0 + $1.directions.filter { $0.quarantined != nil && !$0.complete }.count })
        <= 32
    else {
      throw V4CryptoFailure.capacity
    }
  }
  private func pollTerminal(to publisher: any V4RecordPublisher) throws -> Bool {
    for s in slots {
      guard s.phase == .accepted else { continue }
      let send = s.directions[me]
      let receive = s.directions[peer]
      if send.finRequested, send.terminal == nil, !send.stop, rekey?.frozen != true {
        _ = try write(s, data: Data(), fin: true, to: publisher)
        return true
      }
      if receive.stop, !receive.fin, !receive.stopSent {
        try sendControl(control(2, s, peer), to: publisher)
        receive.stopSent = true
        return true
      }
      if let terminal = send.terminal, !send.stoppedSent, !send.fin || send.stoppedRequested {
        try sendControl(
          control(
            3, s, me,
            [
              (3, u(UInt64(terminal.epoch))),
              (4, u(terminal.next)), (5, u(terminal.offset)),
            ]), to: publisher)
        send.stoppedSent = true
        return true
      }
      if let terminal = receive.terminal, !receive.drainSent {
        let observed = try observed(receive, epoch: terminal.epoch)
        let aborted = observed != terminal || receive.disabled || (receive.stop && !receive.fin)
        guard observed.precedes(terminal) else { throw V4CryptoFailure.authentication }
        if observed != terminal && !receive.disabled { continue }
        let proof = Proof(terminal: terminal, observed: observed, aborted: aborted)
        try sendControl(
          control(
            4, s, peer,
            [
              (3, terminal.encoded), (4, u(aborted ? 1 : 0)),
              (5, observed.encoded),
            ]), to: publisher)
        receive.proof = proof
        receive.drainSent = true
        if aborted {
          receive.disabled = true
          promised -= receive.limit - receive.released
          receive.limit = receive.released
          receive.committed = receive.released
        }
        try recent(s)
        discardBacking(s)
        return true
      }
    }
    return false
  }
  private func pollCredit(to publisher: any V4RecordPublisher) throws -> Bool {
    for s in slots {
      let d = s.directions[peer]
      guard s.phase == .accepted, s.creditDirty, !d.stop, d.terminal == nil else { continue }
      try sendControl(control(0, s, peer, [(3, u(d.ack)), (4, u(d.limit))]), to: publisher)
      d.committed = d.limit
      s.creditDirty = false
      return true
    }
    return false
  }
  private func retireACK(_ sequence: UInt64, _ digest: Data) -> Data {
    V4Crypto.map([(0, u(6)), (1, u(sequence)), (2, V4Crypto.bytes(digest))])
  }
  private func pollRetirement(to publisher: any V4RecordPublisher) throws -> Bool {
    if repeatACK {
      try sendControl(retireACK(lastIn, lastInDigest), to: publisher)
      repeatACK = false
      return true
    }
    if let batch = incoming {
      guard batch.ids.allSatisfy({ find($0)?.unpublished == 0 }) else { return false }
      try sendControl(retireACK(batch.sequence, batch.digest), to: publisher)
      lastIn = batch.sequence
      lastInDigest = batch.digest
      incoming = nil
      try stable(batch.ids)
      return true
    }
    guard outgoing == nil, lastOut < .max else { return false }
    let pressure = slots.contains(where: { $0.phase == .opening }) || slots.count >= maxTokens
    var ids: [UInt64] = []
    // Bound before constructing the complete canonical batch body.
    let capacity = min(1024, max(0, (access.maxFrame - 68) / 9))
    for s in slots.sorted(by: { $0.scope.number < $1.scope.number }) {
      guard ids.count < capacity else { break }
      guard s.phase == .recent, s.opener == access.role, s.batchRefs == 0, s.unpublished == 0,
        let at = s.recentAt
      else { continue }
      if !pressure, try elapsed(at) < 50 { continue }
      ids.append(s.scope.number)
    }
    guard !ids.isEmpty else { return false }
    let array = V4NamespaceValue.head(4, UInt64(ids.count)) + ids.reduce(Data()) { $0 + u($1) }
    let sequence = lastOut + 1
    let body = V4Crypto.map([(0, u(5)), (1, u(sequence)), (2, array)])
    let batch = Batch(
      sequence: sequence, digest: retirementDigest(body, proposer: access.role),
      ids: ids, started: try clock.mark())
    for id in ids { find(id)!.batchRefs += 1 }
    outgoing = batch
    try sendControl(body, to: publisher)
    return true
  }
  // One bounded scheduler step. Every true result is one actual publication;
  // terminal controls precede credit, then acknowledged evidence retirement.
  @discardableResult func poll(to publisher: any V4RecordPublisher) throws -> Bool {
    try run {
      do {
        let epoch = try access.channel.rekeyState(access).epoch
        if let s = slots.first(where: {
          $0.phase == .pending && $0.forced != nil && $0.openEpoch <= epoch
        }) {
          try decide(s, requested: .reject(s.forced!), to: publisher)
          return true
        }
        if try pollTerminal(to: publisher) { return true }
        if let nonce = pendingPong {
          try send(
            access.channel.maintenance, type: 15,
            body: V4Crypto.map([(0, V4Crypto.bytes(nonce))]), to: publisher)
          pendingPong = nil
          return true
        }
        if try rekey!.poll(owner: self, to: publisher) { return true }
        if !rekey!.frozen, let ceiling = localGoAway, !goAwaySent {
          try send(access.channel.maintenance, type: 13, body: V4Crypto.map([
            (0, V4NamespaceValue.head(0, ceiling)), (1, V4NamespaceValue.head(0, 0))]), to: publisher)
          goAwaySent = true
          return true
        }
        if !rekey!.frozen, try pollCredit(to: publisher) { return true }
        // Retirement has its own original barrier publication fence. It can
        // progress while the same rekey waits for its next authenticated phase.
        if try pollRetirement(to: publisher) { return true }
        guard !rekey!.frozen else { return false }
        if let probe = try liveness.nextAutomatic() {
          try publishProbe(probe, to: publisher)
          return true
        }
        return false
      } catch {
        close()
        throw error
      }
    }
  }
  @discardableResult func requestRekey(to publisher: any V4RecordPublisher) throws -> Bool {
    try run {
      do {
        try rekey!.rememberIntent()
        return try rekey!.poll(owner: self, to: publisher)
      } catch {
        close()
        throw error
      }
    }
  }
  func epoch() throws -> UInt32 { try run { try access.channel.rekeyState(access).epoch } }
  private func observed(_ d: Direction, epoch: UInt32) throws -> V4StreamTuple {
    if d.current.epoch == epoch { return d.current }
    if d.last.epoch == epoch { return d.last }
    if epoch > d.last.epoch, epoch < d.current.epoch {
      return V4StreamTuple(epoch: epoch, offset: d.last.offset)
    }
    throw V4CryptoFailure.authentication
  }
  private func checkAccess(_ token: V4ReliableSessionAdmission) throws {
    guard token === access else { throw V4CryptoFailure.phase }
    try check()
  }
  func rekeySnapshot(_ token: V4ReliableSessionAdmission, epoch: UInt32) throws -> [V4RekeyBarrier]
  {
    try checkAccess(token)
    let entries = try slots.filter { [.opening, .accepted].contains($0.phase) }.map {
      V4RekeyBarrier(
        scope: $0.scope.number, next: try observed($0.directions[me], epoch: epoch).next)
    }.sorted { $0.scope < $1.scope }
    guard entries.count <= access.maxStreams else { throw V4CryptoFailure.capacity }
    for entry in entries { try rekeyHold(token, scope: entry.scope, outgoing: true) }
    return entries
  }
  func rekeyHold(_ token: V4ReliableSessionAdmission, scope: UInt64, outgoing: Bool) throws {
    try checkAccess(token)
    if let s = find(scope) {
      s.barrierRefs += 1
      if outgoing { s.unpublished += 1 }
    }
  }
  func rekeyPublished(_ token: V4ReliableSessionAdmission, scope: UInt64) throws {
    try checkAccess(token)
    if let s = find(scope) {
      guard s.unpublished > 0 else { throw V4CryptoFailure.phase }
      s.unpublished -= 1
    }
  }
  func rekeyRelease(_ token: V4ReliableSessionAdmission, scope: UInt64) throws {
    try checkAccess(token)
    if let s = find(scope) {
      guard s.barrierRefs > 0 else { throw V4CryptoFailure.phase }
      s.barrierRefs -= 1
    }
    try collect()
  }
  func rekeyInstall(_ token: V4ReliableSessionAdmission, epoch: UInt32) throws {
    try checkAccess(token)
    for s in slots {
      for d in s.directions where d.current.epoch < epoch {
        d.last = d.current
        d.current = V4StreamTuple(epoch: epoch, offset: d.current.offset)
      }
    }
  }
  func rekeyBarrier(
    _ token: V4ReliableSessionAdmission, scope: UInt64, epoch: UInt32,
    next: UInt64, new: Bool
  ) throws -> Bool {
    try checkAccess(token)
    guard let s = find(scope) else {
      guard !(try access.channel.wasUsed(scope, access: access)),
        scope & 1 == (access.role.peer == .client ? 1 : 0), next == 1,
        !(scope == 1 && access.applicationProfile != 0)
      else { throw V4CryptoFailure.authentication }
      return false
    }
    guard !new || s.phase != .stable else { throw V4CryptoFailure.authentication }
    let d = s.directions[peer]
    if let proof = d.proof {
      guard epoch >= proof.terminal.epoch,
        next == (epoch == proof.terminal.epoch ? proof.terminal.next : 0)
      else {
        throw V4CryptoFailure.authentication
      }
      return d.drainSent || [.recent, .stable].contains(s.phase)
    }
    let current = try observed(d, epoch: epoch)
    guard next >= current.next else { throw V4CryptoFailure.authentication }
    if let terminal = d.terminal {
      guard epoch >= terminal.epoch, next == (epoch == terminal.epoch ? terminal.next : 0) else {
        throw V4CryptoFailure.authentication
      }
    }
    return !d.disabled && current.next == next
  }
  func close() {
    access.environment.gate.withLock {
      guard !closed else { return }
      closed = true
      liveness.close()
      authenticatedInput = nil
      for s in slots {
        s.view.end = 2
        s.ring = V4StreamRing(capacity: 0)
        s.metadata = Data()
      }
      slots.removeAll()
      incoming = nil
      outgoing = nil
      rekey?.close()
      access.channel.close()
      storage.seal()
    }
  }
  deinit { close() }
}
