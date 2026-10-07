import Crypto
import Foundation

struct V4RekeyBarrier: Equatable {
  let scope: UInt64
  let next: UInt64
  var encoded: Data {
    V4Crypto.map([(0, V4NamespaceValue.head(0, scope)), (1, V4NamespaceValue.head(0, next))])
  }
}

// The signed envelope uses exact integer arithmetic. Time spent inside a round
// is excluded from refill; the client uses lower and server upper elapsed bounds.
struct V4RekeyCredit {
  let burst: UInt64
  let period: UInt64
  let startBudget: UInt64
  let maximumRounds: UInt64
  private let clock: V4TrustedClock
  private var balance: UInt64
  private var anchor: V4ClockMark?
  private var rounds: UInt64 = 0
  init(
    burst: UInt64, period: UInt64, startBudget: UInt64, serviceMS: UInt64,
    clock: V4TrustedClock
  ) throws {
    guard burst > 0, burst < 65_536, period > 0, period <= UInt32.max,
      startBudget > 0, startBudget <= UInt32.max, serviceMS > 0,
      period + startBudget + 45_000 < 86_400_000
    else { throw V4CryptoFailure.configuration }
    let d = UInt128(clock.profile.rateDenominator)
    let n = UInt128(clock.profile.rateNumerator)
    guard d > n else { throw V4CryptoFailure.configuration }
    func mul(_ a: UInt128, _ b: UInt128) throws -> UInt128 {
      let (v, overflow) = a.multipliedReportingOverflow(by: b)
      guard !overflow else { throw V4CryptoFailure.capacity }
      return v
    }
    func add(_ a: UInt128, _ b: UInt128) throws -> UInt128 {
      let (v, overflow) = a.addingReportingOverflow(b)
      guard !overflow else { throw V4CryptoFailure.capacity }
      return v
    }
    let uncertainty = try mul(mul(UInt128(clock.profile.quantizationMS), 2), d)
    let e = try add(add(uncertainty / (d - n), uncertainty % (d - n) == 0 ? 0 : 1), 1)
    let cost = try mul(UInt128(burst), e)
    guard UInt128(period) > cost else { throw V4CryptoFailure.configuration }
    let capacity = UInt128(burst) * UInt128(period)
    let numerator = try add(
      mul(capacity, d - n), mul(mul(UInt128(burst), d + n), UInt128(serviceMS)))
    let denominator = try mul(UInt128(period) - cost, d - n)
    let maximum = numerator / denominator
    guard maximum > 0, maximum < 65_536 else { throw V4CryptoFailure.configuration }
    self.burst = burst
    self.period = period
    self.startBudget = startBudget
    maximumRounds = UInt64(maximum)
    balance = UInt64(capacity)
    self.clock = clock
  }
  func available(server: Bool) throws -> UInt64 {
    guard let anchor else { return balance }
    let now = try clock.mark()
    guard now.sameEra(as: anchor), now.milliseconds >= anchor.milliseconds else {
      throw V4TimeFailure.continuity
    }
    let elapsed = try clock.profile.elapsed(now.milliseconds - anchor.milliseconds)
    let delta = server ? elapsed.upperMS : elapsed.lowerMS
    let capacity = burst * period
    if delta >= period { return capacity }
    return min(capacity, balance + burst * delta)
  }
  mutating func charge(server: Bool) throws -> UInt64 {
    let credit = try available(server: server)
    guard rounds < maximumRounds, credit >= period else { throw V4CryptoFailure.capacity }
    rounds += 1
    return credit - period
  }
  mutating func complete(_ post: UInt64) throws {
    balance = post
    anchor = try clock.mark()
  }
}

// Pure transcript math has no way to construct an established owner. The
// coordinator below supplies roots only through the original READY capability.
enum V4RekeyMaterial {
  static func domain(
    _ label: String, profile: V4CryptoProfile, hash: Data, context: Data, epoch: UInt32
  ) -> Data {
    V4Crypto.domain(label, [Data(profile.rawValue.utf8), hash, context])
      + V4Crypto.integer(UInt64(epoch), width: 4)
  }
  static func domain(_ label: String, access: V4ReliableSessionAdmission, epoch: UInt32) -> Data {
    domain(label, profile: access.profile, hash: access.hash, context: access.context, epoch: epoch)
  }
  static func confirmation(
    base: SymmetricKey, profile: V4CryptoProfile, hash: Data, context: Data,
    epoch: UInt32, id: Data, phase: UInt8, unsigned: Data
  ) throws -> Data {
    guard epoch < UInt32.max, (1...4).contains(phase), id.count == 16 else {
      throw V4CryptoFailure.configuration
    }
    let role = (phase + 1) % 2
    let keyInfo =
      domain("rekey-confirm-key", profile: profile, hash: hash, context: context, epoch: epoch)
      + V4Crypto.integer(UInt64(epoch + 1), width: 4) + V4Crypto.lp(id) + Data([phase, role])
    let message =
      domain("rekey-confirm-mac", profile: profile, hash: hash, context: context, epoch: epoch)
      + V4Crypto.integer(UInt64(epoch + 1), width: 4) + Data([phase, role]) + V4Crypto.lp(unsigned)
    return V4Crypto.mac(V4Crypto.expand(base, info: keyInfo), message)
  }
  static func transcript(
    _ label: String, hash: Data, profile: V4CryptoProfile, epoch: UInt32,
    initial: Data, reply: Data? = nil
  ) -> Data {
    V4Crypto.hash(
      V4Crypto.domain(label, [hash, Data(profile.rawValue.utf8)])
        + V4Crypto.integer(UInt64(epoch), width: 4) + V4Crypto.lp(initial)
        + (reply.map(V4Crypto.lp) ?? Data()))
  }
}

final class V4RekeyCoordinator {
  private final class Round {
    let epoch: UInt32
    let id: Data
    let secret: SymmetricKey
    var ephemeral: V4SoftwareDH?
    var candidate: SymmetricKey?
    let post: UInt64
    var initial = Data()
    var reply = Data()
    var initDigest = Data()
    var transcript = Data()
    var outgoing: [V4RekeyBarrier] = []
    var incoming: [V4RekeyBarrier] = []
    var stage: UInt8 = 1
    init(epoch: UInt32, id: Data, secret: SymmetricKey, ephemeral: V4SoftwareDH?, post: UInt64) {
      self.epoch = epoch
      self.id = id
      self.secret = secret
      self.ephemeral = ephemeral
      self.post = post
    }
    deinit { ephemeral?.close() }
  }
  private let access: V4ReliableSessionAdmission
  private let registry: V4NamespaceRegistry
  private let liveness: V4LivenessState
  private let phaseBytes: Int
  private var credit: V4RekeyCredit
  private var round: Round?
  private var intent: V4LocalWorkWindow?
  private var deadline: V4LocalWorkWindow?
  private var requested = false
  private var timeoutRecorded = false
  private var clock: V4TrustedClock { access.environment.clock }
  init(
    _ access: V4ReliableSessionAdmission, registry: V4NamespaceRegistry, liveness: V4LivenessState
  ) throws {
    self.access = access
    self.registry = registry
    self.liveness = liveness
    phaseBytes = 268 + 21 * access.maxStreams
    guard phaseBytes + 36 <= access.maxFrame, 2 * phaseBytes + 3 <= 65_536 else {
      throw V4CryptoFailure.configuration
    }
    let envelope = try V4NamespaceDocument(
      access.rekeyEnvelope, schema: "RekeyEnvelope",
      bytes: 128, nodes: 32, registry: registry
    ).root
    credit = try V4RekeyCredit(
      burst: envelope.u("burst_rounds"), period: envelope.u("refill_period_ms"),
      startBudget: envelope.u("request_start_budget_ms"), serviceMS: access.serviceMS,
      clock: access.environment.clock)
    let calls = UInt64(6 * access.maxStreams + 32)
    let bytes = calls * 4096 + UInt64(2 * phaseBytes)
    try access.channel.rekeyConfigure(
      access,
      margin: V4CryptoUsage(
        seals: calls, opens: calls,
        blocks: (bytes + 15) / 16 + calls * 9, ciphertextBytes: bytes + calls * 16))
  }
  func check() throws {
    do { try intent?.check(); try deadline?.check() }
    catch {
      if (error as? V4TimeFailure) == .expired && !timeoutRecorded {
        timeoutRecorded = true
        let counter: TransportDiagnosticCounter
        if let round {
          counter = round.stage <= 1 ? .rekeyReplyTimeout : round.stage == 2 ? .rekeyCommitTimeout : .rekeyAckTimeout
        } else { counter = requested ? .rekeyInitTimeout : .rekeyRequestTimeout }
        access.environment.root.diagnosticCounters.increment(counter)
      }
      throw error
    }
  }
  var frozen: Bool { round != nil }
  func rememberIntent() throws {
    if intent == nil && round == nil {
      intent = try V4LocalWorkWindow(clock: clock, durationMS: credit.period + credit.startBudget)
      timeoutRecorded = false
      access.environment.root.diagnosticCounters.increment(.rekeyStarted)
      liveness.beginRekey()
    }
  }
  private func u(_ value: UInt64) -> Data { V4NamespaceValue.head(0, value) }
  private func schema(_ phase: UInt8) throws -> String {
    guard phase <= 4 else { throw V4CryptoFailure.authentication }
    return ["REKEY_REQUEST", "REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK"][Int(phase)]
  }
  private func decode(_ body: Data, phase: UInt8) throws -> V4NamespaceValue {
    try V4NamespaceDocument(
      body, schema: schema(phase), bytes: phaseBytes, nodes: 8192,
      registry: registry, context: ["crypto_profile_id": access.profile.rawValue]
    ).root
  }
  private func mac(_ round: Round, phase: UInt8, unsigned: Data) throws -> Data {
    let base: SymmetricKey
    if phase < 3 {
      base = round.secret
    } else {
      guard let root = round.candidate else { throw V4CryptoFailure.phase }
      base = root
    }
    return try V4RekeyMaterial.confirmation(
      base: base, profile: access.profile, hash: access.hash,
      context: access.context, epoch: round.epoch, id: round.id, phase: phase, unsigned: unsigned)
  }
  private func body(_ round: Round, phase: UInt8, frontier: UInt64 = 0) throws -> Data {
    var fields: [(UInt64, Data)] = [
      (0, u(UInt64(phase))), (1, V4Crypto.bytes(round.id)),
      (2, u(UInt64(round.epoch + 1))),
    ]
    if phase <= 2 {
      guard let ephemeral = round.ephemeral else { throw V4CryptoFailure.phase }
      let entries =
        V4NamespaceValue.head(4, UInt64(round.outgoing.count))
        + round.outgoing.reduce(Data()) { $0 + $1.encoded }
      if phase == 2 { fields.append((3, V4Crypto.bytes(round.initDigest))) }
      fields.append((phase == 1 ? 3 : 4, V4Crypto.bytes(ephemeral.publicKey)))
      fields.append((phase == 1 ? 4 : 5, entries))
    } else {
      fields.append((3, V4Crypto.bytes(round.transcript)))
      fields.append((4, u(frontier)))
    }
    fields.append(
      (
        phase == 2 ? 6 : 5,
        V4Crypto.bytes(try mac(round, phase: phase, unsigned: V4Crypto.map(fields)))
      ))
    let encoded = V4Crypto.map(fields)
    guard encoded.count <= phaseBytes else { throw V4CryptoFailure.capacity }
    return encoded
  }
  private func verify(_ v: V4NamespaceValue, round: Round, phase: UInt8) throws {
    guard try v.b("rekey_id") == round.id, try v.u("next_epoch") == UInt64(round.epoch + 1) else {
      throw V4CryptoFailure.authentication
    }
    let expected = try mac(round, phase: phase, unsigned: v.excluding(phase == 2 ? 6 : 5))
    let actual = try v.b("confirmation_mac")
    guard actual.count == expected.count,
      zip(actual, expected).reduce(UInt8(0), { $0 | ($1.0 ^ $1.1) }) == 0
    else {
      throw V4CryptoFailure.authentication
    }
  }
  private func barrier(
    _ value: V4NamespaceValue, phase: UInt8, owner: V4ReliableSession, epoch: UInt32
  )
    throws -> [V4RekeyBarrier]
  {
    let array = try value.field(phase == 1 ? "client_barrier" : "server_barrier")
    guard array.count <= access.maxStreams else { throw V4CryptoFailure.capacity }
    var entries: [V4RekeyBarrier] = []
    for item in array.children {
      let id = try item.u("scope_id")
      let next = try item.u("next_sequence")
      guard V4ReliableSession.valid(id), id > (entries.last?.scope ?? 0) else {
        throw V4CryptoFailure.authentication
      }
      _ = try owner.rekeyBarrier(access, scope: id, epoch: epoch, next: next, new: true)
      entries.append(V4RekeyBarrier(scope: id, next: next))
    }
    for entry in entries { try owner.rekeyHold(access, scope: entry.scope, outgoing: false) }
    return entries
  }
  private func stage(_ round: Round, peer: Data) throws {
    guard let ephemeral = round.ephemeral else { throw V4CryptoFailure.phase }
    round.transcript = V4RekeyMaterial.transcript(
      "rekey-transcript", hash: access.hash,
      profile: access.profile, epoch: round.epoch, initial: round.initial, reply: round.reply)
    var shared = try ephemeral.shared(peer)
    defer {
      V4Crypto.wipe(&shared)
      ephemeral.close()
      round.ephemeral = nil
    }
    var extracted = V4Crypto.mac(round.secret, shared)
    defer { V4Crypto.wipe(&extracted) }
    let info =
      V4RekeyMaterial.domain("rekey-root", access: access, epoch: round.epoch)
      + V4Crypto.integer(UInt64(round.epoch + 1), width: 4) + V4Crypto.lp(round.id)
      + V4Crypto.lp(round.transcript)
    let root = V4Crypto.expand(SymmetricKey(data: extracted), info: info)
    round.candidate = root
    try access.channel.rekeyStage(access, root: root)
  }
  private func newRound(id: Data, server: Bool, owner: V4ReliableSession) throws -> Round {
    let state = try access.channel.rekeyState(access)
    guard round == nil, state.epoch < 65_535 else { throw V4CryptoFailure.phase }
    liveness.beginRekey()
    let generationWindow = try V4LocalWorkWindow(clock: clock, durationMS: 5000)
    let result = try Round(
      epoch: state.epoch, id: id, secret: access.channel.rekeySecret(access),
      ephemeral: V4SoftwareDH.generate(access.profile), post: credit.charge(server: server))
    try generationWindow.check()
    try access.channel.rekeyFreeze(access)
    result.outgoing = try owner.rekeySnapshot(access, epoch: state.epoch)
    deadline = try V4LocalWorkWindow(clock: clock, durationMS: 10_000)
    if intent == nil { access.environment.root.diagnosticCounters.increment(.rekeyStarted) }
    timeoutRecorded = false
    intent?.cancel()
    intent = nil
    return result
  }
  private func send(_ body: Data, marker: Bool, publisher: any V4RecordPublisher) throws {
    try access.channel.publish(
      scope: access.channel.maintenance, frameType: 6, plaintext: body,
      to: publisher, access: access, marker: marker, critical: true)
    if marker { try access.channel.rekeyMarker(access, sent: true) }
  }
  private func finish(_ round: Round, owner: V4ReliableSession) throws {
    let epoch = try access.channel.rekeyFinish(access)
    for entry in round.outgoing + round.incoming {
      try owner.rekeyRelease(access, scope: entry.scope)
    }
    try owner.rekeyInstall(access, epoch: epoch)
    try credit.complete(round.post)
    self.round = nil
    requested = false
    deadline?.cancel()
    deadline = nil
    liveness.completeRekey()
    access.environment.root.diagnosticCounters.increment(.rekeySucceeded)
  }
  @discardableResult func poll(owner: V4ReliableSession, to publisher: any V4RecordPublisher) throws
    -> Bool
  {
    try check()
    if round == nil {
      if try access.channel.rekeySafetyDue(
        access, waitMS: credit.period + credit.startBudget + 45_000)
      {
        try rememberIntent()
      }
      guard intent != nil else { return false }
      if access.role == .server {
        guard !requested else { return false }
        try send(Data([0xa1, 0, 0]), marker: false, publisher: publisher)
        requested = true
        return true
      }
      guard try credit.available(server: false) >= credit.period else { return false }
      let round = try newRound(id: V4Crypto.random(16), server: false, owner: owner)
      round.initial = try body(round, phase: 1)
      round.initDigest = V4RekeyMaterial.transcript(
        "rekey-init-digest", hash: access.hash,
        profile: access.profile, epoch: round.epoch, initial: round.initial)
      self.round = round
      try send(round.initial, marker: false, publisher: publisher)
      for entry in round.outgoing { try owner.rekeyPublished(access, scope: entry.scope) }
      return true
    }
    let round = round!
    let phase: UInt8
    switch (access.role, round.stage) {
    case (.server, 1): phase = 2
    case (.client, 2): phase = 3
    case (.server, 3): phase = 4
    default: return false
    }
    if phase != 4 {
      for entry in round.incoming {
        if try !owner.rekeyBarrier(
          access, scope: entry.scope, epoch: round.epoch, next: entry.next, new: false)
        {
          return false
        }
      }
    }
    let state = try access.channel.rekeyState(access)
    let message = try phase == 2 ? round.reply : body(round, phase: phase, frontier: state.sendNext)
    try access.channel.rekeyArm(access)
    round.stage = phase
    if phase == 3 { deadline = try V4LocalWorkWindow(clock: clock, durationMS: 30_000) }
    try send(message, marker: phase >= 3, publisher: publisher)
    if phase == 2 {
      for entry in round.outgoing { try owner.rekeyPublished(access, scope: entry.scope) }
    } else if phase == 4 {
      try finish(round, owner: owner)
    }
    return true
  }
  func markerForInput(_ wire: Data) throws -> Bool {
    let state = try access.channel.rekeyState(access)
    return V4Crypto.number(wire[8..<12]) == UInt64(state.epoch) + 1
  }
  func receive(_ record: V4AuthenticatedRecord, body bytes: Data, owner: V4ReliableSession) throws {
    try check()
    let state = try access.channel.rekeyState(access)
    if bytes == Data([0xa1, 0, 0]), access.role == .client, record.epoch == state.epoch {
      try rememberIntent()
      return
    }
    let phase: UInt8
    switch (access.role, round?.stage) {
    case (.server, nil): phase = 1
    case (.client, 1): phase = 2
    case (.server, 2): phase = 3
    case (.client, 3): phase = 4
    default: throw V4CryptoFailure.phase
    }
    guard record.epoch == state.epoch + (phase >= 3 ? 1 : 0),
      phase < 3 || record.sequence == 0
    else { throw V4CryptoFailure.authentication }
    let value = try decode(bytes, phase: phase)
    if phase == 1 {
      // A temporary transcript holder carries no live round or barrier authority.
      let id = try value.b("rekey_id")
      let temp = try Round(
        epoch: state.epoch, id: id, secret: access.channel.rekeySecret(access),
        ephemeral: nil, post: 0)
      try verify(value, round: temp, phase: 1)
      temp.ephemeral?.close()
      let round = try newRound(id: id, server: true, owner: owner)
      round.initial = bytes
      round.initDigest = V4RekeyMaterial.transcript(
        "rekey-init-digest", hash: access.hash,
        profile: access.profile, epoch: round.epoch, initial: bytes)
      round.incoming = try barrier(value, phase: 1, owner: owner, epoch: round.epoch)
      round.reply = try body(round, phase: 2)
      try stage(round, peer: value.b("client_ephemeral"))
      self.round = round
    } else {
      guard let round else { throw V4CryptoFailure.phase }
      try verify(value, round: round, phase: phase)
      if phase == 2 {
        guard try value.b("init_digest") == round.initDigest else {
          throw V4CryptoFailure.authentication
        }
        round.incoming = try barrier(value, phase: 2, owner: owner, epoch: round.epoch)
        round.reply = bytes
        try stage(round, peer: value.b("server_ephemeral"))
        try access.channel.rekeyArm(access)
        round.stage = 2
      } else {
        guard try value.b("transcript_digest") == round.transcript,
          try value.u("old_maintenance_next_sequence") == state.receiveNext
        else {
          throw V4CryptoFailure.authentication
        }
        try access.channel.rekeyMarker(access, sent: false)
        round.stage = phase
        if phase == 3 {
          deadline = try V4LocalWorkWindow(clock: clock, durationMS: 30_000)
        } else {
          try finish(round, owner: owner)
        }
      }
    }
  }
  func checkIncomingFrontier(scope: UInt64, epoch: UInt32, next: UInt64) throws {
    guard let round, epoch == round.epoch else { return }
    let known = access.role == .server || round.stage >= 2
    guard !known || round.incoming.contains(where: { $0.scope == scope && next <= $0.next }) else {
      throw V4CryptoFailure.authentication
    }
  }
  func awaiting(_ scope: UInt64) -> Bool {
    round?.incoming.contains { $0.scope == scope && $0.next == 1 } == true
  }
  func barrierReferences(_ scope: UInt64) -> Int {
    round?.incoming.filter { $0.scope == scope }.count ?? 0
  }
  func close() {
    intent?.cancel()
    deadline?.cancel()
    intent = nil
    deadline = nil
    round = nil
  }
}
