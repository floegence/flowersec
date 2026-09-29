import Crypto
import Foundation

struct V4CryptoUsage: Equatable, Sendable {
  var seals: UInt64 = 0
  var opens: UInt64 = 0
  var blocks: UInt64 = 0
  var ciphertextBytes: UInt64 = 0
  static func delta(seal: Bool, aadBytes: UInt64, inputBytes: UInt64) throws -> Self {
    guard seal || inputBytes >= 16 else { throw V4CryptoFailure.authentication }
    let payload = seal ? inputBytes : inputBytes - 16
    func add(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
      let (value, overflow) = a.addingReportingOverflow(b)
      guard !overflow else { throw V4CryptoFailure.capacity }
      return value
    }
    let ciphertext = try seal ? add(inputBytes, 16) : inputBytes
    let blocks = try add(
      add(
        aadBytes / 16 + (aadBytes % 16 == 0 ? 0 : 1),
        payload / 16 + (payload % 16 == 0 ? 0 : 1)), 1)
    return Self(
      seals: seal ? 1 : 0, opens: seal ? 0 : 1, blocks: blocks, ciphertextBytes: ciphertext)
  }
  func adding(_ other: Self) throws -> Self {
    func add(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
      let (value, overflow) = a.addingReportingOverflow(b)
      guard !overflow else { throw V4CryptoFailure.capacity }
      return value
    }
    return try Self(
      seals: add(seals, other.seals), opens: add(opens, other.opens),
      blocks: add(blocks, other.blocks),
      ciphertextBytes: add(ciphertextBytes, other.ciphertextBytes))
  }
  func fits(_ limit: Self) -> Bool {
    seals <= limit.seals && opens <= limit.opens && blocks <= limit.blocks
      && ciphertextBytes <= limit.ciphertextBytes
  }
  static func limits(_ profile: V4CryptoProfile) -> (key: Self, epoch: Self, session: Self) {
    let shift = profile == .x25519 ? 1 : 0
    return (
      Self(seals: 1 << 20, opens: 1 << 20, blocks: 1 << (31 + shift), ciphertextBytes: 1 << 36),
      Self(
        seals: 1 << (30 + shift), opens: 1 << (30 + shift), blocks: 1 << (41 + shift),
        ciphertextBytes: 1 << (45 + shift)),
      Self(
        seals: 1 << (35 + shift), opens: 1 << (35 + shift), blocks: 1 << (51 + shift),
        ciphertextBytes: 1 << (55 + shift))
    )
  }
}

// A scope exists only after explicit admission by its original channel. Peer
// headers never allocate a scope, derive a key, or reset a retired sequence.
struct V4RecordScope: Sendable {
  fileprivate let channel: V4ReliableChannel
  fileprivate let slot: Int
  let number: UInt64
}

protocol V4RecordPublisher {
  func publish(_ buffer: V4CryptoBuffer) throws
  func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws
}
extension V4RecordPublisher {
  // Synchronous providers complete the original handoff on return. Native
  // asynchronous providers must override this to retain the real callback.
  func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws {
    do {
      try publish(buffer)
      completion(true)
    } catch {
      completion(false)
      throw error
    }
  }
}

final class V4AuthenticatedRecord: @unchecked Sendable {
  let frameType: UInt8
  let scope: UInt64
  let sequence: UInt64
  let epoch: UInt32
  private let payload: V4CryptoBuffer
  fileprivate init(
    frameType: UInt8, scope: UInt64, sequence: UInt64, epoch: UInt32, payload: V4CryptoBuffer
  ) {
    self.frameType = frameType
    self.scope = scope
    self.sequence = sequence
    self.epoch = epoch
    self.payload = payload
  }
  func withBytes<T>(_ body: (Data) throws -> T) throws -> T { try payload.withBytes(body) }
  func close() { payload.close() }
}

enum V4RecordMaterial {
  static func key(
    root: SymmetricKey, profile: V4CryptoProfile, hash: Data, epoch: UInt32,
    direction: V4CryptoRole, scope: UInt64
  ) -> SymmetricKey {
    V4Crypto.expand(
      root,
      info: V4Crypto.domain("record-key", [Data(profile.rawValue.utf8), hash])
        + V4Crypto.integer(UInt64(epoch), width: 4) + Data([direction.rawValue])
        + V4Crypto.integer(scope, width: 8))
  }
  static func aad(profile: V4CryptoProfile, envelope: Data, header: Data, direction: V4CryptoRole)
    -> Data
  {
    Data("flowersec/v4/record-aad\0".utf8) + envelope + header
      + V4Crypto.lp(Data(profile.rawValue.utf8)) + Data([direction.rawValue])
  }
  static func nonce(epoch: UInt32, sequence: UInt64) -> Data {
    V4Crypto.integer(UInt64(epoch), width: 4) + V4Crypto.integer(sequence, width: 8)
  }
}

// Only this file can mint the one-use READY-to-Session access capability.
// Raw record aliases lose mutation authority when the Session claims the owner.
final class V4ReliableSessionAdmission {
  let channel: V4ReliableChannel
  let environment: V4EnvironmentFoundation
  let role: V4CryptoRole
  let profile: V4CryptoProfile
  let hash: Data
  let maxFrame: Int
  let maxStreams: Int
  let maxCredit: UInt64
  let applicationProfile: UInt64
  let rekeyEnvelope: Data
  let context: Data
  let serviceMS: UInt64
  let streamStorage: V4CryptoReservation?
  private var claimed = false
  fileprivate init(channel: V4ReliableChannel, established: V4EstablishedAdmission) {
    self.channel = channel
    environment = established.owner.environment
    role = established.role
    profile = established.profile
    hash = established.hash
    maxFrame = established.maxFrame
    maxStreams = established.maxStreams
    maxCredit = established.maxCredit
    applicationProfile = established.applicationProfile
    rekeyEnvelope = established.rekeyEnvelope
    context = established.context
    serviceMS = established.serviceMS
    streamStorage = established.streamStorage
  }
  func claim() throws {
    guard !claimed else { throw V4CryptoFailure.phase }
    claimed = true
  }
}

// This established internal capability proves local Noise and both READYs. It
// does not assert actual TLS/provider identity, durable spend, datagrams or the
// public Session lifecycle. Reliable stream and rekey owners consume it once.
final class V4ReliableChannel: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
  private struct KeyState {
    var key: SymmetricKey?
    var next: UInt64 = 0
    var usage = V4CryptoUsage()
  }
  private final class Scope {
    let number: UInt64
    var retired = false
    var send: KeyState
    var receive: KeyState
    init(number: UInt64, send: KeyState, receive: KeyState) {
      self.number = number
      self.send = send
      self.receive = receive
    }
  }
  private final class Candidate {
    let root: SymmetricKey
    let born: V4ClockSample
    let deadline: V4SecurityDeadline
    var scopes: [Scope]
    var usage = V4CryptoUsage()
    var armed = false
    var sent = false
    var received = false
    init(root: SymmetricKey, born: V4ClockSample, deadline: V4SecurityDeadline, scopes: [Scope]) {
      self.root = root
      self.born = born
      self.deadline = deadline
      self.scopes = scopes
    }
  }
  private let owner: V4CryptoReservation
  private let credential: V4CredentialAdmission
  private let profile: V4CryptoProfile
  private let role: V4CryptoRole
  private let hash: Data
  private var born: V4ClockSample
  private var rootDeadline: V4SecurityDeadline
  private let maxFrame: Int
  private let maxScopes: Int
  private var root: SymmetricKey?
  private var scopes: [Scope] = []
  private var used = [UInt8](repeating: 0, count: 524_292)
  private var established: V4EstablishedAdmission?
  private weak var sessionAccess: V4ReliableSessionAdmission?
  private var sessionClaimed = false
  private var epochUsage = V4CryptoUsage()
  private var sessionUsage = V4CryptoUsage()
  private var keyDerivations: UInt64 = 0
  private var busy = false
  private var closed = false
  private var epoch: UInt32 = 0
  private var candidate: Candidate?
  private var frozen = false
  private var protectedMargin = V4CryptoUsage()
  var description: String { "Flowersec.ReliableChannel(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
  var maintenance: V4RecordScope { V4RecordScope(channel: self, slot: 0, number: 0) }

  init(_ admission: V4EstablishedAdmission) throws {
    owner = admission.owner
    credential = admission.credential
    profile = admission.profile
    role = admission.role
    hash = admission.hash
    born = admission.born
    maxFrame = admission.maxFrame
    maxScopes = min(2 * admission.maxStreams + 128, 4096) + 129
    established = admission
    root = try admission.takeRoot()
    guard let lower = born.interval?.lowerMS else { throw V4TimeFailure.unavailable }
    let (cap, overflow) = lower.addingReportingOverflow(86_400_000)
    guard !overflow else { throw V4TimeFailure.unavailable }
    rootDeadline = try V4SecurityDeadline(clock: owner.environment.clock, capMS: cap)
    scopes.reserveCapacity(maxScopes)
    _ = try install(0)

    try check()
  }
  private func authorize(_ access: V4ReliableSessionAdmission?) throws {
    guard !sessionClaimed || (access != nil && access === sessionAccess) else {
      throw V4CryptoFailure.phase
    }
  }
  func makeSession() throws -> V4ReliableSession {
    try owner.environment.gate.withLock {
      try check()
      guard !busy, !sessionClaimed, scopes.count == 1, let established else {
        throw V4CryptoFailure.phase
      }
      let access = V4ReliableSessionAdmission(channel: self, established: established)
      sessionClaimed = true
      sessionAccess = access
      self.established = nil
      do { return try V4ReliableSession(access) } catch {
        close()
        throw error
      }
    }
  }
  func wasUsed(_ number: UInt64, access: V4ReliableSessionAdmission) throws -> Bool {
    try authorize(access)
    try check()
    guard number <= 4_194_335 else { return false }
    return used[Int(number / 8)] & (1 << (number % 8)) != 0
  }
  func checkSession(_ access: V4ReliableSessionAdmission) throws {
    try authorize(access)
    try check()
  }
  func frontier(_ scope: V4RecordScope, sending: Bool, access: V4ReliableSessionAdmission) throws
    -> (epoch: UInt32, next: UInt64)
  {
    try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      let i = try slot(scope)
      let future = sending ? candidate?.sent == true : candidate?.received == true
      let active = future ? candidate!.scopes : scopes
      return (epoch + (future ? 1 : 0), sending ? active[i].send.next : active[i].receive.next)
    }
  }
  private func check() throws {
    guard !closed, root != nil else { throw V4CryptoFailure.closed }
    try owner.check()
    try credential.checkSessionAuthorization(in: owner.environment)
    try rootDeadline.check()
    try candidate?.deadline.check()
    let now = owner.environment.clock.sample()
    guard let nowMark = now.mark, let bornMark = born.mark, nowMark.sameEra(as: bornMark),
      let current = now.interval, let original = born.interval,
      current.upperMS >= original.lowerMS, current.upperMS - original.lowerMS < 86_400_000
    else { throw now.failure ?? V4TimeFailure.continuity }
  }
  private func install(_ number: UInt64) throws -> V4RecordScope {
    try check()
    guard number <= 4_194_335, used[Int(number / 8)] & (1 << (number % 8)) == 0,
      scopes.count < maxScopes || scopes.contains(where: { $0.retired }),
      keyDerivations <= (1 << 28) - 2
    else { throw V4CryptoFailure.capacity }
    keyDerivations += 2
    let send = V4RecordMaterial.key(
      root: root!, profile: profile, hash: hash, epoch: epoch, direction: role, scope: number)
    let receive = V4RecordMaterial.key(
      root: root!, profile: profile, hash: hash, epoch: epoch, direction: role.peer, scope: number)
    used[Int(number / 8)] |= 1 << (number % 8)
    let scope = Scope(number: number, send: KeyState(key: send), receive: KeyState(key: receive))
    let index: Int
    if let free = scopes.firstIndex(where: { $0.retired }) {
      scopes[free] = scope
      index = free
    } else {
      index = scopes.count
      scopes.append(scope)
    }
    if let candidate {
      guard keyDerivations <= (1 << 28) - 2 else { throw V4CryptoFailure.capacity }
      keyDerivations += 2
      let future = Scope(
        number: number,
        send: KeyState(
          key: V4RecordMaterial.key(
            root: candidate.root, profile: profile, hash: hash,
            epoch: epoch + 1, direction: role, scope: number)),
        receive: KeyState(
          key: V4RecordMaterial.key(
            root: candidate.root, profile: profile, hash: hash,
            epoch: epoch + 1, direction: role.peer, scope: number)))
      if index < candidate.scopes.count {
        candidate.scopes[index] = future
      } else {
        candidate.scopes.append(future)
      }
    }
    return V4RecordScope(channel: self, slot: index, number: number)
  }
  func admitReliableScope(_ number: UInt64, access: V4ReliableSessionAdmission? = nil) throws
    -> V4RecordScope
  {
    try owner.environment.gate.withLock {
      try authorize(access)
      guard !busy, number > 0, number <= 4_194_335,
        number & 1 != 0 || number / 2 <= 2_097_152
      else { throw V4CryptoFailure.configuration }
      return try install(number)
    }
  }
  func retire(_ scope: V4RecordScope, access: V4ReliableSessionAdmission? = nil) throws {
    try owner.environment.gate.withLock {
      guard !busy else { throw V4CryptoFailure.phase }
      try authorize(access)
      let index = try slot(scope)
      guard scope.number != 0 else { throw V4CryptoFailure.configuration }
      scopes[index].retired = true
      scopes[index].send.key = nil
      scopes[index].receive.key = nil
      if let candidate {
        candidate.scopes[index].retired = true
        candidate.scopes[index].send.key = nil
        candidate.scopes[index].receive.key = nil
      }
    }
  }
  private func slot(_ scope: V4RecordScope) throws -> Int {
    guard scope.channel === self, scopes.indices.contains(scope.slot),
      scopes[scope.slot].number == scope.number, !scopes[scope.slot].retired
    else { throw V4CryptoFailure.phase }
    return scope.slot
  }
  private func frame(_ type: UInt8, scope: UInt64) throws {
    let valid =
      scope == 0 ? [UInt8(6), 9, 11, 12, 13, 14, 15].contains(type) : [UInt8(7), 8].contains(type)
    guard valid else { throw V4CryptoFailure.configuration }
  }
  private func charge(
    index: Int, seal: Bool, aad: Int, input: Int, future: Bool = false,
    critical: Bool = false
  ) throws {
    let active = future ? candidate!.scopes : scopes
    let delta = try V4CryptoUsage.delta(
      seal: seal, aadBytes: UInt64(aad), inputBytes: UInt64(input))
    let current = seal ? active[index].send.usage : active[index].receive.usage
    let next = try current.adding(delta)
    let epochTotal = try (future ? candidate!.usage : epochUsage).adding(delta)
    let session = try sessionUsage.adding(delta)
    let limits = V4CryptoUsage.limits(profile)
    guard next.fits(limits.key), epochTotal.fits(limits.epoch), session.fits(limits.session) else {
      throw V4CryptoFailure.capacity
    }
    if seal && !critical {
      guard try epochTotal.adding(protectedMargin).fits(limits.epoch),
        try session.adding(protectedMargin).fits(limits.session),
        try active[index].number != 0 || next.adding(protectedMargin).fits(limits.key)
      else {
        throw V4CryptoFailure.capacity
      }
    }
    if seal { active[index].send.usage = next } else { active[index].receive.usage = next }
    if future { candidate!.usage = epochTotal } else { epochUsage = epochTotal }
    sessionUsage = session
  }
  func usage() -> (epoch: V4CryptoUsage, session: V4CryptoUsage, derivations: UInt64) {
    owner.environment.gate.withLock { (epochUsage, sessionUsage, keyDerivations) }
  }
  func publish(
    scope: V4RecordScope, frameType: UInt8, plaintext: Data, to publisher: any V4RecordPublisher,
    access: V4ReliableSessionAdmission? = nil, marker: Bool = false, critical: Bool = false,
    publication: (any V4RecordPublication)? = nil
  ) throws {
    var publicationTransferred = false
    do {
      try owner.environment.gate.withLock {
        guard !busy else { throw V4CryptoFailure.phase }
        try authorize(access)
        busy = true
        defer { busy = false }
        do {
          try check()
          let index = try slot(scope)
          let future = marker || candidate?.sent == true
          if frozen && !critical && !(scope.number == 0 && frameType == 15) {
            throw V4CryptoFailure.phase
          }
          guard !future || candidate != nil else { throw V4CryptoFailure.phase }
          let active = future ? candidate!.scopes : scopes
          let generation = epoch + (future ? 1 : 0)
          if future && scope.number == 0 && active[index].send.next == 0 && !marker {
            throw V4CryptoFailure.phase
          }
          if marker {
            guard candidate?.armed == true, scope.number == 0, frameType == 6,
              active[index].send.next == 0
            else { throw V4CryptoFailure.phase }
          }
          try frame(frameType, scope: scope.number)
          guard plaintext.count <= maxFrame - 36, active[index].send.next < .max,
            let key = active[index].send.key
          else { throw V4CryptoFailure.capacity }
          let output = try owner.environment.cryptoBuffer(capacity: plaintext.count + 44)
          let sequence = active[index].send.next
          let envelope =
            V4Crypto.integer(UInt64(plaintext.count + 36), width: 4) + Data([frameType, 0, 0, 0])
          let header =
            V4Crypto.integer(UInt64(generation), width: 4)
            + V4Crypto.integer(scope.number, width: 8) + V4Crypto.integer(sequence, width: 8)
          let aad = V4RecordMaterial.aad(
            profile: profile, envelope: envelope, header: header, direction: role)
          // Nonrefundable precharge and sequence reservation precede actual AEAD.
          try charge(
            index: index, seal: true, aad: aad.count, input: plaintext.count, future: future,
            critical: critical)
          active[index].send.next += 1
          publication?.ticket(epoch: generation)
          try check()
          let cipher = try V4Crypto.seal(
            profile, key: key,
            nonce: V4RecordMaterial.nonce(epoch: generation, sequence: sequence), aad: aad,
            plaintext: plaintext)
          try check()
          try output.store(envelope + header + cipher)
          if let publication {
            publicationTransferred = true
            try publisher.publish(output) { success in publication.completed(success) }
          } else {
            try publisher.publish(output)
          }
          try check()
        } catch {
          close()
          throw error
        }
      }
    } catch {
      if !publicationTransferred { publication?.completed(false) }
      throw error
    }
  }
  func receive(
    scope: V4RecordScope, wire input: Data, access: V4ReliableSessionAdmission? = nil,
    isolateFailure: Bool = false, marker: Bool = false
  ) throws -> V4AuthenticatedRecord {
    try owner.environment.gate.withLock {
      guard !busy else { throw V4CryptoFailure.phase }
      try authorize(access)
      busy = true
      defer { busy = false }
      do {
        try check()
        let index = try slot(scope)
        guard input.count >= 44, input.count - 8 <= maxFrame else {
          throw V4CryptoFailure.authentication
        }
        let wire = Data(input)
        let generation = V4Crypto.number(wire[8..<12])
        let future = generation == UInt64(epoch) + 1
        if future {
          guard let candidate, candidate.armed,
            marker
              ? (!candidate.received && scope.number == 0 && wire[4] == 6)
              : (scope.number == 0 ? candidate.received : candidate.sent)
          else { throw V4CryptoFailure.sequence }
        } else {
          guard generation == UInt64(epoch), !marker, candidate?.received != true else {
            throw V4CryptoFailure.sequence
          }
        }
        let active = future ? candidate!.scopes : scopes
        guard wire.count >= 44, wire.count - 8 <= maxFrame,
          V4Crypto.number(wire.prefix(4)) == UInt64(wire.count - 8),
          wire[5..<8].allSatisfy({ $0 == 0 }), V4Crypto.number(wire[8..<12]) == generation,
          V4Crypto.number(wire[12..<20]) == scope.number,
          let key = active[index].receive.key
        else { throw V4CryptoFailure.authentication }
        try frame(wire[4], scope: scope.number)
        let sequence = V4Crypto.number(wire[20..<28])
        guard sequence == active[index].receive.next, sequence < .max else {
          throw V4CryptoFailure.sequence
        }
        let output = try owner.environment.cryptoBuffer(
          capacity: wire.count - 44, credential: credential, delivery: { try self.check() })
        let aad = V4RecordMaterial.aad(
          profile: profile,
          envelope: Data(wire.prefix(8)), header: Data(wire[8..<28]), direction: role.peer)
        try charge(
          index: index, seal: false, aad: aad.count, input: wire.count - 28, future: future)
        try check()
        var plaintext = try V4Crypto.open(
          profile, key: key,
          nonce: V4RecordMaterial.nonce(epoch: UInt32(generation), sequence: sequence), aad: aad,
          ciphertext: Data(wire.dropFirst(28)))
        defer { V4Crypto.wipe(&plaintext) }
        try check()
        try output.store(plaintext)
        active[index].receive.next += 1
        return V4AuthenticatedRecord(
          frameType: wire[4], scope: scope.number, sequence: sequence, epoch: UInt32(generation),
          payload: output
        )
      } catch {
        if isolateFailure, access != nil, scope.number != 0,
          scope.channel === self, scopes.indices.contains(scope.slot),
          scopes[scope.slot].number == scope.number
        {
          scopes[scope.slot].receive.key = nil
        } else {
          close()
        }
        throw error
      }
    }
  }
  func close() {
    owner.environment.gate.withLock {
      guard !closed else { return }
      closed = true
      root = nil
      candidate?.deadline.cancel()
      candidate = nil
      for index in scopes.indices {
        scopes[index].send.key = nil
        scopes[index].receive.key = nil
        scopes[index].retired = true
      }
      rootDeadline.cancel()
      owner.seal()
    }
  }
  deinit { close() }
}

extension V4ReliableChannel {
  func rekeyConfigure(_ access: V4ReliableSessionAdmission, margin: V4CryptoUsage) throws {
    try authorize(access)
    try check()
    protectedMargin = margin
  }
  func rekeyState(_ access: V4ReliableSessionAdmission) throws
    -> (
      epoch: UInt32, frozen: Bool, sent: Bool, received: Bool, sendNext: UInt64, receiveNext: UInt64
    )
  {
    try authorize(access)
    try check()
    return (
      epoch, frozen, candidate?.sent == true, candidate?.received == true,
      scopes[0].send.next, scopes[0].receive.next
    )
  }
  func rekeyFreeze(_ access: V4ReliableSessionAdmission) throws {
    try authorize(access)
    try check()
    guard !frozen, epoch < 65_535 else { throw V4CryptoFailure.phase }
    frozen = true
  }
  func rekeySecret(_ access: V4ReliableSessionAdmission) throws -> SymmetricKey {
    try authorize(access)
    try check()
    return V4Crypto.expand(
      root!,
      info: V4Crypto.domain(
        "rekey-secret",
        [Data(profile.rawValue.utf8), hash, access.context])
        + V4Crypto.integer(UInt64(epoch), width: 4))
  }
  func rekeyStage(_ access: V4ReliableSessionAdmission, root next: SymmetricKey) throws {
    try authorize(access)
    try check()
    guard frozen, candidate == nil, keyDerivations <= (1 << 28) - UInt64(scopes.count * 2) else {
      throw V4CryptoFailure.phase
    }
    var replacement: [Scope] = []
    replacement.reserveCapacity(maxScopes)
    for old in scopes {
      let entry = Scope(number: old.number, send: KeyState(key: nil), receive: KeyState(key: nil))
      entry.retired = old.retired
      if !old.retired {
        keyDerivations += 2
        entry.send.key = V4RecordMaterial.key(
          root: next, profile: profile, hash: hash,
          epoch: epoch + 1, direction: role, scope: old.number)
        if old.receive.key != nil {
          entry.receive.key = V4RecordMaterial.key(
            root: next, profile: profile, hash: hash,
            epoch: epoch + 1, direction: role.peer, scope: old.number)
        }
      }
      replacement.append(entry)
    }
    let born = clockSample()
    guard let interval = born.interval else { throw born.failure ?? V4TimeFailure.unavailable }
    let (cap, overflow) = interval.lowerMS.addingReportingOverflow(86_400_000)
    guard !overflow else { throw V4TimeFailure.unavailable }
    candidate = try Candidate(
      root: next, born: born,
      deadline: V4SecurityDeadline(clock: owner.environment.clock, capMS: cap), scopes: replacement)
  }
  private func clockSample() -> V4ClockSample { owner.environment.clock.sample() }
  func rekeyArm(_ access: V4ReliableSessionAdmission) throws {
    try authorize(access)
    try check()
    guard let candidate else { throw V4CryptoFailure.phase }
    candidate.armed = true
  }
  func rekeyMarker(_ access: V4ReliableSessionAdmission, sent: Bool) throws {
    try authorize(access)
    try check()
    guard let candidate, candidate.armed else { throw V4CryptoFailure.phase }
    if sent {
      guard !candidate.sent, candidate.scopes[0].send.next == 1 else { throw V4CryptoFailure.phase }
      candidate.sent = true
    } else {
      guard !candidate.received, candidate.scopes[0].receive.next == 1 else {
        throw V4CryptoFailure.phase
      }
      candidate.received = true
    }
  }
  func rekeyFinish(_ access: V4ReliableSessionAdmission) throws -> UInt32 {
    try authorize(access)
    try check()
    guard let candidate, candidate.sent, candidate.received, !busy else {
      throw V4CryptoFailure.phase
    }
    // Synchronous publication has returned, so no old AEAD operation or
    // publisher callback remains. Replacing the arrays releases both old
    // direction keys; no logical deletion stands in for a live reference.
    scopes = candidate.scopes
    root = candidate.root
    born = candidate.born
    rootDeadline.cancel()
    rootDeadline = candidate.deadline
    epochUsage = candidate.usage
    epoch += 1
    self.candidate = nil
    frozen = false
    return epoch
  }
  func rekeySafetyDue(_ access: V4ReliableSessionAdmission, waitMS: UInt64) throws -> Bool {
    try authorize(access)
    try check()
    guard waitMS < 86_400_000 else { throw V4CryptoFailure.configuration }
    let now = clockSample()
    guard let current = now.interval, let origin = born.interval else {
      throw V4TimeFailure.unavailable
    }
    if current.upperMS - origin.lowerMS >= 86_400_000 - waitMS { return true }
    let limits = V4CryptoUsage.limits(profile)
    func half(_ v: V4CryptoUsage) -> V4CryptoUsage {
      V4CryptoUsage(
        seals: v.seals / 2, opens: v.opens / 2, blocks: v.blocks / 2,
        ciphertextBytes: v.ciphertextBytes / 2)
    }
    return try !epochUsage.fits(half(limits.epoch))
      || !sessionUsage.adding(protectedMargin).fits(limits.session)
      || keyDerivations + UInt64(maxScopes * 2) >= 1 << 28
      || scopes.contains {
        !$0.send.usage.fits(half(limits.key)) || !$0.receive.usage.fits(half(limits.key))
      }
  }
}
