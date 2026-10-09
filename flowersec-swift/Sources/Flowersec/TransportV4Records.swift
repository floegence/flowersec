import Crypto
import Foundation

#if DEBUG
enum V4CryptoPreparationTestStage: Sendable, Equatable { case scopeKeys, openDigest, recordOutput }
#endif

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
  func reserveRecordOutput(maintenance: Bool) throws -> V4RecordOutput
  func publish(_ buffer: V4CryptoBuffer) throws
  func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws
}
extension V4RecordPublisher {
  func reserveRecordOutput(maintenance: Bool) throws -> V4RecordOutput {
    V4RecordOutput(publish: { buffer, completion in try self.publish(buffer, completion: completion) },
      discard: {})
  }
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

// One previously reserved provider position follows the original record job.
// Discard before handoff returns that position; after handoff the provider owns
// its actual completion tail. There is no intermediate completion queue.
final class V4RecordOutput: @unchecked Sendable {
  private let gate = NSLock()
  private var publication: ((V4CryptoBuffer, @escaping @Sendable (Bool) -> Void) throws -> Void)?
  private var cancellation: (() -> Void)?
  init(publish: @escaping (V4CryptoBuffer, @escaping @Sendable (Bool) -> Void) throws -> Void,
    discard: @escaping () -> Void) {
    publication = publish; cancellation = discard
  }
  func publish(_ buffer: V4CryptoBuffer, completion: @escaping @Sendable (Bool) -> Void) throws {
    let original = try gate.withLock {
      guard let publication else { throw V4CryptoFailure.phase }
      self.publication = nil; cancellation = nil
      return publication
    }
    try original(buffer, completion)
  }
  func discard() {
    let original = gate.withLock {
      let original = cancellation
      cancellation = nil; publication = nil
      return original
    }
    original?()
  }
  deinit { discard() }
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

// Only the original authenticated Session commit can refuse a DATA result
// locally. A thrown decoder, AEAD or maintenance error grants no such scope.
enum V4RecordCommitDisposition {
  case committed, isolatedStream
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
  let features: UInt64
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
    features = established.features
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
    var working = false
  }
  private final class Scope {
    let number: UInt64
    var retired = false
    var installing = false
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
  private var activeJobs = 0
  private var applicationSeals = 0
  private var applicationOpens = 0
  private var rekeyWorking = false
  private var markerPreparing = false
  private var recordStorage: V4CryptoReservation?
  private var closed = false
  private var epoch: UInt32 = 0
  private var candidate: Candidate?
  private var frozen = false
  private var protectedMargin = V4CryptoUsage()
  #if DEBUG
  // Tests can retain an actual completed AEAD job before its final commit.
  // This observer is scoped to this original channel and absent in release.
  var cryptoTestCompleted: (@Sendable (UInt64, UInt8, Bool) -> Void)?
  var cryptoTestPrepared: (@Sendable (UInt64, V4CryptoPreparationTestStage) -> Void)?
  func cryptoTestFrontier(_ scope: UInt64, sending: Bool) -> UInt64? {
    owner.environment.gate.withLock {
      guard let original = scopes.first(where: { $0.number == scope }) else { return nil }
      return sending ? original.send.next : original.receive.next
    }
  }
  func cryptoTestReceiveEnabled(_ scope: UInt64) -> Bool {
    owner.environment.gate.withLock {
      scopes.first(where: { $0.number == scope })?.receive.key != nil
    }
  }
  func cryptoTestReceiveUsage(_ scope: UInt64) -> V4CryptoUsage? {
    owner.environment.gate.withLock {
      scopes.first(where: { $0.number == scope })?.receive.usage
    }
  }
  #endif
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
      guard activeJobs == 0, !sessionClaimed, scopes.count == 1, let established else {
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
    try owner.environment.gate.withLock {
      try check()
      guard number <= 4_194_335, used[Int(number / 8)] & (1 << (number % 8)) == 0,
        scopes.count < maxScopes || scopes.contains(where: { $0.retired && !$0.installing }),
        keyDerivations <= (1 << 28) - 2, let originalRoot = root
      else { throw V4CryptoFailure.capacity }
      let local = number & 1 == (role == .client ? 1 : 0)
      if number != 0 {
        guard local ? applicationSeals < 3 : applicationOpens < 3 else {
          throw V4CryptoFailure.capacity
        }
        if local { applicationSeals += 1 } else { applicationOpens += 1 }
      }
      defer {
        if number != 0 {
          if local { applicationSeals -= 1 } else { applicationOpens -= 1 }
        }
      }
      let generation = epoch
      keyDerivations += 2
      used[Int(number / 8)] |= 1 << (number % 8)
      let entry = Scope(number: number, send: KeyState(), receive: KeyState())
      entry.installing = true
      let index: Int
      if let free = scopes.firstIndex(where: { $0.retired && !$0.installing }) {
        scopes[free] = entry
        index = free
      } else {
        index = scopes.count
        scopes.append(entry)
      }
      defer { entry.installing = false }
      do {
        #if DEBUG
        let preparationObserver = cryptoTestPrepared
        #endif
        let keys = try keyCrypto {
          let result = (V4RecordMaterial.key(root: originalRoot, profile: profile, hash: hash,
            epoch: generation, direction: role, scope: number),
           V4RecordMaterial.key(root: originalRoot, profile: profile, hash: hash,
            epoch: generation, direction: role.peer, scope: number))
          #if DEBUG
          preparationObserver?(number, .scopeKeys)
          #endif
          return result
        }
        guard scopes[index] === entry, !entry.retired else { throw V4CryptoFailure.closed }
        entry.send.key = keys.0
        entry.receive.key = keys.1
        if let candidate {
          guard keyDerivations <= (1 << 28) - 2 else { throw V4CryptoFailure.capacity }
          keyDerivations += 2
          let candidateRoot = candidate.root
          let futureKeys = try keyCrypto {
            (V4RecordMaterial.key(root: candidateRoot, profile: profile, hash: hash,
              epoch: generation + 1, direction: role, scope: number),
             V4RecordMaterial.key(root: candidateRoot, profile: profile, hash: hash,
              epoch: generation + 1, direction: role.peer, scope: number))
          }
          guard self.candidate === candidate, scopes[index] === entry, !entry.retired else {
            throw V4CryptoFailure.closed
          }
          let future = Scope(number: number, send: KeyState(key: futureKeys.0),
            receive: KeyState(key: futureKeys.1))
          if index < candidate.scopes.count { candidate.scopes[index] = future }
          else { candidate.scopes.append(future) }
        }
        return V4RecordScope(channel: self, slot: index, number: number)
      } catch {
        entry.retired = true
        entry.send.key = nil; entry.receive.key = nil
        throw error
      }
    }
  }
  func admitReliableScope(_ number: UInt64, access: V4ReliableSessionAdmission? = nil) throws
    -> V4RecordScope
  {
    try owner.environment.gate.withLock {
      try authorize(access)
      guard number > 0, number <= 4_194_335,
        number & 1 != 0 || number / 2 <= 2_097_152
      else { throw V4CryptoFailure.configuration }
      return try install(number)
    }
  }
  func retire(_ scope: V4RecordScope, access: V4ReliableSessionAdmission? = nil) throws {
    try owner.environment.gate.withLock {
      try authorize(access)
      let index = try slot(scope)
      guard scope.number != 0 else { throw V4CryptoFailure.configuration }
      guard !scopes[index].send.working, !scopes[index].receive.working,
        candidate?.scopes[index].send.working != true,
        candidate?.scopes[index].receive.working != true else { throw V4CryptoFailure.phase }
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
  func disableReceive(_ scope: V4RecordScope, access: V4ReliableSessionAdmission) throws {
    try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      let index = try slot(scope)
      guard scope.number != 0 else { throw V4CryptoFailure.configuration }
      // Physical jobs retain their exact captured key/tail until exit. All
      // installed/candidate aliases permanently lose future receive authority.
      scopes[index].receive.key = nil
      candidate?.scopes[index].receive.key = nil
    }
  }
  private func slot(_ scope: V4RecordScope) throws -> Int {
    guard scope.channel === self, scopes.indices.contains(scope.slot),
      scopes[scope.slot].number == scope.number, !scopes[scope.slot].retired,
      !scopes[scope.slot].installing
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
  // The eight prepaid reliable-session work positions are split into three
  // application jobs per direction and an independent maintenance job per
  // direction. No task or completion queue is created by the record path.
  func bindRecordStorage(_ storage: V4CryptoReservation, access: V4ReliableSessionAdmission) throws {
    try authorize(access)
    try check()
    guard recordStorage == nil else { throw V4CryptoFailure.phase }
    recordStorage = storage
  }
  func canPublish(_ scope: V4RecordScope, access: V4ReliableSessionAdmission) throws -> Bool {
    try authorize(access)
    try check()
    let index = try slot(scope)
    let active = candidate?.sent == true ? candidate!.scopes : scopes
    return !active[index].send.working
      && (scope.number == 0 ? !markerPreparing : applicationSeals < 3)
  }
  // Authenticated schema/hash work keeps the receive job already claimed by
  // receive(). It must never borrow the opposite direction's send position.
  func receiveWork<T>(_ access: V4ReliableSessionAdmission, scope: V4RecordScope,
    epoch generation: UInt32, _ operation: () throws -> T) throws -> T {
    try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      let index = try slot(scope)
      let active = generation == epoch ? scopes : candidate?.scopes
      guard generation == epoch || generation == epoch + 1,
        active?.indices.contains(index) == true,
        let original = active?[index], original.receive.working else {
        throw V4CryptoFailure.phase
      }
      let result = try owner.environment.root.gate.outside(operation)
      try authorize(access)
      try check()
      let current = generation == epoch ? scopes : candidate?.scopes
      guard generation == epoch || generation == epoch + 1,
        current?.indices.contains(index) == true, current?[index] === original,
        !original.retired, original.receive.key != nil, original.receive.working else {
        throw V4CryptoFailure.closed
      }
      return result
    }
  }
  func recordDigest(_ access: V4ReliableSessionAdmission, scope: V4RecordScope, bytes: Data,
    receiving generation: UInt32? = nil) throws -> Data {
    if let generation {
      return try receiveWork(access, scope: scope, epoch: generation) { V4Crypto.hash(bytes) }
    }
    return try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      let index = try slot(scope)
      let future = candidate?.sent == true
      let generation = epoch + (future ? 1 : 0)
      let original = (future ? candidate!.scopes : scopes)[index]
      guard !original.send.working,
        scope.number == 0 ? !markerPreparing : applicationSeals < 3 else { throw V4CryptoFailure.capacity }
      let tails = try jobTails()
      original.send.working = true
      activeJobs += 1
      if scope.number != 0 { applicationSeals += 1 }
      defer {
        original.send.working = false
        activeJobs -= 1
        if scope.number != 0 { applicationSeals -= 1 }
        tails.1?.release(); tails.0.release()
      }
      #if DEBUG
      let preparationObserver = cryptoTestPrepared
      #endif
      let digest = owner.environment.root.gate.outside {
        let result = V4Crypto.hash(bytes)
        #if DEBUG
        preparationObserver?(scope.number, .openDigest)
        #endif
        return result
      }
      try authorize(access)
      try check()
      let current = generation == epoch ? scopes : candidate?.scopes
      guard generation == epoch || generation == epoch + 1,
        current?.indices.contains(index) == true, current?[index] === original,
        !original.retired, original.send.key != nil else {
        throw V4CryptoFailure.closed
      }
      return digest
    }
  }
  private func jobTails() throws -> (V4ResourceReference, V4ResourceReference?) {
    let key = try owner.executionTail()
    do { return (key, try recordStorage?.executionTail()) }
    catch { key.release(); throw error }
  }
  // Scope derivation and rekey calculations use the original channel's fixed
  // key-work position. The caller snapshots inputs before entering this helper;
  // its result grants no authority until the original owner rechecks the gate.
  func rekeyCrypto<T>(_ access: V4ReliableSessionAdmission,
    deadline: (() throws -> Void)? = nil,
    _ operation: () throws -> T) throws -> T {
    try owner.environment.gate.withLock {
      try authorize(access)
      guard !rekeyWorking else { throw V4CryptoFailure.phase }
      rekeyWorking = true
      defer { rekeyWorking = false }
      let result = try keyCrypto {
        try deadline?()
        let result = try operation()
        try deadline?()
        return result
      }
      try deadline?()
      return result
    }
  }
  private func keyCrypto<T>(_ operation: () throws -> T) throws -> T {
    try check()
    let generation = epoch
    let tails = try jobTails()
    activeJobs += 1
    defer { activeJobs -= 1; tails.1?.release(); tails.0.release() }
    let result = try owner.environment.root.gate.outside(operation)
    try check()
    guard epoch == generation else { throw V4CryptoFailure.phase }
    return result
  }
  func reserveMaintenanceOutput(_ access: V4ReliableSessionAdmission, maximum: Int,
    to publisher: any V4RecordPublisher) throws -> (V4CryptoBuffer, V4RecordOutput) {
    try reserveOutput(access, maximum: maximum, maintenance: true, to: publisher)
  }
  func reserveApplicationOutput(_ access: V4ReliableSessionAdmission, maximum: Int,
    to publisher: any V4RecordPublisher) throws -> (V4CryptoBuffer, V4RecordOutput) {
    try reserveOutput(access, maximum: maximum, maintenance: false, to: publisher)
  }
  private func reserveOutput(_ access: V4ReliableSessionAdmission, maximum: Int,
    maintenance: Bool, to publisher: any V4RecordPublisher) throws -> (V4CryptoBuffer, V4RecordOutput) {
    try authorize(access)
    try check()
    guard maximum >= 0, maximum <= maxFrame - 36 else { throw V4CryptoFailure.capacity }
    // Body encoding, immutable plaintext, ciphertext and wire/COW overlap are
    // charged before the Session builds a DATA body or confirmation MAC.
    let buffer = try owner.environment.cryptoBuffer(capacity: maximum + 44, copies: 4)
    let generation = epoch
    let provider = try owner.environment.root.gate.outside {
      try publisher.reserveRecordOutput(maintenance: maintenance)
    }
    do {
      try authorize(access)
      try check()
      guard epoch == generation else { throw V4CryptoFailure.capacity }
      return (buffer, provider)
    } catch { provider.discard(); throw error }
  }
  func publish(
    scope: V4RecordScope, frameType: UInt8, plaintext: Data, to publisher: any V4RecordPublisher,
    access: V4ReliableSessionAdmission? = nil, marker: Bool = false, critical: Bool = false,
    publication: (any V4RecordPublication)? = nil,
    reservedOutput: (V4CryptoBuffer, V4RecordOutput)? = nil,
    beforeTicket: (() throws -> Void)? = nil,
    ticketed: ((UInt32, UInt64) throws -> Void)? = nil,
    mayPublish: (() throws -> Bool)? = nil,
    accepted: (@Sendable () -> Void)? = nil
  ) throws {
    var publicationTransferred = false
    var publicationCompleted = false
    do {
      try owner.environment.gate.withLock {
        try authorize(access)
        try check()
        let index = try slot(scope)
        let future = marker || candidate?.sent == true
        if frozen && !critical && !(scope.number == 0 && frameType == 15) {
          throw V4CryptoFailure.capacity
        }
        guard !future || candidate != nil else { throw V4CryptoFailure.phase }
        let active = future ? candidate!.scopes : scopes
        let original = active[index]
        let originalEpoch = epoch
        let generation = epoch + (future ? 1 : 0)
        let sequence = original.send.next
        guard !original.send.working,
          scope.number == 0 ? (!markerPreparing || marker) : applicationSeals < 3 else {
          throw V4CryptoFailure.capacity
        }
        if future && scope.number == 0 && original.send.next == 0 && !marker {
          throw V4CryptoFailure.phase
        }
        if marker {
          guard candidate?.armed == true, scope.number == 0, frameType == 6,
            original.send.next == 0, !scopes[0].send.working else { throw V4CryptoFailure.phase }
        }
        try frame(frameType, scope: scope.number)
        guard plaintext.count <= maxFrame - 36, original.send.next < .max,
          let key = original.send.key else { throw V4CryptoFailure.capacity }
        // Reserve output and physical key/work custody before the ticket. The
        // value-type input remains immutable throughout this original job.
        let output = try reservedOutput?.0 ?? owner.environment.cryptoBuffer(capacity: plaintext.count + 44, copies: 4)
        #if DEBUG
        let preparationObserver = cryptoTestPrepared
        #endif
        let provider = try reservedOutput?.1 ?? owner.environment.root.gate.outside {
          let result = try publisher.reserveRecordOutput(maintenance: scope.number == 0)
          #if DEBUG
          if frameType == 7 { preparationObserver?(scope.number, .recordOutput) }
          #endif
          return result
        }
        defer { provider.discard() }
        try authorize(access)
        try check()
        let prepared = generation == epoch ? scopes : candidate?.scopes
        guard prepared?.indices.contains(index) == true, prepared?[index] === original,
          !original.retired, !original.installing, !original.send.working,
          original.send.key != nil, original.send.next == sequence,
          epoch == originalEpoch,
          scope.number == 0 ? (!markerPreparing || marker) : applicationSeals < 3 else {
          throw V4CryptoFailure.capacity
        }
        if frozen && !critical && !(scope.number == 0 && frameType == 15) {
          throw V4CryptoFailure.capacity
        }
        let tails = try jobTails()
        original.send.working = true
        activeJobs += 1
        if scope.number != 0 { applicationSeals += 1 }
        defer {
          original.send.working = false
          activeJobs -= 1
          if scope.number != 0 { applicationSeals -= 1 }
          tails.1?.release(); tails.0.release()
        }
        var ticketCommitted = false
        do {
          let envelope =
            V4Crypto.integer(UInt64(plaintext.count + 36), width: 4) + Data([frameType, 0, 0, 0])
          let header =
            V4Crypto.integer(UInt64(generation), width: 4)
            + V4Crypto.integer(scope.number, width: 8) + V4Crypto.integer(sequence, width: 8)
          let aad = V4RecordMaterial.aad(
            profile: profile, envelope: envelope, header: header, direction: role)
          try beforeTicket?()
          try charge(index: index, seal: true, aad: aad.count, input: plaintext.count,
            future: future, critical: critical)
          original.send.next += 1
          ticketCommitted = true
          publication?.ticket(epoch: generation)
          // Session offset/FIN frontiers advance in the very same gate as the
          // sequence, before freeze can capture this not-yet-sealed record.
          try ticketed?(generation, sequence)
          try check()
          #if DEBUG
          let cryptoObserver = cryptoTestCompleted
          #endif
          var cipher = try owner.environment.root.gate.outside {
            let result = try V4Crypto.seal(profile, key: key,
              nonce: V4RecordMaterial.nonce(epoch: generation, sequence: sequence),
              aad: aad, plaintext: plaintext)
            #if DEBUG
            cryptoObserver?(scope.number, frameType, true)
            #endif
            return result
          }
          defer { V4Crypto.wipe(&cipher) }
          try check()
          let current = generation == epoch ? scopes : candidate?.scopes
          guard generation == epoch || generation == epoch + 1,
            current?.indices.contains(index) == true, current?[index] === original,
            !original.retired, original.send.key != nil else { throw V4CryptoFailure.closed }
          if try mayPublish?() == false {
            output.close()
            publicationCompleted = true
            publication?.completed(false)
            return
          }
          try output.store(envelope + header + cipher)
          // Transfer is claimed atomically against Close. Provider handoff is
          // outside all enclosing gates and retains this original buffer/job.
          publicationTransferred = true
          publication?.transferred()
          try owner.environment.root.gate.outside {
            try provider.publish(output) { success in publication?.completed(success) }
          }
          try check()
          let handedOff = generation == epoch ? scopes : candidate?.scopes
          guard handedOff?.indices.contains(index) == true, handedOff?[index] === original,
            generation == epoch || generation == epoch + 1 else { throw V4CryptoFailure.closed }
          accepted?()
        } catch {
          if ticketCommitted { close() }
          throw error
        }
      }
    } catch {
      if !publicationTransferred && !publicationCompleted { publication?.completed(false) }
      throw error
    }
  }
  func receive(
    scope: V4RecordScope, wire input: Data, access: V4ReliableSessionAdmission? = nil,
    isolateFailure: Bool = false, marker: Bool = false,
    commit: ((V4AuthenticatedRecord) throws -> V4RecordCommitDisposition)? = nil
  ) throws -> V4AuthenticatedRecord {
    try owner.environment.gate.withLock {
      try authorize(access)
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
          marker ? (!candidate.received && scope.number == 0 && wire[4] == 6)
            : (scope.number == 0 ? candidate.received : candidate.sent)
        else { throw V4CryptoFailure.sequence }
      } else {
        guard generation == UInt64(epoch), !marker, candidate?.received != true else {
          throw V4CryptoFailure.sequence
        }
      }
      let active = future ? candidate!.scopes : scopes
      let original = active[index]
      guard !original.receive.working, scope.number == 0 || applicationOpens < 3 else {
        throw V4CryptoFailure.capacity
      }
      let tails = try jobTails()
      original.receive.working = true
      activeJobs += 1
      if scope.number != 0 { applicationOpens += 1 }
      defer {
        original.receive.working = false
        activeJobs -= 1
        if scope.number != 0 { applicationOpens -= 1 }
        tails.1?.release(); tails.0.release()
      }
      do {
        guard V4Crypto.number(wire.prefix(4)) == UInt64(wire.count - 8),
          wire[5..<8].allSatisfy({ $0 == 0 }),
          V4Crypto.number(wire[12..<20]) == scope.number,
          let key = original.receive.key else { throw V4CryptoFailure.authentication }
        try frame(wire[4], scope: scope.number)
        let sequence = V4Crypto.number(wire[20..<28])
        guard sequence == original.receive.next, sequence < .max else {
          throw V4CryptoFailure.sequence
        }
        let output = try owner.environment.cryptoBuffer(
          capacity: wire.count - 44, credential: credential, delivery: { try self.check() }, copies: 4)
        let aad = V4RecordMaterial.aad(profile: profile,
          envelope: Data(wire.prefix(8)), header: Data(wire[8..<28]), direction: role.peer)
        try charge(index: index, seal: false, aad: aad.count, input: wire.count - 28, future: future)
        try check()
        #if DEBUG
        let cryptoObserver = cryptoTestCompleted
        #endif
        var plaintext = try owner.environment.root.gate.outside {
          let result = try V4Crypto.open(profile, key: key,
            nonce: V4RecordMaterial.nonce(epoch: UInt32(generation), sequence: sequence),
            aad: aad, ciphertext: Data(wire.dropFirst(28)))
          #if DEBUG
          cryptoObserver?(scope.number, wire[4], false)
          #endif
          return result
        }
        defer { V4Crypto.wipe(&plaintext) }
        try check()
        let current = generation == UInt64(epoch) ? scopes : candidate?.scopes
        guard generation == UInt64(epoch) || generation == UInt64(epoch) + 1,
          current?.indices.contains(index) == true, current?[index] === original,
          !original.retired, original.receive.key != nil,
          original.receive.next == sequence else { throw V4CryptoFailure.closed }
        try output.store(plaintext)
        let record = V4AuthenticatedRecord(frameType: wire[4], scope: scope.number,
          sequence: sequence, epoch: UInt32(generation), payload: output)
        // Keep this original direction claimed through protocol/schema commit,
        // including a maintenance handler's lock-free rekey computation.
        let disposition = try commit?(record) ?? .committed
        if case .isolatedStream = disposition {
          guard access != nil, scope.number != 0, wire[4] == 8 else {
            throw V4CryptoFailure.phase
          }
          try check()
          original.receive.key = nil
          // The failed semantic record consumed its actual AEAD budget but
          // does not advance sequence or publish authenticated plaintext.
          record.close()
          return record
        }
        try check()
        original.receive.next = sequence + 1
        return record
      } catch {
        if isolateFailure, access != nil, scope.number != 0, !closed {
          original.receive.key = nil
        } else { close() }
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
  func rekeySecret(_ access: V4ReliableSessionAdmission,
    deadline: (() throws -> Void)? = nil) throws -> SymmetricKey {
    try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      let original = root!
      let generation = epoch
      return try rekeyCrypto(access, deadline: deadline) {
        V4Crypto.expand(original, info: V4Crypto.domain("rekey-secret",
          [Data(profile.rawValue.utf8), hash, access.context])
          + V4Crypto.integer(UInt64(generation), width: 4))
      }
    }
  }
  func rekeyStage(_ access: V4ReliableSessionAdmission, root next: SymmetricKey,
    deadline: (() throws -> Void)? = nil) throws {
    try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      guard frozen, candidate == nil else { throw V4CryptoFailure.phase }
      // Frozen application admission bounds this reconciliation. Authenticated
      // pending OPEN and retirement can still change the original finite scope
      // set while key derivation is outside the shared gate.
      while true {
        try deadline?()
        let original = scopes
        let generation = epoch
        let snapshot = original.map { ($0.number, $0.retired, $0.receive.key != nil || $0.installing) }
        let derivations = UInt64(snapshot.filter { !$0.1 }.count * 2)
        guard keyDerivations <= (1 << 28) - derivations else { throw V4CryptoFailure.capacity }
        keyDerivations += derivations
        let replacement = try rekeyCrypto(access, deadline: deadline) { () -> [Scope] in
          var result: [Scope] = []
          result.reserveCapacity(maxScopes)
          for (number, retired, receive) in snapshot {
            let entry = Scope(number: number, send: KeyState(), receive: KeyState())
            entry.retired = retired
            if !retired {
              entry.send.key = V4RecordMaterial.key(root: next, profile: profile, hash: hash,
                epoch: generation + 1, direction: role, scope: number)
              if receive {
                entry.receive.key = V4RecordMaterial.key(root: next, profile: profile, hash: hash,
                  epoch: generation + 1, direction: role.peer, scope: number)
              }
            }
            result.append(entry)
          }
          return result
        }
        guard frozen, candidate == nil else { throw V4CryptoFailure.phase }
        try deadline?()
        guard scopes.count == original.count,
          zip(scopes, original).allSatisfy({ $0 === $1 }),
          zip(scopes, snapshot).allSatisfy({ $0.retired == $1.1
            && ($0.receive.key != nil || $0.installing) == $1.2 }) else { continue }
        let born = clockSample()
        guard let interval = born.interval else { throw born.failure ?? V4TimeFailure.unavailable }
        let (cap, overflow) = interval.lowerMS.addingReportingOverflow(86_400_000)
        guard !overflow else { throw V4TimeFailure.unavailable }
        candidate = try Candidate(root: next, born: born,
          deadline: V4SecurityDeadline(clock: owner.environment.clock, capMS: cap), scopes: replacement)
        return
      }
    }
  }
  private func clockSample() -> V4ClockSample { owner.environment.clock.sample() }
  func rekeyArm(_ access: V4ReliableSessionAdmission) throws {
    try authorize(access)
    try check()
    guard let candidate else { throw V4CryptoFailure.phase }
    candidate.armed = true
  }
  func withRekeyMarker<T>(_ access: V4ReliableSessionAdmission, _ operation: () throws -> T) throws -> T {
    try owner.environment.gate.withLock {
      try authorize(access)
      try check()
      guard !markerPreparing, !scopes[0].send.working,
        candidate?.scopes[0].send.working != true else { throw V4CryptoFailure.capacity }
      // Only the marker's MAC-to-ticket interval fences old maintenance. DH,
      // root KDF and inbound MAC use their independent prepaid key-work slot.
      markerPreparing = true
      defer { markerPreparing = false }
      return try operation()
    }
  }
  func rekeyMarker(_ access: V4ReliableSessionAdmission, sent: Bool) throws {
    try authorize(access)
    try check()
    guard let candidate, candidate.armed else { throw V4CryptoFailure.phase }
    if sent {
      guard !candidate.sent, candidate.scopes[0].send.next == 1 else { throw V4CryptoFailure.phase }
      candidate.sent = true
    } else {
      let receive = candidate.scopes[0].receive
      // The original receive job authenticates the marker before its final
      // schema/state callback commits the reliable sequence frontier.
      guard !candidate.received,
        receive.next == 1 || (receive.working && receive.next == 0) else {
        throw V4CryptoFailure.phase
      }
      candidate.received = true
    }
  }
  func rekeyCanFinish(_ access: V4ReliableSessionAdmission) throws -> Bool {
    try authorize(access)
    try check()
    guard let candidate, candidate.sent, candidate.received else { return false }
    return !rekeyWorking
      && !scopes.contains(where: { $0.installing || $0.send.working || $0.receive.working })
  }
  func rekeyFinish(_ access: V4ReliableSessionAdmission) throws -> UInt32 {
    try authorize(access)
    try check()
    guard let candidate, candidate.sent, candidate.received, !rekeyWorking,
      !scopes.contains(where: { $0.installing || $0.send.working || $0.receive.working }) else {
      throw V4CryptoFailure.phase
    }
    // All old-direction jobs have left. New-epoch jobs retain their same
    // candidate Scope object across installation; original output/provider
    // aliases independently retain their charged physical key/work tails.
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
