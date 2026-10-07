import Clibsodium
import Crypto
import Foundation

enum V4CryptoFailure: Error, Equatable, Sendable {
  case configuration, key, authentication, phase, sequence, capacity, closed
}

enum V4CryptoProfile: String, Sendable, CaseIterable {
  case x25519 = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1"
  case p256 = "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"
  var publicBytes: Int { self == .x25519 ? 32 : 65 }
  var noiseName: String {
    self == .x25519 ? "Noise_KKpsk0_25519_ChaChaPoly_SHA256" : "Noise_KKpsk0_P256_AESGCM_SHA256"
  }
}

enum V4CryptoRole: UInt8, Sendable {
  case client = 0
  case server = 1
  var peer: Self { self == .client ? .server : .client }
}

enum V4Crypto {
  static func random(_ count: Int) throws -> Data {
    guard (1...65_536).contains(count), sodium_init() >= 0 else { throw V4CryptoFailure.key }
    var bytes = Data(count: count)
    // libsodium uses the OS CSPRNG and terminates on entropy failure. There is
    // no weak, deterministic, pooled or caller-selected randomness fallback.
    bytes.withUnsafeMutableBytes { randombytes_buf($0.baseAddress!, $0.count) }
    return bytes
  }
  static func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { sodium_memzero($0.baseAddress, $0.count) }
    data.removeAll(keepingCapacity: false)
  }
  static func integer(_ value: UInt64, width: Int) -> Data {
    var n = value.bigEndian
    return withUnsafeBytes(of: &n) { Data($0.suffix(width)) }
  }
  static func number(_ bytes: some Collection<UInt8>) -> UInt64 {
    bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
  }
  static func lp(_ bytes: Data) -> Data { integer(UInt64(bytes.count), width: 4) + bytes }
  static func domain(_ label: String, _ parts: [Data]) -> Data {
    parts.reduce(Data("flowersec/v4/\(label)\0".utf8)) { $0 + lp($1) }
  }
  static func hash(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
  static func mac(_ key: SymmetricKey, _ data: Data) -> Data {
    Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
  }
  static func expand(_ key: SymmetricKey, info: Data) -> SymmetricKey {
    HKDF<SHA256>.expand(pseudoRandomKey: key, info: info, outputByteCount: 32)
  }
  static func noiseKDF(_ chain: SymmetricKey, input: Data, count: Int) -> [SymmetricKey] {
    var extract = mac(chain, input)
    defer { wipe(&extract) }
    let prk = SymmetricKey(data: extract)
    var previous = Data()
    defer { wipe(&previous) }
    var keys: [SymmetricKey] = []
    for i in 1...count {
      var next = mac(prk, previous + Data([UInt8(i)]))
      keys.append(SymmetricKey(data: next))
      wipe(&previous)
      swap(&previous, &next)
    }
    return keys
  }
  static func seal(
    _ profile: V4CryptoProfile, key: SymmetricKey, nonce: Data, aad: Data, plaintext: Data
  ) throws -> Data {
    guard key.bitCount == 256, nonce.count == 12 else { throw V4CryptoFailure.key }
    switch profile {
    case .x25519:
      let box = try ChaChaPoly.seal(
        plaintext, using: key, nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad)
      return box.ciphertext + box.tag
    case .p256:
      let box = try AES.GCM.seal(
        plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
      return box.ciphertext + box.tag
    }
  }
  static func open(
    _ profile: V4CryptoProfile, key: SymmetricKey, nonce: Data, aad: Data, ciphertext: Data
  ) throws -> Data {
    guard key.bitCount == 256, nonce.count == 12, ciphertext.count >= 16 else {
      throw V4CryptoFailure.authentication
    }
    do {
      switch profile {
      case .x25519:
        return try ChaChaPoly.open(
          ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonce),
            ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)),
          using: key, authenticating: aad)
      case .p256:
        return try AES.GCM.open(
          AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)),
          using: key, authenticating: aad)
      }
    } catch { throw V4CryptoFailure.authentication }
  }
  static func bytes(_ value: Data) -> Data { V4NamespaceValue.head(2, UInt64(value.count)) + value }
  static func text(_ value: String) -> Data {
    V4NamespaceValue.head(3, UInt64(value.utf8.count)) + Data(value.utf8)
  }
  static func map(_ fields: [(UInt64, Data)]) -> Data {
    fields.reduce(V4NamespaceValue.head(5, UInt64(fields.count))) {
      $0 + V4NamespaceValue.head(0, $1.0) + $1.1
    }
  }
}

// This primitive does not mint protocol authority. Static keys may be imported
// from the trusted host; every ephemeral is generated from the OS CSPRNG.
final class V4SoftwareDH {
  private enum Key {
    case x(Curve25519.KeyAgreement.PrivateKey)
    case p(P256.KeyAgreement.PrivateKey)
  }
  let profile: V4CryptoProfile
  let publicKey: Data
  private var key: Key?
  init(profile: V4CryptoProfile, material: Data) throws {
    guard material.count == 32 else { throw V4CryptoFailure.key }
    self.profile = profile
    switch profile {
    case .x25519:
      let value = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: material)
      key = .x(value)
      publicKey = value.publicKey.rawRepresentation
    case .p256:
      let value = try P256.KeyAgreement.PrivateKey(rawRepresentation: material)
      key = .p(value)
      publicKey = value.publicKey.x963Representation
    }
  }
  static func generate(_ profile: V4CryptoProfile) throws -> V4SoftwareDH {
    for _ in 0..<128 {
      var bytes = try V4Crypto.random(32)
      defer { V4Crypto.wipe(&bytes) }
      if let key = try? V4SoftwareDH(profile: profile, material: bytes) { return key }
    }
    throw V4CryptoFailure.key
  }
  func shared(_ peer: Data) throws -> Data {
    guard peer.count == profile.publicBytes, let key else { throw V4CryptoFailure.key }
    let secret: SharedSecret
    switch key {
    case .x(let value):
      secret = try value.sharedSecretFromKeyAgreement(
        with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer))
    case .p(let value):
      guard peer.first == 4 else { throw V4CryptoFailure.key }
      let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: peer)
      guard publicKey.x963Representation == peer else { throw V4CryptoFailure.key }
      secret = try value.sharedSecretFromKeyAgreement(with: publicKey)
    }
    return try secret.withUnsafeBytes {
      guard $0.count == 32,
        sodium_is_zero($0.bindMemory(to: UInt8.self).baseAddress!, $0.count) == 0
      else { throw V4CryptoFailure.key }
      return Data($0)
    }
  }
  func close() { key = nil }
}

final class V4LocalIdentity: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
  private let owner: V4CryptoReservation
  private var signer: Curve25519.Signing.PrivateKey?
  private var dh: V4SoftwareDH?
  private var activeOperations = 0
  private var closed = false
  let profile: V4CryptoProfile
  let dhPublicKey: Data
  let identityPublicKey: Data
  var description: String { "Flowersec.LocalIdentity(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
  init(owner: V4CryptoReservation, profile: V4CryptoProfile) throws {
    self.owner = owner
    self.profile = profile
    try owner.check()
    let key = try V4SoftwareDH.generate(profile)
    dh = key
    dhPublicKey = key.publicKey
    var seed = try V4Crypto.random(32)
    defer { V4Crypto.wipe(&seed) }
    let signer = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    self.signer = signer
    identityPublicKey = signer.publicKey.rawRepresentation
    try owner.check()
  }
  init(owner: V4CryptoReservation, profile: V4CryptoProfile, signingSeed: Data, staticKey: Data)
    throws
  {
    self.owner = owner
    self.profile = profile
    try owner.check()
    guard signingSeed.count == 32 else { throw V4CryptoFailure.key }
    let key = try V4SoftwareDH(profile: profile, material: staticKey)
    let signing = try Curve25519.Signing.PrivateKey(rawRepresentation: signingSeed)
    dh = key
    signer = signing
    dhPublicKey = key.publicKey
    identityPublicKey = signing.publicKey.rawRepresentation
    try owner.check()
  }
  func check(in environment: V4EnvironmentFoundation) throws {
    try owner.environment.gate.withLock {
      guard !closed, owner.environment === environment, dh != nil, signer != nil else {
        throw V4CryptoFailure.key
      }
      try owner.check()
    }
  }
  private func withKeyOperation<Value>(in environment: V4EnvironmentFoundation,
    _ operation: (Curve25519.Signing.PrivateKey, V4SoftwareDH) throws -> Value) throws -> Value {
    let (signer, dh, tail) = try environment.gate.withLock { () throws -> (Curve25519.Signing.PrivateKey, V4SoftwareDH, V4ResourceReference) in
      try check(in: environment)
      let tail = try owner.executionTail()
      activeOperations += 1
      return (self.signer!, self.dh!, tail)
    }
    defer {
      environment.gate.withLock {
        activeOperations -= 1
        if closed && activeOperations == 0 { clearKeys() }
      }
      tail.release()
    }
    let result = try operation(signer, dh)
    try check(in: environment)
    return result
  }
  func shared(_ peer: Data, in environment: V4EnvironmentFoundation) throws -> Data {
    try withKeyOperation(in: environment) { _, dh in try dh.shared(peer) }
  }
  func signHandshake(_ message: Data, in environment: V4EnvironmentFoundation) throws -> Data {
    try withKeyOperation(in: environment) { signer, _ in
      guard
        ["fsb4/signature", "fsa4/signature", "ready-identity", "grant-possession"].contains(where: {
          message.starts(with: Data("flowersec/v4/\($0)\0".utf8))
        })
      else { throw V4CryptoFailure.configuration }
      let signature = try signer.signature(for: message)
      guard
        StrictEd25519V4Reference.verify(
          signature: signature, message: message, publicKey: identityPublicKey)
      else { throw V4CryptoFailure.authentication }
      try check(in: environment)
      return signature
    }
  }
  func signRegisteredControl(_ message: Data, in environment: V4EnvironmentFoundation) throws -> Data {
    try environment.gate.withLock {
      try check(in: environment)
      let domain = Data("flowersec/original-tunnel-control/1\0".utf8)
      guard message.starts(with: domain), message.count > domain.count,
        message.count <= 262_144 + domain.count else { throw V4CryptoFailure.configuration }
      let signature = try signer!.signature(for: message)
      guard StrictEd25519V4Reference.verify(signature: signature, message: message,
        publicKey: identityPublicKey) else { throw V4CryptoFailure.authentication }
      try check(in: environment)
      return signature
    }
  }
  #if os(macOS) || os(iOS)
  func signRegisteredAuthorization(_ message: Data, in environment: V4EnvironmentFoundation) throws -> Data {
    try environment.gate.withLock {
      try check(in: environment)
      guard (33...1056).contains(message.count), message.prefix(32).contains(where: { $0 != 0 })
      else { throw V4CryptoFailure.configuration }
      var request = Data(message.dropFirst(32)); defer { V4Crypto.wipe(&request) }
      var cursor = V4PoolWireCursor(request, maximum: 1024)
      try cursor.array(13)
      guard try cursor.text(maximum: 32) == "live-authorization-1",
        V4NamespaceRegistry.securityID(try cursor.text(maximum: 128).utf8),
        V4NamespaceRegistry.securityID(try cursor.text(maximum: 128).utf8),
        try cursor.text(maximum: 128) == profile.rawValue else { throw V4CryptoFailure.configuration }
      for size in [16, 16, 16, 32, 32, 32] {
        let bytes = try cursor.bytes(maximum: size)
        guard bytes.count == size, bytes.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.configuration }
      }
      try cursor.array(3)
      guard try cursor.uint() < 16 else { throw V4CryptoFailure.configuration }
      for size in [16, 32] {
        let bytes = try cursor.bytes(maximum: size)
        guard bytes.count == size, bytes.contains(where: { $0 != 0 }) else { throw V4CryptoFailure.configuration }
      }
      guard try cursor.uint() > 0, try cursor.uint() == 1 else { throw V4CryptoFailure.configuration }
      try cursor.end()
      let signature = try signer!.signature(for: message)
      guard StrictEd25519V4Reference.verify(signature: signature, message: message,
        publicKey: identityPublicKey) else { throw V4CryptoFailure.authentication }
      try check(in: environment)
      return signature
    }
  }
  #endif
  func close() {
    owner.environment.gate.withLock {
      closed = true
      owner.seal()
      if activeOperations == 0 { clearKeys() }
    }
  }
  private func clearKeys() { dh?.close(); dh = nil; signer = nil }
}

// Output aliases retain their actual backing charge after close/cancellation.
// Copies made by a qualified native publisher belong to that publisher's own
// admitted footprint; a retained handle cannot refund this buffer's charge.
final class V4CryptoBuffer: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
  private let owner: V4CryptoReservation
  private let capacity: Int
  private let credential: V4CredentialAdmission?
  private let delivery: (() throws -> Void)?
  private var storage = Data()
  private var stored = false
  var description: String { "Flowersec.CryptoBuffer(<redacted>)" }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
  init(
    owner: V4CryptoReservation, capacity: Int, credential: V4CredentialAdmission? = nil,
    delivery: (() throws -> Void)? = nil
  ) {
    self.delivery = delivery
    self.credential = credential
    self.owner = owner
    self.capacity = capacity
  }
  func store(_ data: Data) throws {
    try owner.environment.gate.withLock {
      try owner.check()
      guard !stored, data.count <= capacity else { throw V4CryptoFailure.capacity }
      storage = data
      stored = true
    }
  }
  func withBytes<T>(_ body: (Data) throws -> T) throws -> T {
    try owner.environment.gate.withLock {
      try owner.check()
      guard stored else { throw V4CryptoFailure.closed }
      try credential?.checkSessionAuthorization(in: owner.environment)
      try delivery?()
      return try body(storage)
    }
  }
  func close() {
    owner.environment.gate.withLock {
      V4Crypto.wipe(&storage)
      stored = false
      owner.seal()
    }
  }
  deinit { V4Crypto.wipe(&storage) }
}
