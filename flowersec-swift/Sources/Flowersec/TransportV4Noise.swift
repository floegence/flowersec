import Crypto
import Foundation

// Exact two-flight KKpsk0 state machine over the production Swift Crypto DH and
// AEAD providers. Split material is consumed only for initial-root derivation.
// It never serves as a record cipher key or establishes a Session by itself.
final class V4NoiseState {
  private let profile: V4CryptoProfile
  private let role: V4CryptoRole
  private let peerStatic: Data
  private var sharedStatic: ((Data) throws -> Data)?
  private var chain: SymmetricKey?
  private var cipher: SymmetricKey?
  private var ephemeral: V4SoftwareDH?
  private var peerEphemeral = Data()
  private var hash: Data
  private var step = 0
  private var finished = false

  init(
    profile: V4CryptoProfile, role: V4CryptoRole, localPublic: Data, peerPublic: Data,
    sharedStatic: @escaping (Data) throws -> Data, psk: Data, prologue: Data
  ) throws {
    guard localPublic.count == profile.publicBytes, peerPublic.count == profile.publicBytes,
      psk.count == 32, prologue.count <= 100_000
    else { throw V4CryptoFailure.configuration }
    self.profile = profile
    self.role = role
    peerStatic = peerPublic
    self.sharedStatic = sharedStatic
    let name = Data(profile.noiseName.utf8)
    hash =
      name.count <= 32 ? name + Data(repeating: 0, count: 32 - name.count) : V4Crypto.hash(name)
    chain = SymmetricKey(data: hash)
    mixHash(prologue)
    mixHash(role == .client ? localPublic : peerPublic)
    mixHash(role == .client ? peerPublic : localPublic)
    let keys = V4Crypto.noiseKDF(chain!, input: psk, count: 3)
    chain = keys[0]
    var temporary = keys[1].withUnsafeBytes { Data($0) }
    defer { V4Crypto.wipe(&temporary) }
    mixHash(temporary)
    cipher = keys[2]
  }
  private func mixHash(_ bytes: Data) { hash = V4Crypto.hash(hash + bytes) }
  private func mixKey(_ bytes: Data) throws {
    guard let chain else { throw V4CryptoFailure.closed }
    let keys = V4Crypto.noiseKDF(chain, input: bytes, count: 2)
    self.chain = keys[0]
    cipher = keys[1]
  }
  private func dh(_ operation: () throws -> Data) throws {
    var bytes = try operation()
    defer { V4Crypto.wipe(&bytes) }
    try mixKey(bytes)
  }
  private func tokens(_ publicKey: Data, writing: Bool) throws {
    guard !finished, let sharedStatic else { throw V4CryptoFailure.closed }
    mixHash(publicKey)
    try mixKey(publicKey)
    if step == 0 {
      if writing {
        try dh { try ephemeral!.shared(peerStatic) }
      } else {
        try dh { try sharedStatic(publicKey) }
      }
      try dh { try sharedStatic(peerStatic) }
    } else {
      try dh { try ephemeral!.shared(writing ? peerEphemeral : publicKey) }
      if writing {
        try dh { try ephemeral!.shared(peerStatic) }
      } else {
        try dh { try sharedStatic(publicKey) }
      }
    }
  }
  // A non-exporting DH handle allows deterministic vector tests. The runtime
  // owner always supplies a freshly generated OS-CSPRNG ephemeral here.
  func write(ephemeral key: V4SoftwareDH) throws -> Data {
    do {
      guard !finished, (role == .client && step == 0) || (role == .server && step == 1),
        key.profile == profile, ephemeral == nil
      else { throw V4CryptoFailure.phase }
      ephemeral = key
      try tokens(key.publicKey, writing: true)
      guard let cipher else { throw V4CryptoFailure.key }
      // Every flight ends immediately after the last MixKey, so Noise's
      // per-key nonce is exactly zero for its sole empty payload operation.
      let tag = try V4Crypto.seal(
        profile, key: cipher, nonce: Data(count: 12), aad: hash, plaintext: Data())
      mixHash(tag)
      step += 1
      return key.publicKey + tag
    } catch {
      close()
      throw error
    }
  }
  func read(_ message: Data) throws {
    do {
      guard !finished, (role == .server && step == 0) || (role == .client && step == 1),
        message.count == profile.publicBytes + 16
      else { throw V4CryptoFailure.phase }
      let publicKey = Data(message.prefix(profile.publicBytes))
      try tokens(publicKey, writing: false)
      guard let cipher else { throw V4CryptoFailure.key }
      let tag = Data(message.suffix(16))
      let payload = try V4Crypto.open(
        profile, key: cipher, nonce: Data(count: 12), aad: hash, ciphertext: tag)
      guard payload.isEmpty else { throw V4CryptoFailure.authentication }
      mixHash(tag)
      peerEphemeral = publicKey
      step += 1
    } catch {
      close()
      throw error
    }
  }
  func finish(context: Data) throws -> (hash: Data, root: SymmetricKey) {
    guard !finished, step == 2, let chain, context.count == 32 else { throw V4CryptoFailure.phase }
    let split = V4Crypto.noiseKDF(chain, input: Data(), count: 2)
    let root = V4Crypto.expand(
      split[0],
      info: V4Crypto.domain(
        "initial-root", [Data(profile.rawValue.utf8), hash, context]))
    let result = (hash, root)
    close()
    return result
  }
  func close() {
    finished = true
    chain = nil
    cipher = nil
    sharedStatic = nil
    ephemeral?.close()
    ephemeral = nil
    peerEphemeral = Data()
  }
  deinit { close() }
}
