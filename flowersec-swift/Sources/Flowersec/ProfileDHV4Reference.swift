import Crypto
import Foundation
import Clibsodium

// Internal fixed-material reference. No production secret export, entropy or
// key-handle/Noise ownership is established by these primitive operations.
enum ProfileDHV4Reference {
  enum Failure: Error, Equatable {
    case invalidDH
    var code: String { TransportV4Registry.dhFailure }
  }

  static func publicKey(profile: String, privateKey: Data) throws -> Data {
    do {
      guard privateKey.count == TransportV4Registry.dhPrivateBytes else { throw Failure.invalidDH }
      switch profile {
      case TransportV4Registry.dhProfileX25519:
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation
      case TransportV4Registry.dhProfileP256:
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.x963Representation
      default: throw Failure.invalidDH
      }
    } catch { throw Failure.invalidDH }
  }

  static func derive(profile: String, privateKey: Data, publicKey: Data) throws -> Data {
    do {
      guard privateKey.count == TransportV4Registry.dhPrivateBytes else { throw Failure.invalidDH }
      let shared: SharedSecret
      switch profile {
      case TransportV4Registry.dhProfileX25519:
        guard publicKey.count == TransportV4Registry.dhX25519PublicBytes else { throw Failure.invalidDH }
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        shared = try key.sharedSecretFromKeyAgreement(with: peer)
      case TransportV4Registry.dhProfileP256:
        guard publicKey.count == TransportV4Registry.dhP256PublicBytes, publicKey.first == 4 else {
          throw Failure.invalidDH
        }
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        guard peer.x963Representation == publicKey else { throw Failure.invalidDH }
        shared = try key.sharedSecretFromKeyAgreement(with: peer)
      default: throw Failure.invalidDH
      }
      // Inspect the library-owned result before creating the returned Data.
      // sodium_is_zero is a public constant-time byte predicate.
      return try shared.withUnsafeBytes { buffer in
        guard buffer.count == TransportV4Registry.dhSecretBytes,
          sodium_is_zero(buffer.bindMemory(to: UInt8.self).baseAddress!, buffer.count) == 0
        else { throw Failure.invalidDH }
        return Data(buffer)
      }
    } catch { throw Failure.invalidDH }
  }
}
