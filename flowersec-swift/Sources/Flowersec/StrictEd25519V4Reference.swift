import Crypto
import Foundation
import Clibsodium

// Reference adapter over stable private values; no credential, key-handle,
// reservation, caching or cancellation ownership is established here.
enum StrictEd25519V4Reference {
  enum Failure: Error, Equatable {
    case signatureGenerationFailed

    var code: String { TransportV4Registry.strictEd25519SigningFailure }
  }

  private static let initialized = sodium_init() >= 0

  static func verify(signature: Data, message: Data, publicKey: Data) -> Bool {
    guard initialized,
      publicKey.count == TransportV4Registry.strictEd25519PublicKeyBytes,
      signature.count == TransportV4Registry.strictEd25519SignatureBytes
    else { return false }
    let commitment = Data(signature.prefix(TransportV4Registry.strictEd25519PointBytes))
    // libsodium's public predicate requires canonical encoding, a curve point,
    // non-small-order and the prime-order subgroup. Apply it to both A and R.
    for encoded in [publicKey, commitment] {
      let valid = encoded.withUnsafeBytes { buffer in
        crypto_core_ed25519_is_valid_point(buffer.bindMemory(to: UInt8.self).baseAddress!)
      }
      guard valid == 1 else { return false }
    }
    // The pure verifier rejects noncanonical S. With both A and R in the
    // prime-order subgroup its equation has the required strict acceptance set.
    return signature.withUnsafeBytes { signatureBytes in
      publicKey.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { messageBytes in
          crypto_sign_ed25519_verify_detached(
            signatureBytes.bindMemory(to: UInt8.self).baseAddress!,
            messageBytes.bindMemory(to: UInt8.self).baseAddress,
            UInt64(message.count), keyBytes.bindMemory(to: UInt8.self).baseAddress!
          ) == 0
        }
      }
    }
  }

  static func sign(message: Data, seed: Data) throws -> Data {
    try signOnce(message: message) {
      let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
      return (key.publicKey.rawRepresentation, try key.signature(for: message))
    }
  }

  // Internal output-gate injection, not a public provider or key-handle API.
  static func signOnce(
    message: Data, signer: () throws -> (publicKey: Data, signature: Data)
  ) throws -> Data {
    do {
      let output = try signer()
      guard verify(signature: output.signature, message: message, publicKey: output.publicKey)
      else { throw Failure.signatureGenerationFailed }
      return output.signature
    } catch {
      throw Failure.signatureGenerationFailed
    }
  }
}
