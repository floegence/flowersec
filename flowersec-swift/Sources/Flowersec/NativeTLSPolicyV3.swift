#if os(macOS) || os(iOS)
  import Foundation
  import NIOCore
  import NIOSSL

  enum NativeTLSPolicyErrorV3: Error, Equatable, Sendable {
    case invalidPolicy
    case invalidCertificate
    case unsupportedTLS
  }

  /// The only native TLS construction boundary used by v3 WebSocket adapters.
  /// Pin verification is performed during the TLS handshake; the resulting
  /// carrier is not exposed until NIOSSL has also completed its TLS proof.
  enum NativeTLSPolicyAdapterV3 {
    static func makeClientHandlerFactory(
      policy: TransportSecurityPolicyV3,
      serverHostname: String,
      configuredRoots: [NIOSSLCertificate] = []
    ) throws -> ProxyTLSClientHandler {
      guard !serverHostname.isEmpty else {
        throw NativeTLSPolicyErrorV3.invalidPolicy
      }
      var configuration = TLSConfiguration.makeClientConfiguration()
      configuration.minimumTLSVersion = .tlsv13
      configuration.maximumTLSVersion = .tlsv13

      switch policy {
      case .ca(_, let rootsSource):
        configuration.certificateVerification = .fullVerification
        switch rootsSource {
        case .platform:
          configuration.trustRoots = .default
        case .configured:
          guard !configuredRoots.isEmpty else {
            throw NativeTLSPolicyErrorV3.invalidPolicy
          }
          configuration.trustRoots = .certificates(configuredRoots)
        }
        let context = try NIOSSLContext(configuration: configuration)
        return ProxyTLSClientHandler {
          try NIOSSLClientHandler(context: context, serverHostname: serverHostname)
        }
      case .pin(_, let activeLeafDERSHA256):
        guard activeLeafDERSHA256.count >= 1, activeLeafDERSHA256.count <= 4,
          activeLeafDERSHA256.allSatisfy({ $0.count == 32 }),
          Set(activeLeafDERSHA256).count == activeLeafDERSHA256.count
        else { throw NativeTLSPolicyErrorV3.invalidPolicy }

        // The callback replaces PKI chain/hostname acceptance only for pin
        // mode. BoringSSL still performs TLS 1.3 CertificateVerify and Finished.
        configuration.certificateVerification = .noHostnameVerification
        let context = try NIOSSLContext(configuration: configuration)
        return ProxyTLSClientHandler {
          let callback: NIOSSLCustomVerificationCallback = { certificates, promise in
            guard let leaf = certificates.first else {
              promise.succeed(.failed)
              return
            }
            do {
              try verifyPinnedCertificate(
                leaf, activePins: activeLeafDERSHA256,
                nowUnixSeconds: Int64(Date().timeIntervalSince1970))
              promise.succeed(.certificateVerified)
            } catch {
              promise.succeed(.failed)
            }
          }
          return try NIOSSLClientHandler(
            context: context,
            serverHostname: serverHostname,
            customVerificationCallback: callback
          )
        }
      }
    }

    static func verifyPinnedCertificate(
      _ certificate: NIOSSLCertificate,
      activePins: [Data],
      nowUnixSeconds: Int64
    ) throws {
      guard
        let result = try? verifyPinnedCertificateResult(
          certificate, activePins: activePins, nowUnixSeconds: nowUnixSeconds
        )
      else { throw TransportSecurityFailureV3.unknownTLS }
      try result.get()
    }

    private static func verifyPinnedCertificateResult(
      _ certificate: NIOSSLCertificate,
      activePins: [Data],
      nowUnixSeconds: Int64
    ) throws -> Result<Void, Error> {
      let der = Data(try certificate.toDERBytes())
      let spki = try certificate.extractPublicKey().toSPKIBytes()
      guard isX509V3CertificateDER(der), isP256SPKI(Data(spki)) else {
        return .failure(TransportSecurityFailureV3.unknownTLS)
      }
      let leaf = PresentedLeafCertificateV3(
        der: der,
        x509Version: 3,
        notBeforeUnixSeconds: Int64(certificate.notValidBefore),
        notAfterUnixSeconds: Int64(certificate.notValidAfter),
        publicKey: .ecdsaP256,
        tlsProofComplete: false
      )
      do {
        // This callback only authorizes the static leaf profile and pin. The
        // NIOSSL handler still has to finish CertificateVerify and Finished
        // before the carrier becomes usable.
        try PinVerifierV3.verifyStatic(
          leaf: leaf, activePins: activePins, nowUnixSeconds: nowUnixSeconds)
        return .success(())
      } catch {
        return .failure(error)
      }
    }

    // Parse exactly SubjectPublicKeyInfo ::= SEQUENCE { algorithm, bit string }
    // and require id-ecPublicKey with namedCurve prime256v1.
    private static func isP256SPKI(_ der: Data) -> Bool {
      var parser = DERCursorV3(bytes: Array(der))
      guard let outer = parser.read(tag: 0x30), parser.isAtEnd else { return false }
      var body = DERCursorV3(bytes: outer)
      guard let algorithm = body.read(tag: 0x30) else { return false }
      var algorithmBody = DERCursorV3(bytes: algorithm)
      guard let keyAlgorithm = algorithmBody.read(tag: 0x06),
        let curve = algorithmBody.read(tag: 0x06), algorithmBody.isAtEnd,
        keyAlgorithm == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01],
        curve == [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        body.read(tag: 0x03) != nil, body.isAtEnd
      else { return false }
      return true
    }

    private static func isX509V3CertificateDER(_ der: Data) -> Bool {
      var parser = DERCursorV3(bytes: Array(der))
      guard let certificate = parser.read(tag: 0x30), parser.isAtEnd else { return false }
      var certificateBody = DERCursorV3(bytes: certificate)
      guard let tbsCertificate = certificateBody.read(tag: 0x30) else { return false }
      var tbsBody = DERCursorV3(bytes: tbsCertificate)
      guard let explicitVersion = tbsBody.read(tag: 0xA0) else { return false }
      var versionBody = DERCursorV3(bytes: explicitVersion)
      guard versionBody.read(tag: 0x02) == [0x02], versionBody.isAtEnd else { return false }
      return true
    }
  }

  private struct DERCursorV3 {
    private let bytes: [UInt8]
    private var offset = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func read(tag expectedTag: UInt8) -> [UInt8]? {
      guard offset < bytes.count, bytes[offset] == expectedTag else { return nil }
      offset += 1
      guard let length = readLength(), offset + length <= bytes.count else { return nil }
      defer { offset += length }
      return Array(bytes[offset..<(offset + length)])
    }

    private mutating func readLength() -> Int? {
      guard offset < bytes.count else { return nil }
      let first = bytes[offset]
      offset += 1
      if first & 0x80 == 0 { return Int(first) }
      let count = Int(first & 0x7F)
      guard count > 0, count <= 4, offset + count <= bytes.count else { return nil }
      var value = 0
      for _ in 0..<count {
        value = value << 8 | Int(bytes[offset])
        offset += 1
      }
      return value
    }
  }
#endif
