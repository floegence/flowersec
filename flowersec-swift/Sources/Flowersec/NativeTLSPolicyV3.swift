#if os(macOS) || os(iOS)
  import Darwin
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
      let tlsServerHostname = try tlsServerHostname(serverHostname)

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
          guard let dnsHostname = tlsServerHostname else {
            guard let ipAddress = ipAddressBytes(serverHostname) else {
              throw NativeTLSPolicyErrorV3.invalidPolicy
            }
            return try NIOSSLClientHandler._makeSSLClientHandler(
              context: context,
              serverHostname: nil,
              additionalPeerCertificateVerificationCallback: { certificate, channel in
                guard certificateMatchesIPAddress(certificate, address: ipAddress) else {
                  return channel.eventLoop.makeFailedFuture(
                    TransportSecurityFailureV3.unknownTLS)
                }
                return channel.eventLoop.makeSucceededVoidFuture()
              }
            )
          }
          return try NIOSSLClientHandler._makeSSLClientHandler(
            context: context,
            serverHostname: dnsHostname,
            additionalPeerCertificateVerificationCallback: { certificate, channel in
              guard certificateMatchesDNSHostname(certificate, hostname: dnsHostname) else {
                return channel.eventLoop.makeFailedFuture(
                  TransportSecurityFailureV3.unknownTLS)
              }
              return channel.eventLoop.makeSucceededVoidFuture()
            }
          )
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
            serverHostname: tlsServerHostname,
            customVerificationCallback: callback
          )
        }
      }
    }

    private static func tlsServerHostname(_ hostname: String) throws -> String? {
      let unbracketed: String
      if hostname.hasPrefix("[") && hostname.hasSuffix("]") {
        unbracketed = String(hostname.dropFirst().dropLast())
      } else {
        unbracketed = hostname
      }
      guard !unbracketed.isEmpty else { throw NativeTLSPolicyErrorV3.invalidPolicy }
      if ipAddressBytes(unbracketed) != nil { return nil }
      return unbracketed
    }

    private static func ipAddressBytes(_ hostname: String) -> [UInt8]? {
      let unbracketed: String
      if hostname.hasPrefix("[") && hostname.hasSuffix("]") {
        unbracketed = String(hostname.dropFirst().dropLast())
      } else {
        unbracketed = hostname
      }
      guard !unbracketed.isEmpty else { return nil }

      var ipv4 = in_addr()
      if unbracketed.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
        return withUnsafeBytes(of: ipv4) { Array($0) }
      }

      var ipv6 = in6_addr()
      if unbracketed.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
        return withUnsafeBytes(of: ipv6) { Array($0) }
      }
      return nil
    }

    static func certificateMatchesIPAddress(
      _ certificate: NIOSSLCertificate,
      address: [UInt8]
    ) -> Bool {
      guard address.count == 4 || address.count == 16 else { return false }
      for alternativeName in certificate._subjectAlternativeNames()
      where alternativeName.nameType == .ipAddress {
        let presented = alternativeName.contents.withUnsafeBufferPointer(Array.init)
        if presented == address { return true }
      }
      return false
    }

    private static func certificateMatchesDNSHostname(
      _ certificate: NIOSSLCertificate,
      hostname: String
    ) -> Bool {
      var target = Array(hostname.utf8)
      if target.last == UInt8(ascii: ".") { target.removeLast() }
      guard !target.isEmpty, target.allSatisfy(isDNSHostnameByte) else { return false }

      for alternativeName in certificate._subjectAlternativeNames()
      where alternativeName.nameType == .dnsName {
        let presented = alternativeName.contents.withUnsafeBufferPointer(Array.init)
        if dnsName(presented, matches: target) { return true }
      }
      return false
    }

    private static func dnsName(_ rawPresented: [UInt8], matches rawTarget: [UInt8]) -> Bool {
      var presented = rawPresented
      var target = rawTarget
      if presented.last == UInt8(ascii: ".") { presented.removeLast() }
      if target.last == UInt8(ascii: ".") { target.removeLast() }
      guard !presented.isEmpty, !target.isEmpty else { return false }

      let wildcardIndices = presented.indices.filter { presented[$0] == UInt8(ascii: "*") }
      guard wildcardIndices.count <= 1,
        presented.allSatisfy({ isDNSHostnameByte($0) || $0 == UInt8(ascii: "*") })
      else { return false }

      guard let wildcardIndex = wildcardIndices.first else {
        return asciiCaseInsensitiveEqual(presented, target)
      }
      let presentedDot = presented.firstIndex(of: UInt8(ascii: "."))
      guard presentedDot.map({ wildcardIndex < $0 }) ?? true else { return false }

      let presentedLabelEnd = presentedDot ?? presented.endIndex
      let targetDot = target.firstIndex(of: UInt8(ascii: "."))
      let targetLabelEnd = targetDot ?? target.endIndex
      let presentedLabel = presented[..<presentedLabelEnd]
      let targetLabel = target[..<targetLabelEnd]
      guard !hasIDNAPrefix(presentedLabel), !hasIDNAPrefix(targetLabel),
        targetLabel.count >= presentedLabel.count
      else { return false }

      let presentedRemainder =
        presentedDot.map { presented[presented.index(after: $0)...] }
        ?? presented[presented.endIndex...]
      let targetRemainder =
        targetDot.map { target[target.index(after: $0)...] } ?? target[target.endIndex...]
      guard asciiCaseInsensitiveEqual(presentedRemainder, targetRemainder) else { return false }

      let wildcardOffset = presented.distance(from: presented.startIndex, to: wildcardIndex)
      let prefix = presentedLabel.prefix(wildcardOffset)
      let suffix = presentedLabel.dropFirst(wildcardOffset + 1)
      return asciiCaseInsensitiveEqual(prefix, targetLabel.prefix(prefix.count))
        && asciiCaseInsensitiveEqual(suffix, targetLabel.suffix(suffix.count))
    }

    private static func isDNSHostnameByte(_ byte: UInt8) -> Bool {
      (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
        || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
        || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".")
    }

    private static func asciiCaseInsensitiveEqual<C1: Collection, C2: Collection>(
      _ lhs: C1,
      _ rhs: C2
    ) -> Bool where C1.Element == UInt8, C2.Element == UInt8 {
      lhs.elementsEqual(rhs) { asciiLowercase($0) == asciiLowercase($1) }
    }

    private static func asciiLowercase(_ byte: UInt8) -> UInt8 {
      (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) ? byte | 0x20 : byte
    }

    private static func hasIDNAPrefix<C: Collection>(_ bytes: C) -> Bool
    where C.Element == UInt8 {
      bytes.count >= 4
        && asciiCaseInsensitiveEqual(bytes.prefix(4), Array("xn--".utf8))
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
