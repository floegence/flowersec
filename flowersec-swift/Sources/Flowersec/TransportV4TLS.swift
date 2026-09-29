import Foundation

struct V4TLSPin: Sendable {
  let digest: Data
  let notBefore: UInt64
  let notAfter: UInt64
}

#if os(macOS) || os(iOS)
  import Crypto
  import NIOSSL

  // The active set is captured once before the original native TLS handshake.
  // A match retains its own deadline; later rotation cannot extend that socket.
  final class V4PinnedTLS: @unchecked Sendable {
    private let route: V4WebSocketRoute
    private let active: [V4TLSPin]
    private var matched: V4TLSPin?
    private var deadline: V4SecurityDeadline?
    init(route: V4WebSocketRoute) throws {
      self.route = route
      let sample = route.environment.clock.sample()
      guard let now = sample.interval, let pins = route.pins else {
        throw V4WebSocketFailure.policy
      }
      active = pins.filter { $0.notBefore <= now.lowerMS && now.upperMS < $0.notAfter }
      guard !active.isEmpty else { throw V4TimeFailure.pending }
    }
    func verify(_ certificate: NIOSSLCertificate) throws {
      try route.environment.gate.withLock {
        try route.check()
        guard matched == nil else { throw V4WebSocketFailure.policy }
        let der = Data(try certificate.toDERBytes())
        let bounds = try V4PinnedCertificate.inspect(certificate, der: der)
        let digest = V4Crypto.hash(der)
        guard let pin = active.first(where: { $0.digest == digest }),
          pin.notBefore >= bounds.lowerMS, pin.notAfter <= bounds.upperMS
        else { throw V4WebSocketFailure.policy }
        let cap = try V4SecurityDeadline(clock: route.environment.clock, capMS: pin.notAfter)
        guard let now = try cap.sample().interval, now.lowerMS >= pin.notBefore else {
          throw V4TimeFailure.pending
        }
        matched = pin
        deadline = cap
      }
    }
    func check(required: Bool) throws {
      try route.environment.gate.withLock {
        guard let matched, let deadline else {
          if required { throw V4WebSocketFailure.policy }
          return
        }
        guard let now = try deadline.sample().interval, now.lowerMS >= matched.notBefore else {
          throw V4TimeFailure.pending
        }
      }
    }
  }

  enum V4PinnedCertificate {
    static func inspect(_ certificate: NIOSSLCertificate, der: Data) throws -> V4TimeInterval {
      guard !der.isEmpty, der.count <= 65536, certificate.notValidBefore >= 0,
        certificate.notValidAfter > certificate.notValidBefore
      else { throw V4WebSocketFailure.policy }
      let (start, a) = UInt64(certificate.notValidBefore).multipliedReportingOverflow(by: 1000)
      let (end, b) = UInt64(certificate.notValidAfter).multipliedReportingOverflow(by: 1000)
      guard !a, !b, end - start <= 1_209_600_000 else { throw V4WebSocketFailure.policy }
      var root = V4DER(der)
      var certificateBody = V4DER(try root.take(0x30))
      guard root.empty else { throw V4WebSocketFailure.policy }
      var tbs = V4DER(try certificateBody.take(0x30))
      _ = try certificateBody.take(0x30)
      _ = try certificateBody.take(0x03)
      guard certificateBody.empty else { throw V4WebSocketFailure.policy }
      var version = V4DER(try tbs.take(0xA0))
      guard try version.take(0x02) == Data([2]), version.empty else {
        throw V4WebSocketFailure.policy
      }
      _ = try tbs.take(0x02)
      for _ in 0..<4 { _ = try tbs.take(0x30) }
      var spki = V4DER(try tbs.take(0x30))
      var algorithm = V4DER(try spki.take(0x30))
      guard try algorithm.take(0x06) == Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 2, 1]),
        try algorithm.take(0x06) == Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 3, 1, 7]), algorithm.empty
      else { throw V4WebSocketFailure.policy }
      let key = try spki.take(0x03)
      guard key.count == 66, key.first == 0, spki.empty else { throw V4WebSocketFailure.policy }
      _ = try P256.Signing.PublicKey(x963Representation: key.dropFirst())
      if tbs.tag == 0x81 { _ = try tbs.take(0x81) }
      if tbs.tag == 0x82 { _ = try tbs.take(0x82) }
      if tbs.tag == 0xA3 {
        var wrapper = V4DER(try tbs.take(0xA3))
        var extensions = V4DER(try wrapper.take(0x30))
        guard wrapper.empty else { throw V4WebSocketFailure.policy }
        var seen: Set<Data> = []
        while !extensions.empty {
          guard seen.count < 64 else { throw V4WebSocketFailure.policy }
          var item = V4DER(try extensions.take(0x30))
          let oid = try item.take(0x06)
          guard seen.insert(oid).inserted else { throw V4WebSocketFailure.policy }
          var critical = false
          if item.tag == 1 {
            guard try item.take(1) == Data([0xff]) else { throw V4WebSocketFailure.policy }
            critical = true
          }
          let value = try item.take(0x04)
          guard item.empty else { throw V4WebSocketFailure.policy }
          try checkExtension(oid, value: value, critical: critical)
        }
      }
      guard tbs.empty else { throw V4WebSocketFailure.policy }
      return V4TimeInterval(lowerMS: start, upperMS: end)
    }
    private static func checkExtension(_ oid: Data, value: Data, critical: Bool) throws {
      var reader = V4DER(value)
      switch oid {
      case Data([0x55, 0x1d, 0x0f]):
        let bits = try reader.take(0x03)
        guard bits.count >= 2, bits.count <= 3, bits[0] <= 7, bits[1] & 0x80 != 0,
          bits.last! & UInt8((1 << bits[0]) - 1) == 0, reader.empty
        else { throw V4WebSocketFailure.policy }
      case Data([0x55, 0x1d, 0x25]):
        var purposes = V4DER(try reader.take(0x30))
        var server = false
        var count = 0
        while !purposes.empty {
          let purpose = try purposes.take(0x06)
          server =
            server || purpose == Data([0x2b, 6, 1, 5, 5, 7, 3, 1])
            || purpose == Data([0x55, 0x1d, 0x25, 0])
          count += 1
          guard count <= 64 else { throw V4WebSocketFailure.policy }
        }
        guard reader.empty, server else { throw V4WebSocketFailure.policy }
      case Data([0x55, 0x1d, 0x13]):
        var constraints = V4DER(try reader.take(0x30))
        if constraints.tag == 1 {
          guard try constraints.take(1) == Data([0xff]) else { throw V4WebSocketFailure.policy }
          if constraints.tag == 2 { _ = try constraints.take(2) }
        }
        guard reader.empty, constraints.empty else { throw V4WebSocketFailure.policy }
      case Data([0x55, 0x1d, 0x11]):
        var names = V4DER(try reader.take(0x30))
        guard reader.empty, !names.empty else { throw V4WebSocketFailure.policy }
        while let tag = names.tag {
          guard (0x80...0x88).contains(tag) || [0xA0, 0xA3, 0xA4, 0xA5].contains(tag) else {
            throw V4WebSocketFailure.policy
          }
          _ = try names.take(tag)
        }
      default:
        guard !critical else { throw V4WebSocketFailure.policy }
      }
    }
  }

  private struct V4DER {
    private let bytes: Data
    private var offset = 0
    init(_ bytes: Data) { self.bytes = Data(bytes) }
    var empty: Bool { offset == bytes.count }
    var tag: UInt8? { empty ? nil : bytes[offset] }
    mutating func take(_ tag: UInt8) throws -> Data {
      guard offset + 2 <= bytes.count, bytes[offset] == tag else { throw V4WebSocketFailure.policy }
      offset += 1
      var length = Int(bytes[offset])
      offset += 1
      if length >= 128 {
        let count = length & 127
        guard (1...3).contains(count), offset + count <= bytes.count, bytes[offset] != 0 else {
          throw V4WebSocketFailure.policy
        }
        length = 0
        for _ in 0..<count {
          length = (length << 8) | Int(bytes[offset])
          offset += 1
        }
        guard length >= 128 else { throw V4WebSocketFailure.policy }
      }
      guard length <= bytes.count - offset else { throw V4WebSocketFailure.policy }
      defer { offset += length }
      return Data(bytes[offset..<offset + length])
    }
  }
#endif
