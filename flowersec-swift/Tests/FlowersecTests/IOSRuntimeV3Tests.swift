#if os(iOS)
  import Crypto
  import Foundation
  import NIOSSL
  import XCTest

  @testable import Flowersec

  final class IOSRuntimeV3Tests: XCTestCase {
    func testProductionIOSAdapterBuildsPinnedTLSHandlerAndVerifiesLeaf() throws {
      let certificate = try loadCertificate()
      let pin = Data(SHA256.hash(data: Data(try certificate.toDERBytes())))
      let handler = try NativeTLSPolicyAdapterV3.makeClientHandlerFactory(
        policy: .pin(serverName: "localhost", activeLeafDERSHA256: [pin]),
        serverHostname: "localhost")

      _ = try handler.make()
      try NativeTLSPolicyAdapterV3.verifyPinnedCertificate(
        certificate,
        activePins: [pin],
        nowUnixSeconds: Int64(Date().timeIntervalSince1970))
    }

    func testProductionIOSAdapterRejectsWrongPinAndBuildsConfiguredCA() throws {
      let certificate = try loadCertificate()
      let pin = Data(SHA256.hash(data: Data(try certificate.toDERBytes())))

      XCTAssertThrowsError(
        try NativeTLSPolicyAdapterV3.verifyPinnedCertificate(
          certificate,
          activePins: [Data(repeating: 0xA5, count: 32)],
          nowUnixSeconds: Int64(Date().timeIntervalSince1970)))
      _ = try NativeTLSPolicyAdapterV3.makeClientHandlerFactory(
        policy: .ca(serverName: "localhost", rootsSource: .configured),
        serverHostname: "localhost",
        configuredRoots: [certificate]
      ).make()
      _ = try NativeTLSPolicyAdapterV3.makeClientHandlerFactory(
        policy: .pin(serverName: "localhost", activeLeafDERSHA256: [pin]),
        serverHostname: "localhost"
      ).make()
    }

    private func loadCertificate() throws -> NIOSSLCertificate {
      let certificatePath = try XCTUnwrap(
        ProcessInfo.processInfo.environment["FLOWERSEC_IOS_TEST_CERT"])
      let pem = try Data(contentsOf: URL(fileURLWithPath: certificatePath))
      return try XCTUnwrap(NIOSSLCertificate.fromPEMBytes(Array(pem)).first)
    }
  }
#endif
