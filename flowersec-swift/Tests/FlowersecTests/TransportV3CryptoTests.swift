import Foundation
import XCTest

@testable import Flowersec

final class TransportV3CryptoTests: XCTestCase {
  func testFixtureMetadataAndKeyScheduleMatch() throws {
    let fixture = try cryptoVectors()
    XCTAssertEqual(fixture.version, 3)
    XCTAssertEqual(fixture.profile, "flowersec/3")
    XCTAssertFalse(fixture.source.isEmpty)
    XCTAssertFalse(fixture.vectors.isEmpty)

    for vector in fixture.vectors {
      let direction = try XCTUnwrap(TransportDirectionV3(rawValue: vector.direction))
      let roots = try TransportV3Crypto.deriveEpochZero(
        sessionPRK: try Data(validatingHex: vector.sessionPRKHex),
        direction: direction
      )
      XCTAssertEqual(roots.epochSecret, try Data(validatingHex: vector.epochSecretHex), vector.id)
      XCTAssertEqual(roots.controlRoot, try Data(validatingHex: vector.controlRootHex), vector.id)
      XCTAssertEqual(roots.streamRoot, try Data(validatingHex: vector.streamRootHex), vector.id)
      XCTAssertEqual(roots.setupRoot, try Data(validatingHex: vector.setupRootHex), vector.id)
      XCTAssertEqual(roots.rekeyRoot, try Data(validatingHex: vector.rekeyRootHex), vector.id)

      let material = try TransportV3Crypto.deriveStreamMaterial(
        streamRoot: roots.streamRoot,
        h3: try Data(validatingHex: vector.h3Hex),
        logicalStreamID: vector.logicalStreamID,
        direction: direction,
        epoch: vector.epoch
      )
      XCTAssertEqual(material.secret, try Data(validatingHex: vector.streamSecretHex), vector.id)
      XCTAssertEqual(material.recordKey, try Data(validatingHex: vector.recordKeyHex), vector.id)
      XCTAssertEqual(
        material.noncePrefix, try Data(validatingHex: vector.noncePrefixHex), vector.id)

      XCTAssertEqual(roots.description, "EpochRootsV3([REDACTED])")
      XCTAssertEqual(roots.debugDescription, "EpochRootsV3([REDACTED])")
      XCTAssertEqual(material.description, "RecordMaterialV3([REDACTED])")
      XCTAssertEqual(material.debugDescription, "RecordMaterialV3([REDACTED])")
      for secret in [
        vector.epochSecretHex,
        vector.streamRootHex,
        vector.streamSecretHex,
        vector.recordKeyHex,
      ] {
        XCTAssertFalse(String(reflecting: roots).contains(secret), vector.id)
        XCTAssertFalse(String(reflecting: material).contains(secret), vector.id)
      }
    }
  }

  func testFSS3FSR3InnerRecordAndAADMatch() throws {
    for vector in try cryptoVectors().vectors {
      let context = try context(for: vector)
      var preface = try SetupPrefaceV3(
        openerRole: .client,
        logicalStreamID: vector.logicalStreamID,
        initialEpoch: vector.epoch
      )
      let setupMAC = try TransportV3Crypto.computeSetupMAC(
        setupRoot: context.roots.setupRoot,
        h3: context.h3,
        preface: preface
      )
      preface = try preface.withSetupMAC(setupMAC)

      XCTAssertEqual(try preface.encoded(), try Data(validatingHex: vector.fss3Hex), vector.id)
      XCTAssertTrue(
        try TransportV3Crypto.verifySetupMAC(
          setupRoot: context.roots.setupRoot,
          h3: context.h3,
          preface: preface
        ),
        vector.id
      )

      var tamperedMAC = setupMAC
      tamperedMAC[tamperedMAC.startIndex] ^= 1
      let tamperedPreface = try preface.withSetupMAC(tamperedMAC)
      XCTAssertFalse(
        try TransportV3Crypto.verifySetupMAC(
          setupRoot: context.roots.setupRoot,
          h3: context.h3,
          preface: tamperedPreface
        ),
        vector.id
      )

      XCTAssertEqual(context.inner, try Data(validatingHex: vector.innerHex), vector.id)
      XCTAssertEqual(
        try context.header.encoded(),
        try Data(validatingHex: vector.fsr3HeaderHex),
        vector.id
      )
      XCTAssertEqual(
        try TransportV3Crypto.recordAAD(
          h3: context.h3,
          logicalStreamID: vector.logicalStreamID,
          direction: context.direction,
          header: context.header
        ),
        try Data(validatingHex: vector.aadHex),
        vector.id
      )
    }
  }

  func testBothAEADSuitesMatchAndOpenFixture() throws {
    for vector in try cryptoVectors().vectors {
      let context = try context(for: vector)
      for (suite, expectedHex) in [
        (TransportCipherSuiteV3.chacha20Poly1305, vector.chacha20Poly1305CiphertextHex),
        (TransportCipherSuiteV3.aes256GCM, vector.aes256GCMCiphertextHex),
      ] {
        let ciphertext = try TransportV3Crypto.sealRecord(
          suite: suite,
          key: context.material.recordKey,
          noncePrefix: context.material.noncePrefix,
          h3: context.h3,
          logicalStreamID: vector.logicalStreamID,
          direction: context.direction,
          header: context.header,
          plaintext: context.inner
        )
        XCTAssertEqual(ciphertext, try Data(validatingHex: expectedHex), vector.id)
        XCTAssertEqual(
          try TransportV3Crypto.openRecord(
            suite: suite,
            key: context.material.recordKey,
            noncePrefix: context.material.noncePrefix,
            h3: context.h3,
            logicalStreamID: vector.logicalStreamID,
            direction: context.direction,
            header: context.header,
            ciphertext: ciphertext
          ),
          context.inner,
          vector.id
        )
      }
    }
  }

  func testCiphertextTagAndAADTamperingFailAuthentication() throws {
    for vector in try cryptoVectors().vectors {
      let context = try context(for: vector)
      for (suite, expectedHex) in [
        (TransportCipherSuiteV3.chacha20Poly1305, vector.chacha20Poly1305CiphertextHex),
        (TransportCipherSuiteV3.aes256GCM, vector.aes256GCMCiphertextHex),
      ] {
        let ciphertext = try Data(validatingHex: expectedHex)
        var tamperedCiphertext = ciphertext
        tamperedCiphertext[tamperedCiphertext.startIndex] ^= 1
        try assertAuthenticationFailure(
          suite: suite,
          context: context,
          vector: vector,
          h3: context.h3,
          ciphertext: tamperedCiphertext
        )

        var tamperedTag = ciphertext
        tamperedTag[tamperedTag.index(before: tamperedTag.endIndex)] ^= 1
        try assertAuthenticationFailure(
          suite: suite,
          context: context,
          vector: vector,
          h3: context.h3,
          ciphertext: tamperedTag
        )

        var tamperedAADInput = context.h3
        tamperedAADInput[tamperedAADInput.startIndex] ^= 1
        try assertAuthenticationFailure(
          suite: suite,
          context: context,
          vector: vector,
          h3: tamperedAADInput,
          ciphertext: ciphertext
        )
      }
    }
  }

  func testWireAndKeyMaterialValidationIsBounded() throws {
    XCTAssertThrowsError(
      try TransportV3Crypto.deriveEpochZero(
        sessionPRK: Data(repeating: 0, count: 31),
        direction: .clientToServer
      )
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .invalidKeyMaterial)
    }
    XCTAssertThrowsError(
      try SetupPrefaceV3(openerRole: .client, logicalStreamID: 2, initialEpoch: 0)
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .invalidSetupPreface)
    }
    XCTAssertThrowsError(
      try RecordHeaderV3(epoch: 0, sequence: 0, ciphertextLength: 15).encoded()
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .invalidRecordHeader)
    }
    XCTAssertThrowsError(
      try RecordHeaderV3(
        epoch: 0,
        sequence: 0,
        ciphertextLength: UInt32(TransportV3Crypto.maxCiphertextBytes + 1)
      ).encoded()
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .recordTooLarge)
    }
    XCTAssertThrowsError(
      try TransportV3Crypto.encodeInnerRecord(type: .data, payload: Data())
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .invalidInnerRecord)
    }
    XCTAssertThrowsError(
      try TransportV3Crypto.encodeInnerRecord(
        type: .data,
        payload: Data(repeating: 0, count: TransportV3Crypto.maxDataBytes + 1)
      )
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .invalidInnerRecord)
    }
  }

  private func context(for vector: TransportV3CryptoVector) throws -> TransportV3TestContext {
    let direction = try XCTUnwrap(TransportDirectionV3(rawValue: vector.direction))
    let h3 = try Data(validatingHex: vector.h3Hex)
    let roots = try TransportV3Crypto.deriveEpochZero(
      sessionPRK: try Data(validatingHex: vector.sessionPRKHex),
      direction: direction
    )
    let material = try TransportV3Crypto.deriveStreamMaterial(
      streamRoot: roots.streamRoot,
      h3: h3,
      logicalStreamID: vector.logicalStreamID,
      direction: direction,
      epoch: vector.epoch
    )
    let inner = try TransportV3Crypto.encodeInnerRecord(
      type: .data,
      payload: Data("abc".utf8)
    )
    let header = RecordHeaderV3(
      epoch: vector.epoch,
      sequence: vector.sequence,
      ciphertextLength: UInt32(inner.count + TransportV3Crypto.aeadTagBytes)
    )
    return TransportV3TestContext(
      direction: direction,
      h3: h3,
      roots: roots,
      material: material,
      inner: inner,
      header: header
    )
  }

  private func assertAuthenticationFailure(
    suite: TransportCipherSuiteV3,
    context: TransportV3TestContext,
    vector: TransportV3CryptoVector,
    h3: Data,
    ciphertext: Data
  ) throws {
    XCTAssertThrowsError(
      try TransportV3Crypto.openRecord(
        suite: suite,
        key: context.material.recordKey,
        noncePrefix: context.material.noncePrefix,
        h3: h3,
        logicalStreamID: vector.logicalStreamID,
        direction: context.direction,
        header: context.header,
        ciphertext: ciphertext
      ),
      vector.id
    ) { error in
      XCTAssertEqual(error as? TransportV3CryptoError, .authenticationFailed, vector.id)
    }
  }

  private func cryptoVectors() throws -> TransportV3CryptoVectorFile {
    let url = packageRoot().appendingPathComponent("testdata/transport_v3/crypto_vectors.json")
    return try JSONDecoder().decode(
      TransportV3CryptoVectorFile.self,
      from: Data(contentsOf: url)
    )
  }
}

private struct TransportV3TestContext {
  let direction: TransportDirectionV3
  let h3: Data
  let roots: EpochRootsV3
  let material: RecordMaterialV3
  let inner: Data
  let header: RecordHeaderV3
}

private struct TransportV3CryptoVectorFile: Decodable {
  let version: UInt8
  let profile: String
  let source: String
  let vectors: [TransportV3CryptoVector]
}

private struct TransportV3CryptoVector: Decodable {
  let id: String
  let direction: UInt8
  let epoch: UInt32
  let logicalStreamID: UInt64
  let sequence: UInt64
  let sessionPRKHex: String
  let h3Hex: String
  let epochSecretHex: String
  let controlRootHex: String
  let streamRootHex: String
  let setupRootHex: String
  let rekeyRootHex: String
  let streamSecretHex: String
  let recordKeyHex: String
  let noncePrefixHex: String
  let fss3Hex: String
  let fsr3HeaderHex: String
  let innerHex: String
  let aadHex: String
  let chacha20Poly1305CiphertextHex: String
  let aes256GCMCiphertextHex: String

  private enum CodingKeys: String, CodingKey {
    case id
    case direction
    case epoch
    case logicalStreamID = "logical_stream_id"
    case sequence
    case sessionPRKHex = "session_prk_hex"
    case h3Hex = "h3_hex"
    case epochSecretHex = "epoch_secret_hex"
    case controlRootHex = "control_root_hex"
    case streamRootHex = "stream_root_hex"
    case setupRootHex = "setup_root_hex"
    case rekeyRootHex = "rekey_root_hex"
    case streamSecretHex = "stream_secret_hex"
    case recordKeyHex = "record_key_hex"
    case noncePrefixHex = "nonce_prefix_hex"
    case fss3Hex = "fss3_hex"
    case fsr3HeaderHex = "fsr3_header_hex"
    case innerHex = "inner_hex"
    case aadHex = "aad_hex"
    case chacha20Poly1305CiphertextHex = "chacha20_poly1305_ciphertext_hex"
    case aes256GCMCiphertextHex = "aes_256_gcm_ciphertext_hex"
  }
}

private enum HexDecodingError: Error {
  case invalidLength
  case invalidByte
}

extension Data {
  fileprivate init(validatingHex value: String) throws {
    guard value.utf8.count.isMultiple(of: 2) else {
      throw HexDecodingError.invalidLength
    }
    var decoded = Data()
    decoded.reserveCapacity(value.utf8.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        throw HexDecodingError.invalidByte
      }
      decoded.append(byte)
      index = next
    }
    self = decoded
  }
}
