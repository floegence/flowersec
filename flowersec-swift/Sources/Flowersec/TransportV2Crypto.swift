import Crypto
import Foundation

enum TransportV2CryptoError: Error, Equatable, Sendable {
  case invalidKeyMaterial
  case invalidSetupPreface
  case invalidRecordHeader
  case recordTooLarge
  case invalidInnerRecord
  case authenticationFailed
  case cryptographicFailure
}

enum TransportDirectionV2: UInt8, Codable, Equatable, Sendable {
  case clientToServer = 1
  case serverToClient = 2
}

enum TransportCipherSuiteV2: UInt16, Codable, Equatable, Sendable {
  case chacha20Poly1305 = 1
  case aes256GCM = 2
}

enum StreamOpenerRoleV2: UInt8, Codable, Equatable, Sendable {
  case client = 1
  case server = 2
}

enum InnerRecordTypeV2: UInt8, Codable, Equatable, Sendable {
  case open = 1
  case openACK = 2
  case openReject = 3
  case data = 4
  case fin = 5
  case streamKeyUpdate = 6
  case sessionReady = 16
  case ping = 17
  case pong = 18
  case sessionKeyUpdate = 19
  case streamReset = 20
  case goAway = 21
  case sessionClose = 22
  case sessionReadyACK = 23
  case sessionKeyUpdateACK = 24
  case streamKeyUpdateACK = 25
}

struct EpochRootsV2: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  private let epochSecretStorage: SensitiveBytesV2
  private let controlRootStorage: SensitiveBytesV2
  private let streamRootStorage: SensitiveBytesV2
  private let setupRootStorage: SensitiveBytesV2
  private let rekeyRootStorage: SensitiveBytesV2

  var epochSecret: Data { epochSecretStorage.copy() }
  var controlRoot: Data { controlRootStorage.copy() }
  var streamRoot: Data { streamRootStorage.copy() }
  var setupRoot: Data { setupRootStorage.copy() }
  var rekeyRoot: Data { rekeyRootStorage.copy() }

  var description: String { "EpochRootsV2([REDACTED])" }
  var debugDescription: String { description }

  fileprivate init(
    epochSecret: Data,
    controlRoot: Data,
    streamRoot: Data,
    setupRoot: Data,
    rekeyRoot: Data
  ) {
    epochSecretStorage = SensitiveBytesV2(epochSecret)
    controlRootStorage = SensitiveBytesV2(controlRoot)
    streamRootStorage = SensitiveBytesV2(streamRoot)
    setupRootStorage = SensitiveBytesV2(setupRoot)
    rekeyRootStorage = SensitiveBytesV2(rekeyRoot)
  }
}

struct RecordMaterialV2: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  private let secretStorage: SensitiveBytesV2
  private let recordKeyStorage: SensitiveBytesV2
  private let noncePrefixStorage: SensitiveBytesV2

  var secret: Data { secretStorage.copy() }
  var recordKey: Data { recordKeyStorage.copy() }
  var noncePrefix: Data { noncePrefixStorage.copy() }

  var description: String { "RecordMaterialV2([REDACTED])" }
  var debugDescription: String { description }

  fileprivate init(secret: Data, recordKey: Data, noncePrefix: Data) {
    secretStorage = SensitiveBytesV2(secret)
    recordKeyStorage = SensitiveBytesV2(recordKey)
    noncePrefixStorage = SensitiveBytesV2(noncePrefix)
  }
}

struct SetupPrefaceV2: Equatable, Sendable {
  let openerRole: StreamOpenerRoleV2
  let logicalStreamID: UInt64
  let initialEpoch: UInt32
  let setupMAC: Data

  init(
    openerRole: StreamOpenerRoleV2,
    logicalStreamID: UInt64,
    initialEpoch: UInt32
  ) throws {
    guard Self.validLogicalStreamID(role: openerRole, id: logicalStreamID) else {
      throw TransportV2CryptoError.invalidSetupPreface
    }
    self.init(
      openerRole: openerRole,
      logicalStreamID: logicalStreamID,
      initialEpoch: initialEpoch,
      setupMAC: Data(repeating: 0, count: TransportV2Crypto.setupMACBytes)
    )
  }

  func withSetupMAC(_ setupMAC: Data) throws -> SetupPrefaceV2 {
    guard setupMAC.count == TransportV2Crypto.setupMACBytes else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    return SetupPrefaceV2(
      openerRole: openerRole,
      logicalStreamID: logicalStreamID,
      initialEpoch: initialEpoch,
      setupMAC: setupMAC
    )
  }

  func encoded() throws -> Data {
    guard
      Self.validLogicalStreamID(role: openerRole, id: logicalStreamID),
      setupMAC.count == TransportV2Crypto.setupMACBytes
    else {
      throw TransportV2CryptoError.invalidSetupPreface
    }

    var output = Data()
    output.reserveCapacity(TransportV2Crypto.setupPrefaceBytes)
    output.append(Data("FSS2".utf8))
    output.append(TransportV2Crypto.protocolVersion)
    output.append(openerRole.rawValue)
    output.append(contentsOf: [0, 0])
    output.appendUInt64BE(logicalStreamID)
    output.appendUInt32BE(initialEpoch)
    output.append(contentsOf: [0, 0, 0, 0])
    output.append(setupMAC)
    return output
  }

  init(encoded: Data) throws {
    guard
      encoded.count == TransportV2Crypto.setupPrefaceBytes,
      Data(encoded[0..<4]) == Data("FSS2".utf8),
      encoded[4] == TransportV2Crypto.protocolVersion,
      encoded[6] == 0,
      encoded[7] == 0,
      encoded.readUInt32BE(at: 20) == 0,
      let role = StreamOpenerRoleV2(rawValue: encoded[5])
    else {
      throw TransportV2CryptoError.invalidSetupPreface
    }
    let logicalStreamID = encoded.readUInt64BE(at: 8)
    guard Self.validLogicalStreamID(role: role, id: logicalStreamID) else {
      throw TransportV2CryptoError.invalidSetupPreface
    }
    self.init(
      openerRole: role,
      logicalStreamID: logicalStreamID,
      initialEpoch: encoded.readUInt32BE(at: 16),
      setupMAC: Data(encoded[24..<56])
    )
  }

  private init(
    openerRole: StreamOpenerRoleV2,
    logicalStreamID: UInt64,
    initialEpoch: UInt32,
    setupMAC: Data
  ) {
    self.openerRole = openerRole
    self.logicalStreamID = logicalStreamID
    self.initialEpoch = initialEpoch
    self.setupMAC = setupMAC
  }

  private static func validLogicalStreamID(role: StreamOpenerRoleV2, id: UInt64) -> Bool {
    guard id != 0 else { return false }
    switch role {
    case .client:
      return id & 1 == 1
    case .server:
      return id & 1 == 0
    }
  }
}

struct RecordHeaderV2: Equatable, Sendable {
  let epoch: UInt32
  let sequence: UInt64
  let ciphertextLength: UInt32

  init(epoch: UInt32, sequence: UInt64, ciphertextLength: UInt32) {
    self.epoch = epoch
    self.sequence = sequence
    self.ciphertextLength = ciphertextLength
  }

  func encoded() throws -> Data {
    guard Int(ciphertextLength) >= TransportV2Crypto.aeadTagBytes else {
      throw TransportV2CryptoError.invalidRecordHeader
    }
    guard Int(ciphertextLength) <= TransportV2Crypto.maxCiphertextBytes else {
      throw TransportV2CryptoError.recordTooLarge
    }

    var output = Data()
    output.reserveCapacity(TransportV2Crypto.recordHeaderBytes)
    output.append(Data("FSR2".utf8))
    output.append(TransportV2Crypto.protocolVersion)
    output.append(UInt8(TransportV2Crypto.recordHeaderBytes))
    output.append(contentsOf: [0, 0])
    output.appendUInt32BE(epoch)
    output.appendUInt64BE(sequence)
    output.appendUInt32BE(ciphertextLength)
    return output
  }

  init(encoded: Data) throws {
    guard
      encoded.count == TransportV2Crypto.recordHeaderBytes,
      Data(encoded[0..<4]) == Data("FSR2".utf8),
      encoded[4] == TransportV2Crypto.protocolVersion,
      encoded[5] == UInt8(TransportV2Crypto.recordHeaderBytes),
      encoded[6] == 0,
      encoded[7] == 0
    else {
      throw TransportV2CryptoError.invalidRecordHeader
    }
    self.init(
      epoch: encoded.readUInt32BE(at: 8),
      sequence: encoded.readUInt64BE(at: 12),
      ciphertextLength: encoded.readUInt32BE(at: 20)
    )
    _ = try self.encoded()
  }
}

/// Stateless v2 wire and crypto primitives. Session code must enforce nonce and epoch invariants.
enum TransportV2Crypto {
  static let protocolVersion: UInt8 = 2
  static let setupPrefaceBytes = 56
  static let setupMACBytes = 32
  static let recordHeaderBytes = 24
  static let innerHeaderBytes = 8
  static let aeadTagBytes = 16
  static let maxDataBytes = 16_384
  static let maxCiphertextBytes = innerHeaderBytes + maxDataBytes + aeadTagBytes

  static func deriveEpochZero(
    sessionPRK: Data,
    direction: TransportDirectionV2
  ) throws -> EpochRootsV2 {
    guard sessionPRK.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }

    var epochSecret = expand(
      pseudoRandomKey: sessionPRK,
      info: labelWith("flowersec v2 epoch zero", Data([direction.rawValue])),
      outputByteCount: 32
    )
    var controlRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith("flowersec v2 control root"),
      outputByteCount: 32
    )
    var streamRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith("flowersec v2 stream root"),
      outputByteCount: 32
    )
    var setupRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith("flowersec v2 setup root"),
      outputByteCount: 32
    )
    var rekeyRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith("flowersec v2 rekey root"),
      outputByteCount: 32
    )
    let roots = EpochRootsV2(
      epochSecret: epochSecret,
      controlRoot: controlRoot,
      streamRoot: streamRoot,
      setupRoot: setupRoot,
      rekeyRoot: rekeyRoot
    )
    zeroize(&epochSecret)
    zeroize(&controlRoot)
    zeroize(&streamRoot)
    zeroize(&setupRoot)
    zeroize(&rekeyRoot)
    return roots
  }

  static func deriveStreamMaterial(
    streamRoot: Data,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV2,
    epoch: UInt32
  ) throws -> RecordMaterialV2 {
    guard streamRoot.count == 32, h3.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    guard logicalStreamID != 0 else {
      throw TransportV2CryptoError.invalidSetupPreface
    }

    var streamID = Data()
    streamID.appendUInt64BE(logicalStreamID)
    var epochBytes = Data()
    epochBytes.appendUInt32BE(epoch)
    var secret = expand(
      pseudoRandomKey: streamRoot,
      info: labelWith(
        "flowersec v2 stream",
        h3,
        streamID,
        Data([direction.rawValue]),
        epochBytes
      ),
      outputByteCount: 32
    )
    var recordKey = expand(
      pseudoRandomKey: secret,
      info: labelWith("flowersec v2 record key"),
      outputByteCount: 32
    )
    var noncePrefix = expand(
      pseudoRandomKey: secret,
      info: labelWith("flowersec v2 nonce"),
      outputByteCount: 4
    )
    let material = RecordMaterialV2(
      secret: secret,
      recordKey: recordKey,
      noncePrefix: noncePrefix
    )
    zeroize(&secret)
    zeroize(&recordKey)
    zeroize(&noncePrefix)
    return material
  }

  static func deriveControlMaterial(
    controlRoot: Data,
    h3: Data,
    direction: TransportDirectionV2,
    epoch: UInt32
  ) throws -> RecordMaterialV2 {
    try deriveRecordMaterial(
      root: controlRoot,
      label: "flowersec v2 control",
      h3: h3,
      logicalStreamID: 0,
      direction: direction,
      epoch: epoch
    )
  }

  static func deriveNextEpoch(
    rekeyRoot: Data,
    h3: Data,
    direction: TransportDirectionV2,
    nextEpoch: UInt32
  ) throws -> Data {
    guard rekeyRoot.count == 32, h3.count == 32, nextEpoch != 0 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    var epoch = Data()
    epoch.appendUInt32BE(nextEpoch)
    return expand(
      pseudoRandomKey: rekeyRoot,
      info: labelWith(
        "flowersec v2 next epoch",
        h3,
        Data([direction.rawValue]),
        epoch
      ),
      outputByteCount: 32
    )
  }

  static func deriveEpochRoots(epochSecret: Data) throws -> EpochRootsV2 {
    guard epochSecret.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    return EpochRootsV2(
      epochSecret: epochSecret,
      controlRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith("flowersec v2 control root"),
        outputByteCount: 32
      ),
      streamRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith("flowersec v2 stream root"),
        outputByteCount: 32
      ),
      setupRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith("flowersec v2 setup root"),
        outputByteCount: 32
      ),
      rekeyRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith("flowersec v2 rekey root"),
        outputByteCount: 32
      )
    )
  }

  static func computeSetupMAC(
    setupRoot: Data,
    h3: Data,
    preface: SetupPrefaceV2
  ) throws -> Data {
    guard setupRoot.count == 32, h3.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    let message = try setupMACMessage(h3: h3, preface: preface)
    return Data(
      HMAC<SHA256>.authenticationCode(
        for: message,
        using: SymmetricKey(data: setupRoot)
      )
    )
  }

  static func verifySetupMAC(
    setupRoot: Data,
    h3: Data,
    preface: SetupPrefaceV2
  ) throws -> Bool {
    guard setupRoot.count == 32, h3.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    return HMAC<SHA256>.isValidAuthenticationCode(
      preface.setupMAC,
      authenticating: try setupMACMessage(h3: h3, preface: preface),
      using: SymmetricKey(data: setupRoot)
    )
  }

  static func encodeInnerRecord(type: InnerRecordTypeV2, payload: Data) throws -> Data {
    try validateInnerRecord(type: type, payloadCount: payload.count)

    var output = Data()
    output.reserveCapacity(innerHeaderBytes + payload.count)
    output.append(type.rawValue)
    output.append(contentsOf: [0, 0, 0])
    output.appendUInt32BE(UInt32(payload.count))
    output.append(payload)
    return output
  }

  static func decodeInnerRecord(_ encoded: Data) throws -> (InnerRecordTypeV2, Data) {
    guard
      encoded.count >= innerHeaderBytes,
      encoded[1] == 0,
      encoded[2] == 0,
      encoded[3] == 0,
      let type = InnerRecordTypeV2(rawValue: encoded[0])
    else {
      throw TransportV2CryptoError.invalidInnerRecord
    }
    let payloadCount = Int(encoded.readUInt32BE(at: 4))
    guard payloadCount + innerHeaderBytes == encoded.count else {
      throw TransportV2CryptoError.invalidInnerRecord
    }
    try validateInnerRecord(type: type, payloadCount: payloadCount)
    return (type, Data(encoded[innerHeaderBytes...]))
  }

  static func recordAAD(
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV2,
    header: RecordHeaderV2
  ) throws -> Data {
    guard h3.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    var streamID = Data()
    streamID.appendUInt64BE(logicalStreamID)
    return try labelWith(
      "flowersec-v2-record",
      h3,
      streamID,
      Data([direction.rawValue]),
      header.encoded()
    )
  }

  static func sealRecord(
    suite: TransportCipherSuiteV2,
    key: Data,
    noncePrefix: Data,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV2,
    header: RecordHeaderV2,
    plaintext: Data
  ) throws -> Data {
    try validateRecordMaterial(key: key, noncePrefix: noncePrefix, h3: h3)
    let (expectedLength, overflow) = plaintext.count.addingReportingOverflow(aeadTagBytes)
    guard !overflow, expectedLength == Int(header.ciphertextLength) else {
      throw TransportV2CryptoError.invalidRecordHeader
    }
    let aad = try recordAAD(
      h3: h3,
      logicalStreamID: logicalStreamID,
      direction: direction,
      header: header
    )
    let nonce = recordNonce(prefix: noncePrefix, sequence: header.sequence)
    let symmetricKey = SymmetricKey(data: key)

    do {
      switch suite {
      case .chacha20Poly1305:
        let sealed = try ChaChaPoly.seal(
          plaintext,
          using: symmetricKey,
          nonce: ChaChaPoly.Nonce(data: nonce),
          authenticating: aad
        )
        return combined(ciphertext: sealed.ciphertext, tag: sealed.tag)
      case .aes256GCM:
        let sealed = try AES.GCM.seal(
          plaintext,
          using: symmetricKey,
          nonce: AES.GCM.Nonce(data: nonce),
          authenticating: aad
        )
        return combined(ciphertext: sealed.ciphertext, tag: sealed.tag)
      }
    } catch {
      throw TransportV2CryptoError.cryptographicFailure
    }
  }

  static func openRecord(
    suite: TransportCipherSuiteV2,
    key: Data,
    noncePrefix: Data,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV2,
    header: RecordHeaderV2,
    ciphertext: Data
  ) throws -> Data {
    try validateRecordMaterial(key: key, noncePrefix: noncePrefix, h3: h3)
    _ = try header.encoded()
    guard
      ciphertext.count == Int(header.ciphertextLength),
      ciphertext.count >= aeadTagBytes
    else {
      throw TransportV2CryptoError.invalidRecordHeader
    }
    let aad = try recordAAD(
      h3: h3,
      logicalStreamID: logicalStreamID,
      direction: direction,
      header: header
    )
    let nonce = recordNonce(prefix: noncePrefix, sequence: header.sequence)
    let tagStart = ciphertext.index(ciphertext.endIndex, offsetBy: -aeadTagBytes)
    let encrypted = Data(ciphertext[..<tagStart])
    let tag = Data(ciphertext[tagStart...])
    let symmetricKey = SymmetricKey(data: key)

    do {
      switch suite {
      case .chacha20Poly1305:
        let box = try ChaChaPoly.SealedBox(
          nonce: ChaChaPoly.Nonce(data: nonce),
          ciphertext: encrypted,
          tag: tag
        )
        return try ChaChaPoly.open(box, using: symmetricKey, authenticating: aad)
      case .aes256GCM:
        let box = try AES.GCM.SealedBox(
          nonce: AES.GCM.Nonce(data: nonce),
          ciphertext: encrypted,
          tag: tag
        )
        return try AES.GCM.open(box, using: symmetricKey, authenticating: aad)
      }
    } catch {
      throw TransportV2CryptoError.authenticationFailed
    }
  }

  private static func setupMACMessage(h3: Data, preface: SetupPrefaceV2) throws -> Data {
    var message = labelWith("flowersec-v2-setup")
    message.append(h3)
    message.append(try preface.encoded().prefix(24))
    return message
  }

  private static func validateRecordMaterial(key: Data, noncePrefix: Data, h3: Data) throws {
    guard key.count == 32, noncePrefix.count == 4, h3.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
  }

  private static func deriveRecordMaterial(
    root: Data,
    label: String,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV2,
    epoch: UInt32
  ) throws -> RecordMaterialV2 {
    guard root.count == 32, h3.count == 32 else {
      throw TransportV2CryptoError.invalidKeyMaterial
    }
    var streamID = Data()
    streamID.appendUInt64BE(logicalStreamID)
    var epochBytes = Data()
    epochBytes.appendUInt32BE(epoch)
    let secret = expand(
      pseudoRandomKey: root,
      info: labelWith(label, h3, streamID, Data([direction.rawValue]), epochBytes),
      outputByteCount: 32
    )
    return RecordMaterialV2(
      secret: secret,
      recordKey: expand(
        pseudoRandomKey: secret,
        info: labelWith("flowersec v2 record key"),
        outputByteCount: 32
      ),
      noncePrefix: expand(
        pseudoRandomKey: secret,
        info: labelWith("flowersec v2 nonce"),
        outputByteCount: 4
      )
    )
  }

  private static func validateInnerRecord(
    type: InnerRecordTypeV2,
    payloadCount: Int
  ) throws {
    let valid: Bool
    switch type {
    case .open:
      valid = payloadCount > 0 && payloadCount <= 8_192
    case .data:
      valid = payloadCount > 0 && payloadCount <= maxDataBytes
    case .fin, .sessionReady, .sessionReadyACK:
      valid = payloadCount == 0
    case .openACK:
      valid = payloadCount == 32
    case .openReject:
      valid = payloadCount == 34
    case .streamKeyUpdate:
      valid = payloadCount == 12
    case .ping, .pong:
      valid = payloadCount == 8
    case .sessionKeyUpdate, .sessionKeyUpdateACK, .streamKeyUpdateACK:
      valid = payloadCount == 20
    case .streamReset, .goAway:
      valid = payloadCount == 10
    case .sessionClose:
      valid = payloadCount == 2
    }
    guard valid else { throw TransportV2CryptoError.invalidInnerRecord }
  }

  private static func recordNonce(prefix: Data, sequence: UInt64) -> Data {
    var nonce = Data(prefix)
    nonce.appendUInt64BE(sequence)
    return nonce
  }

  private static func combined<Ciphertext: DataProtocol, Tag: DataProtocol>(
    ciphertext: Ciphertext,
    tag: Tag
  ) -> Data {
    var output = Data(ciphertext)
    output.append(contentsOf: tag)
    return output
  }

  private static func expand(
    pseudoRandomKey: Data,
    info: Data,
    outputByteCount: Int
  ) -> Data {
    FlowersecHKDF.expandSHA256(
      pseudoRandomKey: pseudoRandomKey,
      info: info,
      outputByteCount: outputByteCount
    )
  }

  private static func labelWith(_ label: String, _ parts: Data...) -> Data {
    var output = Data(label.utf8)
    output.append(0)
    for part in parts {
      output.append(part)
    }
    return output
  }

  private static func zeroize(_ data: inout Data) {
    guard !data.isEmpty else { return }
    data.resetBytes(in: data.startIndex..<data.endIndex)
  }
}

private final class SensitiveBytesV2: @unchecked Sendable {
  private var bytes: Data

  init(_ bytes: Data) {
    self.bytes = bytes
  }

  func copy() -> Data {
    Data(bytes)
  }

  deinit {
    // Data may have external copies; clear this storage on release as a best effort.
    guard !bytes.isEmpty else { return }
    bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex)
  }
}
