import Crypto
import Foundation

enum TransportV3CryptoError: Error, Equatable, Sendable {
  case invalidKeyMaterial
  case invalidSetupPreface
  case invalidRecordHeader
  case invalidUnreliableMessage
  case recordTooLarge
  case unreliableMessageTooLarge
  case invalidInnerRecord
  case authenticationFailed
  case cryptographicFailure
}

enum TransportDirectionV3: UInt8, Codable, Equatable, Sendable {
  case clientToServer = 1
  case serverToClient = 2
}

enum TransportCipherSuiteV3: UInt16, Codable, Equatable, Sendable {
  case chacha20Poly1305 = 1
  case aes256GCM = 2
}

enum StreamOpenerRoleV3: UInt8, Codable, Equatable, Sendable {
  case client = 1
  case server = 2
}

enum InnerRecordTypeV3: UInt8, Codable, Equatable, Sendable {
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
  case sessionReadyConfirm = 26
}

struct EpochRootsV3: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  private let epochSecretStorage: SensitiveBytesV3
  private let controlRootStorage: SensitiveBytesV3
  private let streamRootStorage: SensitiveBytesV3
  private let setupRootStorage: SensitiveBytesV3
  private let rekeyRootStorage: SensitiveBytesV3

  var epochSecret: Data { epochSecretStorage.copy() }
  var controlRoot: Data { controlRootStorage.copy() }
  var streamRoot: Data { streamRootStorage.copy() }
  var setupRoot: Data { setupRootStorage.copy() }
  var rekeyRoot: Data { rekeyRootStorage.copy() }

  var description: String { "EpochRootsV3([REDACTED])" }
  var debugDescription: String { description }

  fileprivate init(
    epochSecret: Data,
    controlRoot: Data,
    streamRoot: Data,
    setupRoot: Data,
    rekeyRoot: Data
  ) {
    epochSecretStorage = SensitiveBytesV3(epochSecret)
    controlRootStorage = SensitiveBytesV3(controlRoot)
    streamRootStorage = SensitiveBytesV3(streamRoot)
    setupRootStorage = SensitiveBytesV3(setupRoot)
    rekeyRootStorage = SensitiveBytesV3(rekeyRoot)
  }
}

struct RecordMaterialV3: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  private let secretStorage: SensitiveBytesV3
  private let recordKeyStorage: SensitiveBytesV3
  private let noncePrefixStorage: SensitiveBytesV3

  var secret: Data { secretStorage.copy() }
  var recordKey: Data { recordKeyStorage.copy() }
  var noncePrefix: Data { noncePrefixStorage.copy() }

  var description: String { "RecordMaterialV3([REDACTED])" }
  var debugDescription: String { description }

  fileprivate init(secret: Data, recordKey: Data, noncePrefix: Data) {
    secretStorage = SensitiveBytesV3(secret)
    recordKeyStorage = SensitiveBytesV3(recordKey)
    noncePrefixStorage = SensitiveBytesV3(noncePrefix)
  }
}

struct UnreliableMaterialV3: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  private let rootStorage: SensitiveBytesV3
  private let secretStorage: SensitiveBytesV3
  private let recordKeyStorage: SensitiveBytesV3
  private let noncePrefixStorage: SensitiveBytesV3

  var root: Data { rootStorage.copy() }
  var secret: Data { secretStorage.copy() }
  var recordKey: Data { recordKeyStorage.copy() }
  var noncePrefix: Data { noncePrefixStorage.copy() }

  var description: String { "UnreliableMaterialV3([REDACTED])" }
  var debugDescription: String { description }

  fileprivate init(root: Data, secret: Data, recordKey: Data, noncePrefix: Data) {
    rootStorage = SensitiveBytesV3(root)
    secretStorage = SensitiveBytesV3(secret)
    recordKeyStorage = SensitiveBytesV3(recordKey)
    noncePrefixStorage = SensitiveBytesV3(noncePrefix)
  }
}

struct UnreliableHeaderV3: Equatable, Sendable {
  let epoch: UInt32
  let sequence: UInt64
  let expiresAtUnixMilliseconds: UInt64
  let ciphertextLength: UInt32

  func encoded() throws -> Data {
    guard expiresAtUnixMilliseconds != 0,
      (TransportV3Crypto.aeadTagBytes...TransportV3Crypto.maxUnreliableCiphertextBytes)
        .contains(Int(ciphertextLength))
    else { throw TransportV3CryptoError.invalidUnreliableMessage }

    var output = Data()
    output.reserveCapacity(TransportV3Crypto.unreliableHeaderBytes)
    output.append(Data("FSD3".utf8))
    output.append(TransportV3Crypto.protocolVersion)
    output.append(0)
    output.appendUInt16BE(UInt16(TransportV3Crypto.unreliableHeaderBytes))
    output.appendUInt32BE(epoch)
    output.appendUInt64BE(sequence)
    output.appendUInt64BE(expiresAtUnixMilliseconds)
    output.appendUInt32BE(ciphertextLength)
    return output
  }

  init(
    epoch: UInt32,
    sequence: UInt64,
    expiresAtUnixMilliseconds: UInt64,
    ciphertextLength: UInt32
  ) {
    self.epoch = epoch
    self.sequence = sequence
    self.expiresAtUnixMilliseconds = expiresAtUnixMilliseconds
    self.ciphertextLength = ciphertextLength
  }

  init(encoded: Data) throws {
    guard encoded.count == TransportV3Crypto.unreliableHeaderBytes,
      Data(encoded[0..<4]) == Data("FSD3".utf8),
      encoded[4] == TransportV3Crypto.protocolVersion,
      encoded[5] == 0,
      encoded.readUInt16BE(at: 6) == UInt16(TransportV3Crypto.unreliableHeaderBytes)
    else { throw TransportV3CryptoError.invalidUnreliableMessage }
    self.init(
      epoch: encoded.readUInt32BE(at: 8),
      sequence: encoded.readUInt64BE(at: 12),
      expiresAtUnixMilliseconds: encoded.readUInt64BE(at: 20),
      ciphertextLength: encoded.readUInt32BE(at: 28)
    )
    _ = try self.encoded()
  }
}

struct SetupPrefaceV3: Equatable, Sendable {
  let openerRole: StreamOpenerRoleV3
  let logicalStreamID: UInt64
  let initialEpoch: UInt32
  let setupMAC: Data

  init(
    openerRole: StreamOpenerRoleV3,
    logicalStreamID: UInt64,
    initialEpoch: UInt32
  ) throws {
    guard Self.validLogicalStreamID(role: openerRole, id: logicalStreamID) else {
      throw TransportV3CryptoError.invalidSetupPreface
    }
    self.init(
      openerRole: openerRole,
      logicalStreamID: logicalStreamID,
      initialEpoch: initialEpoch,
      setupMAC: Data(repeating: 0, count: TransportV3Crypto.setupMACBytes)
    )
  }

  func withSetupMAC(_ setupMAC: Data) throws -> SetupPrefaceV3 {
    guard setupMAC.count == TransportV3Crypto.setupMACBytes else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    return SetupPrefaceV3(
      openerRole: openerRole,
      logicalStreamID: logicalStreamID,
      initialEpoch: initialEpoch,
      setupMAC: setupMAC
    )
  }

  func encoded() throws -> Data {
    guard
      Self.validLogicalStreamID(role: openerRole, id: logicalStreamID),
      setupMAC.count == TransportV3Crypto.setupMACBytes
    else {
      throw TransportV3CryptoError.invalidSetupPreface
    }

    var output = Data()
    output.reserveCapacity(TransportV3Crypto.setupPrefaceBytes)
    output.append(Data("FSS3".utf8))
    output.append(TransportV3Crypto.protocolVersion)
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
      encoded.count == TransportV3Crypto.setupPrefaceBytes,
      Data(encoded[0..<4]) == Data("FSS3".utf8),
      encoded[4] == TransportV3Crypto.protocolVersion,
      encoded[6] == 0,
      encoded[7] == 0,
      encoded.readUInt32BE(at: 20) == 0,
      let role = StreamOpenerRoleV3(rawValue: encoded[5])
    else {
      throw TransportV3CryptoError.invalidSetupPreface
    }
    let logicalStreamID = encoded.readUInt64BE(at: 8)
    guard Self.validLogicalStreamID(role: role, id: logicalStreamID) else {
      throw TransportV3CryptoError.invalidSetupPreface
    }
    self.init(
      openerRole: role,
      logicalStreamID: logicalStreamID,
      initialEpoch: encoded.readUInt32BE(at: 16),
      setupMAC: Data(encoded[24..<56])
    )
  }

  private init(
    openerRole: StreamOpenerRoleV3,
    logicalStreamID: UInt64,
    initialEpoch: UInt32,
    setupMAC: Data
  ) {
    self.openerRole = openerRole
    self.logicalStreamID = logicalStreamID
    self.initialEpoch = initialEpoch
    self.setupMAC = setupMAC
  }

  private static func validLogicalStreamID(role: StreamOpenerRoleV3, id: UInt64) -> Bool {
    guard id != 0 else { return false }
    switch role {
    case .client:
      return id & 1 == 1
    case .server:
      return id & 1 == 0
    }
  }
}

struct RecordHeaderV3: Equatable, Sendable {
  let epoch: UInt32
  let sequence: UInt64
  let ciphertextLength: UInt32

  init(epoch: UInt32, sequence: UInt64, ciphertextLength: UInt32) {
    self.epoch = epoch
    self.sequence = sequence
    self.ciphertextLength = ciphertextLength
  }

  func encoded() throws -> Data {
    guard Int(ciphertextLength) >= TransportV3Crypto.aeadTagBytes else {
      throw TransportV3CryptoError.invalidRecordHeader
    }
    guard Int(ciphertextLength) <= TransportV3Crypto.maxCiphertextBytes else {
      throw TransportV3CryptoError.recordTooLarge
    }

    var output = Data()
    output.reserveCapacity(TransportV3Crypto.recordHeaderBytes)
    output.append(Data("FSR3".utf8))
    output.append(TransportV3Crypto.protocolVersion)
    output.append(UInt8(TransportV3Crypto.recordHeaderBytes))
    output.append(contentsOf: [0, 0])
    output.appendUInt32BE(epoch)
    output.appendUInt64BE(sequence)
    output.appendUInt32BE(ciphertextLength)
    return output
  }

  init(encoded: Data) throws {
    guard
      encoded.count == TransportV3Crypto.recordHeaderBytes,
      Data(encoded[0..<4]) == Data("FSR3".utf8),
      encoded[4] == TransportV3Crypto.protocolVersion,
      encoded[5] == UInt8(TransportV3Crypto.recordHeaderBytes),
      encoded[6] == 0,
      encoded[7] == 0
    else {
      throw TransportV3CryptoError.invalidRecordHeader
    }
    self.init(
      epoch: encoded.readUInt32BE(at: 8),
      sequence: encoded.readUInt64BE(at: 12),
      ciphertextLength: encoded.readUInt32BE(at: 20)
    )
    _ = try self.encoded()
  }
}

/// Stateless v3 wire and crypto primitives. Session code must enforce nonce and epoch invariants.
enum TransportV3Crypto {
  static let protocolVersion: UInt8 = 3
  static let setupPrefaceBytes = 56
  static let setupMACBytes = 32
  static let recordHeaderBytes = 24
  static let unreliableHeaderBytes = 32
  static let innerHeaderBytes = 8
  static let aeadTagBytes = 16
  static let maxDataBytes = 16_384
  static let maxCiphertextBytes = innerHeaderBytes + maxDataBytes + aeadTagBytes
  static let maxUnreliablePlaintextBytes = 976
  static let maxUnreliableCiphertextBytes = maxUnreliablePlaintextBytes + aeadTagBytes

  static func deriveEpochZero(
    sessionPRK: Data,
    direction: TransportDirectionV3
  ) throws -> EpochRootsV3 {
    guard sessionPRK.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }

    var epochSecret = expand(
      pseudoRandomKey: sessionPRK,
      info: labelWith(TransportV3Contract.epochZeroLabel, Data([direction.rawValue])),
      outputByteCount: 32
    )
    var controlRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith(TransportV3Contract.controlRootLabel),
      outputByteCount: 32
    )
    var streamRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith(TransportV3Contract.streamRootLabel),
      outputByteCount: 32
    )
    var setupRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith(TransportV3Contract.setupRootLabel),
      outputByteCount: 32
    )
    var rekeyRoot = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith(TransportV3Contract.rekeyRootLabel),
      outputByteCount: 32
    )
    let roots = EpochRootsV3(
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
    direction: TransportDirectionV3,
    epoch: UInt32
  ) throws -> RecordMaterialV3 {
    guard streamRoot.count == 32, h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    guard logicalStreamID != 0 else {
      throw TransportV3CryptoError.invalidSetupPreface
    }

    var streamID = Data()
    streamID.appendUInt64BE(logicalStreamID)
    var epochBytes = Data()
    epochBytes.appendUInt32BE(epoch)
    var secret = expand(
      pseudoRandomKey: streamRoot,
      info: labelWith(
        TransportV3Contract.streamLabel,
        h3,
        streamID,
        Data([direction.rawValue]),
        epochBytes
      ),
      outputByteCount: 32
    )
    var recordKey = expand(
      pseudoRandomKey: secret,
      info: labelWith(TransportV3Contract.recordKeyLabel),
      outputByteCount: 32
    )
    var noncePrefix = expand(
      pseudoRandomKey: secret,
      info: labelWith(TransportV3Contract.nonceLabel),
      outputByteCount: 4
    )
    let material = RecordMaterialV3(
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
    direction: TransportDirectionV3,
    epoch: UInt32
  ) throws -> RecordMaterialV3 {
    try deriveRecordMaterial(
      root: controlRoot,
      label: TransportV3Contract.controlLabel,
      h3: h3,
      logicalStreamID: 0,
      direction: direction,
      epoch: epoch
    )
  }

  static func deriveNextEpoch(
    rekeyRoot: Data,
    h3: Data,
    direction: TransportDirectionV3,
    nextEpoch: UInt32
  ) throws -> Data {
    guard rekeyRoot.count == 32, h3.count == 32, nextEpoch != 0 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    var epoch = Data()
    epoch.appendUInt32BE(nextEpoch)
    return expand(
      pseudoRandomKey: rekeyRoot,
      info: labelWith(
        TransportV3Contract.nextEpochLabel,
        h3,
        Data([direction.rawValue]),
        epoch
      ),
      outputByteCount: 32
    )
  }

  static func deriveEpochRoots(epochSecret: Data) throws -> EpochRootsV3 {
    guard epochSecret.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    return EpochRootsV3(
      epochSecret: epochSecret,
      controlRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith(TransportV3Contract.controlRootLabel),
        outputByteCount: 32
      ),
      streamRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith(TransportV3Contract.streamRootLabel),
        outputByteCount: 32
      ),
      setupRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith(TransportV3Contract.setupRootLabel),
        outputByteCount: 32
      ),
      rekeyRoot: expand(
        pseudoRandomKey: epochSecret,
        info: labelWith(TransportV3Contract.rekeyRootLabel),
        outputByteCount: 32
      )
    )
  }

  static func deriveUnreliableMaterial(
    epochSecret: Data,
    h3: Data,
    direction: TransportDirectionV3,
    epoch: UInt32
  ) throws -> UnreliableMaterialV3 {
    guard epochSecret.count == 32, h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    var epochBytes = Data()
    epochBytes.appendUInt32BE(epoch)
    var root = expand(
      pseudoRandomKey: epochSecret,
      info: labelWith(TransportV3Contract.unreliableRootLabel),
      outputByteCount: 32
    )
    var secret = expand(
      pseudoRandomKey: root,
      info: labelWith(
        TransportV3Contract.unreliableLabel, h3, Data([direction.rawValue]), epochBytes),
      outputByteCount: 32
    )
    var recordKey = expand(
      pseudoRandomKey: secret,
      info: labelWith(TransportV3Contract.unreliableKeyLabel),
      outputByteCount: 32
    )
    var noncePrefix = expand(
      pseudoRandomKey: secret,
      info: labelWith(TransportV3Contract.unreliableNonceLabel),
      outputByteCount: 4
    )
    let material = UnreliableMaterialV3(
      root: root, secret: secret, recordKey: recordKey, noncePrefix: noncePrefix)
    zeroize(&root)
    zeroize(&secret)
    zeroize(&recordKey)
    zeroize(&noncePrefix)
    return material
  }

  static func computeSetupMAC(
    setupRoot: Data,
    h3: Data,
    preface: SetupPrefaceV3
  ) throws -> Data {
    guard setupRoot.count == 32, h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
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
    preface: SetupPrefaceV3
  ) throws -> Bool {
    guard setupRoot.count == 32, h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    return HMAC<SHA256>.isValidAuthenticationCode(
      preface.setupMAC,
      authenticating: try setupMACMessage(h3: h3, preface: preface),
      using: SymmetricKey(data: setupRoot)
    )
  }

  static func encodeInnerRecord(type: InnerRecordTypeV3, payload: Data) throws -> Data {
    try validateInnerRecord(type: type, payloadCount: payload.count)

    var output = Data()
    output.reserveCapacity(innerHeaderBytes + payload.count)
    output.append(type.rawValue)
    output.append(contentsOf: [0, 0, 0])
    output.appendUInt32BE(UInt32(payload.count))
    output.append(payload)
    return output
  }

  static func decodeInnerRecord(_ encoded: Data) throws -> (InnerRecordTypeV3, Data) {
    guard
      encoded.count >= innerHeaderBytes,
      encoded[1] == 0,
      encoded[2] == 0,
      encoded[3] == 0,
      let type = InnerRecordTypeV3(rawValue: encoded[0])
    else {
      throw TransportV3CryptoError.invalidInnerRecord
    }
    let payloadCount = Int(encoded.readUInt32BE(at: 4))
    guard payloadCount + innerHeaderBytes == encoded.count else {
      throw TransportV3CryptoError.invalidInnerRecord
    }
    try validateInnerRecord(type: type, payloadCount: payloadCount)
    return (type, Data(encoded[innerHeaderBytes...]))
  }

  static func recordAAD(
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV3,
    header: RecordHeaderV3
  ) throws -> Data {
    guard h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
    var streamID = Data()
    streamID.appendUInt64BE(logicalStreamID)
    return try labelWith(
      TransportV3Contract.recordDomain,
      h3,
      streamID,
      Data([direction.rawValue]),
      header.encoded()
    )
  }

  static func sealRecord(
    suite: TransportCipherSuiteV3,
    key: Data,
    noncePrefix: Data,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV3,
    header: RecordHeaderV3,
    plaintext: Data
  ) throws -> Data {
    try validateRecordMaterial(key: key, noncePrefix: noncePrefix, h3: h3)
    let (expectedLength, overflow) = plaintext.count.addingReportingOverflow(aeadTagBytes)
    guard !overflow, expectedLength == Int(header.ciphertextLength) else {
      throw TransportV3CryptoError.invalidRecordHeader
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
      throw TransportV3CryptoError.cryptographicFailure
    }
  }

  static func openRecord(
    suite: TransportCipherSuiteV3,
    key: Data,
    noncePrefix: Data,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV3,
    header: RecordHeaderV3,
    ciphertext: Data
  ) throws -> Data {
    try validateRecordMaterial(key: key, noncePrefix: noncePrefix, h3: h3)
    _ = try header.encoded()
    guard
      ciphertext.count == Int(header.ciphertextLength),
      ciphertext.count >= aeadTagBytes
    else {
      throw TransportV3CryptoError.invalidRecordHeader
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
      throw TransportV3CryptoError.authenticationFailed
    }
  }

  static func unreliableNonce(noncePrefix: Data, sequence: UInt64) throws -> Data {
    guard noncePrefix.count == 4 else { throw TransportV3CryptoError.invalidKeyMaterial }
    return recordNonce(prefix: noncePrefix, sequence: sequence)
  }

  static func unreliableAAD(
    h3: Data,
    direction: TransportDirectionV3,
    header: UnreliableHeaderV3
  ) throws -> Data {
    guard h3.count == 32 else { throw TransportV3CryptoError.invalidKeyMaterial }
    return try labelWith(
      TransportV3Contract.unreliableDomain, h3, Data([direction.rawValue]), header.encoded())
  }

  static func sealUnreliable(
    suite: TransportCipherSuiteV3,
    material: UnreliableMaterialV3,
    h3: Data,
    direction: TransportDirectionV3,
    header: UnreliableHeaderV3,
    plaintext: Data
  ) throws -> Data {
    guard (1...maxUnreliablePlaintextBytes).contains(plaintext.count),
      plaintext.count + aeadTagBytes == Int(header.ciphertextLength)
    else { throw TransportV3CryptoError.unreliableMessageTooLarge }
    try validateRecordMaterial(
      key: material.recordKey, noncePrefix: material.noncePrefix, h3: h3)
    let nonce = try unreliableNonce(noncePrefix: material.noncePrefix, sequence: header.sequence)
    let aad = try unreliableAAD(h3: h3, direction: direction, header: header)
    let symmetricKey = SymmetricKey(data: material.recordKey)

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
      throw TransportV3CryptoError.cryptographicFailure
    }
  }

  static func openUnreliable(
    suite: TransportCipherSuiteV3,
    material: UnreliableMaterialV3,
    h3: Data,
    direction: TransportDirectionV3,
    header: UnreliableHeaderV3,
    ciphertext: Data
  ) throws -> Data {
    guard ciphertext.count == Int(header.ciphertextLength) else {
      throw TransportV3CryptoError.invalidUnreliableMessage
    }
    try validateRecordMaterial(
      key: material.recordKey, noncePrefix: material.noncePrefix, h3: h3)
    _ = try header.encoded()
    let nonce = try unreliableNonce(noncePrefix: material.noncePrefix, sequence: header.sequence)
    let aad = try unreliableAAD(h3: h3, direction: direction, header: header)
    let tagStart = ciphertext.index(ciphertext.endIndex, offsetBy: -aeadTagBytes)
    let encrypted = Data(ciphertext[..<tagStart])
    let tag = Data(ciphertext[tagStart...])
    let symmetricKey = SymmetricKey(data: material.recordKey)

    do {
      switch suite {
      case .chacha20Poly1305:
        let box = try ChaChaPoly.SealedBox(
          nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: encrypted, tag: tag)
        return try ChaChaPoly.open(box, using: symmetricKey, authenticating: aad)
      case .aes256GCM:
        let box = try AES.GCM.SealedBox(
          nonce: AES.GCM.Nonce(data: nonce), ciphertext: encrypted, tag: tag)
        return try AES.GCM.open(box, using: symmetricKey, authenticating: aad)
      }
    } catch {
      throw TransportV3CryptoError.authenticationFailed
    }
  }

  private static func setupMACMessage(h3: Data, preface: SetupPrefaceV3) throws -> Data {
    var message = labelWith(TransportV3Contract.setupDomain)
    message.append(h3)
    message.append(try preface.encoded().prefix(24))
    return message
  }

  private static func validateRecordMaterial(key: Data, noncePrefix: Data, h3: Data) throws {
    guard key.count == 32, noncePrefix.count == 4, h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
    }
  }

  private static func deriveRecordMaterial(
    root: Data,
    label: String,
    h3: Data,
    logicalStreamID: UInt64,
    direction: TransportDirectionV3,
    epoch: UInt32
  ) throws -> RecordMaterialV3 {
    guard root.count == 32, h3.count == 32 else {
      throw TransportV3CryptoError.invalidKeyMaterial
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
    return RecordMaterialV3(
      secret: secret,
      recordKey: expand(
        pseudoRandomKey: secret,
        info: labelWith(TransportV3Contract.recordKeyLabel),
        outputByteCount: 32
      ),
      noncePrefix: expand(
        pseudoRandomKey: secret,
        info: labelWith(TransportV3Contract.nonceLabel),
        outputByteCount: 4
      )
    )
  }

  private static func validateInnerRecord(
    type: InnerRecordTypeV3,
    payloadCount: Int
  ) throws {
    let valid: Bool
    switch type {
    case .open:
      valid = payloadCount > 0 && payloadCount <= 8_192
    case .data:
      valid = payloadCount > 0 && payloadCount <= maxDataBytes
    case .fin, .sessionReady, .sessionReadyACK, .sessionReadyConfirm:
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
    guard valid else { throw TransportV3CryptoError.invalidInnerRecord }
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

private final class SensitiveBytesV3: @unchecked Sendable {
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
