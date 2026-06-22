import Crypto
import Foundation

struct FlowersecRecord {
  var flags: UInt8
  var seq: UInt64
  var plaintext: Data
}

enum FlowersecRecordCodec {
  static func encrypt(
    key: Data,
    noncePrefix: Data,
    flags: UInt8,
    seq: UInt64,
    plaintext: Data
  ) throws -> Data {
    guard key.count == 32, noncePrefix.count == 4 else {
      throw FlowersecError.invalidRecord("Invalid record key material.")
    }
    guard 18 + plaintext.count + 16 <= FlowersecWire.maxRecordBytes else {
      throw FlowersecError.invalidRecord("Record is too large.")
    }
    let header = recordHeader(flags: flags, seq: seq, ciphertextLength: plaintext.count + 16)
    let sealed = try seal(
      plaintext: plaintext, key: key, noncePrefix: noncePrefix, seq: seq, header: header)
    var out = header
    out.append(sealed.ciphertext)
    out.append(sealed.tag)
    return out
  }

  static func decrypt(
    key: Data,
    noncePrefix: Data,
    frame: Data,
    expectedSeq: UInt64
  ) throws -> FlowersecRecord {
    guard key.count == 32, noncePrefix.count == 4 else {
      throw FlowersecError.invalidRecord("Invalid record key material.")
    }
    let metadata = try decodeMetadata(frame: frame, expectedSeq: expectedSeq)
    let plaintext = try open(
      frame: frame,
      metadata: metadata,
      key: key,
      noncePrefix: noncePrefix
    )
    return FlowersecRecord(flags: metadata.flags, seq: metadata.seq, plaintext: plaintext)
  }

  static func deriveRekeyKey(
    rekeyBase: Data,
    transcript: Data,
    seq: UInt64,
    direction: UInt8
  ) throws -> Data {
    guard rekeyBase.count == 32, transcript.count == 32 else {
      throw FlowersecError.invalidRecord("Invalid rekey material.")
    }
    var message = Data(transcript)
    message.appendUInt64BE(seq)
    message.append(direction)
    let saltCode = HMAC<SHA256>.authenticationCode(
      for: message,
      using: SymmetricKey(data: rekeyBase)
    )
    let prk = FlowersecHKDF.extractSHA256(
      salt: Data(saltCode),
      inputKeyMaterial: Data("flowersec-e2ee-v1:rekey".utf8)
    )
    return FlowersecHKDF.expandSHA256(
      pseudoRandomKey: prk,
      info: Data("flowersec-e2ee-v1:rekey:key".utf8),
      outputByteCount: 32
    )
  }

  private static func recordHeader(flags: UInt8, seq: UInt64, ciphertextLength: Int) -> Data {
    var header = Data()
    header.append(FlowersecWire.recordMagic)
    header.append(FlowersecWire.protocolVersion)
    header.append(flags)
    header.appendUInt64BE(seq)
    header.appendUInt32BE(UInt32(ciphertextLength))
    return header
  }

  private static func seal(
    plaintext: Data,
    key: Data,
    noncePrefix: Data,
    seq: UInt64,
    header: Data
  ) throws -> AES.GCM.SealedBox {
    let nonce = try AES.GCM.Nonce(data: nonce(prefix: noncePrefix, seq: seq))
    return try AES.GCM.seal(
      plaintext,
      using: SymmetricKey(data: key),
      nonce: nonce,
      authenticating: header
    )
  }

  private static func open(
    frame: Data,
    metadata: FlowersecRecordMetadata,
    key: Data,
    noncePrefix: Data
  ) throws -> Data {
    let box = try AES.GCM.SealedBox(
      nonce: AES.GCM.Nonce(data: nonce(prefix: noncePrefix, seq: metadata.seq)),
      ciphertext: frame.subdata(in: 18..<(frame.count - 16)),
      tag: frame.suffix(16)
    )
    do {
      return try AES.GCM.open(
        box,
        using: SymmetricKey(data: key),
        authenticating: frame.prefix(18)
      )
    } catch {
      throw FlowersecError.invalidRecord("Record could not be decrypted.")
    }
  }

  private static func decodeMetadata(
    frame: Data,
    expectedSeq: UInt64
  ) throws -> FlowersecRecordMetadata {
    guard frame.count >= 18, frame.count <= FlowersecWire.maxRecordBytes else {
      throw FlowersecError.invalidRecord("Record frame length is invalid.")
    }
    guard frame.prefix(4) == FlowersecWire.recordMagic else {
      throw FlowersecError.invalidRecord("Record frame magic is invalid.")
    }
    guard frame[4] == FlowersecWire.protocolVersion else {
      throw FlowersecError.invalidRecord("Record frame version is invalid.")
    }
    let flags = frame[5]
    guard flags == 0 || flags == 1 || flags == 2 else {
      throw FlowersecError.invalidRecord("Record frame flag is invalid.")
    }
    let seq = frame.readUInt64BE(at: 6)
    guard seq == expectedSeq else {
      throw FlowersecError.invalidRecord("Record sequence is invalid.")
    }
    let ciphertextLength = Int(frame.readUInt32BE(at: 14))
    guard ciphertextLength >= 16, frame.count == 18 + ciphertextLength else {
      throw FlowersecError.invalidRecord("Record ciphertext length is invalid.")
    }
    return FlowersecRecordMetadata(flags: flags, seq: seq)
  }

  private static func nonce(prefix: Data, seq: UInt64) -> Data {
    var nonceData = Data(prefix)
    nonceData.appendUInt64BE(seq)
    return nonceData
  }
}

private struct FlowersecRecordMetadata {
  var flags: UInt8
  var seq: UInt64
}
