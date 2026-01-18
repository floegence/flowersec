package e2ee

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/internal/bin"
	"github.com/floegence/flowersec/flowersec-go/internal/hkdf"
)

var (
	// ErrRecordTooLarge signals plaintext or frame exceeds limits.
	ErrRecordTooLarge = errors.New("record too large")
	// ErrRecordBadSeq indicates a sequence mismatch when strict ordering is enabled.
	ErrRecordBadSeq = errors.New("record bad seq")
	// ErrRecordDecrypt indicates AEAD decryption failed.
	ErrRecordDecrypt = errors.New("record decrypt failed")
	// ErrRecordBadFlag indicates an unknown record flag.
	ErrRecordBadFlag = errors.New("record bad flag")
	// ErrRecordBadVersion indicates the record header version mismatched.
	ErrRecordBadVersion = errors.New("record bad version")
)

// RecordFlag encodes the semantic type of a record frame.
type RecordFlag uint8

const (
	// RecordFlagApp carries application payload.
	RecordFlagApp RecordFlag = 0
	// RecordFlagPing is a keepalive frame with empty payload.
	RecordFlagPing RecordFlag = 1
	// RecordFlagRekey signals a key update at the given sequence number.
	RecordFlagRekey RecordFlag = 2
)

// Direction describes the key direction for rekey derivation.
type Direction uint8

const (
	DirC2S Direction = 1
	DirS2C Direction = 2
)

// RecordKeyState tracks symmetric keys, nonce prefixes, and sequence counters.
type RecordKeyState struct {
	SendKey      [32]byte  // Current send AEAD key.
	RecvKey      [32]byte  // Current receive AEAD key.
	SendNoncePre [4]byte   // Send nonce prefix (first 4 bytes of 12-byte nonce).
	RecvNoncePre [4]byte   // Receive nonce prefix (first 4 bytes of 12-byte nonce).
	RekeyBase    [32]byte  // Base secret for deriving per-sequence rekeyed keys.
	Transcript   [32]byte  // Handshake transcript hash bound into rekey derivation.
	SendDir      Direction // Direction label for send rekey derivation.
	RecvDir      Direction // Direction label for receive rekey derivation.

	SendSeq uint64 // Next outbound record sequence number.
	RecvSeq uint64 // Next expected inbound record sequence number.
}

// MaxPlaintextBytes returns the maximum payload bytes allowed by the record size.
func MaxPlaintextBytes(maxRecordBytes int) int {
	if maxRecordBytes <= 0 {
		return 0
	}
	// record = header(18) + ciphertext(plaintext + gcmTag(16))
	return maxRecordBytes - recordHeaderLen - 16
}

// EncryptRecord builds an authenticated record frame for the given plaintext.
func EncryptRecord(sendKey [32]byte, noncePrefix [4]byte, flags RecordFlag, seq uint64, plaintext []byte, maxRecordBytes int) ([]byte, error) {
	const maxCipherLen = uint64(0xffffffff)
	if uint64(len(plaintext))+16 > maxCipherLen {
		return nil, ErrRecordTooLarge
	}
	if maxRecordBytes > 0 {
		if recordHeaderLen+len(plaintext)+16 > maxRecordBytes {
			return nil, ErrRecordTooLarge
		}
	}
	aead, err := NewAESGCM(sendKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce[:4], noncePrefix[:])
	bin.PutU64BE(nonce[4:12], seq)

	out := make([]byte, recordHeaderLen)
	copy(out[:4], []byte(RecordMagic))
	out[4] = ProtocolVersion
	out[5] = byte(flags)
	bin.PutU64BE(out[6:14], seq)
	cipherLen := len(plaintext) + 16
	bin.PutU32BE(out[14:18], uint32(cipherLen))
	ciphertext := aead.Seal(nil, nonce, plaintext, out)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptRecord validates and decrypts a record frame.
func DecryptRecord(recvKey [32]byte, noncePrefix [4]byte, frame []byte, expectSeq uint64, maxRecordBytes int) (flags RecordFlag, seq uint64, plaintext []byte, err error) {
	if maxRecordBytes > 0 && len(frame) > maxRecordBytes {
		return 0, 0, nil, ErrRecordTooLarge
	}
	if len(frame) < recordHeaderLen {
		return 0, 0, nil, ErrInvalidLength
	}
	if string(frame[:4]) != RecordMagic {
		return 0, 0, nil, ErrInvalidMagic
	}
	if frame[4] != ProtocolVersion {
		return 0, 0, nil, ErrRecordBadVersion
	}
	flags = RecordFlag(frame[5])
	switch flags {
	case RecordFlagApp, RecordFlagPing, RecordFlagRekey:
	default:
		return 0, 0, nil, ErrRecordBadFlag
	}
	seq = bin.U64BE(frame[6:14])
	if expectSeq != 0 && seq != expectSeq {
		return 0, 0, nil, ErrRecordBadSeq
	}
	n := int(bin.U32BE(frame[14:18]))
	if n < 0 || recordHeaderLen+n != len(frame) {
		return 0, 0, nil, ErrInvalidLength
	}

	aead, err := NewAESGCM(recvKey)
	if err != nil {
		return 0, 0, nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce[:4], noncePrefix[:])
	bin.PutU64BE(nonce[4:12], seq)
	plain, err := aead.Open(nil, nonce, frame[recordHeaderLen:], frame[:recordHeaderLen])
	if err != nil {
		return 0, 0, nil, ErrRecordDecrypt
	}
	return flags, seq, plain, nil
}

// DeriveRekeyKey computes a new send/receive key tied to a specific record sequence.
func DeriveRekeyKey(rekeyBase [32]byte, transcriptHash [32]byte, seq uint64, dir Direction) ([32]byte, error) {
	msg := make([]byte, 0, 32+8+1)
	msg = append(msg, transcriptHash[:]...)
	tmp := make([]byte, 8)
	bin.PutU64BE(tmp, seq)
	msg = append(msg, tmp...)
	msg = append(msg, byte(dir))

	mac := hmac.New(sha256.New, rekeyBase[:])
	_, _ = mac.Write(msg)
	var salt [32]byte
	copy(salt[:], mac.Sum(nil))

	prk := hkdf.ExtractSHA256(salt[:], []byte("flowersec-e2ee-v1:rekey"))
	okm, err := hkdf.ExpandSHA256(prk, []byte("flowersec-e2ee-v1:rekey:key"), 32)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], okm)
	return out, nil
}
