package bin

import "encoding/binary"

// PutU16BE writes a uint16 in big-endian order.
func PutU16BE(dst []byte, v uint16) { binary.BigEndian.PutUint16(dst, v) }

// PutU32BE writes a uint32 in big-endian order.
func PutU32BE(dst []byte, v uint32) { binary.BigEndian.PutUint32(dst, v) }

// PutU64BE writes a uint64 in big-endian order.
func PutU64BE(dst []byte, v uint64) { binary.BigEndian.PutUint64(dst, v) }

// U16BE reads a uint16 in big-endian order.
func U16BE(src []byte) uint16 { return binary.BigEndian.Uint16(src) }

// U32BE reads a uint32 in big-endian order.
func U32BE(src []byte) uint32 { return binary.BigEndian.Uint32(src) }

// U64BE reads a uint64 in big-endian order.
func U64BE(src []byte) uint64 { return binary.BigEndian.Uint64(src) }
