package bin

import "encoding/binary"

func PutU16BE(dst []byte, v uint16) { binary.BigEndian.PutUint16(dst, v) }
func PutU32BE(dst []byte, v uint32) { binary.BigEndian.PutUint32(dst, v) }
func PutU64BE(dst []byte, v uint64) { binary.BigEndian.PutUint64(dst, v) }
func U16BE(src []byte) uint16       { return binary.BigEndian.Uint16(src) }
func U32BE(src []byte) uint32       { return binary.BigEndian.Uint32(src) }
func U64BE(src []byte) uint64       { return binary.BigEndian.Uint64(src) }
