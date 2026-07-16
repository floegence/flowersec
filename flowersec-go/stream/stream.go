// Package stream defines Flowersec's stable multiplexed byte-stream contract.
package stream

import "io"

// Stream is a bidirectional Flowersec stream.
//
// Close performs an orderly FIN close. Reset aborts the stream immediately and
// sends a Yamux RST to the peer.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	Reset() error
}
