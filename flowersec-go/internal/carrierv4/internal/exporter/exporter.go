// Package exporter fixes the transport binding inputs for the original TLS
// connection. Callers cannot substitute a label or choose another mapping.
package exporter

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
)

const Label = "EXPORTER-flowersec-v4"
const WebTransportLabel = "EXPORTER-WebTransport"

var ErrUnavailable = errors.New("carrierv4: original TLS exporter unavailable")

func derive(state tls.ConnectionState, label string, context []byte) ([32]byte, error) {
	var result [32]byte
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.DidResume {
		return result, ErrUnavailable
	}
	value, err := state.ExportKeyingMaterial(label, context, len(result))
	defer clear(value)
	if err != nil {
		return result, errors.Join(ErrUnavailable, err)
	}
	if len(value) != len(result) {
		return result, ErrUnavailable
	}
	copy(result[:], value)
	return result, nil
}

func Raw(state tls.ConnectionState, artifact [32]byte) ([32]byte, error) {
	if artifact == ([32]byte{}) {
		return [32]byte{}, ErrUnavailable
	}
	return derive(state, Label, artifact[:])
}

// WebTransport uses draft-16 section 4.8's session wrapper, including the
// actual CONNECT stream ID as eight big-endian bytes. Go's TLS API accepts the
// complete exporter label and does not add an EXPORTER- prefix itself.
func WebTransport(state tls.ConnectionState, sessionID uint64, artifact [32]byte) ([32]byte, error) {
	if sessionID >= 1<<62 || sessionID%4 != 0 || artifact == ([32]byte{}) {
		return [32]byte{}, ErrUnavailable
	}
	var context [63]byte
	binary.BigEndian.PutUint64(context[:8], sessionID)
	context[8] = byte(len(Label))
	copy(context[9:30], Label)
	context[30] = byte(len(artifact))
	copy(context[31:], artifact[:])
	return derive(state, WebTransportLabel, context[:])
}
