package controlv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func tunnelAllowWireLimit() (int, error) {
	n, err := protocolv4.SchemaByteLimit("Grant")
	return n + 1024, err
}

// EncodeTunnelServerAllow writes the reference control application's complete
// original instruction. It is not a credential, receipt or new dispatch right;
// the independently authenticated recipient must verify the enclosed Grant.
func EncodeTunnelServerAllow(dst []byte, r sessionv4.TunnelServerAllowRequest, grant []byte) (int, error) {
	if err := r.Check(); err != nil {
		return 0, err
	}
	limit, err := tunnelAllowWireLimit()
	if err != nil {
		return 0, err
	}
	if len(grant) == 0 || len(grant) > limit-1024 {
		return 0, resourcev4.ErrConfiguration
	}
	w := poolWireWriter{dst: dst[:min(len(dst), limit)]}
	w.array(14)
	w.text("tunnel-server-allow-1")
	w.text(r.Tenant)
	w.text(r.Audience)
	for _, b := range [][]byte{r.Artifact[:], r.Grant[:], r.RelayIdentity[:], r.Attempt[:], r.Pairing[:], r.Leg[:], r.Recipient[:], r.Incarnation[:]} {
		w.blob(b)
	}
	w.array(3)
	w.uint(r.Candidate.Index)
	w.blob(r.Candidate.CandidateID[:])
	w.blob(r.Candidate.RouteDigest[:])
	w.uint(r.NotAfterMS)
	w.blob(grant)
	if w.err != nil {
		clear(dst[:w.n])
		return 0, w.err
	}
	return w.n, nil
}

type TunnelServerAllowCodec struct {
	mu      sync.Mutex
	decoder *protocolv4.Decoder
}

func TunnelServerAllowCodecBackingBytes() (uint64, error) {
	limit, err := tunnelAllowWireLimit()
	if err != nil {
		return 0, err
	}
	n, err := protocolv4.DecoderBackingBytes(limit, 18)
	return n + uint64(unsafe.Sizeof(TunnelServerAllowCodec{})), err
}

func NewTunnelServerAllowCodec() (*TunnelServerAllowCodec, error) {
	limit, err := tunnelAllowWireLimit()
	if err != nil {
		return nil, err
	}
	d, err := protocolv4.NewDecoder(limit, 18)
	if err != nil {
		return nil, err
	}
	return &TunnelServerAllowCodec{decoder: d}, nil
}

// Decode copies only the Grant into the recipient's preadmitted workspace.
// Request fields are detached values; no document alias escapes the call.
func (c *TunnelServerAllowCodec) Decode(wire, grant []byte) (out sessionv4.TunnelServerAllowRequest, n int, err error) {
	if c == nil || c.decoder == nil {
		return out, 0, ErrResponse
	}
	if !c.mu.TryLock() {
		return out, 0, ErrBusy
	}
	defer c.mu.Unlock()
	doc, err := c.decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return out, 0, ErrResponse
	}
	defer doc.Release()
	x, r := doc.Root(), poolWireReader{}
	r.array(x, 14)
	if r.text(x.Index(0)) != "tunnel-server-allow-1" {
		return out, 0, ErrResponse
	}
	out.Tenant, out.Audience = r.text(x.Index(1)), r.text(x.Index(2))
	for i, dst := range [][]byte{out.Artifact[:], out.Grant[:], out.RelayIdentity[:], out.Attempt[:], out.Pairing[:], out.Leg[:], out.Recipient[:], out.Incarnation[:]} {
		r.blob(x.Index(i+3), dst)
	}
	winner := x.Index(11)
	r.array(winner, 3)
	out.Candidate.Index = r.uint(winner.Index(0))
	r.blob(winner.Index(1), out.Candidate.CandidateID[:])
	r.blob(winner.Index(2), out.Candidate.RouteDigest[:])
	out.NotAfterMS = r.uint(x.Index(12))
	value, ok := x.Index(13).ByteString()
	limit, limitErr := protocolv4.SchemaByteLimit("Grant")
	if r.err != nil || out.Check() != nil || !ok || limitErr != nil || len(value) == 0 || len(value) > limit {
		return sessionv4.TunnelServerAllowRequest{}, 0, ErrResponse
	}
	if len(grant) < len(value) {
		return sessionv4.TunnelServerAllowRequest{}, 0, resourcev4.ErrCapacity
	}
	return out, copy(grant, value), nil
}
