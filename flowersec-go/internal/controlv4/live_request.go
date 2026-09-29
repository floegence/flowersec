package controlv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// LiveAuthorizationCodec parses the bounded reference application's request
// envelope. Its host reserves BackingBytes before construction and keeps that
// reservation until all calls exit. Decoding confers no authority: authenticated
// tenant/client context and the original durable spend owner are separate gates.
type LiveAuthorizationCodec struct {
	mu      sync.Mutex
	decoder *protocolv4.Decoder
}

func LiveAuthorizationCodecBackingBytes() (uint64, error) {
	n, err := protocolv4.DecoderBackingBytes(liveRequestBytes, 17)
	return n + uint64(unsafe.Sizeof(LiveAuthorizationCodec{})), err
}

func NewLiveAuthorizationCodec() (*LiveAuthorizationCodec, error) {
	d, err := protocolv4.NewDecoder(liveRequestBytes, 17)
	if err != nil {
		return nil, err
	}
	return &LiveAuthorizationCodec{decoder: d}, nil
}

func (c *LiveAuthorizationCodec) Decode(wire []byte) (out sessionv4.LiveAuthorizationRequest, err error) {
	if c == nil || c.decoder == nil {
		return out, ErrResponse
	}
	if !c.mu.TryLock() {
		return out, ErrBusy
	}
	defer c.mu.Unlock()
	doc, err := c.decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return out, ErrResponse
	}
	defer doc.Release()
	x, r := doc.Root(), poolWireReader{}
	r.array(x, 13)
	if r.text(x.Index(0)) != "live-authorization-1" {
		return out, ErrResponse
	}
	out.Tenant, out.Audience, out.CryptoProfile = r.text(x.Index(1)), r.text(x.Index(2)), r.text(x.Index(3))
	for i, dst := range [][]byte{out.Issuer[:], out.Lease[:], out.Attempt[:], out.Artifact[:], out.ClientIdentity[:], out.ServerIdentity[:]} {
		r.blob(x.Index(i+4), dst)
	}
	winner := x.Index(10)
	r.array(winner, 3)
	out.Winner.Index = r.uint(winner.Index(0))
	r.blob(winner.Index(1), out.Winner.CandidateID[:])
	r.blob(winner.Index(2), out.Winner.RouteDigest[:])
	out.ActivationNotAfterMS = r.uint(x.Index(11))
	if r.uint(x.Index(12)) != 1 || r.err != nil {
		return sessionv4.LiveAuthorizationRequest{}, ErrResponse
	}
	out.AttemptNo = 1
	if checkLiveRequest(out) != nil {
		return sessionv4.LiveAuthorizationRequest{}, ErrResponse
	}
	return out, nil
}
