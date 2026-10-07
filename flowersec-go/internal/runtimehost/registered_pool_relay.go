package runtimehost

import (
	"bytes"
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func RegisteredPoolRelayCharge(c LiveRelayConfig) (resourcev4.Vector, error) {
	cost, err := registeredRelayCharge(c)
	if err != nil {
		return cost, err
	}
	decoder, err := protocolv4.DecoderBackingBytes(65536, 4096)
	if err != nil {
		return cost, err
	}
	codec, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return cost, err
	}
	proof, err := protocolv4.DecoderBackingBytes(4096, 4096)
	if err != nil {
		return cost, err
	}
	parent, err := protocolv4.SignedMapBackingBytes("Artifact", 65536, 16384)
	if err != nil {
		return cost, err
	}
	return cost.Add(resourcev4.Vector{resourcev4.SDKBytes: decoder + codec + proof + parent + 16384})
}

// NewRegisteredPoolRelay installs the same bounded physical route host around
// an independently configured pool issuer. It has no live spend/publication API.
func NewRegisteredPoolRelay(ctx context.Context, c LiveRelayConfig, reservation, dependencies resourcev4.Reference) (*Relay, error) {
	return newRegisteredRelay(ctx, c, reservation, dependencies, "preauthorized_pool")
}

func (r *Relay) RegisteredPoolTable() (*ledgerv4.SQLiteRelayAuthorityTable, error) {
	if r == nil || r.registeredSource != "preauthorized_pool" {
		return nil, resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, resourcev4.ErrClosed
	}
	return r.liveTable, nil
}

// DispatchOriginalRegisteredPool is called inside PoolService's first COMMIT
// continuation. Both the exact outbox and its original publication are required;
// copied Grant bytes and replayed history cannot open a new route.
func (r *Relay) DispatchOriginalRegisteredPool(ctx context.Context, request protocolv4.TopUpRequestFacts, response []byte, original *ledgerv4.SQLitePoolRelayPublication) error {
	if r == nil || r.registeredSource != "preauthorized_pool" || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.dispatched || r.livePreparing {
		r.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	r.livePreparing = true
	r.beginCallLocked()
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.livePreparing = false; r.endCallLocked(); r.mu.Unlock() }()
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return original.CheckOriginalMaterial(request, response)
	}
	if err := guard(); err != nil {
		return err
	}
	codec, err := protocolv4.NewTopUpCodec()
	if err != nil {
		return err
	}
	batch, err := codec.ParseResponse(response, request)
	if err != nil {
		return err
	}
	defer batch.Release()
	facts, err := batch.Facts()
	if err != nil {
		return err
	}
	if facts.Count != 1 {
		return ledgerv4.ErrOwner
	}
	wire, err := batch.Material(0)
	if err != nil {
		return err
	}
	decoder, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		return err
	}
	doc, err := decoder.DecodeShape(wire, "", protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	defer doc.Release()
	root, c := doc.Root(), r.live
	if root.Len() != 5 || root.Index(4).Len() != 2 {
		return ledgerv4.ErrOwner
	}
	for i, expected := range [3][]byte{c.Artifact, c.ClientCertificate, c.ServerCertificate} {
		slot := [3]int{0, 2, 3}[i]
		actual, ok := root.Index(slot).ByteString()
		if !ok || !bytes.Equal(actual, expected) {
			return ledgerv4.ErrOwner
		}
	}
	var material [3][]byte
	material[0], _ = root.Index(1).ByteString()
	for side := range 2 {
		entry := root.Index(4).Index(side)
		index, indexOK := entry.Index(0).Uint()
		role, roleOK := entry.Index(1).Uint()
		relay, relayOK := entry.Index(3).ByteString()
		if entry.Len() != 4 || !indexOK || index != c.Candidate || !roleOK || role != uint64(side) || !relayOK || !bytes.Equal(relay, c.RelayCertificate) {
			return ledgerv4.ErrOwner
		}
		material[side+1], _ = entry.Index(2).ByteString()
	}
	proofDecoder, err := protocolv4.NewDecoder(4096, 4096)
	if err != nil {
		return err
	}
	proof, err := proofDecoder.DecodeMap(material[0], "ActivationAuthorization", protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "preauthorized_pool"}})
	if err != nil {
		return err
	}
	attempt, ok := proof.Root().Named("ActivationAuthorization", "attempt_id").ByteString()
	end, endOK := proof.Root().Named("ActivationAuthorization", "activation_not_after_ms").Uint()
	if !ok || len(attempt) != 16 || !endOK {
		proof.Release()
		return ledgerv4.ErrOwner
	}
	q := sessionv4.LiveAuthorizationRequest{Artifact: c.ParentDigest, Attempt: [16]byte(attempt), ActivationNotAfterMS: end}
	proof.Release()
	parentCodec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 16384)
	if err != nil {
		return err
	}
	parent, err := parentCodec.VerifyCredential(c.Artifact, c.Trust[0])
	if err != nil {
		return err
	}
	defer parent.Release()
	_, digest, err := parent.CopyCandidateRoute(c.Candidate, make([]byte, 16384))
	if err != nil {
		return err
	}
	id, ok := parent.Field("candidates").Index(int(c.Candidate)).Named("Candidate", "candidate_id").ByteString()
	if !ok || len(id) != 16 {
		return ledgerv4.ErrOwner
	}
	q.Winner = protocolv4.PoolMember{Index: c.Candidate, CandidateID: [16]byte(id), RouteDigest: digest}
	return r.dispatchOriginalRegistered(ctx, q, material, guard)
}
