package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// Authenticate performs the physical HELLO order followed by the endpoint
// possession proof. Only this original claim's confirmed Dispatch invokes the
// relay signer and publishes its proof. A duplicate durable fact has no path
// to signing, pairing or transfer of this carrier.
func (r *RelayHop) Authenticate(store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteRelayAuthority) (err error) {
	if r == nil || store == nil || authority == nil {
		return cryptov4.ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.started || r.initial == nil {
		r.mu.Unlock()
		return cryptov4.ErrTransition
	}
	r.started, r.running = true, true
	x, pair := r.initial, r.c.Pair
	r.mu.Unlock()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		x.mu.Lock()
		x.authenticating = false
		if err != nil {
			x.failLocked(err)
		}
		x.cleanupLocked()
		x.mu.Unlock()
		r.mu.Lock()
		r.running = false
		r.authenticated = err == nil && !r.closed
		r.mu.Unlock()
		pair.notify()
		if err != nil {
			r.Close()
		}
	}()
	err = func() error {
		x.mu.Lock()
		if err := x.checkLocked(); err != nil {
			x.mu.Unlock()
			return err
		}
		if x.phase != 0 || x.hopPhase != 0 || x.authenticating || x.sending || x.receiving {
			x.mu.Unlock()
			return ErrInitialPhase
		}
		x.authenticating = true
		x.mu.Unlock()
		for index := uint8(0); index < 2; index++ {
			_, _, send := r.hop.flight(index)
			if send {
				if _, err := x.sendFlight(protocolv4.FrameHopAuth, r.hop.hello, nil, true); err != nil {
					return err
				}
			} else {
				if err := x.receiveFlight(protocolv4.FrameHopAuth, func(wire []byte) error { return r.hop.receiveHello(x.receiveDecoder, wire) }, true); err != nil {
					return err
				}
			}
		}
		if err := x.receiveFlight(protocolv4.FrameHopAuth, func(wire []byte) error {
			proof, err := protocolv4.DecodeHopAuthProof(x.receiveDecoder, wire, protocolv4.HopAuthEndpointProofPhase)
			if err != nil {
				return err
			}
			r.facts, err = protocolv4.BindRelayClaim(r.maps[0], r.maps[1], r.maps[2], r.hop.context, proof)
			return err
		}, true); err != nil {
			return err
		}
		// The completed read has already settled actual envelope bytes into the
		// same meter. Reserve the complete remaining legal initial exchange.
		need, err := relayInitialRemainingBytes(r.c.Initial.Profile, r.prepared.binding.Session.Contract.Limits().MaxFrame)
		if err != nil {
			return err
		}
		if err = r.budget.claim(need); err != nil {
			return err
		}
		ledger, err := ledgerv4.NewSQLiteRelayActivation(x.ctx, store, authority, r.facts, r.owner, r.c.Clock, r.c.Initial.Deadline, r.guard.Check, r.claimReservation, r.invocationReservation, r.reservation)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.ledger = ledger
		closed := r.closed
		r.mu.Unlock()
		if closed {
			ledger.Close(cryptov4.ErrClosed)
			return cryptov4.ErrClosed
		}
		end, err := ledger.SessionNotAfterMS()
		if err != nil {
			return err
		}
		if err = r.forwardDeadline.Tighten(end); err != nil {
			return err
		}
		return ledger.Claim(func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := x.check(); err != nil {
				return err
			}
			_, err := x.sendFlight(protocolv4.FrameHopAuth, func(dst []byte) (int, error) {
				message, err := protocolv4.GrantPossessionMessage(r.hop.possession)
				if err != nil {
					return 0, err
				}
				defer clear(message)
				if err = x.check(); err != nil {
					return 0, err
				}
				proof, err := r.hop.signer.Sign(message)
				if err != nil {
					return 0, err
				}
				if !protocolv4.VerifyEd25519(proof, message, r.hop.localKey[:]) {
					return 0, protocolv4.ErrHopAuthProof
				}
				wire, err := protocolv4.EncodeHopAuthProof(dst, protocolv4.HopAuthProof{Phase: protocolv4.HopAuthRelayProofPhase, Proof: [64]byte(proof)})
				return len(wire), err
			}, nil, true)
			return err
		})
	}()
	returned = true
	return err
}

func relayInitialRemainingBytes(profile string, maxFrame uint32) (uint64, error) {
	proof, err := protocolv4.SchemaByteLimit("HOP_AUTH_RELAY_PROOF")
	if err != nil {
		return 0, err
	}
	total := uint64(proof + protocolv4.EnvelopePrefixSize)
	for _, flight := range []struct {
		frame  protocolv4.FrameType
		sender protocolv4.Direction
	}{
		{protocolv4.FrameNegotiate, protocolv4.ClientToServer}, {protocolv4.FrameNegotiate, protocolv4.ServerToClient},
		{protocolv4.FrameAdmission, protocolv4.ClientToServer}, {protocolv4.FrameAdmissionResult, protocolv4.ServerToClient},
		{protocolv4.FrameHandshake, protocolv4.ClientToServer}, {protocolv4.FrameHandshake, protocolv4.ServerToClient},
		{protocolv4.FrameReady, protocolv4.ClientToServer}, {protocolv4.FrameReady, protocolv4.ServerToClient},
	} {
		spec, err := protocolv4.InitialFrame(flight.frame, flight.sender, profile)
		if err != nil {
			return 0, err
		}
		maximum := min(uint64(maxFrame), uint64(spec.Maximum))
		if flight.frame == protocolv4.FrameReady {
			maximum = uint64(maxFrame)
		}
		total += maximum + protocolv4.EnvelopePrefixSize
	}
	// Include one full initial maintenance envelope in each direction under
	// the same signed cap. Subsequent maintenance has no exemption from it.
	return total + 2*(uint64(maxFrame)+protocolv4.EnvelopePrefixSize), nil
}
