package rpcv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// StreamPreparation selects a per-item response limit explicitly. Aggregate
// count, bytes and duration come only from the exact trusted stream contract.
// Execution windows and guarantees use the same immutable request engine.
type StreamPreparation struct {
	Clock                                                *timev4.Clock
	DeadlineAtMS, DefaultLifetimeMS, AdmissionNotAfterMS uint64
	MaxItemBytes                                         uint32
	AdmissionMode                                        uint8
	ExplicitAdmissionMode                                bool
	RequireExecution, RequireDurable                     bool
	Offer                                                protocolv4.AdmissionOfferBounds
	RuntimeBytes                                         uint64
}

func (o StreamPreparation) RequestOptions() UnaryPreparation {
	return UnaryPreparation{Clock: o.Clock, DeadlineAtMS: o.DeadlineAtMS, DefaultLifetimeMS: o.DefaultLifetimeMS, AdmissionNotAfterMS: o.AdmissionNotAfterMS, ResponseLimitBytes: o.MaxItemBytes, AdmissionMode: o.AdmissionMode, ExplicitAdmissionMode: o.ExplicitAdmissionMode, RequireExecution: o.RequireExecution, RequireDurable: o.RequireDurable, Offer: o.Offer, RuntimeBytes: o.RuntimeBytes}
}

func PrepareStream(route ContractRoute, payload []byte, options StreamPreparation, reservation, routeReservation resourcev4.Reference) (*PreparedRequest, error) {
	if uint64(len(payload)) > 1048576 {
		return nil, ErrConfiguration
	}
	p, err := BeginStreamPreparation(route, uint32(len(payload)), options, reservation, routeReservation)
	if err != nil {
		return nil, err
	}
	if err := p.FinalizePayload(payload); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// BeginStreamPreparation fixes operation identity before any arbitrary request
// encoder. Finalization hashes the complete original encoding once, and Start
// never changes its shape, selected offer, deadline or item limit.
func BeginStreamPreparation(route ContractRoute, payloadLimit uint32, options StreamPreparation, reservation, routeReservation resourcev4.Reference) (*PreparedRequest, error) {
	return beginRequestPreparation(route, payloadLimit, options.RequestOptions(), 1, reservation, routeReservation)
}
