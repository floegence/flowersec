package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// CarrierPreparationAdmissionRequest describes one original candidate method
// position before credentials are acquired. It has no route, credential, key or
// remote input. The factory fixes its own qualified native provider geometry.
type CarrierPreparationAdmissionRequest struct {
	Clock                    *timev4.Clock
	Environment, Reservation resourcev4.Reference
	Scope                    SessionResourceScope
}

// AdmittingConsumerCarrierFactory is implemented by SDK factories whose local
// slots and native backing can be captured before Acquire. Admission is bounded
// local construction: it must not dial, invoke application callbacks or create
// workers. Every nonnil output transfers cleanup even when admission returns an error.
type AdmittingConsumerCarrierFactory interface {
	ConsumerCarrierFactory
	PreparationParallelism() uint8
	AdmitPreparations(CarrierPreparationAdmissionRequest, []CarrierPreparation) error
}

// CarrierPreparation holds the same factory's original position and resources
// across numeric attempts. Close seals future use and returns only idle backing;
// a live provider retains its original charge until its physical retirement.
type CarrierPreparation interface {
	ConsumerCarrierFactory
	Matches(ConsumerCarrierFactory) bool
	Check() error
	Close()
}
