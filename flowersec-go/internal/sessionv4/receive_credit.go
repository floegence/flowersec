package sessionv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// protectReceiveCredit converts an already admitted promise into continuous
// service. Its backing remains the original ReceivePool ring. Returning bytes
// atomically restores the protected minimum before another flow can take them.
func (o *StreamOwnership) protectReceiveCredit(minimum uint64) error {
	_, _, flow, _, err := o.beginCapabilityMethod(nil, false, false)
	if err != nil {
		return err
	}
	defer o.end()
	f := flow.receive
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.limit > math.MaxInt64 || minimum == 0 || minimum > uint64(len(f.storage)) || f.minimumPromise != 0 || f.delivered != 0 || f.readPending || f.readTails != 0 || f.limit-f.released < minimum || f.termination.service == nil {
		return ErrCredit
	}
	if err := f.readOwnershipLocked(o); err != nil {
		return err
	}
	if f.abandoned || f.hasTerminal || f.fenced {
		return ErrFlowClosed
	}
	f.minimumPromise = minimum
	f.creditAck = f.released
	f.creditLimit = f.limit
	return nil
}
func (f *ReceiveFlow) replenishCreditLocked() error {
	if f.minimumPromise == 0 || f.messageAdmissionPaused || f.hasTerminal || f.abandoned || f.fenced || f.pool.closed {
		return nil
	}
	current := f.limit - f.released
	if current < f.minimumPromise {
		delta := f.minimumPromise - current
		credit, _, _ := f.pool.availableLocked(f.protection)
		if delta > math.MaxInt64-f.limit || delta > credit {
			return ErrCredit
		}
		f.limit += delta
		f.pool.used += delta
	}
	if f.creditReadyLocked() {
		f.termination.service.notify()
	}
	return nil
}
func (f *ReceiveFlow) creditReadyLocked() bool {
	return f.minimumPromise != 0 && !f.cleaned && !f.pool.closed && !f.hasTerminal && !f.abandoned && !f.fenced && (f.released > f.creditAck || f.limit > f.creditLimit)
}
func (f *ReceiveFlow) encodeCredit(dst []byte) ([]byte, error) {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	// Selection can race input termination before the record builder obtains
	// its ticket. A duplicate of the latest valid absolute frontier is harmless;
	// no promise is invented or withdrawn by publishing it.
	if f.cleaned || f.pool.closed {
		return nil, ErrFlowClosed
	}
	variant, err := protocolv4.ConstantField("STREAM_ACK_CREDIT", "variant")
	if err != nil {
		return nil, err
	}
	limit := max(f.limit, f.creditLimit)
	fields := [5]protocolv4.Field{variant, {Name: "stream_id", Number: f.scope}, {Name: "direction", Number: uint64(f.direction)}, {Name: "ack_offset", Number: f.released}, {Name: "receive_limit", Number: limit}}
	wire, err := protocolv4.EncodeMap(dst, "STREAM_ACK_CREDIT", fields[:])
	if err == nil {
		f.creditAck = f.released
		f.creditLimit = limit
	}
	return wire, err
}
