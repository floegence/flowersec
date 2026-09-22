package rpcv4

import (
	"errors"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// ContractQueryDecode retains the original complete response through the real
// fixed decoder exit. The Session shares one decoder arena, while both Q2
// vectors independently retain their full network and provider responsibility.
// It invokes no application codec and grants no snapshot publication authority.
type ContractQueryDecode struct {
	mu       sync.Mutex
	call     ContractQueryCall
	read     *protocolv4.ContractSnapshotRead
	borrow   ContractQueryResponseBorrow
	closed   bool
	receiver *Receiver
}

func (call ContractQueryCall) BeginDecode(known []*protocolv4.ServiceContract, windows []uint64, outputs [][]byte) (*ContractQueryDecode, error) {
	q := call.client
	if q == nil {
		return nil, ErrOwner
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := call.slotLocked()
	if err != nil || q.closed || s.closed || s.stepping || s.taken {
		return nil, ErrOwner
	}
	if q.decoding != nil {
		return nil, ErrCapacity
	}
	if err = q.reservation.Check(); err != nil {
		return nil, err
	}
	c := s.completion
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.terminal {
		return nil, ErrCapacity
	}
	if c.closed || c.abandoned || c.reason != "" || c.header.Kind() != "query_contracts_response" {
		return nil, ErrOwner
	}
	read, err := q.reader.Begin(s.targets, c.payload[:c.next:c.next], known, windows, outputs)
	if err != nil {
		return nil, err
	}
	d := &ContractQueryDecode{receiver: s.receiver, call: call, read: read, borrow: ContractQueryResponseBorrow{call}}
	s.borrowed, s.taken = true, true
	q.decoding = d
	return d, nil
}

// check reads original gates, not a new timeout. Environment acquisition and
// current authenticated authority still gate final installation/delivery.
func (d *ContractQueryDecode) check() error {
	q := d.call.client
	q.mu.Lock()
	s, err := d.call.slotLocked()
	if err != nil || q.closed || s.closed || q.decoding != d {
		q.mu.Unlock()
		return ErrClosed
	}
	deadline := s.deadline
	err = q.reservation.Check()
	q.mu.Unlock()
	if err != nil {
		return err
	}
	return deadline.Check()
}
func (d *ContractQueryDecode) Step() (bool, error) {
	if d == nil {
		return false, ErrOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false, ErrClosed
	}
	if err := d.check(); err != nil {
		return false, err
	}
	done, err := d.read.Step()
	var malformed protocolv4.CBORFailure
	if errors.As(err, &malformed) {
		switch malformed {
		case "configuration_capacity", "document_released", "decoder_busy", "encoder_capacity", "query_output_alias":
		default:
			d.receiver.failContractQuery()
		}
	}
	return done, err
}
func (d *ContractQueryDecode) Result() (protocolv4.ContractSnapshotSet, error) {
	if d == nil {
		return protocolv4.ContractSnapshotSet{}, ErrOwner
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return protocolv4.ContractSnapshotSet{}, ErrClosed
	}
	if err := d.check(); err != nil {
		return protocolv4.ContractSnapshotSet{}, err
	}
	return d.read.Result()
}
func (d *ContractQueryDecode) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	d.read.Close()
	d.read = nil
	d.borrow.Release()
	q := d.call.client
	q.mu.Lock()
	if q.decoding == d {
		q.decoding = nil
		q.notifyLocked()
		q.cleanupLocked()
	}
	q.mu.Unlock()
	d.receiver = nil
	d.call = ContractQueryCall{}
	d.borrow = ContractQueryResponseBorrow{}
}
