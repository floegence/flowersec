package controlv4

import (
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// PoolResultDecoderConfig is trusted application wiring. Access and ClientStore
// are independently installed, never selected from response fields. The decoder
// must be used only by a transport authenticated for this control authority;
// parsing arbitrary network bytes does not authenticate a receipt.
type PoolResultDecoderConfig struct {
	Tenant       string
	Source       [16]byte
	ClientStore  ledgerv4.SQLiteIdentity
	Access       ledgerv4.TopUpAccess
	RuntimeBytes uint64
}

// PoolResultDecoder owns one parser and at most one outstanding receipt. Close
// fences checks immediately; actual receipt release returns the charged backing.
type PoolResultDecoder struct {
	mu                  sync.Mutex
	config              PoolResultDecoderConfig
	reservation, shared resourcev4.Reference
	decoder             *protocolv4.Decoder
	codec               *protocolv4.TopUpCodec
	receipt             *poolResultReceipt
	done                chan struct{}
	closed, cleaned     bool
}

func PoolResultDecoderCharge(c PoolResultDecoderConfig) (resourcev4.Vector, error) {
	if c.Tenant == "" || len(c.Tenant) > 128 || c.Source == ([16]byte{}) || c.ClientStore.Authority == "" || len(c.ClientStore.Authority) > 128 || c.ClientStore.StoreID == ([32]byte{}) || c.ClientStore.Generation == 0 || c.Access == nil || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	parser, err := protocolv4.DecoderBackingBytes(524288, 128)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	codec, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: parser + codec + uint64(unsafe.Sizeof(PoolResultDecoder{})) + uint64(unsafe.Sizeof(poolResultReceipt{})) + 1024, resourcev4.Items: 2, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolResultDecoder(c PoolResultDecoderConfig, reservation, dependencies resourcev4.Reference) (*PoolResultDecoder, error) {
	cost, err := PoolResultDecoderCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		shared.Release()
		return nil, err
	}
	c.Tenant, c.ClientStore.Authority = strings.Clone(c.Tenant), strings.Clone(c.ClientStore.Authority)
	d := &PoolResultDecoder{config: c, reservation: owned, shared: shared, done: make(chan struct{})}
	d.decoder, err = protocolv4.NewDecoder(524288, 128)
	if err == nil {
		d.codec, err = protocolv4.NewTopUpCodec()
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

func poolPermissionDenied() error {
	fact, _ := protocolv4.TopUpErrorProjection(protocolv4.V4TopUpErrorCodePermissionDenied, protocolv4.V4TopUpWriteActionNone)
	return ledgerv4.TopUpFailure{Fact: fact}
}

func (d *PoolResultDecoder) checkLocked() error {
	// Permission takes precedence over availability and retained history. Keep
	// this finite gate until cleanup, including while a closed receipt is held.
	if d.config.Access == nil || d.config.Access.CheckTopUpAccess(d.config.Tenant, d.config.Source) != nil {
		return poolPermissionDenied()
	}
	if d.closed {
		return resourcev4.ErrClosed
	}
	if err := d.reservation.Check(); err != nil {
		return err
	}
	return d.shared.Check()
}

func (d *PoolResultDecoder) DecodePoolControlResult(ctx context.Context, method uint32, applicationError bool, payload, dst []byte) (result sessionv4.TopUpExchangeResult, err error) {
	if d == nil || ctx == nil {
		return result, resourcev4.ErrConfiguration
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err = d.checkLocked(); err != nil {
		return result, err
	}
	defer func() {
		// A failed parse does not mask permission revoked during that work.
		if d.config.Access.CheckTopUpAccess(d.config.Tenant, d.config.Source) != nil {
			if d.receipt != nil && (result.Evidence == d.receipt || result.FenceEvidence == d.receipt) {
				// This receipt has not been published or shared with another caller.
				d.receipt.owner = nil
				d.receipt.terminal = ledgerv4.TopUpServerSnapshot{}
				d.receipt.fence = ledgerv4.TopUpPermanentFenceReceipt{}
				d.receipt = nil
			}
			clear(dst[:result.ResponseBytes])
			result, err = sessionv4.TopUpExchangeResult{}, poolPermissionDenied()
		}
	}()
	if d.receipt != nil {
		return result, ErrBusy
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if len(payload) == 0 || len(payload) > 524288 {
		return result, ErrResponse
	}
	doc, err := d.decoder.DecodeShape(payload, "", protocolv4.DecodeContext{})
	if err != nil {
		return result, ErrResponse
	}
	defer doc.Release()
	r := poolWireReader{}
	x := doc.Root()
	r.array(x, 4)
	reply := PoolControlReply{Code: protocolv4.V4TopUpWireResult(r.text(x.Index(0)))}
	var ok bool
	reply.Response, ok = x.Index(1).ByteString()
	if !ok {
		return result, ErrResponse
	}
	if !poolWireAbsent(x.Index(2)) {
		terminal := r.terminal(x.Index(2), protocolv4.V4TopUpErrorCode(reply.Code))
		reply.Terminal = &terminal
	}
	if !poolWireAbsent(x.Index(3)) {
		f := x.Index(3)
		r.array(f, 3)
		fence := ledgerv4.TopUpPermanentFenceReceipt{Tenant: r.text(f.Index(0)), Generation: r.uint(f.Index(2))}
		r.blob(f.Index(1), fence.Source[:])
		reply.Fence = &fence
	}
	if r.err != nil || validatePoolReply(method, reply) != nil || applicationError != (reply.Code != "success" && reply.Code != "replay") || len(reply.Response) > len(dst) {
		return result, ErrResponse
	}
	if reply.Terminal != nil {
		t := reply.Terminal
		if t.Request.Tenant != d.config.Tenant || t.Request.Source != d.config.Source {
			return result, ErrResponse
		}
		digest, e := d.codec.RequestDigest(t.Request)
		if e != nil || digest != t.Request.Digest {
			return result, ErrResponse
		}
	}
	if reply.Fence != nil && (reply.Fence.Tenant != d.config.Tenant || reply.Fence.Source != d.config.Source) {
		return result, ErrResponse
	}
	if err = d.checkLocked(); err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if applicationError {
		result.Code = protocolv4.V4TopUpErrorCode(reply.Code)
	} else {
		result.Replay = reply.Code == "replay"
	}
	if reply.Terminal != nil || reply.Fence != nil {
		receipt := &poolResultReceipt{owner: d}
		if reply.Terminal != nil {
			receipt.terminal = *reply.Terminal
			result.Terminal, result.Evidence = *reply.Terminal, receipt
		} else {
			receipt.fence = *reply.Fence
			result.Fence, result.FenceEvidence = *reply.Fence, receipt
		}
		d.receipt = receipt
	}
	result.ResponseBytes = copy(dst, reply.Response)
	return result, nil
}

// Each receipt has its own inert-after-release cell. Old interface aliases can
// neither check nor release a later reply, and retain no decoder/dependency graph.
type poolResultReceipt struct {
	mu       sync.Mutex
	owner    *PoolResultDecoder
	terminal ledgerv4.TopUpServerSnapshot
	fence    ledgerv4.TopUpPermanentFenceReceipt
}

func (r *poolResultReceipt) CheckTopUpTerminal(identity ledgerv4.SQLiteIdentity, request protocolv4.TopUpRequestFacts, terminal ledgerv4.TopUpServerSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.owner
	if d == nil {
		return resourcev4.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkLocked(); err != nil {
		return err
	}
	if d.receipt != r || identity != d.config.ClientStore || terminal != r.terminal || request != r.terminal.Request || r.fence != (ledgerv4.TopUpPermanentFenceReceipt{}) || ledgerv4.CheckTopUpTerminalFacts(terminal) != nil {
		return ErrResponse
	}
	return nil
}

func (r *poolResultReceipt) CheckTopUpPermanentFence(identity ledgerv4.SQLiteIdentity, fence ledgerv4.TopUpPermanentFenceReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.owner
	if d == nil {
		return resourcev4.ErrClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.checkLocked(); err != nil {
		return err
	}
	if d.receipt != r || identity != d.config.ClientStore || fence != r.fence || fence.Generation == 0 || r.terminal != (ledgerv4.TopUpServerSnapshot{}) {
		return ErrResponse
	}
	return nil
}

func (r *poolResultReceipt) ReleaseTopUpEvidence() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.owner
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.receipt == r {
		d.receipt = nil
	}
	r.owner, r.terminal, r.fence = nil, ledgerv4.TopUpServerSnapshot{}, ledgerv4.TopUpPermanentFenceReceipt{}
	d.cleanupLocked()
}

func (d *PoolResultDecoder) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	d.cleanupLocked()
}
func (d *PoolResultDecoder) cleanupLocked() {
	if !d.closed || d.receipt != nil || d.cleaned {
		return
	}
	d.config, d.decoder, d.codec = PoolResultDecoderConfig{}, nil, nil
	d.shared.Release()
	d.reservation.Release()
	d.shared, d.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	d.cleaned = true
	close(d.done)
}
func (d *PoolResultDecoder) WaitCleanup(ctx context.Context) error {
	if d == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-d.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ PoolControlResultDecoder = (*PoolResultDecoder)(nil)

func (*PoolResultDecoder) String() string               { return "Flowersec.PoolResultDecoder" }
func (*PoolResultDecoder) GoString() string             { return "Flowersec.PoolResultDecoder" }
func (*PoolResultDecoder) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
func (*poolResultReceipt) String() string               { return "Flowersec.PoolControlReceipt" }
func (*poolResultReceipt) GoString() string             { return "Flowersec.PoolControlReceipt" }
func (*poolResultReceipt) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
