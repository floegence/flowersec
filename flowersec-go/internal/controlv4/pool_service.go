package controlv4

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PoolIssueResult either names the complete private canonical TopUpResponse or
// explicitly denies the already occupied operation. An ordinary issuer error
// is never a denial. A denial becomes authoritative only after Store.Deny.
type PoolIssueResult struct {
	ResponseBytes int
	Deny          protocolv4.V4TopUpErrorCode
}

// PoolBatchIssuer runs outside the SQLite transaction and service mutex. The
// pending snapshot fixes the original identity/intent/generation and next
// artifact sequence. No input byte, output buffer or provider task may outlive
// this original invocation. The independently configured store authority still
// verifies every complete issued batch at the commit boundary.
type PoolBatchIssuer interface {
	IssuePoolBatch(context.Context, ledgerv4.TopUpServerSnapshot, []byte) (PoolIssueResult, error)
}

// PoolRelayPublicationFactory resolves independent trusted relay policy for
// the exact original batch. It admits the publication owner and every target
// position before outbox commit. Replays receive the original retained bytes;
// this factory must not issue, sign, send server allow or prepare a carrier.
// A nil owner is permitted only for a batch containing no tunnel material.
type PoolRelayPublicationFactory interface {
	PreparePoolRelayPublication(context.Context, ledgerv4.TopUpServerSnapshot, []byte) (*ledgerv4.SQLitePoolRelayPublication, error)
}

type PoolServiceConfig struct {
	Store             *ledgerv4.SQLiteTopUpServer
	Issuer            PoolBatchIssuer
	RelayPublications PoolRelayPublicationFactory
	// OriginalCommitted runs only after this invocation's complete first COMMIT
	// and relay publication. Replays and recovery reads never call it. The
	// callback must retain any continuation before the publication closes.
	OriginalCommitted          func(context.Context, protocolv4.TopUpRequestFacts, []byte, *ledgerv4.SQLitePoolRelayPublication) error
	Tenant                     string
	Source                     [16]byte
	TopUpContract, AckContract [32]byte
	CallMS, RuntimeBytes       uint64
	// Both transient contracts must declare this nonzero application-error
	// catalog entry for the pool-result-1 error envelope.
	ApplicationErrorCode uint32
}

// PoolService owns one synchronous control invocation and its complete private
// response backing. One separately admitted refusal position authenticates a
// busy caller and sends a small refusal without occupying another intent. A
// saturated refusal position rejects locally without entering another callback.
// Closing cancels work but retains dependencies until the issuer/provider and
// result writer actually return. The borrowed shared store is never closed.
type PoolService struct {
	mu                              sync.Mutex
	config                          PoolServiceConfig
	reservation, shared             resourcev4.Reference
	response, envelope              []byte
	codec                           *protocolv4.TopUpCodec
	cancel, refusalCancel           context.CancelFunc
	done                            chan struct{}
	busy, refusing, closed, cleaned bool
}

func PoolServiceCharge(c PoolServiceConfig) (resourcev4.Vector, error) {
	if c.OriginalCommitted != nil && c.RelayPublications == nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	if c.Store == nil || c.Issuer == nil || c.Tenant == "" || len(c.Tenant) > 128 || c.Source == ([16]byte{}) || c.TopUpContract == ([32]byte{}) || c.AckContract == ([32]byte{}) || c.TopUpContract == c.AckContract || c.CallMS == 0 || c.CallMS > 90000 || c.RuntimeBytes == 0 || c.ApplicationErrorCode == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	codec, err := protocolv4.TopUpCodecBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(PoolService{})) + 2*controlCallContextBytes + codec + 2*524288 + 256, resourcev4.Items: 1, resourcev4.WorkSlots: 2, resourcev4.Tasks: 2, resourcev4.Timers: 2}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewPoolService(c PoolServiceConfig, reservation, dependencies resourcev4.Reference) (*PoolService, error) {
	cost, err := PoolServiceCharge(c)
	if err != nil {
		return nil, err
	}
	if err = c.Store.CheckSourceBinding(c.Tenant, c.Source); err != nil {
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
	c.Tenant = strings.Clone(c.Tenant)
	p := &PoolService{config: c, reservation: owned, shared: shared, response: make([]byte, 524288), envelope: make([]byte, 524288), done: make(chan struct{})}
	p.codec, err = protocolv4.NewTopUpCodec()
	if err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Exchange is the independently authenticated HTTPS adapter's bounded service
// entry. dst remains caller-owned; no success is returned before actual COMMIT.
func (p *PoolService) Exchange(ctx context.Context, method uint32, access ledgerv4.TopUpAccess, wire, dst []byte) (n int, applicationError bool, err error) {
	if len(dst) < 524288 {
		return 0, false, resourcev4.ErrConfiguration
	}
	returned := false
	defer func() {
		if !returned || err != nil {
			clear(dst[:n])
			n, applicationError = 0, false
		}
	}()
	err = p.serve(ctx, method, access, wire, func(b []byte, failure bool) error {
		n, applicationError = copy(dst, b), failure
		return nil
	})
	returned = true
	return
}

// Unary is registered for 41006 and 41007 in an explicit transient application
// plan. The trusted SessionPlan installs a TopUpAccess in ApplicationContext
// after binding it to the authenticated caller. Peer payload cannot create it.
// The original InputBorrow/UnaryResponse own delivery and cleanup; no
// execution-header operation ID or independently scheduled worker is created.
func (p *PoolService) Unary(ctx context.Context, request sessionv4.UnaryRequest, response *sessionv4.UnaryResponse) (uint32, error) {
	if p == nil || ctx == nil || response == nil {
		return 0, resourcev4.ErrConfiguration
	}
	p.mu.Lock()
	c := p.config
	p.mu.Unlock()
	wire, header, err := request.Input.Bytes()
	if err != nil {
		return 0, err
	}
	method := header.Fields().Type
	if header.Kind() != "transient_unary_request" || header.HasExecutionIdentity() || method != ControlPoolTopUp && method != ControlPoolAck {
		return 0, ErrResponse
	}
	digest := c.TopUpContract
	if method == ControlPoolAck {
		digest = c.AckContract
	}
	if digest == ([32]byte{}) || header.Fields().ServiceContractDigest != digest {
		return 0, ErrResponse
	}
	access, _ := request.ApplicationContext.(ledgerv4.TopUpAccess)
	var code uint32
	err = p.serve(ctx, method, access, wire, func(b []byte, failure bool) error {
		if failure {
			code = c.ApplicationErrorCode
		}
		_, e := response.Write(b)
		return e
	})
	return code, err
}

func (p *PoolService) serve(ctx context.Context, method uint32, access ledgerv4.TopUpAccess, wire []byte, deliver func([]byte, bool) error) (err error) {
	if p == nil || ctx == nil || deliver == nil || method != ControlPoolTopUp && method != ControlPoolAck {
		return resourcev4.ErrConfiguration
	}
	if !p.mu.TryLock() {
		return ErrBusy
	}
	if p.closed {
		p.mu.Unlock()
		return resourcev4.ErrClosed
	}
	refusing := p.busy
	if refusing && p.refusing {
		p.mu.Unlock()
		return ErrBusy
	}
	if err = p.reservation.Check(); err == nil {
		err = p.shared.Check()
	}
	if err != nil {
		p.mu.Unlock()
		return err
	}
	config := p.config
	call := newControlCallContext(time.Duration(config.CallMS) * time.Millisecond)
	if refusing {
		p.refusing, p.refusalCancel = true, call.stopCall
	} else {
		p.busy, p.cancel = true, call.stopCall
	}
	p.mu.Unlock()
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil || !returned {
			err = ErrControlTaskExit
			call.cancel(err)
		}
		call.finish()
		p.mu.Lock()
		if err == nil {
			err = p.checkCallLocked(call)
		}
		call.stopCall()
		if refusing {
			p.refusing, p.refusalCancel = false, nil
		} else {
			clear(p.response)
			clear(p.envelope)
			p.busy, p.cancel = false, nil
		}
		p.cleanupLocked()
		p.mu.Unlock()
	}()
	if err = call.start(ctx); err == nil {
		err = p.serveBody(call, config, method, access, wire, deliver, refusing)
	}
	returned = true
	return err
}

func (p *PoolService) checkCallLocked(call *controlCallContext) error {
	if p.closed {
		return resourcev4.ErrClosed
	}
	if err := call.cause(); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

func (p *PoolService) checkCall(call *controlCallContext) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkCallLocked(call)
}

func (p *PoolService) serveBody(call *controlCallContext, config PoolServiceConfig, method uint32, access ledgerv4.TopUpAccess, wire []byte, deliver func([]byte, bool) error, refusing bool) (err error) {
	denied := access == nil || access.CheckTopUpAccess(config.Tenant, config.Source) != nil
	if denied || refusing {
		// Authorization precedes the response choice. Neither refusal path
		// inspects source history, uses full reply buffers or enters issuance.
		code := protocolv4.V4TopUpWireResult("capacity_exhausted")
		if denied {
			code = "permission_denied"
		}
		var b [64]byte
		defer clear(b[:])
		n, err := EncodePoolControlReply(b[:], method, PoolControlReply{Code: code})
		if err != nil {
			return err
		}
		if err = p.checkCall(call); err != nil {
			return err
		}
		return deliver(b[:n:n], true)
	}
	if err = p.checkCall(call); err != nil {
		return err
	}
	var reply PoolControlReply
	if len(wire) == 0 || len(wire) > 524288 {
		reply.Code = "source_contract_invalid"
	} else if method == ControlPoolAck {
		reply, err = p.ack(call, access, wire)
	} else {
		reply, err = p.topUp(call, access, wire)
	}
	// Failed permission is the only returned result, even if a provider/store
	// also failed. A committed response remains history, never publication rights.
	if access.CheckTopUpAccess(config.Tenant, config.Source) != nil {
		reply, err = PoolControlReply{Code: "permission_denied"}, nil
	} else if err != nil {
		reply, err = poolServiceFailure(err)
	}
	if err != nil {
		return err
	}
	if err = call.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	if p.closed {
		err = resourcev4.ErrClosed
	} else if err = p.reservation.Check(); err == nil {
		err = p.shared.Check()
	}
	p.mu.Unlock()
	if err != nil {
		return err
	}
	n, err := EncodePoolControlReply(p.envelope, method, reply)
	if err != nil {
		return err
	}
	if access.CheckTopUpAccess(config.Tenant, config.Source) != nil {
		clear(p.envelope[:n])
		reply = PoolControlReply{Code: "permission_denied"}
		n, err = EncodePoolControlReply(p.envelope, method, reply)
		if err != nil {
			return err
		}
	}
	if err = p.checkCall(call); err != nil {
		return err
	}
	return deliver(p.envelope[:n:n], reply.Code != "success" && reply.Code != "replay")
}

func poolServiceFailure(err error) (PoolControlReply, error) {
	var failure ledgerv4.TopUpFailure
	if errors.As(err, &failure) {
		if _, ok := protocolv4.TopUpErrorProjection(failure.Fact.Code, protocolv4.V4TopUpWriteActionNone); ok {
			return PoolControlReply{Code: protocolv4.V4TopUpWireResult(failure.Fact.Code)}, nil
		}
	}
	var malformed protocolv4.CBORFailure
	if errors.As(err, &malformed) {
		code := protocolv4.V4TopUpErrorCode(malformed)
		if _, ok := protocolv4.TopUpErrorProjection(code, protocolv4.V4TopUpWriteActionNone); !ok {
			code = protocolv4.V4TopUpErrorCodeSourceContractInvalid
		}
		return PoolControlReply{Code: protocolv4.V4TopUpWireResult(code)}, nil
	}
	// Unknown storage/issuer/transport outcomes have no authoritative terminal.
	// These are call errors only; no durable sequence is released by the code.
	code := protocolv4.V4TopUpErrorCodeSourceUnavailable
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return PoolControlReply{}, err
	case errors.Is(err, ledgerv4.ErrUnknown), errors.Is(err, ledgerv4.ErrAuditUnknown), errors.Is(err, ledgerv4.ErrStorageFormat):
		code = protocolv4.V4TopUpErrorCodeSourceStateUnknown
	case errors.Is(err, ledgerv4.ErrConflict):
		code = protocolv4.V4TopUpErrorCodeOperationConflict
	case errors.Is(err, ledgerv4.ErrFenced):
		code = protocolv4.V4TopUpErrorCodeStaleGeneration
	case errors.Is(err, resourcev4.ErrCapacity), errors.Is(err, ledgerv4.ErrCapacity), errors.Is(err, ledgerv4.ErrAuditCapacity):
		code = protocolv4.V4TopUpErrorCodeCapacityExhausted
	case errors.Is(err, ledgerv4.ErrAuditDenied):
		code = protocolv4.V4TopUpErrorCodePermissionDenied
	case errors.Is(err, ErrResponse), errors.Is(err, ledgerv4.ErrConfiguration):
		code = protocolv4.V4TopUpErrorCodeSourceContractInvalid
	case errors.Is(err, timev4.ErrExpired):
		code = protocolv4.V4TopUpErrorCodeTopUpRequestExpired
	}
	return PoolControlReply{Code: protocolv4.V4TopUpWireResult(code)}, nil
}

func (p *PoolService) topUp(ctx context.Context, access ledgerv4.TopUpAccess, wire []byte) (PoolControlReply, error) {
	prepared, err := p.config.Store.Prepare(ctx, access, wire, p.response)
	if err != nil {
		return p.historyAfterError(ctx, access, wire, err)
	}
	s := prepared.Snapshot
	if s.State == ledgerv4.TopUpServerCommitted && prepared.Replay && prepared.ResponseBytes > 0 {
		publication, err := p.prepareRelayPublication(ctx, s, p.response[:prepared.ResponseBytes])
		if err != nil {
			return PoolControlReply{}, err
		}
		if publication != nil {
			defer publication.Close()
			if err = publication.PublishCommitted(ctx, access, p.response[:prepared.ResponseBytes]); err != nil {
				return PoolControlReply{}, err
			}
		}
		return PoolControlReply{Code: "replay", Response: p.response[:prepared.ResponseBytes]}, nil
	}
	if s.State == ledgerv4.TopUpServerTerminal {
		return p.terminalReply(ctx, access, s)
	}
	if s.State != ledgerv4.TopUpServerPending || prepared.ResponseBytes != 0 || prepared.Replay {
		return PoolControlReply{}, ErrResponse
	}
	issued, err := p.config.Issuer.IssuePoolBatch(ctx, s, p.response)
	if err != nil {
		return PoolControlReply{}, err
	}
	if err = ctx.Err(); err != nil {
		return PoolControlReply{}, err
	}
	if issued.Deny != "" {
		if issued.ResponseBytes != 0 {
			return PoolControlReply{}, ErrResponse
		}
		s, err = p.config.Store.Deny(ctx, access, wire, issued.Deny)
		if err != nil {
			return PoolControlReply{}, err
		}
		return p.terminalReply(ctx, access, s)
	}
	if issued.ResponseBytes < 1 || issued.ResponseBytes > len(p.response) {
		return PoolControlReply{}, ErrResponse
	}
	publication, err := p.prepareRelayPublication(ctx, s, p.response[:issued.ResponseBytes])
	if err != nil {
		return PoolControlReply{}, err
	}
	if publication != nil {
		defer publication.Close()
		s, err = p.config.Store.CommitWithRelay(ctx, access, wire, p.response[:issued.ResponseBytes], publication)
	} else {
		s, err = p.config.Store.Commit(ctx, access, wire, p.response[:issued.ResponseBytes])
	}
	if err != nil {
		return PoolControlReply{}, err
	}
	if s.State == ledgerv4.TopUpServerTerminal {
		return p.terminalReply(ctx, access, s)
	}
	if s.State != ledgerv4.TopUpServerCommitted {
		return PoolControlReply{}, ErrResponse
	}
	if p.config.OriginalCommitted != nil {
		if err = publication.CheckOriginalMaterial(s.Request, p.response[:issued.ResponseBytes]); err != nil {
			return PoolControlReply{}, err
		}
		if err = p.config.OriginalCommitted(ctx, s.Request, p.response[:issued.ResponseBytes], publication); err != nil {
			return PoolControlReply{}, err
		}
	}
	return PoolControlReply{Code: "success", Response: p.response[:issued.ResponseBytes]}, nil
}

func (p *PoolService) prepareRelayPublication(ctx context.Context, s ledgerv4.TopUpServerSnapshot, response []byte) (*ledgerv4.SQLitePoolRelayPublication, error) {
	if p.config.RelayPublications == nil {
		return nil, nil
	}
	publication, err := p.config.RelayPublications.PreparePoolRelayPublication(ctx, s, response)
	if err != nil {
		if publication != nil {
			_ = publication.Close()
		}
		return nil, err
	}
	if publication == nil {
		// Independently enforce the factory's direct-only nil result.
		batch, err := p.codec.ParseResponse(response, s.Request)
		if err != nil {
			return nil, err
		}
		defer batch.Release()
		facts, err := batch.Facts()
		if err != nil {
			return nil, err
		}
		for i := uint32(0); i < facts.Count; i++ {
			material, err := batch.Material(i)
			if err != nil || len(material) == 0 || material[0] != 0x84 {
				return nil, ErrResponse
			}
		}
	}
	return publication, nil
}

func (p *PoolService) ack(ctx context.Context, access ledgerv4.TopUpAccess, wire []byte) (PoolControlReply, error) {
	s, err := p.config.Store.Ack(ctx, access, wire)
	if err != nil {
		var failure ledgerv4.TopUpFailure
		if errors.As(err, &failure) && failure.Fact.Code == protocolv4.V4TopUpErrorCodeSourceResetRequired {
			return p.permanentFence(ctx, access, err)
		}
		return PoolControlReply{}, err
	}
	if s.Terminal != "" {
		return p.terminalReply(ctx, access, s)
	}
	if s.State != ledgerv4.TopUpServerRetired {
		return PoolControlReply{}, ErrResponse
	}
	return PoolControlReply{Code: "success"}, nil
}

func (p *PoolService) terminalReply(ctx context.Context, access ledgerv4.TopUpAccess, s ledgerv4.TopUpServerSnapshot) (PoolControlReply, error) {
	latest, err := p.config.Store.AdvanceRetirement(ctx, access)
	if err != nil {
		return PoolControlReply{}, err
	}
	if latest.Request != s.Request {
		return PoolControlReply{}, ledgerv4.ErrConflict
	}
	if ledgerv4.CheckTopUpTerminalFacts(latest) != nil {
		return PoolControlReply{}, ErrResponse
	}
	return PoolControlReply{Code: protocolv4.V4TopUpWireResult(latest.Terminal), Terminal: &latest}, nil
}

func (p *PoolService) permanentFence(ctx context.Context, access ledgerv4.TopUpAccess, original error) (PoolControlReply, error) {
	s, err := p.config.Store.AdvanceRetirement(ctx, access)
	if err != nil {
		return PoolControlReply{}, err
	}
	if !s.Permanent {
		return PoolControlReply{}, original
	}
	f := ledgerv4.TopUpPermanentFenceReceipt{Tenant: p.config.Tenant, Source: p.config.Source, Generation: s.BindingGeneration}
	return PoolControlReply{Code: "source_reset_required", Fence: &f}, nil
}

func (p *PoolService) historyAfterError(ctx context.Context, access ledgerv4.TopUpAccess, wire []byte, original error) (PoolControlReply, error) {
	var failure ledgerv4.TopUpFailure
	if !errors.As(original, &failure) {
		return PoolControlReply{}, original
	}
	if failure.Fact.Code == protocolv4.V4TopUpErrorCodeSourceResetRequired {
		return p.permanentFence(ctx, access, original)
	}
	if failure.Fact.Code != protocolv4.V4TopUpErrorCodeStaleOperation {
		return PoolControlReply{}, original
	}
	// An expired owner proof may read its exact retained terminal; it cannot
	// append, issue or replay material. Never turn a stale-operation code alone
	// into retirement evidence for an operation absent from retained history.
	r, err := p.codec.InspectRequest(wire)
	if err != nil {
		return PoolControlReply{}, err
	}
	s, err := p.config.Store.Recover(ctx, access)
	if err != nil {
		return PoolControlReply{}, err
	}
	r.Generation = s.Request.Generation
	if r != s.Request || ledgerv4.CheckTopUpTerminalFacts(s) != nil {
		return PoolControlReply{}, original
	}
	return PoolControlReply{Code: protocolv4.V4TopUpWireResult(s.Terminal), Terminal: &s}, nil
}

func (p *PoolService) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.cancel != nil {
		p.cancel()
	}
	if p.refusalCancel != nil {
		p.refusalCancel()
	}
	p.cleanupLocked()
}
func (p *PoolService) cleanupLocked() {
	if !p.closed || p.busy || p.refusing || p.cleaned {
		return
	}
	clear(p.response)
	clear(p.envelope)
	p.response, p.envelope, p.codec = nil, nil, nil
	p.config = PoolServiceConfig{}
	p.shared.Release()
	p.reservation.Release()
	p.shared, p.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	p.cleaned = true
	close(p.done)
}
func (p *PoolService) WaitCleanup(ctx context.Context) error {
	if p == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*PoolService) String() string               { return "Flowersec.PoolService" }
func (*PoolService) GoString() string             { return "Flowersec.PoolService" }
func (*PoolService) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
