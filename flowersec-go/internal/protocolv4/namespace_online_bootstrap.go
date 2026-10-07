package protocolv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceBootstrapRequest is an original fresh control query. The provider
// must represent the independently installed, current linearizable authority,
// not a consumer cache or a service possessing only a Head signing key.
type NamespaceBootstrapRequest struct {
	Tenant, Authority string
	Nonce             [32]byte
}

// NamespaceBootstrapProvider borrows each output only until its method exits.
// It must include all actual transport/read/verification cleanup in that exit.
// Cancellation is a request; it never proves that a provider has stopped using
// a buffer. Providers are trusted deployment adapters with separately admitted
// bounded native resources, and may not retain outputs or launch orphan work.
type NamespaceBootstrapProvider interface {
	Query(context.Context, NamespaceBootstrapRequest, []byte) (int, error)
	Fetch(context.Context, NamespaceContent, []byte) (int, error)
}

type NamespaceBootstrapLimits struct {
	ResponseBytes, ResponseNodes, StateBytes int
	DurationMS, FetchDurationMS              uint64
	FetchAttempts                            uint8
	Subscribers                              uint32
	RuntimeBytes                             uint64
	Provider                                 resourcev4.Vector
}

// NamespaceOnlineBootstrap owns one cold-start query and one fixed complete
// pair. It cannot restore or replace an old verification incarnation. Run joins
// actual provider method tails, including cancellation and abnormal exit. Close
// stops only this operation; a delivered namespace belongs to its Environment.
type NamespaceOnlineBootstrap struct {
	sampling          uint32
	runInput          context.Context
	taskContext       namespaceTaskContext
	mu                sync.Mutex
	trust             *NamespaceTrustStore
	clock             *timev4.Clock
	environment       context.Context
	limits            NamespaceBootstrapLimits
	allocation        NamespaceAllocation
	accounts          [resourcev4.MaxAccountsPerCharge]resourcev4.Account
	reservation       resourcev4.Reference
	response, state   []byte
	codec, headCodec  *SignedMapCodec
	headDecoder       *Decoder
	window            *timev4.Window
	deadline          *timev4.Deadline
	ctx               context.Context
	cancel            context.CancelCauseFunc
	done              chan struct{}
	wake, poke        chan struct{}
	started, finished bool
	waiting           bool
	pendingIssued     uint64
	closed, retired   bool
	terminal          error
	durable           *namespaceDurability
}

func NamespaceBootstrapCharge(l NamespaceBootstrapLimits) (resourcev4.Vector, error) {
	maximum, err := SchemaByteLimit("TrustBootstrapResponse")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if l.ResponseBytes < 1024 || l.ResponseBytes > maximum || l.ResponseNodes < 1 || l.ResponseNodes > 1<<20 || l.StateBytes < 1 || l.StateBytes > 1<<30 || l.DurationMS == 0 || l.DurationMS > 90000 || l.FetchDurationMS == 0 || l.FetchDurationMS > 90000 || l.FetchAttempts == 0 || l.RuntimeBytes == 0 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	codec, err := SignedMapBackingBytes("TrustBootstrapResponse", l.ResponseBytes, l.ResponseNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	headLimit, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	headCodec, err := SignedMapBackingBytes("FreshnessHead", headLimit, headLimit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	decoder, err := DecoderBackingBytes(headLimit, headLimit)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	head, err := NamespaceHeadBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceOnlineBootstrap{})) + uint64(l.ResponseBytes+l.StateBytes) + codec + headCodec + decoder + head + uint64(unsafe.Sizeof(timev4.Window{})) + uint64(unsafe.Sizeof(timev4.Deadline{})), resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 1}
	charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: l.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(l.Provider)
}

// NewNamespaceOnlineBootstrap consumes one original reservation before any
// nonce, provider call or decoder allocation. The trust owner remains pinned
// through Retire; no parallel bootstrap may borrow its startup position.
func NewNamespaceOnlineBootstrap(environment context.Context, trust *NamespaceTrustStore, limits NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation resourcev4.Reference) (_ *NamespaceOnlineBootstrap, err error) {
	return newNamespaceBootstrap(environment, trust, limits, allocation, reservation, OnlineBootstrap)
}

func newNamespaceBootstrap(environment context.Context, trust *NamespaceTrustStore, limits NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation resourcev4.Reference, profile VerificationContinuity) (_ *NamespaceOnlineBootstrap, err error) {
	if environment == nil || trust == nil || allocation.Root == nil || len(allocation.Accounts) > resourcev4.MaxAccountsPerCharge {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := environment.Err(); err != nil {
		return nil, err
	}
	charge, err := NamespaceBootstrapCharge(limits)
	if err != nil {
		return nil, err
	}
	trust.mu.Lock()
	defer trust.mu.Unlock()
	if err = trust.checkContinuityProfileLocked(profile); err != nil {
		return nil, err
	}
	if trust.closed || trust.retired || trust.bootstrapStarted || trust.namespace != nil || trust.busy {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := reservation.CheckSameEnvironment(trust.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			owned.Release()
		}
	}()
	b := &NamespaceOnlineBootstrap{trust: trust, clock: trust.clock, environment: environment, limits: limits, allocation: allocation, reservation: owned, done: make(chan struct{}), wake: make(chan struct{}, 1), poke: make(chan struct{}, 1)}
	copy(b.accounts[:], allocation.Accounts)
	b.allocation.Accounts = b.accounts[:len(allocation.Accounts):len(allocation.Accounts)]
	b.response, b.state = make([]byte, limits.ResponseBytes), make([]byte, limits.StateBytes)
	b.codec, err = NewSignedMapCodec("TrustBootstrapResponse", limits.ResponseBytes, limits.ResponseNodes)
	if err != nil {
		return nil, err
	}
	headLimit, err := SchemaByteLimit("FreshnessHead")
	if err != nil {
		return nil, err
	}
	b.headCodec, err = NewSignedMapCodec("FreshnessHead", headLimit, headLimit)
	if err != nil {
		return nil, err
	}
	b.headDecoder, err = NewDecoder(headLimit, headLimit)
	if err != nil {
		return nil, err
	}
	trust.bootstrap, trust.bootstrapStarted = true, true
	return b, nil
}

// NewNamespaceDurableBootstrap obtains a fresh independent authority baseline
// and commits it before delivery. The profile is fixed for the resulting owner;
// store failure cannot fall back to online-only verification.
func NewNamespaceDurableBootstrap(environment context.Context, trust *NamespaceTrustStore, limits NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation resourcev4.Reference, config NamespaceDurabilityConfig) (*NamespaceOnlineBootstrap, error) {
	if trust == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := trust.checkContinuityProfile(DurableRestore); err != nil {
		return nil, err
	}
	if config.Scope.Limits.FetchDurationMS != limits.FetchDurationMS || config.Scope.Limits.FetchAttempts != limits.FetchAttempts {
		return nil, CBORFailure("revocation_continuity_binding")
	}
	d, err := newNamespaceDurability(config, trust)
	if err != nil {
		return nil, err
	}
	b, err := newNamespaceBootstrap(environment, trust, limits, allocation, reservation, DurableRestore)
	if err != nil {
		d.destroy()
		return nil, err
	}
	b.durable = d
	return b, nil
}

// The gate is held on entry and on normal or abnormal return. The synchronous
// caller and watchdog already own the two admitted tasks; retaining this read
// does not allocate an observer, timer, reference or replacement operation.
func (b *NamespaceOnlineBootstrap) sampleLocked() (sample timev4.Sample, sampleErr, inputErr error) {
	if b.closed || b.retired || !b.started || b.finished || b.sampling == math.MaxUint32 {
		return sample, nil, CBORFailure("revocation_namespace_owner")
	}
	clock, environment, input := b.clock, b.environment, b.runInput
	b.sampling++
	b.mu.Unlock()
	returned := false
	defer func() {
		b.mu.Lock()
		b.sampling--
		if !returned && !b.finished {
			if b.terminal == nil {
				b.terminal = CBORFailure("revocation_bootstrap_provider")
			}
			b.cancel(b.terminal)
		}
	}()
	inputErr = environment.Err()
	if inputErr == nil {
		inputErr = input.Err()
	}
	if inputErr == nil {
		sample, sampleErr = clock.Sample()
	}
	returned = true
	return sample, sampleErr, inputErr
}

func (b *NamespaceOnlineBootstrap) checkLockedAt(sample timev4.Sample, sampleErr, inputErr error) error {
	if b.terminal != nil {
		return b.terminal
	}
	if b.closed || b.retired || !b.started || b.window == nil {
		return context.Canceled
	}
	if inputErr != nil {
		return inputErr
	}
	if err := context.Cause(b.taskContext.Context); err != nil {
		return err
	}
	if err := b.reservation.Check(); err != nil {
		return err
	}
	b.trust.mu.Lock()
	closed := b.trust.closed
	err := b.trust.dependencies.Check()
	b.trust.mu.Unlock()
	if closed {
		return CBORFailure("revocation_trust_owner")
	}
	if err != nil {
		return err
	}
	if b.deadline != nil {
		err := b.deadline.CheckAt(sample)
		if sampleErr != nil && err != timev4.ErrExpired {
			return sampleErr
		}
		if err != nil {
			return err
		}
	}
	if err := b.window.CheckAt(sample.Mark); err != nil {
		// Only the original local work window can exhaust a pending proof.
		// A signed material deadline above keeps its independent expiry cause.
		if err == timev4.ErrExpired && b.waiting {
			b.terminal = timev4.ErrNotProven
			b.cancel(b.terminal)
			return b.terminal
		}
		return err
	}
	// Before a signed response, only the original local work window applies.
	// A missing wall anchor does not invalidate a proven monotonic sample.
	return nil
}

func (b *NamespaceOnlineBootstrap) check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	sample, sampleErr, inputErr := b.sampleLocked()
	return b.checkLockedAt(sample, sampleErr, inputErr)
}

// waitForIssued retains the original response and nonce while a trusted wall
// interval proves that its issuance time is still pending. Every pass checks
// the original local window, caller/operation cancellation, trust dependencies,
// and the response's own not-after cap. It never creates a new query or owner.
func (b *NamespaceOnlineBootstrap) waitForIssued(target, end uint64, revalidate func() error) error {
	b.mu.Lock()
	b.waiting = true
	b.pendingIssued = target
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.waiting = false
		b.pendingIssued = 0
		b.mu.Unlock()
		select {
		case b.poke <- struct{}{}:
		default:
		}
	}()
	select {
	case b.poke <- struct{}{}:
	default:
	}
	for {
		var revalidationErr error
		if revalidate != nil {
			revalidationErr = revalidate()
			if revalidationErr != nil && revalidationErr != timev4.ErrPending {
				return revalidationErr
			}
		}
		b.mu.Lock()
		sample, sampleErr, inputErr := b.sampleLocked()
		err := b.checkLockedAt(sample, sampleErr, inputErr)
		if err == nil && sampleErr != nil {
			err = sampleErr
		}
		if err == nil && !sample.Interval.ValidBefore(end) {
			err = timev4.ErrExpired
		}
		if err == nil {
			err = sample.Interval.LowerBound(target, true)
		}
		if err == nil && revalidationErr == timev4.ErrPending {
			err = timev4.ErrPending
		}
		b.mu.Unlock()
		if err != timev4.ErrPending {
			return err
		}
		select {
		case <-b.wake:
		case <-b.ctx.Done():
			if cause := context.Cause(b.ctx); cause != nil {
				return cause
			}
			return context.Canceled
		case <-b.environment.Done():
			return b.environment.Err()
		case <-b.runInput.Done():
			return b.runInput.Err()
		}
	}
}

func (b *NamespaceOnlineBootstrap) watch(stop <-chan struct{}, exited chan<- struct{}) {
	timer := time.NewTimer(time.Millisecond)
	returned := false
	defer close(exited)
	defer timer.Stop()
	defer func() {
		if recover() != nil || !returned {
			b.mu.Lock()
			if !b.finished {
				if b.terminal == nil {
					b.terminal = CBORFailure("revocation_bootstrap_provider")
				}
				b.cancel(b.terminal)
			}
			b.mu.Unlock()
		}
	}()
	for {
		var remaining uint64
		var stopped bool
		err := func() error {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.finished {
				stopped = true
				return nil
			}
			sample, sampleErr, inputErr := b.sampleLocked()
			if b.finished {
				stopped = true
				return nil
			}
			err := b.checkLockedAt(sample, sampleErr, inputErr)
			remaining = 100
			if err == nil {
				var n uint64
				n, err = b.window.RemainingMSAt(sample.Mark)
				remaining = min(remaining, n)
				if err == nil && b.deadline != nil {
					n, err = b.deadline.RemainingMSAt(sample)
					remaining = min(remaining, n)
				}
				if err == nil && b.waiting {
					n, err = b.clock.Profile().Rate.ProveDelta(sample.Interval.LowerMS, b.pendingIssued)
					remaining = min(remaining, n)
				}
			}
			if err != nil {
				b.terminal = err
				b.cancel(err)
			}
			return err
		}()
		if stopped || err != nil {
			returned = true
			return
		}
		timer.Reset(time.Duration(max(1, remaining)) * time.Millisecond)
		select {
		case <-stop:
			returned = true
			return
		case <-b.ctx.Done():
		case <-b.environment.Done():
		case <-b.runInput.Done():
		case <-b.poke:
		case <-timer.C:
			select {
			case b.wake <- struct{}{}:
			default:
			}
		}
	}
}

// Run makes exactly one query and one content read. The response authenticates
// this nonce and the original config/Head bytes with the independent root key;
// State is verified against that exact Head, never a later publication. The
// supplied wait context ceases to own the namespace at successful delivery.
func (b *NamespaceOnlineBootstrap) Run(ctx context.Context, provider NamespaceBootstrapProvider) (result *LiveNamespace, err error) {
	if ctx == nil || provider == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	b.mu.Lock()
	if b.started || b.closed || b.retired {
		b.mu.Unlock()
		return nil, CBORFailure("revocation_namespace_owner")
	}
	b.started, b.runInput = true, ctx
	b.taskContext.Context, b.cancel = context.WithCancelCause(context.Background())
	b.taskContext.parent = ctx
	b.ctx = &b.taskContext
	clock, duration := b.clock, b.limits.DurationMS
	b.mu.Unlock()
	stop, exited := make(chan struct{}), make(chan struct{})
	returned, watching := false, false
	defer func() {
		if recover() != nil || !returned {
			err = CBORFailure("revocation_bootstrap_provider")
		}
		if watching {
			close(stop)
			<-exited
		}
		b.mu.Lock()
		b.cancel(err)
		b.terminal, b.finished = err, true
		close(b.done)
		b.mu.Unlock()
	}()
	// Close can seal this original operation while either adapter is blocked.
	// Run keeps all backing until the actual setup/provider/watch tails return.
	window, err := timev4.NewWindow(clock, duration)
	b.mu.Lock()
	b.window = window
	if err != nil && b.terminal == nil {
		b.terminal = err
	}
	if b.terminal != nil {
		err = b.terminal
	}
	b.mu.Unlock()
	if err != nil {
		returned = true
		return nil, err
	}
	watching = true
	go b.watch(stop, exited)
	result, _, _, err = b.run(provider)
	returned = true
	return result, err
}

// responseBytesInInput maps a validated byte-string field back to the fixed
// provider response backing. The decoder copies the original wire into its own
// arena, so retaining the decoder view after Release would be invalid. The
// node offsets are wire offsets and therefore identify the same bytes in the
// still-owned response buffer without creating an uncharged clone.
func responseBytesInInput(response *SignedMap, name string, input []byte) ([]byte, error) {
	if response == nil || response.document == nil || response.document.decoder == nil {
		return nil, CBORFailure("revocation_bootstrap_binding")
	}
	value := response.Field(name)
	bytesValue, ok := value.ByteString()
	if !ok {
		return nil, CBORFailure("revocation_bootstrap_binding")
	}
	node := value.document.decoder.nodes[value.index]
	if node.dataStart < 0 || node.end < node.dataStart || node.end > len(input) || len(bytesValue) != node.end-node.dataStart {
		return nil, CBORFailure("revocation_bootstrap_binding")
	}
	return input[node.dataStart:node.end:node.end], nil
}

func (b *NamespaceOnlineBootstrap) run(provider NamespaceBootstrapProvider) (_ *LiveNamespace, candidate *LiveNamespace, refs [3]resourcev4.Reference, err error) {
	delivered := false
	defer func() {
		if !delivered && candidate != nil {
			candidate.Close(err)
			_ = candidate.WaitCleanup(context.Background())
		}
		for _, ref := range refs {
			ref.Release()
		}
	}()
	if err = b.check(); err != nil {
		return nil, nil, refs, err
	}
	request := NamespaceBootstrapRequest{Tenant: b.trust.root.Tenant, Authority: b.trust.root.Authority}
	// A bootstrap response is bound to this nonce.  If the system CSPRNG is
	// unavailable, continuing would turn the request into a replayable query
	// (and a zero nonce is not an acceptable substitute).  Fail closed before
	// invoking the provider so it cannot observe or retain an unauthenticated
	// bootstrap attempt.
	if _, err = rand.Read(request.Nonce[:]); err != nil || request.Nonce == ([32]byte{}) {
		if err == nil {
			err = CBORFailure("revocation_bootstrap_nonce")
		}
		return nil, nil, refs, err
	}
	n, err := provider.Query(b.ctx, request, b.response)
	if post := b.check(); post != nil {
		return nil, nil, refs, post
	}
	if err != nil {
		return nil, nil, refs, err
	}
	if n < 1 || n > len(b.response) {
		return nil, nil, refs, CBORFailure("map_size")
	}
	responseBytes := n
	response, err := b.codec.Verify(b.response[:responseBytes:responseBytes], b.trust.root.PublicKey, DecodeContext{})
	if err != nil {
		return nil, nil, refs, err
	}
	responseReleased := false
	defer func() {
		if !responseReleased {
			response.Release()
		}
	}()
	if err = response.document.ValidateRules(DecodeContext{}); err != nil {
		return nil, nil, refs, err
	}
	text := func(name string) string { v, _ := response.Field(name).Text(); return v }
	data := func(name string) []byte { v, _ := response.Field(name).ByteString(); return v }
	if text("tenant_id") != request.Tenant || text("revocation_authority_id") != request.Authority || !bytes.Equal(data("request_nonce"), request.Nonce[:]) || !bytes.Equal(data("signing_key_id"), b.trust.root.KeyID[:]) {
		return nil, nil, refs, CBORFailure("revocation_bootstrap_binding")
	}
	config, err := responseBytesInInput(response, "trust_config", b.response[:responseBytes])
	if err != nil {
		return nil, nil, refs, err
	}
	headWire, err := responseBytesInInput(response, "freshness_head", b.response[:responseBytes])
	if err != nil {
		return nil, nil, refs, err
	}
	issued, _ := response.Field("issued_at_ms").Uint()
	end, _ := response.Field("not_after_ms").Uint()
	response.Release()
	responseReleased = true
	now, err := b.clock.Sample()
	if err == nil && end-issued > b.trust.root.MaxLifetimeMS {
		err = CBORFailure("revocation_trust_lifetime")
	}
	if err == nil && !now.Interval.ValidBefore(end) {
		err = timev4.ErrExpired
	}
	if err == nil {
		err = now.Interval.LowerBound(issued, true)
	}
	pendingTarget := uint64(0)
	if err == timev4.ErrPending {
		pendingTarget = issued
		err = nil
	}
	if err != nil {
		return nil, nil, refs, err
	}
	configPending, err := b.trust.updateBootstrap(config)
	if err != nil {
		return nil, nil, refs, err
	}
	pendingTarget = max(pendingTarget, configPending)
	head, headPending, err := b.bindHeadBootstrap(config, headWire)
	if err != nil {
		return nil, nil, refs, err
	}
	pendingTarget = max(pendingTarget, headPending)
	if head.rules.stateBytes > uint64(b.limits.StateBytes) {
		return nil, nil, refs, CBORFailure("configuration_capacity")
	}
	deadline, err := timev4.NewDeadline(b.clock, min(end, head.next, head.trustEnd, head.signerEnd))
	if err != nil {
		return nil, nil, refs, err
	}
	b.mu.Lock()
	b.deadline = deadline
	b.mu.Unlock()
	refs, err = reserveNamespace(head.rules, b.limits.Subscribers, b.allocation)
	if err != nil {
		return nil, nil, refs, err
	}
	for _, ref := range refs {
		if err = b.reservation.CheckSameEnvironment(ref); err != nil {
			return nil, nil, refs, err
		}
	}
	if err = b.check(); err != nil {
		return nil, nil, refs, err
	}
	n, err = provider.Fetch(b.ctx, NamespaceContent{Digest: head.stateDigest, EncodedBytes: head.stateBytes}, b.state[:head.stateBytes:head.stateBytes])
	if post := b.check(); post != nil {
		return nil, nil, refs, post
	}
	if err != nil {
		return nil, nil, refs, err
	}
	if n < 0 || uint64(n) != head.stateBytes {
		return nil, nil, refs, CBORFailure("revocation_state_length")
	}
	candidate, err = newBootstrappedNamespace(b.environment, b.clock, b.trust, NamespaceBootstrap{Rules: head.rules, Head: head, State: b.state[:n:n]}, b.limits.FetchDurationMS, b.limits.FetchAttempts, b.limits.Subscribers, refs, true, pendingTarget != 0)
	if err != nil {
		return nil, nil, refs, err
	}
	// Start the candidate watchdog before any wait so every candidate has a
	// real cleanup tail joined by run's defer. Attach it before the coverage
	// check because coverage validates the exact installed owner relationship;
	// no continuity commit is made until the final gate below.
	go candidate.watch()
	candidate.mu.Lock()
	// The candidate remains Environment-owned after delivery, but its first
	// continuity commit is still part of this bootstrap operation. Keep the
	// bootstrap task context only until that commit and final gate complete.
	candidate.initialContinuityContext = b.ctx
	b.trust.mu.Lock()
	b.trust.namespace = candidate
	candidate.durable, b.durable = b.durable, nil
	b.trust.mu.Unlock()
	candidate.mu.Unlock()
	coverageErr := b.trust.checkReplacementCoverage(candidate)
	if coverageErr != nil && (coverageErr != timev4.ErrPending || pendingTarget == 0) {
		return nil, candidate, refs, coverageErr
	}
	setPendingTarget := func(target uint64) {
		if target == 0 || target <= pendingTarget {
			return
		}
		pendingTarget = target
		b.mu.Lock()
		if target > b.pendingIssued {
			b.pendingIssued = target
		}
		b.mu.Unlock()
	}
	revalidate := func() error {
		verified, err := b.codec.Verify(b.response[:responseBytes:responseBytes], b.trust.root.PublicKey, DecodeContext{})
		if err != nil {
			return err
		}
		if err = verified.document.ValidateRules(DecodeContext{}); err == nil {
			textAgain := func(name string) string { value, _ := verified.Field(name).Text(); return value }
			dataAgain := func(name string) []byte { value, _ := verified.Field(name).ByteString(); return value }
			if textAgain("tenant_id") != request.Tenant || textAgain("revocation_authority_id") != request.Authority || !bytes.Equal(dataAgain("request_nonce"), request.Nonce[:]) || !bytes.Equal(dataAgain("signing_key_id"), b.trust.root.KeyID[:]) || !bytes.Equal(dataAgain("trust_config"), config) || !bytes.Equal(dataAgain("freshness_head"), headWire) {
				err = CBORFailure("revocation_bootstrap_binding")
			}
		}
		verified.Release()
		if err != nil {
			return err
		}
		if err = b.check(); err != nil {
			return err
		}
		pending := false
		_, headPending, err := b.bindHeadBootstrap(config, headWire)
		if err != nil {
			return err
		}
		if headPending != 0 {
			setPendingTarget(headPending)
			pending = true
		}
		sample, err := b.clock.Sample()
		if err != nil {
			return err
		}
		candidate.mu.Lock()
		err = candidate.checkAvailable()
		if err == nil {
			var candidateHeadPending uint64
			candidateHeadPending, err = candidate.checkHeadAtPending(head, sample)
			if candidateHeadPending != 0 {
				setPendingTarget(candidateHeadPending)
				pending = true
			}
		}
		if err == nil {
			var historyPending uint64
			historyPending, err = candidate.checkStateHistoryAtPending(candidate.active, sample)
			if historyPending != 0 {
				setPendingTarget(historyPending)
				pending = true
			}
		}
		candidate.mu.Unlock()
		if err != nil && err != timev4.ErrPending {
			return err
		}
		if err == timev4.ErrPending {
			pending = true
		}
		coverageErr := b.trust.checkReplacementCoverage(candidate)
		if coverageErr != nil && coverageErr != timev4.ErrPending {
			return coverageErr
		}
		if coverageErr == timev4.ErrPending {
			pending = true
		}
		if pending {
			return timev4.ErrPending
		}
		return nil
	}
	if pendingTarget != 0 {
		if err = b.waitForIssued(pendingTarget, end, revalidate); err != nil {
			return nil, candidate, refs, err
		}
	}
	// The candidate is already attached for coverage, but continuity remains
	// uncommitted until the strict original pair gate completes below.
	if err = b.trust.prepareReplacementCommit(b.ctx, candidate); err != nil {
		return nil, candidate, refs, err
	}
	if err = b.check(); err != nil {
		return nil, candidate, refs, err
	}
	candidate.mu.Lock()
	func() { defer candidate.mu.Unlock(); err = candidate.persistContinuity() }()
	if err != nil {
		return nil, candidate, refs, err
	}
	err = func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		sample, sampleErr, inputErr := b.sampleLocked()
		if err := b.checkLockedAt(sample, sampleErr, inputErr); err != nil {
			return err
		}
		candidate.mu.Lock()
		defer candidate.mu.Unlock()
		if err := candidate.checkAvailable(); err != nil {
			return err
		}
		if err := candidate.checkHeadAt(head, sample); err != nil {
			return err
		}
		if err := candidate.checkStateHistoryAt(candidate.active, sample); err != nil {
			return err
		}
		b.trust.mu.Lock()
		candidate.initializing = false
		candidate.initialContinuityContext = nil
		b.trust.continuityReady = true
		b.trust.mu.Unlock()
		candidate.signal()
		b.finished = true
		return nil
	}()
	if err != nil {
		return nil, candidate, refs, err
	}
	delivered = true
	return candidate, candidate, refs, nil
}

func (b *NamespaceOnlineBootstrap) bindHead(config, wire []byte) (*NamespaceHead, error) {
	head, _, err := b.bindHeadBootstrap(config, wire)
	if err == nil {
		now, sampleErr := b.clock.Sample()
		if sampleErr != nil {
			err = sampleErr
		} else {
			err = head.CheckTime(now.Interval)
		}
	}
	return head, err
}

func (b *NamespaceOnlineBootstrap) bindHeadBootstrap(config, wire []byte) (*NamespaceHead, uint64, error) {
	head, pending, err := b.trust.bindHeadBootstrap(b.headDecoder, b.headCodec, config, wire)
	if err != nil {
		return nil, 0, err
	}
	now, err := b.clock.Sample()
	if err != nil {
		return nil, 0, err
	}
	headPending, err := head.CheckTimePending(now.Interval)
	if err != nil {
		return nil, 0, err
	}
	return head, max(pending, headPending), nil
}

func (b *NamespaceOnlineBootstrap) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.finished {
		return
	}
	b.closed = true
	b.terminal = context.Canceled
	if b.cancel != nil {
		b.cancel(context.Canceled)
	}
	if !b.started {
		b.finished = true
		close(b.done)
	}
}

func (b *NamespaceOnlineBootstrap) WaitCleanup(ctx context.Context) error {
	if ctx == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *NamespaceOnlineBootstrap) Retire() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retired {
		return nil
	}
	if b.sampling != 0 {
		return CBORFailure("revocation_namespace_owner")
	}
	select {
	case <-b.done:
	default:
		return CBORFailure("revocation_namespace_owner")
	}
	if b.durable != nil {
		b.durable.destroy()
		b.durable = nil
	}
	clear(b.response)
	clear(b.state)
	b.response, b.state, b.codec, b.headCodec, b.headDecoder = nil, nil, nil, nil, nil
	b.deadline, b.window, b.ctx, b.environment, b.cancel, b.runInput = nil, nil, nil, nil, nil, nil
	b.taskContext = namespaceTaskContext{}
	b.allocation = NamespaceAllocation{}
	clear(b.accounts[:])
	b.trust.mu.Lock()
	b.trust.bootstrap = false
	registry := b.trust.registry
	b.trust.mu.Unlock()
	if registry != nil {
		registry.signalPressure()
	}
	b.trust, b.clock = nil, nil
	b.reservation.Release()
	b.reservation = resourcev4.Reference{}
	b.retired = true
	return nil
}
