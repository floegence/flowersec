package protocolv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceHeadTrust identifies the exact original independently authorized
// trust entry. It is internal metadata, never a public diagnostic projection.
type NamespaceHeadTrust struct {
	Tenant, Authority                          string
	Capacity, Delegation                       [32]byte
	Signer                                     [16]byte
	Generation, TrustIssuedMS, TrustNotAfterMS uint64
}

// NamespaceTrust is the Environment's independent current trust owner. All
// operations are bounded local reads, not I/O or application callbacks. Head
// checks the original full delegation and selected trust interval against the
// current generation/key rejection fence. Issuer validates the exact original
// permission, including the original role/subject/profile/audience and signing
// bounds. A Grant's parent issuer/namespace must resolve to the same fixed
// authority and permitted grant-issuer mapping. Policy authenticates the exact
// immutable credential-policy reference. Activation also fixes the
// complete original delegation and parent-to-once-authority mapping across
// trust revisions; matching key IDs alone is insufficient. RetiredIssuer is true only
// for independent permanent retirement, never expiry or a Head's assertion.
type NamespaceTrust interface {
	Head(NamespaceHeadTrust) error
	Issuer(IssuerPermission, CredentialScope) error
	Policy(*CredentialPolicy) error
	Activation(ActivationTrustBinding) error
	RetiredIssuer([16]byte) bool
	// StateHistory verifies the original complete issuer authorization impact
	// evidence against independent retained trust history. The State document
	// is immutable and borrowed only for this bounded local check.
	StateHistory(*NamespaceState) error
}

// NamespaceContent fixes the selected original content identity. Providers
// fetch into the owner's pre-admitted buffer and cannot select another Head.
type NamespaceContent struct {
	Digest       [32]byte
	EncodedBytes uint64
}

type NamespaceFetch func(context.Context, NamespaceContent, []byte) (int, error)

// LiveNamespace is the shared live verification engine for both continuity
// profiles. Online construction requires the independently authenticated nonce
// bootstrap; durable construction commits that baseline or revalidates complete
// independently proven storage history. Neither path restores a Session, changes
// generation, forgets history on cache eviction or supplies root trust.
type LiveNamespace struct {
	sampling        uint32
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelCauseFunc
	taskContext     namespaceTaskContext
	parentDone      <-chan struct{}
	clock           *timev4.Clock
	trust           NamespaceTrust
	rules           *NamespaceRules
	active          *NamespaceState
	observed        *NamespaceHead
	pin             *NamespacePin
	spare           *RevocationWorkspace
	input           []byte
	retired         [][16]byte
	fetchDuration   uint64
	attemptLimit    uint8
	settledSequence uint64
	terminal        error
	cleaned         bool
	wake, done      chan struct{}
	watcherExited   bool
	subscribers     []namespaceSubscriber
	reservation     resourcev4.Reference
	destroyed       bool
	refresh         *NamespaceRefresh
	refreshActive   bool
	durable         *namespaceDurability
	initializing    bool
}

// NamespacePin is private to this live incarnation. New Head observations do
// not replace it, reset its deadline or start a second fetch/verification task.
type NamespacePin struct {
	owner    *LiveNamespace
	head     *NamespaceHead
	deadline *timev4.Deadline
	window   *timev4.Window
	ctx      context.Context
	cancel   context.CancelCauseFunc
	attempts uint8
	running  bool
	terminal error
}

// LiveNamespaceBackingBytes is additional to the two complete State workspaces,
// immutable namespace mapping and the independent trust owner. It includes one
// real fetch buffer, three original Head/chain slots and retirement workspace.
func (r *NamespaceRules) LiveNamespaceBackingBytes(subscriberSlots uint32) (uint64, error) {
	if r == nil || uint64(subscriberSlots) > uint64(math.MaxInt)/uint64(unsafe.Sizeof(namespaceSubscriber{})) {
		return 0, CBORFailure("revocation_namespace_binding")
	}
	head, err := NamespaceHeadBackingBytes()
	if err != nil {
		return 0, err
	}
	return namespaceAdd(r.stateBytes, 3*head+r.limits["max_revoked_issuers"]*16+uint64(unsafe.Sizeof(LiveNamespace{}))+uint64(unsafe.Sizeof(NamespacePin{}))+uint64(unsafe.Sizeof(timev4.Deadline{}))+uint64(unsafe.Sizeof(timev4.Window{}))+uint64(subscriberSlots)*uint64(unsafe.Sizeof(namespaceSubscriber{})))
}

// LiveNamespaceCharge reserves the retained owner plus one actual fetch task,
// the watchdog and its reusable timer. Complete State workspaces, independent
// trust/mapping, provider and Go runtime allocation overhead are additional.
// Each configured subscriber also needs one original root reference slot;
// construction admits all of them before publishing this shared namespace.
func (r *NamespaceRules) LiveNamespaceCharge(subscriberSlots uint32) (resourcev4.Vector, error) {
	bytes, err := r.LiveNamespaceBackingBytes(subscriberSlots)
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(subscriberSlots) + 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 1}, err
}

func NewLiveNamespace(ctx context.Context, clock *timev4.Clock, trust NamespaceTrust, bootstrap *NamespaceState, spare *RevocationWorkspace, fetchDuration uint64, attemptLimit uint8, subscriberSlots uint32, reservation resourcev4.Reference) (*LiveNamespace, error) {
	return newLiveNamespace(ctx, clock, trust, bootstrap, spare, fetchDuration, attemptLimit, subscriberSlots, reservation, false)
}

func newLiveNamespace(ctx context.Context, clock *timev4.Clock, trust NamespaceTrust, bootstrap *NamespaceState, spare *RevocationWorkspace, fetchDuration uint64, attemptLimit uint8, subscriberSlots uint32, reservation resourcev4.Reference, recovering bool) (_ *LiveNamespace, err error) {
	if ctx == nil || clock == nil || trust == nil || bootstrap == nil || spare == nil || bootstrap.workspace == spare || bootstrap.workspace.rules != spare.rules || fetchDuration == 0 || attemptLimit == 0 {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	cost, err := spare.rules.LiveNamespaceCharge(subscriberSlots)
	if err != nil {
		return nil, CBORFailure("configuration_capacity")
	}
	if err := reservation.CheckSameEnvironment(bootstrap.workspace.reservation); err != nil {
		return nil, err
	}
	if err := reservation.CheckSameEnvironment(spare.reservation); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			owned.Release()
		}
	}()
	// Opaque context methods run only after original admission, outside both
	// State workspace gates. Abnormal exits return the unpublished owner.
	parentDone := ctx.Done()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now, err := clock.Sample()
	if err != nil {
		return nil, err
	}
	w := bootstrap.workspace
	if !w.mu.TryLock() {
		return nil, CBORFailure("decoder_busy")
	}
	defer w.mu.Unlock()
	if !spare.mu.TryLock() {
		return nil, CBORFailure("decoder_busy")
	}
	defer spare.mu.Unlock()
	if w.current != bootstrap || w.owner != nil || spare.current != nil || spare.owner != nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := owned.CheckSameEnvironment(w.reservation); err != nil {
		return nil, err
	}
	if err := owned.CheckSameEnvironment(spare.reservation); err != nil {
		return nil, err
	}
	n := &LiveNamespace{clock: clock, trust: trust, rules: spare.rules, active: bootstrap, spare: spare, observed: bootstrap.head, fetchDuration: fetchDuration, attemptLimit: attemptLimit, reservation: owned, initializing: recovering, parentDone: parentDone}
	if !recovering {
		if err := n.checkHeadAt(bootstrap.head, now); err != nil {
			return nil, err
		}
	}
	if err := n.checkStateHistoryAt(bootstrap, now); err != nil {
		return nil, err
	}
	n.subscribers = make([]namespaceSubscriber, int(subscriberSlots))
	defer func() {
		if !adopted {
			for _, slot := range n.subscribers {
				slot.reservation.Release()
			}
		}
	}()
	for i := range n.subscribers {
		n.subscribers[i].reservation, err = owned.Borrow()
		if err != nil {
			return nil, err
		}
	}
	select {
	case <-parentDone:
		return nil, context.Canceled
	default:
	}
	n.taskContext.Context, n.cancel = context.WithCancelCause(context.Background())
	n.taskContext.parent = ctx
	n.ctx = &n.taskContext
	n.wake, n.done = make(chan struct{}, 1), make(chan struct{})
	n.input = make([]byte, int(n.rules.stateBytes))
	n.retired = make([][16]byte, 0, int(n.rules.limits["max_revoked_issuers"]))
	w.owner, spare.owner = n, n
	adopted = true
	if !recovering {
		go n.watch()
	}
	return n, nil
}

func (n *LiveNamespace) checkAvailable() error {
	if n.terminal == nil {
		select {
		case <-n.parentDone:
			n.closeLocked(context.Canceled)
		default:
		}
	}
	if n.terminal == nil {
		n.terminal = context.Cause(n.ctx)
	}
	if n.terminal == nil {
		n.terminal = n.reservation.CheckSameEnvironment(n.active.workspace.reservation)
	}
	if n.terminal == nil {
		n.terminal = n.spare.reservation.Check()
	}
	if n.terminal != nil {
		n.reservation.Seal()
		n.cancel(n.terminal)
		return n.terminal
	}
	return nil
}

func (n *LiveNamespace) selectPin(h *NamespaceHead, now timev4.Sample) error {
	if n.pin != nil || h.sequence <= max(n.active.head.sequence, n.settledSequence) {
		return nil
	}
	end, err := namespaceAdd(now.LowerMS, n.fetchDuration)
	if err != nil {
		return err
	}
	end = min(end, h.next, h.signerEnd, h.trustEnd)
	deadline, err := timev4.NewDeadlineAt(n.clock, now, end)
	if err != nil {
		return err
	}
	window, err := timev4.NewWindowAt(n.clock, now.Mark, n.fetchDuration)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancelCause(n.ctx)
	n.pin = &NamespacePin{owner: n, head: h, deadline: deadline, window: window, ctx: ctx, cancel: cancel}
	n.continuityChanged()
	n.signal()
	return nil
}

// Observe advances only the signed Head high-water mark and known floors. The
// original active pair remains usable under its own time and current denials.
func (n *LiveNamespace) Observe(h *NamespaceHead) (err error) {
	now, err := n.sampleCurrent()
	if err != nil {
		return err
	}
	n.mu.Lock()
	if err = n.continuityAvailable(); err != nil {
		n.mu.Unlock()
		return err
	}
	defer n.unlockContinuity(&err)
	err = n.checkAvailable()
	if err != nil {
		return err
	}
	if h == nil || h.rules != n.rules || h.schema != n.observed.schema {
		return CBORFailure("revocation_namespace_binding")
	}
	if err := h.follows(n.observed); err != nil {
		return err
	}
	err = n.checkHeadAt(h, now)
	if errors.Is(err, timev4.ErrPending) {
		// Complete eligible observed work takes precedence over a new pending
		// input. Extra pending Heads acquire no second retained owner.
		if n.pin == nil {
			selected := h
			if n.observed.sequence > n.active.head.sequence {
				selected = n.observed
			}
			if pinErr := n.selectPin(selected, now); pinErr != nil {
				return pinErr
			}
		}
		return err
	}
	if err != nil {
		return err
	}
	if h.sequence > n.observed.sequence {
		n.observed = h
		n.continuityChanged()
		n.notifySubscribers()
	}
	return n.selectPin(n.observed, now)
}

func (p *NamespacePin) check(now timev4.Sample) error {
	n := p.owner
	if n.pin != p || p.terminal != nil {
		return CBORFailure("revocation_candidate_owner")
	}
	if err := context.Cause(p.ctx); err != nil {
		return err
	}
	if err := p.window.CheckAt(now.Mark); err != nil {
		return err
	}
	if err := p.deadline.CheckAt(now); err != nil {
		return err
	}
	return n.checkHeadAt(p.head, now)
}

func (n *LiveNamespace) finishPin(p *NamespacePin, reason error) {
	if p.terminal == nil {
		n.continuityChanged()
	}
	p.terminal = reason
	p.cancel(reason)
	n.settledSequence = max(n.settledSequence, p.head.sequence)
	if !p.running && n.pin == p {
		n.pin = nil
	}
	n.signal()
}

// Pending exposes only the original local task handle. Environment scheduling
// may poll it without changing the selected content or work deadline.
func (n *LiveNamespace) Pending() (out *NamespacePin, err error) {
	now, err := n.sampleCurrent()
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	if err = n.continuityAvailable(); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	defer n.unlockContinuity(&err)
	err = n.checkAvailable()
	if err != nil {
		n.cleanup()
		return nil, err
	}
	if p := n.pin; p != nil {
		if err := p.check(now); err != nil && !errors.Is(err, timev4.ErrPending) {
			n.finishPin(p, err)
			return nil, err
		}
	}
	return n.pin, nil
}

// Fetch executes at most one actual provider/decoder task at a time. A failed
// read may retry only the same original pin within its finite attempt/window
// bounds. Successful decoding switches the complete pair under the live gate;
// a newer observed Head never cancels this selected work or lends its time.
func (p *NamespacePin) Fetch(fetch NamespaceFetch) error {
	return p.fetchOriginal(fetch, false, nil)
}

func (p *NamespacePin) prepareFetch(fetch NamespaceFetch) (spare *RevocationWorkspace, active *NamespaceState, err error) {
	n := p.owner
	now, err := n.sampleCurrent()
	if err != nil {
		return nil, nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	prepared, claimed := false, false
	defer func() {
		if !prepared && claimed {
			p.running = false
			n.cleanup()
		}
	}()
	if err = n.continuityAvailable(); err != nil {
		return nil, nil, err
	}
	err = n.checkAvailable()
	if err == nil {
		err = p.check(now)
	}
	if err != nil {
		if n.pin == p && !errors.Is(err, timev4.ErrPending) {
			n.finishPin(p, err)
		}
		if e := n.persistContinuity(); e != nil {
			err = errors.Join(err, e)
		}
		return nil, nil, err
	}
	if fetch == nil || p.running || p.attempts == n.attemptLimit {
		return nil, nil, CBORFailure("revocation_fetch_capacity")
	}
	if p.head.sequence > n.observed.sequence {
		if err := p.head.follows(n.observed); err != nil {
			n.finishPin(p, err)
			if e := n.persistContinuity(); e != nil {
				err = errors.Join(err, e)
			}
			return nil, nil, err
		}
		n.observed = p.head
		n.continuityChanged()
		n.notifySubscribers()
	}
	err = CBORFailure("revocation_continuity_provider")
	claimed = true
	p.running = true
	p.attempts++
	n.continuityChanged()
	if err = n.persistContinuity(); err != nil {
		p.running = false
		n.cleanup()
		return nil, nil, err
	}
	now, err = n.sampleAfterContinuityLocked()
	if err == nil {
		err = n.continuityAvailable()
	}
	if err == nil {
		err = n.checkAvailable()
	}
	if err == nil {
		err = p.check(now)
	}
	if err != nil {
		n.finishPin(p, err)
		if e := n.persistContinuity(); e != nil {
			err = errors.Join(err, e)
		}
		return nil, nil, err
	}
	prepared = true
	return n.spare, n.active, nil
}

func (p *NamespacePin) fetchOriginal(fetch NamespaceFetch, cached bool, guard func(timev4.Sample) error) (err error) {
	n := p.owner
	spare, active, err := p.prepareFetch(fetch)
	if err != nil {
		return err
	}
	returned := false
	defer func() {
		abnormal := recover() != nil || !returned
		// The original provider stack (including its defers) has exited here.
		// A canceled or abnormal callback cannot leave an immortal work slot.
		n.lockAfterContinuity()
		defer n.unlockContinuity(&err)
		clear(n.input)
		clear(n.retired)
		n.retired = n.retired[:0]
		p.running = false
		if abnormal {
			err = CBORFailure("revocation_fetch_provider")
			n.finishPin(p, err)
		} else if n.pin == p && p.terminal != nil {
			n.pin = nil
		}
		n.cleanup()
		n.signal()
	}()
	err = p.fetch(fetch, spare, active, cached, guard)
	returned = true
	return err
}

func (p *NamespacePin) fetch(fetch NamespaceFetch, spare *RevocationWorkspace, active *NamespaceState, cached bool, guard func(timev4.Sample) error) (err error) {
	n := p.owner
	var size int
	var fetchErr error
	if cached && p.head.stateDigest == active.head.stateDigest && p.head.stateBytes == active.head.stateBytes {
		// Reuse only the complete authenticated bytes. Binding the spare still
		// validates this new original Head and all monotonic/history rules.
		active.workspace.mu.Lock()
		size = copy(n.input, active.document.Bytes())
		active.workspace.mu.Unlock()
	} else {
		size, fetchErr = fetch(p.ctx, NamespaceContent{Digest: p.head.stateDigest, EncodedBytes: p.head.stateBytes}, n.input[:p.head.stateBytes:p.head.stateBytes])
	}
	postRead, err := n.sampleCurrent()
	n.mu.Lock()
	if err == nil {
		err = n.checkAvailable()
	}
	if err == nil {
		err = p.check(postRead)
	}
	n.mu.Unlock()
	var candidate *NamespaceState
	if fetchErr == nil && err == nil {
		if size < 0 || uint64(size) != p.head.stateBytes {
			err = CBORFailure("revocation_state_length")
		} else {
			candidate, err = spare.bind(n, p.head, n.input[:size:size])
		}
	}
	clear(n.input)
	if candidate != nil {
		// No second installer can replace active while this pin owns the only
		// real work slot. Close retains both workspaces until this task exits.
		active.workspace.mu.Lock()
		issuers := active.document.Root().Named("RevocationState", "revoked_issuers")
		for i := 0; i < issuers.Len(); i++ {
			key, _ := issuers.Index(i).Named("RevokedIssuerEntry", "issuer_key_id").ByteString()
			if n.trust.RetiredIssuer([16]byte(key)) {
				n.retired = append(n.retired, [16]byte(key))
			}
		}
		active.workspace.mu.Unlock()
		err = active.CheckSuccessor(candidate, n.retired)
		clear(n.retired)
		n.retired = n.retired[:0]
	}

	// Join any previous commit before publishing this already owned result.
	n.mu.Lock()
	defer n.unlockContinuity(&err)
	now, currentErr := n.sampleAfterContinuityLocked()
	if currentErr == nil {
		currentErr = n.checkAvailable()
	}
	if currentErr == nil {
		currentErr = p.check(now)
	}
	if currentErr == nil && guard != nil {
		currentErr = guard(now)
	}
	if currentErr != nil {
		err = currentErr
	}
	if err == nil && fetchErr == nil && candidate != nil {
		err = n.checkStateHistoryAt(candidate, now)
	}
	if err != nil || fetchErr != nil {
		if candidate != nil {
			candidate.release(n)
		}
		if err != nil || p.attempts == n.attemptLimit {
			reason := err
			if reason == nil {
				reason = fetchErr
			}
			n.finishPin(p, reason)
		}
		n.cleanup()
		if err != nil {
			return err
		}
		return fetchErr
	}
	n.active, n.spare = candidate, active.workspace
	n.continuityChanged()
	n.notifySubscribers()
	active.release(n)
	n.finishPin(p, CBORFailure("revocation_candidate_complete"))
	// The next scheduler turn selects the latest observed, skipping obsolete
	// intermediate objects without taking another download in this task.
	return nil
}

// Advance selects the newest already accepted observed Head after the previous
// original task has actually returned. It does not poll the network or retry.
func (n *LiveNamespace) Advance() (out *NamespacePin, err error) {
	now, err := n.sampleCurrent()
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	if err = n.continuityAvailable(); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	defer n.unlockContinuity(&err)
	err = n.checkAvailable()
	if err != nil {
		return nil, err
	}
	if err := n.checkHeadAt(n.observed, now); err != nil {
		return nil, err
	}
	if err := n.selectPin(n.observed, now); err != nil {
		return nil, err
	}
	return n.pin, nil
}

// CheckCredential uses the active complete pair and the independent observed
// rejection frontier together. A short subscriber staleness requirement does
// not expire this shared owner or interrupt another subscriber's chosen fetch.
func (n *LiveNamespace) CheckCredential(credential *SignedMap, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64) (facts CredentialStateFacts, deadline uint64, err error) {
	detached, err := credential.DetachCredential()
	if err != nil {
		return facts, 0, err
	}
	return n.CheckDetachedCredential(detached, permission, staleness, signerLifetime, hardEnd)
}

func (n *LiveNamespace) sampleCurrent() (timev4.Sample, error) {
	n.mu.Lock()
	if err := n.checkAvailable(); err != nil {
		n.mu.Unlock()
		return timev4.Sample{}, err
	}
	if n.sampling == math.MaxUint32 {
		n.mu.Unlock()
		return timev4.Sample{}, CBORFailure("configuration_capacity")
	}
	n.sampling++
	clock, parent := n.clock, n.taskContext.parent
	n.mu.Unlock()
	returned := false
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.sampling--
		if !returned {
			n.closeLocked(CBORFailure("revocation_namespace_context"))
		}
		n.cleanup()
	}()
	if err := parent.Err(); err != nil {
		n.Close(err)
		returned = true
		return timev4.Sample{}, err
	}
	sample, err := clock.Sample()
	returned = true
	return sample, err
}

func (n *LiveNamespace) CheckDetachedCredential(credential *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64) (facts CredentialStateFacts, deadline uint64, err error) {
	now, err := n.sampleCurrent()
	if err != nil {
		return facts, 0, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.checkCredentialAt(credential, permission, staleness, signerLifetime, hardEnd, now)
}

func (n *LiveNamespace) checkBoundCredential(credential *Credential, permission IssuerPermission, policy *CredentialPolicy, requirement CredentialRequirements, hardEnd uint64) (uint64, error) {
	now, err := n.sampleCurrent()
	if err != nil {
		return 0, err
	}
	return n.checkBoundCredentialAt(credential, permission, policy, requirement, hardEnd, now)
}

func (n *LiveNamespace) checkBoundCredentialAt(credential *Credential, permission IssuerPermission, policy *CredentialPolicy, requirement CredentialRequirements, hardEnd uint64, now timev4.Sample) (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.checkAvailable(); err != nil {
		return 0, err
	}
	if current, err := n.clock.RefreshSample(now); err != nil {
		return 0, err
	} else {
		now = current
	}
	if policy == nil || credential == nil || policy.id != credential.facts.PolicyID || policy.revision != credential.facts.PolicyRevision {
		return 0, CBORFailure("credential_policy_reference")
	}
	if err := n.rules.CheckPublication(requirement); err != nil {
		return 0, err
	}
	if err := n.checkPolicyAt(policy, now); err != nil {
		return 0, err
	}
	_, deadline, err := n.checkCredentialAt(credential, permission, requirement.StalenessMS, requirement.SignerLifetimeMS, hardEnd, now)
	return deadline, err
}

func (n *LiveNamespace) checkCredentialAt(credential *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64, now timev4.Sample) (facts CredentialStateFacts, deadline uint64, err error) {
	if err = n.continuityAvailable(); err != nil {
		return facts, 0, err
	}
	if err = n.checkAvailable(); err != nil {
		return facts, 0, err
	}
	if now, err = n.clock.RefreshSample(now); err != nil {
		return facts, 0, err
	}
	if err := credential.checkPermission(permission); err != nil {
		return facts, 0, err
	}
	if err := n.checkHeadAt(n.active.head, now); err != nil {
		return facts, 0, err
	}
	if err := n.checkIssuerAt(permission, credential.scope, now); err != nil {
		return facts, 0, err
	}
	facts, err = n.active.CheckDetachedCredential(credential, permission, now.Interval)
	if err != nil {
		return facts, 0, err
	}
	if facts.Cohort < n.observed.floors[facts.class] {
		return facts, 0, CBORFailure("revocation_floor_rejected")
	}
	deadline, err = n.active.head.Deadline(staleness, signerLifetime, min(hardEnd, facts.HardDeadlineMS), now.Interval)
	return facts, deadline, err
}

// CheckActivation composes the exact original parent, fixed logical authority,
// current independent activation permission and shared namespace denials. It
// reports the original Session authorization deadline; admission additionally
// uses ActivationAuthority.CheckAdmission at its original publication gate.
func (n *LiveNamespace) CheckActivation(a *ActivationAuthority, artifact *SignedMap, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64) (uint64, error) {
	detached, err := artifact.DetachCredential()
	if err != nil {
		return 0, err
	}
	return n.CheckDetachedActivation(a, detached, permission, staleness, signerLifetime, hardEnd)
}

func (n *LiveNamespace) CheckDetachedActivation(a *ActivationAuthority, artifact *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64) (uint64, error) {
	return n.checkDetachedActivation(a, artifact, permission, staleness, signerLifetime, hardEnd, false)
}

func (n *LiveNamespace) checkDetachedActivation(a *ActivationAuthority, artifact *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64, admission bool) (uint64, error) {
	now, err := n.sampleCurrent()
	if err != nil {
		return 0, err
	}
	return n.checkDetachedActivationAt(a, artifact, permission, staleness, signerLifetime, hardEnd, admission, now)
}

func (n *LiveNamespace) checkDetachedActivationAt(a *ActivationAuthority, artifact *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64, admission bool, now timev4.Sample) (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var err error
	now, err = n.clock.RefreshSample(now)
	if err != nil {
		return 0, err
	}
	if err := n.checkAvailable(); err != nil {
		return 0, err
	}
	if a == nil || a.rules != n.rules || permission.Schema != "Artifact" {
		return 0, CBORFailure("activation_authority_owner")
	}
	parent, deadline, err := n.checkCredentialAt(artifact, permission, staleness, signerLifetime, hardEnd, now)
	if err != nil {
		return 0, err
	}
	if parent.Digest != a.binding.artifactDigest {
		return 0, CBORFailure("activation_parent_binding")
	}
	if err := n.checkActivationTrustAt(a.trust, now); err != nil {
		return 0, err
	}
	if err := n.active.CheckActivation(a, now.Interval); err != nil {
		return 0, err
	}
	if admission {
		if err := artifact.CheckAdmission(now.Interval); err != nil {
			return 0, err
		}
		if err := a.CheckAdmission(now.Interval); err != nil {
			return 0, err
		}
	}
	deadline = min(deadline, a.binding.sessionEnd)
	if !now.ValidBefore(deadline) {
		return 0, timev4.ErrExpired
	}
	return deadline, nil
}

func (n *LiveNamespace) cleanup() {
	if n.terminal == nil || n.cleaned || !n.watcherExited || n.refreshActive || n.sampling != 0 || n.durable != nil && n.durable.busy || n.pin != nil && n.pin.running {
		return
	}
	if n.pin != nil {
		n.finishPin(n.pin, n.terminal)
	}
	// History remains owned until Environment destruction or independently
	// proven retirement. Closing authorization does not turn this into an empty
	// namespace that may be reconstructed from an old cached Head.
	clear(n.input)
	clear(n.retired)
	n.input, n.retired = nil, nil
	n.cleaned = true
	close(n.done)
}

func (n *LiveNamespace) signal() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// NotifyTrust wakes the existing watchdog after an independent current trust
// update. Authorization itself always checks that fence synchronously.
func (n *LiveNamespace) NotifyTrust() {
	n.mu.Lock()
	n.notifySubscribers()
	n.mu.Unlock()
	n.signal()
}

func (n *LiveNamespace) watch() {
	var timer *time.Timer
	returned := false
	defer func() {
		abnormal := recover() != nil || !returned
		if timer != nil {
			timer.Stop()
		}
		n.mu.Lock()
		if abnormal {
			n.closeLocked(CBORFailure("revocation_namespace_context"))
		}
		n.watcherExited = true
		n.cleanup()
		n.mu.Unlock()
	}()
	for {
		now, err := n.sampleCurrent()
		wakeAfter, terminal := n.watchStep(now, err)
		if terminal {
			returned = true
			return
		}
		var tick <-chan time.Time
		if timer != nil {
			timer.Stop()
		}
		if wakeAfter != 0 {
			if timer == nil {
				timer = time.NewTimer(time.Duration(wakeAfter) * time.Millisecond)
			} else {
				timer.Reset(time.Duration(wakeAfter) * time.Millisecond)
			}
			tick = timer.C
		}
		select {
		case <-n.ctx.Done():
		case <-n.parentDone:
		case <-n.wake:
		case <-tick:
		}
	}
}

// Every watchdog turn releases the gate on abnormal trust or continuity
// callbacks before the outer task finalizer seals this original incarnation.
func (n *LiveNamespace) watchStep(now timev4.Sample, err error) (wakeAfter uint64, terminal bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err == nil {
		err = n.checkAvailable()
	}
	if n.terminal != nil {
		n.notifySubscribers()
		if n.pin != nil {
			n.finishPin(n.pin, n.terminal)
		}
		return 0, true
	}
	if p := n.pin; p != nil && p.terminal == nil {
		if err == nil {
			err = p.check(now)
		}
		pending := errors.Is(err, timev4.ErrPending)
		if err == nil || pending {
			remaining, e := p.window.RemainingMSAt(now.Mark)
			if e == nil {
				var absolute uint64
				absolute, e = p.deadline.RemainingMSAt(now)
				remaining = min(remaining, absolute)
			}
			if e != nil {
				err = e
			} else {
				wakeAfter = max(1, min(remaining, 1000))
				if pending {
					wakeAfter = min(wakeAfter, 100)
				}
			}
		}
		if err != nil && !errors.Is(err, timev4.ErrPending) {
			n.finishPin(p, err)
		}
	}
	if !n.initializing && n.durable != nil && !n.durable.busy {
		_ = n.persistContinuity()
	}
	return wakeAfter, n.terminal != nil
}

// Close fences this incarnation immediately. It intentionally keeps exact
// verification history; retained history is separate from actual task cleanup.
func (n *LiveNamespace) Close(reason error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closeLocked(reason)
	n.cleanup()
}

func (n *LiveNamespace) closeLocked(reason error) {
	if n.terminal == nil {
		if reason == nil {
			reason = context.Canceled
		}
		n.terminal = reason
		n.reservation.Seal()
		n.notifySubscribers()
		n.cancel(reason)
		if n.pin != nil {
			n.finishPin(n.pin, reason)
		}
	}
}

// DestroyEnvironment releases retained verification history only after the
// original Environment budget is permanently closed, all actual tasks have
// exited and all subscribers have returned their references. Ordinary Close
// is not retirement evidence and cannot turn a live Environment's namespace
// into an empty cache. Same-Environment history retirement is a separate gate.
func (n *LiveNamespace) DestroyEnvironment() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.destroyed {
		return nil
	}
	if !n.cleaned || n.refresh != nil || !n.reservation.EnvironmentClosed() {
		return CBORFailure("revocation_namespace_owner")
	}
	for _, slot := range n.subscribers {
		if slot.wake != nil {
			return CBORFailure("revocation_namespace_owner")
		}
	}
	for _, slot := range n.subscribers {
		slot.reservation.Release()
	}
	for _, w := range [...]*RevocationWorkspace{n.active.workspace, n.spare} {
		w.mu.Lock()
		w.destroyLocked()
		w.mu.Unlock()
	}
	n.active, n.spare, n.observed, n.pin = nil, nil, nil, nil
	n.subscribers = nil
	if n.durable != nil {
		n.durable.destroy()
		n.durable = nil
	}
	n.trust, n.rules = nil, nil
	n.ctx, n.cancel, n.parentDone = nil, nil, nil
	n.taskContext = namespaceTaskContext{}
	n.destroyed = true
	n.reservation.Release()
	return nil
}

func (n *LiveNamespace) CleanupComplete() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.terminal == nil {
		n.terminal = context.Cause(n.ctx)
	}
	n.cleanup()
	return n.cleaned
}

func (n *LiveNamespace) WaitCleanup(ctx context.Context) error {
	select {
	case <-n.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
