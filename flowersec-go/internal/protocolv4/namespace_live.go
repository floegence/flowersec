package protocolv4

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
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

// LiveNamespace implements the online_bootstrap live atomic continuity owner.
// Construction requires the independent current-authority nonce bootstrap's
// complete authenticated pair; cached Heads alone must never call this API.
// It cannot restore an old Session, change generation, forget history on cache
// eviction, or supply the independent trust/authority bootstrap implementation.
type LiveNamespace struct {
	mu              sync.Mutex
	ctx             context.Context
	cancel          context.CancelCauseFunc
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
func (r *NamespaceRules) LiveNamespaceCharge(subscriberSlots uint32) (resourcev4.Vector, error) {
	bytes, err := r.LiveNamespaceBackingBytes(subscriberSlots)
	return resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: uint64(subscriberSlots) + 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 2, resourcev4.Timers: 1}, err
}

func NewLiveNamespace(ctx context.Context, clock *timev4.Clock, trust NamespaceTrust, bootstrap *NamespaceState, spare *RevocationWorkspace, fetchDuration uint64, attemptLimit uint8, subscriberSlots uint32, reservation resourcev4.Reference) (_ *LiveNamespace, err error) {
	if ctx == nil || clock == nil || trust == nil || bootstrap == nil || spare == nil || bootstrap.workspace == spare || bootstrap.workspace.rules != spare.rules || fetchDuration == 0 || attemptLimit == 0 {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	cost, err := spare.rules.LiveNamespaceCharge(subscriberSlots)
	if err != nil {
		return nil, CBORFailure("configuration_capacity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
	defer func() {
		if err != nil {
			owned.Release()
		}
	}()
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
	n := &LiveNamespace{clock: clock, trust: trust, rules: spare.rules, active: bootstrap, spare: spare, observed: bootstrap.head, fetchDuration: fetchDuration, attemptLimit: attemptLimit, reservation: owned}
	now, err := clock.Sample()
	if err != nil {
		return nil, err
	}
	if err := n.checkHead(bootstrap.head, now.Interval); err != nil {
		return nil, err
	}
	if err := trust.StateHistory(bootstrap); err != nil {
		return nil, err
	}
	n.ctx, n.cancel = context.WithCancelCause(ctx)
	n.wake, n.done = make(chan struct{}, 1), make(chan struct{})
	n.input = make([]byte, int(n.rules.stateBytes))
	n.retired = make([][16]byte, 0, int(n.rules.limits["max_revoked_issuers"]))
	n.subscribers = make([]namespaceSubscriber, int(subscriberSlots))
	w.owner, spare.owner = n, n
	go n.watch()
	return n, nil
}

func (n *LiveNamespace) checkHead(h *NamespaceHead, now timev4.Interval) error {
	if h == nil || h.rules != n.rules || h.generation != n.observed.generation {
		return CBORFailure("revocation_namespace_binding")
	}
	if err := n.trust.Head(NamespaceHeadTrust{Tenant: n.rules.tenant, Authority: n.rules.authority, Capacity: n.rules.capacityDigest, Delegation: h.delegationDigest, Signer: h.signerID, Generation: h.generation, TrustIssuedMS: h.trustIssued, TrustNotAfterMS: h.trustEnd}); err != nil {
		return err
	}
	return h.CheckTime(now)
}

func (n *LiveNamespace) check() (timev4.Sample, error) {
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
		return timev4.Sample{}, n.terminal
	}
	return n.clock.Sample()
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
	deadline, err := timev4.NewDeadline(n.clock, end)
	if err != nil {
		return err
	}
	window, err := timev4.NewWindowAt(n.clock, now.Mark, n.fetchDuration)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancelCause(n.ctx)
	n.pin = &NamespacePin{owner: n, head: h, deadline: deadline, window: window, ctx: ctx, cancel: cancel}
	n.signal()
	return nil
}

// Observe advances only the signed Head high-water mark and known floors. The
// original active pair remains usable under its own time and current denials.
func (n *LiveNamespace) Observe(h *NamespaceHead) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	now, err := n.check()
	if err != nil {
		return err
	}
	if h == nil || h.rules != n.rules || h.schema != n.observed.schema {
		return CBORFailure("revocation_namespace_binding")
	}
	if err := h.follows(n.observed); err != nil {
		return err
	}
	err = n.checkHead(h, now.Interval)
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
	return n.checkHead(p.head, now.Interval)
}

func (n *LiveNamespace) finishPin(p *NamespacePin, reason error) {
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
func (n *LiveNamespace) Pending() (*NamespacePin, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now, err := n.check()
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

func (p *NamespacePin) fetchOriginal(fetch NamespaceFetch, cached bool, guard func() error) (err error) {
	n := p.owner
	n.mu.Lock()
	now, err := n.check()
	if err == nil {
		err = p.check(now)
	}
	if err != nil {
		if n.pin == p && !errors.Is(err, timev4.ErrPending) {
			n.finishPin(p, err)
		}
		n.mu.Unlock()
		return err
	}
	if fetch == nil || p.running || p.attempts == n.attemptLimit {
		n.mu.Unlock()
		return CBORFailure("revocation_fetch_capacity")
	}
	if p.head.sequence > n.observed.sequence {
		if err := p.head.follows(n.observed); err != nil {
			n.finishPin(p, err)
			n.mu.Unlock()
			return err
		}
		n.observed = p.head
		n.notifySubscribers()
	}
	p.running = true
	p.attempts++
	spare, active := n.spare, n.active
	n.mu.Unlock()
	returned := false
	defer func() {
		abnormal := recover() != nil || !returned
		// The original provider stack (including its defers) has exited here.
		// A canceled or abnormal callback cannot leave an immortal work slot.
		n.mu.Lock()
		defer n.mu.Unlock()
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

func (p *NamespacePin) fetch(fetch NamespaceFetch, spare *RevocationWorkspace, active *NamespaceState, cached bool, guard func() error) error {
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
	n.mu.Lock()
	postRead, err := n.check()
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

	n.mu.Lock()
	defer n.mu.Unlock()
	now, currentErr := n.check()
	if currentErr == nil {
		currentErr = p.check(now)
	}
	if currentErr == nil && guard != nil {
		currentErr = guard()
	}
	if currentErr != nil {
		err = currentErr
	}
	if err == nil && fetchErr == nil && candidate != nil {
		err = n.trust.StateHistory(candidate)
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
	n.notifySubscribers()
	active.release(n)
	n.finishPin(p, CBORFailure("revocation_candidate_complete"))
	// The next scheduler turn selects the latest observed, skipping obsolete
	// intermediate objects without taking another download in this task.
	return nil
}

// Advance selects the newest already accepted observed Head after the previous
// original task has actually returned. It does not poll the network or retry.
func (n *LiveNamespace) Advance() (*NamespacePin, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now, err := n.check()
	if err != nil {
		return nil, err
	}
	if err := n.checkHead(n.observed, now.Interval); err != nil {
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

func (n *LiveNamespace) CheckDetachedCredential(credential *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64) (facts CredentialStateFacts, deadline uint64, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.checkCredential(credential, permission, staleness, signerLifetime, hardEnd)
}

func (n *LiveNamespace) checkBoundCredential(credential *Credential, permission IssuerPermission, policy *CredentialPolicy, requirement CredentialRequirements, hardEnd uint64) (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if policy == nil || credential == nil || policy.id != credential.facts.PolicyID || policy.revision != credential.facts.PolicyRevision {
		return 0, CBORFailure("credential_policy_reference")
	}
	if err := n.rules.CheckPublication(requirement); err != nil {
		return 0, err
	}
	if err := n.trust.Policy(policy); err != nil {
		return 0, err
	}
	_, deadline, err := n.checkCredential(credential, permission, requirement.StalenessMS, requirement.SignerLifetimeMS, hardEnd)
	return deadline, err
}

func (n *LiveNamespace) checkCredential(credential *Credential, permission IssuerPermission, staleness, signerLifetime, hardEnd uint64) (facts CredentialStateFacts, deadline uint64, err error) {
	if err := credential.checkPermission(permission); err != nil {
		return facts, 0, err
	}
	now, err := n.check()
	if err != nil {
		return facts, 0, err
	}
	if err := n.checkHead(n.active.head, now.Interval); err != nil {
		return facts, 0, err
	}
	if err := n.trust.Issuer(permission, credential.scope); err != nil {
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
	n.mu.Lock()
	defer n.mu.Unlock()
	if a == nil || a.rules != n.rules || permission.Schema != "Artifact" {
		return 0, CBORFailure("activation_authority_owner")
	}
	parent, deadline, err := n.checkCredential(artifact, permission, staleness, signerLifetime, hardEnd)
	if err != nil {
		return 0, err
	}
	if parent.Digest != a.binding.artifactDigest {
		return 0, CBORFailure("activation_parent_binding")
	}
	if err := n.trust.Activation(a.trust); err != nil {
		return 0, err
	}
	now, err := n.check()
	if err != nil {
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
	if n.terminal == nil || n.cleaned || !n.watcherExited || n.refreshActive || n.pin != nil && n.pin.running {
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
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		n.mu.Lock()
		n.watcherExited = true
		n.cleanup()
		n.mu.Unlock()
	}()
	for {
		n.mu.Lock()
		now, err := n.check()
		if n.terminal != nil {
			n.notifySubscribers()
			if n.pin != nil {
				n.finishPin(n.pin, n.terminal)
			}
			n.mu.Unlock()
			return
		}
		var wakeAfter uint64
		if p := n.pin; p != nil && p.terminal == nil {
			if err == nil {
				err = p.check(now)
			}
			pending := errors.Is(err, timev4.ErrPending)
			if err == nil || pending {
				remaining, e := p.window.RemainingMS()
				if e == nil {
					var absolute uint64
					absolute, e = p.deadline.RemainingMS()
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
		n.mu.Unlock()
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
		case <-n.wake:
		case <-tick:
		}
	}
}

// Close fences this incarnation immediately. It intentionally keeps exact
// verification history; retained history is separate from actual task cleanup.
func (n *LiveNamespace) Close(reason error) {
	n.mu.Lock()
	defer n.mu.Unlock()
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
	n.cleanup()
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
	for _, w := range [...]*RevocationWorkspace{n.active.workspace, n.spare} {
		w.mu.Lock()
		w.destroyLocked()
		w.mu.Unlock()
	}
	n.active, n.spare, n.observed, n.pin = nil, nil, nil, nil
	n.subscribers = nil
	n.trust, n.rules = nil, nil
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
