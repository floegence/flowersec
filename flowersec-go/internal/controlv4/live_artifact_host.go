package controlv4

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type SQLiteLiveIdentity = ledgerv4.SQLiteIdentity

// LiveArtifactHost connects original Artifact issuance to live authorization.
// Its bounded volatile material cache is not a spend ledger. Process loss drops
// undispatched material and never reconstructs signing or server dispatch from
// durable history. Existing SQLite issuance/spend obligations remain unchanged.
type LiveArtifactHost struct {
	mu                                          sync.Mutex
	template                                    liveArtifactTemplate
	reservation, shared                         resourcev4.Reference
	slots                                       []liveArtifactSlot
	done                                        chan struct{}
	closed, cleaned, collecting, collectPending bool
	operations                                  uint32
}
type liveArtifactSlot struct {
	generation                                                uint64
	request                                                   [32]byte
	facts                                                     protocolv4.ArtifactIssueFacts
	deadline                                                  *timev4.Deadline
	codec                                                     *protocolv4.SignedMapCodec
	artifact                                                  *protocolv4.SignedMap
	credential                                                *protocolv4.Credential
	planWork                                                  *resourcev4.ProtectedReservation
	plan                                                      *protocolv4.LiveActivationPlan
	fields                                                    protocolv4.LiveActivationFields
	query                                                     sessionv4.LiveAuthorizationRequest
	server                                                    LiveArtifactServerRegistration
	serverAllow                                               LiveServerAllowConfig
	projection                                                []byte
	issuing, working, access, ready, frozen, failed, retiring bool
	policyStarted, constructionStarted                        bool
}
type retainedArtifactIssue struct {
	host       *LiveArtifactHost
	index      int
	generation uint64
}

// Charges returns host storage and one protected plan charge PER material slot.
// Constructors require all MaxArtifacts original plan reservations up front.
func LiveArtifactHostCharges(c LiveArtifactHostConfig) (host, plan resourcev4.Vector, err error) {
	template, err := liveArtifactTemplateBytes(c)
	if err != nil {
		return host, plan, err
	}
	tunnel := false
	for _, entry := range c.Tunnels {
		tunnel = tunnel || entry != nil
	}
	minimum, err := protocolv4.LiveActivationPlanCharge(tunnel)
	if err != nil {
		return host, plan, err
	}
	plan, err = resourcev4.ProtectedCharge(minimum)
	if err != nil {
		return host, plan, err
	}
	codec, err := protocolv4.SignedMapBackingBytes("Artifact", 65536, 16384)
	if err != nil {
		return host, plan, err
	}
	credential, err := protocolv4.CredentialBackingBytes("Artifact")
	if err != nil {
		return host, plan, err
	}
	proof, err := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return host, plan, err
	}
	closure, err := protocolv4.EndpointCredentialsBackingBytes()
	if err != nil {
		return host, plan, err
	}
	slot := uint64(unsafe.Sizeof(liveArtifactSlot{})) + uint64(unsafe.Sizeof(retainedArtifactIssue{})) + uint64(unsafe.Sizeof(retainedLiveAccess{})) + codec + 2*credential + uint64(proof) + 2*uint64(unsafe.Sizeof(timev4.Deadline{})) + uint64(unsafe.Sizeof(protocolv4.LiveGrantPreparation{}))*2 + protocolv4.MaxArtifactIssueNamespaces*1024 + 4096 + 2*closure + uint64(unsafe.Sizeof(LiveArtifactServerMaterial{}))
	host, err = (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(LiveArtifactHost{})) + template + uint64(c.MaxArtifacts)*slot, resourcev4.Items: uint64(c.MaxArtifacts) + 1, resourcev4.WorkSlots: uint64(c.MaxArtifacts) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	return
}

func NewLiveArtifactHost(c LiveArtifactHostConfig, reservation resourcev4.Reference, plans []resourcev4.Reference, dependencies resourcev4.Reference) (_ *LiveArtifactHost, err error) {
	cost, _, err := LiveArtifactHostCharges(c)
	if err != nil {
		return nil, err
	}
	if len(plans) != int(c.MaxArtifacts) {
		return nil, resourcev4.ErrConfiguration
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	for i, ref := range plans {
		if err = reservation.CheckSameEnvironment(ref); err != nil {
			return nil, err
		}
		if ref == reservation || ref == dependencies {
			return nil, resourcev4.ErrOwner
		}
		for _, prior := range plans[:i] {
			if prior == ref {
				return nil, resourcev4.ErrOwner
			}
		}
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	h := &LiveArtifactHost{reservation: owned, done: make(chan struct{})}
	adopted := false
	defer func() {
		if !adopted {
			h.Close()
		}
	}()
	h.shared, err = dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	if err = h.template.initialize(c, owned); err != nil {
		return nil, err
	}
	h.slots = make([]liveArtifactSlot, c.MaxArtifacts)
	tunnel := false
	for _, entry := range c.Tunnels {
		tunnel = tunnel || entry != nil
	}
	minimum, _ := protocolv4.LiveActivationPlanCharge(tunnel)
	proof, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	for i := range h.slots {
		s := &h.slots[i]
		s.planWork, err = resourcev4.NewProtectedReservation(plans[i], minimum)
		if err != nil {
			return nil, err
		}
		s.codec, err = protocolv4.NewSignedMapCodec("Artifact", 65536, 16384)
		if err != nil {
			return nil, err
		}
		s.projection = make([]byte, proof)
	}
	adopted = true
	return h, nil
}

func (h *LiveArtifactHost) checkLocked() error {
	if h.closed {
		return resourcev4.ErrClosed
	}
	if err := h.reservation.Check(); err != nil {
		return err
	}
	return h.shared.Check()
}
func cloneArtifactFacts(f protocolv4.ArtifactIssueFacts) protocolv4.ArtifactIssueFacts {
	for _, s := range []*string{&f.Scope.Schema, &f.Scope.Tenant, &f.Scope.Authority, &f.Scope.Audience, &f.Scope.Profile, &f.Scope.Subject, &f.Scope.Service, &f.Scope.ParentAuthority, &f.RevocationPolicyID} {
		*s = strings.Clone(*s)
	}
	for i := range f.Namespaces {
		f.Namespaces[i].Tenant = strings.Clone(f.Namespaces[i].Tenant)
		f.Namespaces[i].Authority = strings.Clone(f.Namespaces[i].Authority)
	}
	return f
}

func boundedArtifactFacts(f protocolv4.ArtifactIssueFacts) bool {
	if f.NamespaceCount == 0 || int(f.NamespaceCount) > len(f.Namespaces) {
		return false
	}
	for _, s := range []string{f.Scope.Schema, f.Scope.Tenant, f.Scope.Authority, f.Scope.Audience, f.Scope.Profile, f.Scope.Subject, f.Scope.Service, f.Scope.ParentAuthority, f.RevocationPolicyID} {
		if len(s) > 128 {
			return false
		}
	}
	for i, ref := range f.Namespaces {
		if i >= int(f.NamespaceCount) {
			if ref != (protocolv4.NamespaceReference{}) {
				return false
			}
			continue
		}
		if len(ref.Tenant) == 0 || len(ref.Tenant) > 128 || len(ref.Authority) == 0 || len(ref.Authority) > 128 || ref.Generation == 0 || ref.CapacityDigest == ([32]byte{}) || ref.RoleMask == 0 || ref.RoleMask&^uint64(7) != 0 {
			return false
		}
	}
	return true
}

func (h *LiveArtifactHost) ReserveArtifact(ctx context.Context, q protocolv4.ArtifactIssueRequest, f protocolv4.ArtifactIssueFacts) (_ protocolv4.ArtifactRetentionSlot, err error) {
	if h == nil || ctx == nil || !boundedArtifactFacts(f) {
		return nil, resourcev4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := h.CollectExpired(); err != nil {
		return nil, err
	}
	h.mu.Lock()
	if err := h.checkLocked(); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	c := h.template.config
	if !bytes.Equal(q.Authentication, c.ClientCertificateDigest[:]) || q.RequestID == ([32]byte{}) || f.LeaseID == ([16]byte{}) || f.Scope.Schema != "Artifact" || f.NamespaceCount == 0 || int(f.NamespaceCount) > len(f.Namespaces) || f.InitiationNotAfterMS <= f.Scope.IssuedMS || f.InitiationNotAfterMS > f.Scope.ExpiresMS || f.ClientIdentity != h.template.credentials[0].Facts().Digest || f.ServerIdentity != h.template.credentials[1].Facts().Digest {
		h.mu.Unlock()
		return nil, ledgerv4.ErrDenied
	}
	index := -1
	for i := range h.slots {
		s := &h.slots[i]
		if s.request == q.RequestID || s.request != ([32]byte{}) && s.facts.Scope.Tenant == f.Scope.Tenant && s.facts.Scope.Issuer == f.Scope.Issuer && s.facts.LeaseID == f.LeaseID {
			h.mu.Unlock()
			return nil, ledgerv4.ErrConflict
		}
		if index < 0 && s.request == ([32]byte{}) && !s.retiring && s.generation != ^uint64(0) {
			index = i
		}
	}
	if index < 0 {
		h.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	s := &h.slots[index]
	if err := s.planWork.CheckAvailable(); err != nil {
		h.mu.Unlock()
		return nil, err
	}
	s.generation++
	s.request = q.RequestID
	s.facts = cloneArtifactFacts(f)
	s.issuing, s.working = true, true
	p := &retainedArtifactIssue{h, index, s.generation}
	h.mu.Unlock()
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = sessionv4.ErrEnvironmentTaskExit
		}
		h.mu.Lock()
		s.working = false
		if err != nil {
			s.issuing = false
			s.failed = true
		}
		h.mu.Unlock()
		h.collect(nil)
	}()
	s.deadline, err = timev4.NewDeadline(c.Clock, f.InitiationNotAfterMS)
	if err == nil {
		err = h.checkIssue(ctx, s)
	}
	returned = true
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Each callback executes outside the host gate while the original slot keeps
// all copied input, trust and provider references charged through actual return.
func (h *LiveArtifactHost) checkIssue(ctx context.Context, s *liveArtifactSlot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	err := h.checkLocked()
	h.mu.Unlock()
	if err != nil {
		return err
	}
	if err = h.template.check(); err != nil {
		return err
	}
	if err = s.deadline.Check(); err != nil {
		return err
	}
	if err = liveArtifactCall(func() error {
		return h.template.config.Policy.CheckLiveArtifact(ctx, h.template.config.ClientCertificateDigest, s.facts)
	}); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.checkLocked()
}
func (p *retainedArtifactIssue) begin() (*liveArtifactSlot, error) {
	if p == nil || p.host == nil {
		return nil, resourcev4.ErrOwner
	}
	h := p.host
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.checkLocked(); err != nil {
		return nil, err
	}
	s := &h.slots[p.index]
	if s.generation != p.generation || !s.issuing || s.failed || s.working {
		return nil, resourcev4.ErrOwner
	}
	s.working = true
	return s, nil
}
func (p *retainedArtifactIssue) finish(s *liveArtifactSlot) {
	h := p.host
	h.mu.Lock()
	s.working = false
	h.mu.Unlock()
	h.collect(nil)
}
func (p *retainedArtifactIssue) Check(ctx context.Context) error {
	if ctx == nil {
		return resourcev4.ErrConfiguration
	}
	s, err := p.begin()
	if err != nil {
		return err
	}
	defer p.finish(s)
	return p.host.checkIssue(ctx, s)
}
func (p *retainedArtifactIssue) Publish(ctx context.Context, wire []byte) (err error) {
	if ctx == nil || len(wire) == 0 || len(wire) > 65536 {
		return resourcev4.ErrConfiguration
	}
	s, err := p.begin()
	if err != nil {
		return err
	}
	defer p.finish(s)
	h := p.host
	if s.ready || s.artifact != nil {
		return resourcev4.ErrOwner
	}
	if err = h.checkIssue(ctx, s); err != nil {
		return err
	}
	artifact, err := s.codec.VerifyCredential(wire, h.template.config.Trust[0])
	if err != nil {
		return err
	}
	adopted := false
	defer func() {
		if !adopted {
			artifact.Release()
		}
	}()
	credential, err := artifact.DetachCredential()
	if err != nil {
		return err
	}
	if err = artifact.CheckArtifactIssueFacts(s.facts); err != nil {
		return err
	}
	if err = h.template.validateMaterial(artifact, credential, h.reservation); err != nil {
		return err
	}
	if err = h.checkIssue(ctx, s); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err = h.checkLocked(); err != nil {
		return err
	}
	if !s.issuing || s.generation != p.generation {
		return resourcev4.ErrOwner
	}
	s.artifact, s.credential, s.ready = artifact, credential, true
	adopted = true
	return nil
}
func (p *retainedArtifactIssue) Close() {
	if p == nil || p.host == nil {
		return
	}
	h := p.host
	h.mu.Lock()
	if !h.cleaned {
		s := &h.slots[p.index]
		if s.generation == p.generation && s.issuing {
			s.issuing = false
			s.failed = s.failed || !s.ready
		}
	}
	h.mu.Unlock()
	h.collect(nil)
}

// CollectExpired releases only local material whose original initiation window
// has ended. It never changes durable issuance, spend or revocation history.
func (h *LiveArtifactHost) CollectExpired() error {
	if h == nil {
		return resourcev4.ErrOwner
	}
	h.mu.Lock()
	if err := h.checkLocked(); err != nil {
		h.mu.Unlock()
		return err
	}
	clock := h.template.config.Clock
	if h.operations != 0 {
		h.mu.Unlock()
		return resourcev4.ErrCapacity
	}
	h.operations++
	h.mu.Unlock()
	sample, err := clock.Sample()
	if err == nil {
		h.collect(&sample)
	}
	h.mu.Lock()
	h.operations--
	h.mu.Unlock()
	h.collect(nil)
	return err
}
func (h *LiveArtifactHost) collect(sample *timev4.Sample) {
	h.mu.Lock()
	if h.cleaned {
		h.mu.Unlock()
		return
	}
	if h.collecting {
		h.collectPending = true
		h.mu.Unlock()
		return
	}
	h.collecting = true
	h.mu.Unlock()
	finished := false
	defer func() {
		if !finished {
			h.mu.Lock()
			h.collecting = false
			h.mu.Unlock()
		}
	}()
	for {
		h.collectPass(sample)
		h.mu.Lock()
		if h.collectPending && !h.cleaned {
			h.collectPending = false
			h.mu.Unlock()
			sample = nil
			continue
		}
		h.collecting = false
		h.collectPending = false
		finished = true
		h.mu.Unlock()
		return
	}
}

func (h *LiveArtifactHost) collectPass(sample *timev4.Sample) {
	for i := range h.slots {
		h.mu.Lock()
		s := &h.slots[i]
		idle := !s.issuing && !s.working && !s.access && !s.retiring
		expired := idle && sample != nil && s.deadline != nil && s.deadline.CheckAt(*sample) == timev4.ErrExpired
		retire := idle && (h.closed || s.failed || expired) && (s.request != ([32]byte{}) || h.closed)
		if retire {
			s.retiring = true
		}
		h.mu.Unlock()
		if !retire {
			continue
		}
		// Provider Close and credential cleanup run outside the registry mutex.
		if s.plan != nil {
			if err := s.plan.Close(); err != nil {
				h.mu.Lock()
				s.failed = true
				s.retiring = false
				h.mu.Unlock()
				continue
			}
		}
		if s.server != nil {
			if err := liveArtifactCall(func() error { s.server.Close(); return nil }); err != nil {
				h.mu.Lock()
				s.failed = true
				s.retiring = false
				h.mu.Unlock()
				continue
			}
		}
		if s.artifact != nil {
			s.artifact.Release()
		}
		if s.deadline != nil {
			s.deadline.Cancel()
		}
		clear(s.projection)
		h.mu.Lock()
		generation, codec, work, projection := s.generation, s.codec, s.planWork, s.projection
		*s = liveArtifactSlot{generation: generation, codec: codec, planWork: work, projection: projection}
		h.mu.Unlock()
	}
	h.mu.Lock()
	if !h.closed || h.operations != 0 {
		h.mu.Unlock()
		return
	}
	for i := range h.slots {
		s := &h.slots[i]
		if s.issuing || s.working || s.access || s.retiring || s.request != ([32]byte{}) {
			h.mu.Unlock()
			return
		}
	}
	// No source callback or access can now be admitted or retain the template.
	h.mu.Unlock()
	h.template.close()
	for i := range h.slots {
		s := &h.slots[i]
		if s.planWork != nil {
			s.planWork.Close()
			if !s.planWork.CleanupComplete() {
				return
			}
		}
		s.codec, s.projection = nil, nil
	}
	h.shared.Release()
	h.reservation.Release()
	h.mu.Lock()
	h.cleaned = true
	close(h.done)
	h.mu.Unlock()
}

func liveArtifactCall(call func() error) (err error) {
	returned := false
	defer func() {
		if recover() != nil || !returned {
			err = sessionv4.ErrEnvironmentTaskExit
		}
	}()
	err = call()
	returned = true
	return
}
func (h *LiveArtifactHost) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.collect(nil)
}
func (h *LiveArtifactHost) WaitCleanup(ctx context.Context) error {
	if h == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*LiveArtifactHost) String() string   { return "LiveArtifactHost(<redacted>)" }
func (*LiveArtifactHost) GoString() string { return "LiveArtifactHost(<redacted>)" }
func (*LiveArtifactHost) MarshalJSON() ([]byte, error) {
	return []byte(`"LiveArtifactHost(<redacted>)"`), nil
}
