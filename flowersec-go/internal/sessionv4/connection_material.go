package sessionv4

import (
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// MaterialGeneration is local source fencing metadata, never a wire field,
// consumption key or authorization. A caller captures it once with the complete
// lease/identity pair and cannot replace either component after acquisition.
type MaterialGeneration struct {
	Source     [16]byte
	Generation uint64
}

type ConnectionMaterial struct {
	mu                                        sync.Mutex
	lease                                     artifactLeaseUse
	identity                                  identityUse
	generation                                MaterialGeneration
	reservation                               resourcev4.Reference
	used, building, attached, closed, cleaned bool
	done                                      chan struct{}
	environment                               *Environment
	preparing                                 bool
}

func (*ConnectionMaterial) String() string               { return "Flowersec.ConnectionMaterial" }
func (*ConnectionMaterial) GoString() string             { return "Flowersec.ConnectionMaterial" }
func (*ConnectionMaterial) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func ConnectionMaterialCharge(runtimeBytes uint64) (resourcev4.Vector, error) {
	if runtimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	closure, err := protocolv4.EndpointCredentialsBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ConnectionMaterial{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: closure})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: runtimeBytes})
}

func NewConnectionMaterial(lease *ArtifactLease, identity *ApplicationIdentity, generation MaterialGeneration, runtimeBytes uint64, reservation resourcev4.Reference) (_ *ConnectionMaterial, err error) {
	if generation.Source == ([16]byte{}) || generation.Generation == 0 {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := ConnectionMaterialCharge(runtimeBytes)
	if err != nil {
		return nil, err
	}
	i, err := identity.capture(reservation)
	if err != nil {
		return nil, err
	}
	return newConnectionMaterialCaptured(lease, i, generation, charge, reservation)
}

// The original asynchronous source moves its already captured identity use;
// it must not reacquire the source's current identity after issuance returns.
func newConnectionMaterialCaptured(lease *ArtifactLease, i identityUse, generation MaterialGeneration, charge resourcev4.Vector, reservation resourcev4.Reference) (_ *ConnectionMaterial, err error) {
	l, err := lease.capture(reservation)
	if err != nil {
		i.release()
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		i.release()
		l.release()
		return nil, err
	}
	m := &ConnectionMaterial{lease: l, identity: i, generation: generation, reservation: owned, building: true, done: make(chan struct{})}
	adopted := false
	defer func() {
		m.mu.Lock()
		m.building = false
		if !adopted {
			m.closed = true
		}
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	if err = m.check(); err != nil {
		return nil, err
	}
	adopted = true
	return m, nil
}

func (m *ConnectionMaterial) check() error {
	if err := m.reservation.Check(); err != nil {
		return err
	}
	l, i := m.lease.lease, m.identity.identity
	if err := i.check(); err != nil {
		return err
	}
	// The identity's actual key-provider calls precede the final complete
	// credential closure, including independently hosted parent namespaces.
	if err := l.checkForUse(i.role == protocolv4.ClientToServer); err != nil {
		return err
	}
	local := l.credentials[int(i.role)+1]
	if local.Facts().Digest != i.credential.Facts().Digest || local.Scope() != i.credential.Scope() {
		return cryptov4.ErrConfiguration
	}
	return nil
}

// Establishment takes the selected original winner after preparation. Both
// roles use this same frozen application identity and credential closure. A
// pool attempt is read from its issuance proof; a live attempt is supplied by
// the original Connect owner. No live proof cache or source fallback exists.
func (m *ConnectionMaterial) Establishment(hello InitialHello, limits EstablishmentLimits, generation MaterialGeneration, reservation, subscriptions resourcev4.Reference) (p *SessionEstablishment, credentials *protocolv4.CredentialSubscriptions, err error) {
	return m.establishment(hello, limits, generation, reservation, subscriptions, false)
}

func (m *ConnectionMaterial) establishment(hello InitialHello, limits EstablishmentLimits, generation MaterialGeneration, reservation, subscriptions resourcev4.Reference, prepared bool) (p *SessionEstablishment, credentials *protocolv4.CredentialSubscriptions, err error) {
	if m == nil {
		return nil, nil, cryptov4.ErrConfiguration
	}
	m.mu.Lock()
	if m.closed || m.used || m.generation != generation || m.building && !(prepared && m.preparing) || prepared != m.preparing {
		m.mu.Unlock()
		return nil, nil, cryptov4.ErrTransition
	}
	if err = m.reservation.CheckSameEnvironment(reservation); err == nil {
		err = m.reservation.CheckSameEnvironment(subscriptions)
	}
	if err != nil {
		m.mu.Unlock()
		return nil, nil, err
	}
	l, i := m.lease.lease, m.identity.identity
	l.mu.Lock()
	if l.claimed || l.preparing != nil && (!prepared || l.preparing != m) {
		l.mu.Unlock()
		m.mu.Unlock()
		return nil, nil, cryptov4.ErrTransition
	}
	l.claimed = true
	l.preparing = nil
	l.mu.Unlock()
	m.preparing = false
	m.used, m.building = true, true
	m.mu.Unlock()
	adopted := false
	defer func() {
		if !adopted && credentials != nil {
			credentials.Close()
			credentials = nil
		}
		m.mu.Lock()
		m.building = false
		m.closed = true
		m.attached = adopted
		m.cleanupLocked()
		m.mu.Unlock()
	}()
	if err = m.check(); err != nil {
		return nil, nil, err
	}
	material := EstablishmentMaterial{Artifact: l.maps[0], Proof: l.maps[1], ClientCertificate: l.maps[2], ServerCertificate: l.maps[3], Signer: i.signer, LocalDH: i.dh, Role: i.role, Source: l.source, Hello: hello, Live: l.verification}
	if l.source == "preauthorized_pool" {
		material.Activation, material.Authority, err = l.activation(hello.Index)
		if err != nil {
			return nil, nil, err
		}
		// MatchOriginal below rejects an attempt different from issuance.
		if err = material.Activation.MatchOriginal(l.session, hello.Attempt, material.Activation.Winner()); err != nil {
			return nil, nil, err
		}
	}
	closure, err := protocolv4.BindEndpointCredentials(i.role, l.maps[0], hello.Index, l.maps[2], l.maps[3], nil, nil)
	if err != nil {
		return nil, nil, err
	}
	credentials, err = closure.Subscribe(l.validation[:], l.session.SessionNotAfterMS, subscriptions)
	if err != nil {
		return nil, nil, err
	}
	p, err = NewSessionEstablishment(material, limits, reservation, m.reservation, m.reservation)
	if err != nil {
		return nil, credentials, err
	}
	// The original establishment returns this material only at physical
	// retirement, after all key calls and credential subscriptions are gone.
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = p.Retire()
		return nil, credentials, cryptov4.ErrClosed
	}
	p.connectionMaterial = m
	p.materialSubscriptions = credentials
	adopted = true
	m.mu.Unlock()
	return p, credentials, nil
}

func (m *ConnectionMaterial) finishSession() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attached = false
	m.cleanupLocked()
}

func (m *ConnectionMaterial) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.cleanupLocked()
}

func (m *ConnectionMaterial) cleanupLocked() {
	if !m.closed || m.cleaned || m.building || m.attached {
		return
	}
	m.identity.release()
	m.lease.release()
	m.reservation.Release()
	m.reservation = resourcev4.Reference{}
	m.cleaned = true
	close(m.done)
	if m.environment != nil {
		m.environment.signalMaterials()
	}
}

func (m *ConnectionMaterial) WaitCleanup(ctx context.Context) error {
	if m == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-m.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
