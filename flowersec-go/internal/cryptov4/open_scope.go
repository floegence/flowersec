package cryptov4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"

// IncomingScope owns one bounded temporary receive key, then the authenticated
// OPEN association. It consumes neither a positive active slot nor a lifetime
// bit until its unique accepted/rejected outcome. The Session must retain it
// while pending; releasing a decoder or cancelling a waiter cannot forget it.
type IncomingScope struct {
	engine                             *Engine
	header                             protocolv4.RecordHeader
	authenticated, resolved, preparing bool
}

func (e *Engine) unusedScope(scope uint64) bool {
	if scope == 0 || scope >= uint64(1)<<63 {
		return false
	}
	role, ordinal := (scope+1)%2, (scope-1)/2
	return ordinal < e.ordinal[role] && e.used[role][ordinal/64]&(uint64(1)<<(ordinal%64)) == 0
}

func (e *Engine) consumeScope(scope uint64) {
	role, ordinal := (scope+1)%2, (scope-1)/2
	e.used[role][ordinal/64] |= uint64(1) << (ordinal % 64)
}

// OpenIncoming is used only for a carrier's unbound first OPEN. A hostile
// header gets at most one preadmitted temporary key; it cannot select another
// Session, steal a known scope, or allocate an application Stream. Failure
// drops the temporary key but never refunds derivation or AEAD usage.
func (e *Engine) OpenIncoming(input []byte, validate func(protocolv4.FrameType, protocolv4.RecordHeader, []byte) error) (*Packet, *IncomingScope, error) {
	frame, header, _, err := protocolv4.ParseRecord(input, e.config.Profile, e.config.MaxFrame)
	if err != nil {
		return nil, nil, err
	}
	if e.bootstrapEnabled && header.Scope == e.bootstrap.Scope {
		packet, _, _, err := e.Open(input, validate)
		return packet, nil, err
	}
	e.mu.Lock()
	if err = e.inputLive(); err == nil && (frame != protocolv4.FrameOpenStream || header.Sequence != 0 || protocolv4.Direction((header.Scope+1)%2) == e.config.SendDirection || !e.unusedScope(header.Scope) || e.current.keys.get(header.Scope) != nil) {
		err = ErrScope
	}
	if err == nil && e.staged != nil && e.staged.keys.get(header.Scope) != nil {
		err = ErrScope
	}
	epoch, epochErr := e.receiveEpoch(frame, header, nil)
	if err == nil {
		err = epochErr
	}
	// These bounded transient positions let a full ingress table transfer a
	// direct rejection to its protected proof owner. That owner can release the
	// decoder before publication; it retains this same incoming key position
	// until the rejection is committed, never an additional application slot.
	if err == nil && (e.config.PendingScopes == 0 || e.pending >= e.config.PendingScopes+e.config.WorkSlots) {
		err = ErrCapacity
	}
	if err != nil {
		e.mu.Unlock()
		return nil, nil, err
	}
	owner := &IncomingScope{engine: e, header: header}
	keys := &scopeKeys{incoming: owner}
	jobs := [2]scopeKeyJob{{epoch: epoch, owner: keys, scope: header.Scope, direction: 1 - e.config.SendDirection}}
	count := 1
	var futureKeys *scopeKeys
	if e.staged != nil && epoch != e.staged {
		futureKeys = &scopeKeys{incoming: owner}
		jobs[1] = scopeKeyJob{epoch: e.staged, owner: futureKeys, scope: header.Scope, direction: 1 - e.config.SendDirection}
		count++
	}
	if err := epoch.keys.insert(header.Scope, keys); err != nil {
		e.mu.Unlock()
		return nil, nil, err
	}
	if futureKeys != nil {
		if err := e.staged.keys.insert(header.Scope, futureKeys); err != nil {
			epoch.keys.remove(header.Scope)
			e.mu.Unlock()
			return nil, nil, err
		}
	}
	work, err := e.reserveKeyWork(true, jobs[:count]...)
	if err != nil {
		epoch.keys.remove(header.Scope)
		if futureKeys != nil {
			e.staged.keys.remove(header.Scope)
		}
		e.mu.Unlock()
		return nil, nil, err
	}
	e.pending++
	e.mu.Unlock()
	err = work.run()
	var packet *Packet
	if err == nil {
		packet, _, _, err = e.openReserved(input, validate, nil, work.takeWorkspace())
	} else {
		work.release()
	}
	if err != nil {
		e.mu.Lock()
		if !owner.authenticated {
			removed := false
			for _, activeEpoch := range []*epochState{e.current, e.staged} {
				if activeEpoch == nil {
					continue
				}
				if keys := activeEpoch.keys.get(header.Scope); keys != nil && keys.incoming == owner {
					activeEpoch.keys.remove(header.Scope)
					removed = true
				}
			}
			if removed {
				e.pending--
			}
		}
		e.mu.Unlock()
		return nil, nil, err
	}
	return packet, owner, nil
}

func (e *Engine) ScopeLimits() (active, pending uint32, direction protocolv4.Direction) {
	return e.config.MaxScopes, e.config.PendingScopes, e.config.SendDirection
}

// SignedScopeLimit preserves the peer's authorized maintenance envelope even
// when the local positive acceptance cap is lower (including zero).
func (e *Engine) SignedScopeLimit() uint32 { return e.config.SignedMaxScopes }

func (e *Engine) SessionBinding() ([32]byte, string) { return e.config.HandshakeHash, e.config.Profile }

// TransportContextDigest is the original negotiated end-to-end context. It
// is independent of the Noise handshake hash and remains fixed through rekey.
// Only the SDK captures this value when binding an explicit recovery target.
func (e *Engine) TransportContextDigest() [32]byte { return e.config.ContextDigest }

func (e *Engine) NegotiatedFeatures() uint64 { return e.config.Features }

func (e *Engine) SessionParameters() protocolv4.ArtifactSessionParameters { return e.session }

func (e *Engine) MaxFrame() uint32 { return e.config.MaxFrame }

func (s *IncomingScope) Header() protocolv4.RecordHeader { return s.header }

// PrepareAccept runs outside the Session outcome gate, after the original
// positive/proof/flow reservations exist. It prepares send keys without
// selecting accepted or enabling DATA. Staging inherits any in-progress key
// requirement, so a concurrent rekey cannot lose the new direction's key.
func (s *IncomingScope) PrepareAccept() error {
	e := s.engine
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return err
	}
	keys := e.current.keys.get(s.header.Scope)
	if s.resolved || !s.authenticated || s.preparing || keys == nil || keys.incoming != s || s.header.Epoch > e.current.number {
		e.mu.Unlock()
		return ErrScope
	}
	if e.active >= e.config.MaxScopes {
		e.mu.Unlock()
		return ErrCapacity
	}
	var jobs [2]scopeKeyJob
	count := 0
	for _, epoch := range []*epochState{e.current, e.staged} {
		if epoch == nil {
			continue
		}
		owner := epoch.keys.get(s.header.Scope)
		if owner == nil || owner.incoming != s {
			e.mu.Unlock()
			return ErrScope
		}
		if owner.keys[e.config.SendDirection] != nil || owner.deriving[e.config.SendDirection] {
			continue
		}
		jobs[count] = scopeKeyJob{epoch: epoch, owner: owner, scope: s.header.Scope, direction: e.config.SendDirection}
		count++
	}
	if count == 0 {
		e.mu.Unlock()
		return nil
	}
	work, err := e.reserveKeyWork(false, jobs[:count]...)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	s.preparing = true
	e.mu.Unlock()
	defer work.release()
	err = work.run()
	e.mu.Lock()
	s.preparing = false
	if err == nil {
		err = e.live()
	}
	keys = e.current.keys.get(s.header.Scope)
	if err == nil && (s.resolved || keys == nil || keys.incoming != s || keys.keys[e.config.SendDirection] == nil || keys.deriving[e.config.SendDirection]) {
		err = ErrTransition
	}
	e.mu.Unlock()
	return err
}

// Resolve runs inside the Session's outcome gate, after its proof/metadata/
// credit reservations exist. Accepted transfers the exact authenticated receive
// frontier and prepared send key. Rejected burns the ID without ever
// consuming an active slot. Failure leaves the same pending owner intact.
func (s *IncomingScope) Resolve(accepted bool) error {
	e := s.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if s.header.Epoch > e.current.number {
		return ErrTransition
	}
	keys := e.current.keys.get(s.header.Scope)
	if s.resolved || !s.authenticated || s.preparing || keys == nil || keys.incoming != s {
		return ErrScope
	}
	if accepted {
		if e.active >= e.config.MaxScopes {
			return ErrCapacity
		}
		if keys.keys[e.config.SendDirection] == nil || keys.deriving[e.config.SendDirection] {
			return ErrNotReady
		}
		if e.staged != nil {
			futureKeys := e.staged.keys.get(s.header.Scope)
			if futureKeys == nil || futureKeys.incoming != s {
				return ErrScope
			}
			if futureKeys.keys[e.config.SendDirection] == nil && !futureKeys.deriving[e.config.SendDirection] {
				return ErrNotReady
			}
			futureKeys.incoming = nil
		}
		keys.incoming = nil
		e.active++
	} else {
		e.current.keys.remove(s.header.Scope)
		if e.staged != nil {
			e.staged.keys.remove(s.header.Scope)
		}
	}
	e.consumeScope(s.header.Scope)
	e.pending--
	select {
	case e.receiveWake <- struct{}{}:
	default:
	}
	s.resolved = true
	return nil
}

// OpenLocalScope is the initiator's reserved opening. The OPEN ticket is the
// only permitted record until its original authenticated acceptance arrives.
func (e *Engine) OpenLocalScope(scope uint64) error {
	if protocolv4.Direction((scope+1)%2) != e.config.SendDirection {
		return ErrScope
	}
	return e.openScope(scope, true)
}

func (e *Engine) AcceptLocalScope(scope uint64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	keys := e.current.keys.get(scope)
	if keys == nil || !keys.opening || !keys.openSubmitted {
		return ErrScope
	}
	keys.opening = false
	if e.staged != nil {
		if future := e.staged.keys.get(scope); future != nil {
			future.opening = false
		}
	}
	return nil
}

// ScopeFrontier is a snapshot for the owning Session under its transition
// gate. It never resets an authenticated prefix after acceptance or rekey.
func (e *Engine) ScopeFrontier(scope uint64, direction protocolv4.Direction) (protocolv4.RecordHeader, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return protocolv4.RecordHeader{}, err
	}
	keys := e.current.keys.get(scope)
	if direction > protocolv4.ServerToClient || keys == nil || keys.keys[direction] == nil {
		return protocolv4.RecordHeader{}, ErrScope
	}
	return protocolv4.RecordHeader{Epoch: e.current.number, Scope: scope, Sequence: keys.keys[direction].next}, nil
}
