package cryptov4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"

func (e *Engine) BootstrapSpec() (protocolv4.BootstrapSpec, bool) {
	return e.bootstrap, e.bootstrapEnabled
}

// BindBootstrapResources confirms that the original Session initializer has
// transferred the fixed channel's actual flow/proof/native reservations. It
// must happen before READY; it is not a peer claim or a public feature option.
func (e *Engine) BindBootstrapResources() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ready || !e.bootstrapEnabled || e.bootstrapReserved || e.initialSigning || e.current.deadline.Check() != nil {
		return ErrTransition
	}
	if e.initial != nil {
		if err := e.initialLive(e.initial); err != nil {
			return err
		}
	}
	e.bootstrapReserved = true
	return nil
}

// BootstrapFrontier is only for attaching the private initial flow. Public
// scope snapshots keep the normal dual-READY gate. No nonce is consumed here.
func (e *Engine) BootstrapFrontier(direction protocolv4.Direction) (protocolv4.RecordHeader, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.ready || !e.bootstrapEnabled || direction > protocolv4.ServerToClient || e.current.number != 0 || e.current.deadline.Check() != nil {
		return protocolv4.RecordHeader{}, ErrNotReady
	}
	keys := e.current.keys.get(e.bootstrap.Scope)
	if keys == nil || !keys.bootstrap {
		return protocolv4.RecordHeader{}, ErrScope
	}
	return protocolv4.RecordHeader{Scope: e.bootstrap.Scope, Sequence: keys.keys[direction].next}, nil
}

type BootstrapCreation struct {
	Variant                      string
	ApplicationProfile           string
	HandshakeHash                [32]byte
	Role                         protocolv4.Direction
	LocalSubmitted, PeerVerified bool
}

// BootstrapCreation projects the completed original READY facts. It neither
// synthesizes an OPEN/ACCEPT digest nor resets an early authenticated frontier.
func (e *Engine) BootstrapCreation() (BootstrapCreation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return BootstrapCreation{}, err
	}
	if !e.bootstrapEnabled || !e.bootstrapReserved {
		return BootstrapCreation{}, ErrNotReady
	}
	return BootstrapCreation{Variant: e.bootstrap.Creation, ApplicationProfile: e.config.ApplicationProfile, HandshakeHash: e.config.HandshakeHash, Role: e.config.SendDirection, LocalSubmitted: true, PeerVerified: true}, nil
}
