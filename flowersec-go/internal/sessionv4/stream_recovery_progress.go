package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// The accepted target owns this immutable progress until its original Stream
// capability retires. It grants no new recovery, token issuance or I/O rights.
type streamRecoveryProgress struct {
	result      protocolv4.ResumeResult
	reservation resourcev4.Reference
}

func (s *resumeStreamServer) transferProgress(owner *StreamOwnership) error {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.admission == nil || owner.revoked.Load() || owner.sealed.Load() || owner.resume != nil || owner.messages != nil || owner.recoveryProgress != nil || s.progress == nil {
		return ErrStreamOwned
	}
	if err := owner.checkLifetime(); err != nil {
		return err
	}
	owner.recoveryProgress, s.progress = s.progress, nil
	return nil
}

// RecoveryProgress returns the confirmed checkpoint and generation associated
// with this accepted Stream. A non-recovery Stream reports present=false.
// The returned bounded value owns its position; no Session or store alias is
// handed to the handler. Current authorization governs the disclosure.
func (o *StreamOwnership) RecoveryProgress() (result protocolv4.ResumeResult, present bool, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.admission == nil || o.revoked.Load() || o.sealed.Load() {
		return result, false, ErrStreamOwned
	}
	a := o.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.slot(o.handle)
	if err != nil {
		return result, false, err
	}
	if a.closed || s.cancelled || s.owner != o {
		return result, false, cryptov4.ErrClosed
	}
	if err := o.checkLifetime(); err != nil {
		return result, false, err
	}
	if err := a.engine.CheckApplicationAuthorization(); err != nil {
		return result, false, err
	}
	if o.recoveryProgress == nil {
		return result, false, nil
	}
	return o.recoveryProgress.result, true, nil
}
