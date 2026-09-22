package cryptov4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"

// A dynamic scope key job borrows an ordinary work position for its entire
// lifetime. It cannot borrow either maintenance position or the rekey stage
// job. At most two epochs and two directions coexist for one original scope.
type scopeKeyJob struct {
	epoch     *epochState
	owner     *scopeKeys
	scope     uint64
	direction protocolv4.Direction
	root      [32]byte
}

type scopeKeyWork struct {
	engine  *Engine
	work    *workspace
	jobs    [4]scopeKeyJob
	count   int
	private bool
}

// reserveKeyWork is called inside the original Engine gate, before publishing
// any scope entry. Failed/cancelled KDF work never refunds its usage charge.
func (e *Engine) reserveKeyWork(private bool, jobs ...scopeKeyJob) (*scopeKeyWork, error) {
	if len(jobs) == 0 || len(jobs) > 4 {
		return nil, ErrConfiguration
	}
	for _, job := range jobs {
		if job.owner.deriving[job.direction] || job.owner.keys[job.direction] != nil {
			return nil, ErrTransition
		}
	}
	if e.derivations > e.limits.Derivations || uint64(len(jobs)) > e.limits.Derivations-e.derivations {
		return nil, ErrUsage
	}
	var w *workspace
	var err error
	if private {
		w, err = e.inputWorkspace(false, false)
	} else {
		w, err = e.workspace(false, e.config.SendDirection)
	}
	if err != nil {
		return nil, err
	}
	b := &scopeKeyWork{engine: e, work: w, count: len(jobs), private: private}
	copy(b.jobs[:], jobs)
	for i := range b.count {
		job := &b.jobs[i]
		job.root = job.epoch.root
		job.owner.deriving[job.direction] = true
	}
	e.derivations += uint64(len(jobs))
	e.flight++
	e.reliableFlight++
	return b, nil
}

func (b *scopeKeyWork) check(job *scopeKeyJob) error {
	e := b.engine
	var err error
	if b.private {
		err = e.inputLive()
	} else {
		err = e.live()
	}
	if err != nil {
		return err
	}
	if err := job.epoch.deadline.Check(); err != nil {
		return securityTimeError(err)
	}
	if job.epoch != e.current && job.epoch != e.staged || job.epoch.keys.get(job.scope) != job.owner || !job.owner.deriving[job.direction] {
		return ErrScope
	}
	return nil
}

// run keeps the work position until the caller finishes its original scope
// publication gate, or transfers that position to incoming authentication.
func (b *scopeKeyWork) run() (err error) {
	e := b.engine
	defer func() {
		e.mu.Lock()
		for i := range b.count {
			job := &b.jobs[i]
			job.owner.deriving[job.direction] = false
			clear(job.root[:])
		}
		e.flight--
		e.reliableFlight--
		e.mu.Unlock()
		clear(b.jobs[:])
		b.count = 0
	}()
	for i := range b.count {
		job := &b.jobs[i]
		e.mu.Lock()
		// The same pending scope may cross a completed rekey while its outcome
		// is still private. Obsolete old-root work cannot install anything; its
		// separately reserved current-epoch job must still finish or fail.
		obsolete := job.epoch.number < e.current.number
		err = b.check(job)
		e.mu.Unlock()
		if obsolete {
			continue
		}
		if err != nil {
			return err
		}
		key, err := e.constructKey(job.root, job.epoch.number, job.scope, job.direction)
		if err != nil {
			return err
		}
		e.mu.Lock()
		obsolete = job.epoch.number < e.current.number
		err = b.check(job)
		if err == nil {
			job.owner.keys[job.direction] = key
		}
		e.mu.Unlock()
		if err != nil && !obsolete {
			return err
		}
	}
	return nil
}

// takeWorkspace transfers the same position from KDF to authentication without
// a free/reacquire gap or another charged KDF. Only the original caller uses it.
func (b *scopeKeyWork) takeWorkspace() *workspace {
	w := b.work
	b.work, b.engine = nil, nil
	return w
}

func (b *scopeKeyWork) release() {
	e := b.engine
	w := b.takeWorkspace()
	if w != nil {
		e.release(w)
	}
}
