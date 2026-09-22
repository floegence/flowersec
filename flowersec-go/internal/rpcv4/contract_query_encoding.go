package rpcv4

// EncodeStep uses one bounded fixed SDK codec opportunity. The admitted full
// output stays with this original query between steps. Deadline failure, Close,
// panic or Goexit never refunds an active step or allows a second output owner.
func (j ContractQueryJob) EncodeStep() (done bool, err error) {
	q := j.service
	if q == nil {
		return false, ErrOwner
	}
	q.mu.Lock()
	s, err := j.slotLocked()
	if err != nil {
		q.mu.Unlock()
		return false, err
	}
	if s.stepping || s.queued || s.read == nil {
		q.mu.Unlock()
		return false, ErrOwner
	}
	s.stepping = true
	read, codec, buffer, deadline := s.read, q.snapshots, s.payload, s.deadline
	q.mu.Unlock()
	returned := false
	written := 0
	defer func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		s.stepping = false
		if !returned {
			s.canceled = true
		}
		if q.closed || s.canceled {
			q.releaseOutputLocked(j.index, j.generation)
			done, err = false, ErrClosed
		} else if err == nil {
			s.bytes, s.encoded = written, done
		}
	}()
	err = deadline.Check()
	if err == nil {
		written, done, err = read.EncodeStep(codec, buffer)
	}
	returned = true
	return done, err
}
