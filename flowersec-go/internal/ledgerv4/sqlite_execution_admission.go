package ledgerv4

import (
	"context"
	"crypto/rand"
	"database/sql/driver"
	"math"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func (e *SQLiteExecutions) check(guard func() error) error {
	if guard == nil {
		return ErrConfiguration
	}
	for _, ref := range [...]resourcev4.Reference{e.store.reservation, e.store.environment, e.store.disk} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	return guard()
}

func executionMatches(r storedExecution, q SQLiteExecutionRequest) error {
	if r.Found && (r.request != q.RequestDigest || r.contract != q.ContractDigest) {
		return ErrConflict
	}
	return nil
}

func (e *SQLiteExecutions) observation(r storedExecution) SQLiteExecutionObservation {
	v := r.SQLiteExecutionObservation
	if v.ResultFormed && !v.ResultDeleted {
		now, err := e.config.Clock.Sample()
		v.ResultAvailable = err == nil && (v.ResultNotAfterMS == 0 && v.WorkActive || v.ResultNotAfterMS != 0 && now.ValidBefore(v.ResultNotAfterMS))
	}
	return v
}

// Register receives a fully verified original request from the service adapter.
// The adapter must already own input, executor admission and full output tails;
// workReservation owns this storage responsibility in the original shared scope.
// Duplicates need no new work reservation and are looked up before current
// registration, Offer, clock, floor and capacity admission checks.
//
// A non-nil work returned alongside an error is cleanup-only. The caller must
// retain it and call Exit after its actual original task returns. Uncertain
// registration can never grant Enter, even if later Query observes the record.
func (e *SQLiteExecutions) Register(ctx context.Context, q SQLiteExecutionRequest, workReservation resourcev4.Reference, guard func() error) (SQLiteExecutionObservation, *SQLiteExecutionWork, error) {
	return e.register(ctx, q, workReservation, guard, nil)
}

func (e *SQLiteExecutions) RegisterReserved(ctx context.Context, q SQLiteExecutionRequest, workReservation resourcev4.Reference, guard func() error, capacity *SQLiteExecutionCapacity) (SQLiteExecutionObservation, *SQLiteExecutionWork, error) {
	if err := capacity.begin(e); err != nil {
		return SQLiteExecutionObservation{}, nil, err
	}
	defer capacity.finish()
	return e.register(ctx, q, workReservation, guard, capacity)
}

func (e *SQLiteExecutions) register(ctx context.Context, q SQLiteExecutionRequest, workReservation resourcev4.Reference, guard func() error, capacity *SQLiteExecutionCapacity) (observation SQLiteExecutionObservation, work *SQLiteExecutionWork, err error) {
	key, err := e.encodeKey(q.Key)
	if err != nil {
		return observation, nil, err
	}
	if q.RequestDigest == ([32]byte{}) || q.ContractDigest == ([32]byte{}) || guard == nil {
		return observation, nil, ErrConfiguration
	}
	s := e.store.sqliteStore
	if err = s.begin(ctx); err != nil {
		return observation, nil, err
	}
	defer s.end()
	var policy protocolv4.ServiceContractPolicy
	var registration executionContract
	var floor uint64
	var admitted bool
	check := func() error {
		if err := e.check(guard); err != nil {
			return err
		}
		if !admitted {
			return nil
		}
		return e.checkNewWindow(q, key[:], policy, registration, floor, work)
	}
	attempted := false
	err = s.writeTransaction(ctx, check, func() error {
		r, err := e.readExecution(key[:])
		if err != nil {
			return err
		}
		if err = executionMatches(r, q); err != nil {
			return err
		}
		if r.Found {
			observation = e.observation(r)
			return nil
		}
		if q.RegistrationRevision == 0 || q.DeadlineAtMS == 0 {
			return ErrConfiguration
		}
		registration, err = e.readContract(q.ContractDigest)
		if err != nil {
			return err
		}
		if !registration.enabled || registration.revision != q.RegistrationRevision {
			return ErrExecutionContract
		}
		c, err := e.codec.Decode(e.contract[:registration.bytes])
		if err != nil {
			return err
		}
		defer c.Release()
		policy, err = e.checkContract(c)
		if err != nil {
			return err
		}
		if policy.Digest != q.ContractDigest || q.ResponseLimitBytes < policy.MinResponseBytes || q.ResponseLimitBytes > policy.MaxResponseBytes || policy.Shape == 2 && q.ResponseLimitBytes != 0 {
			return ErrExecutionContract
		}
		floor, err = e.floor(q.Key.CallerAuthority)
		if err != nil {
			return err
		}
		if err = e.checkNewWindow(q, key[:], policy, registration, floor, nil); err != nil {
			return err
		}
		var counts [2]driver.Value
		if err = s.one("SELECT record_count,active_count FROM manifest WHERE id=1", counts[:]); err != nil {
			return err
		}
		records, rok := counts[0].(int64)
		active, aok := counts[1].(int64)
		if !rok || !aok || records < 0 || active < 0 || active > records {
			return ErrStorageFormat
		}
		s.mu.Lock()
		reserved := int64(e.capacityReserved)
		if capacity != nil {
			reserved--
		}
		s.mu.Unlock()
		if records+reserved >= int64(s.backing.limits.MaxRecords) || active+reserved >= int64(e.config.Active) {
			return ErrCapacity
		}
		if err = workReservation.CheckAllocationScope(e.config.Root, e.config.Owner, e.config.Accounts); err != nil {
			return err
		}
		charge, err := SQLiteExecutionWorkCharge(e.config.WorkRuntimeBytes)
		if err != nil {
			return err
		}
		owned, err := workReservation.Take(charge)
		if err != nil {
			return err
		}
		var pin resourcev4.Reference
		if capacity == nil {
			pin, err = s.reservation.Borrow()
		} else {
			pin = capacity.backing
			err = pin.Check()
		}
		if err != nil {
			owned.Release()
			return err
		}
		deadline, err := timev4.NewDeadline(e.config.Clock, q.DeadlineAtMS)
		if err != nil {
			if capacity == nil {
				pin.Release()
			}
			owned.Release()
			return err
		}
		var invocation [32]byte
		if _, err = rand.Read(invocation[:]); err != nil {
			if capacity == nil {
				pin.Release()
			}
			owned.Release()
			return err
		}
		q.Key.CallerSubject = strings.Clone(q.Key.CallerSubject)
		work = &SQLiteExecutionWork{&sqliteExecutionWork{store: e, capacity: capacity, key: key, request: q, reservation: owned, backing: pin, epoch: s.epoch, deadline: deadline, invocation: invocation}}
		s.mu.Lock()
		s.workPins++
		if capacity != nil {
			capacity.consumeLocked()
		}
		s.mu.Unlock()
		observation = SQLiteExecutionObservation{StreamMetadataOnly: policy.Shape == 1, Found: true, Version: 1, Epoch: s.epoch, RegistrationRevision: q.RegistrationRevision, State: SQLiteExecutionAccepted, WorkActive: true, DeadlineAtMS: q.DeadlineAtMS, HistoryNotBeforeGCMS: q.DeadlineAtMS + policy.HistoryRetentionMS, ResponseLimitBytes: q.ResponseLimitBytes}
		resultCapacity := q.ResponseLimitBytes
		if policy.Shape == 1 {
			resultCapacity = 0
		}
		facts := encodeExecutionFacts(observation)
		admitted = true
		// Unary result bytes are reserved in this transaction. Streaming
		// records retain execution metadata, never an implicit item archive.
		attempted = true
		if err = s.exec("INSERT INTO executions VALUES (?1,?2,?3,?4,?5,?6,1,zeroblob(?7))", named(1, key[:]), named(2, q.RequestDigest[:]), named(3, q.ContractDigest[:]), named(4, invocation[:]), named(5, e.contract[:registration.bytes]), named(6, facts[:]), named(7, int64(resultCapacity))); err != nil {
			return err
		}
		if policy.RetainedContent {
			now, err := e.config.Clock.Sample()
			if err != nil {
				return err
			}
			if policy.Content.RetentionMS > math.MaxUint64-now.UpperMS {
				return ErrConfiguration
			}
			if err := s.exec("INSERT INTO content_heads VALUES (?1,?2,0,0)", named(1, key[:]), named(2, sqliteUint(now.UpperMS))); err != nil {
				return err
			}
		}
		return s.exec("UPDATE manifest SET record_count=record_count+1,active_count=active_count+1 WHERE id=1")
	})
	if err != nil {
		if work != nil && !attempted {
			work.release()
			work = nil
		}
		return SQLiteExecutionObservation{}, work, err
	}
	if work != nil {
		work.registered = true
		work.committed = true
	}
	return observation, work, nil
}

func (e *SQLiteExecutions) checkNewWindow(q SQLiteExecutionRequest, key []byte, p protocolv4.ServiceContractPolicy, registration executionContract, floor uint64, w *SQLiteExecutionWork) error {
	now, err := e.config.Clock.Sample()
	if err != nil {
		return err
	}
	if w != nil {
		if err = w.deadline.CheckAt(now); err != nil {
			return err
		}
	}
	cutoff := storageOperationCutoff(key)
	if cutoff <= floor || p.AdmissionWindowMS == 0 || p.ExecutionHorizonMS == 0 || p.ExecutionRunMS == 0 || p.HistoryRetentionMS == 0 || p.AdmissionWindowMS > math.MaxUint64-now.LowerMS || p.ExecutionHorizonMS > math.MaxUint64-now.LowerMS || cutoff <= now.UpperMS || cutoff > now.LowerMS+p.AdmissionWindowMS || q.DeadlineAtMS <= now.UpperMS || q.DeadlineAtMS > now.LowerMS+p.ExecutionHorizonMS || p.HistoryRetentionMS > math.MaxUint64-q.DeadlineAtMS || !registration.admission(now, cutoff) {
		return ErrExecutionWindowClosed
	}
	return nil
}

// Query returns only recorded facts or proven absence in this complete logical
// authority. It never creates work from a surviving or recovered database row.
func (e *SQLiteExecutions) Query(ctx context.Context, q SQLiteExecutionRequest, guard func() error) (SQLiteExecutionObservation, error) {
	key, err := e.encodeKey(q.Key)
	if err != nil {
		return SQLiteExecutionObservation{}, err
	}
	if q.RequestDigest == ([32]byte{}) || q.ContractDigest == ([32]byte{}) || guard == nil {
		return SQLiteExecutionObservation{}, ErrConfiguration
	}
	if err = e.store.begin(ctx); err != nil {
		return SQLiteExecutionObservation{}, err
	}
	defer e.store.end()
	if err = e.check(guard); err != nil {
		return SQLiteExecutionObservation{}, err
	}
	if err = e.store.checkFence(); err != nil {
		return SQLiteExecutionObservation{}, err
	}
	r, err := e.readExecution(key[:])
	if err != nil {
		return SQLiteExecutionObservation{}, err
	}
	if err = executionMatches(r, q); err != nil {
		return SQLiteExecutionObservation{}, err
	}
	if !r.Found {
		floor, err := e.floor(q.Key.CallerAuthority)
		if err != nil {
			return SQLiteExecutionObservation{}, err
		}
		if storageOperationCutoff(key[:]) <= floor {
			return SQLiteExecutionObservation{}, ErrExecutionHistoryUnknown
		}
	}
	if err = ctx.Err(); err != nil {
		return SQLiteExecutionObservation{}, err
	}
	if err = e.check(guard); err != nil {
		return SQLiteExecutionObservation{}, err
	}
	return e.observation(r), nil
}
