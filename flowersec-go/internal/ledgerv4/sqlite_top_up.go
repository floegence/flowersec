package ledgerv4

import (
	"context"
	"database/sql/driver"
	"math"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// SQLiteTopUpAuthority is independently installed current owner evidence. Its
// check is bounded local work with no I/O, callbacks or database reentry. Store
// continuity additionally proves the complete history has not been rolled back.
type SQLiteTopUpAuthority interface {
	CheckTopUpOwner(SQLiteIdentity, string, [16]byte, uint64) error
	// CheckTopUpIdentity rechecks the original admitted immutable identity
	// owner, its matching key handles and current authorization. It cannot
	// retrieve a different identity or perform provider I/O here.
	CheckTopUpIdentity(protocolv4.TopUpRequestFacts) error
}
type SQLiteTopUpConfig struct {
	Tenant                           string
	Source                           [16]byte
	BindingGeneration                uint64
	IdentityBytes, KeyReferenceBytes uint32
	PoolBytes                        uint64
	Clock                            *timev4.Clock
	Authority                        SQLiteTopUpAuthority
}

// SQLiteTopUpJournal is the client transaction group. It persists the original
// pending intent, complete installed batch and Applied frontier atomically. It
// grants neither server append authority nor an in-memory identity/key handle.
// One synchronous provider call is admitted at a time; no waiter queue exists.
type SQLiteTopUpJournal struct {
	store              *SQLiteStore
	config             SQLiteTopUpConfig
	configuration      [512]byte
	configurationBytes int
	pending, applied   [1024]byte
	record             []byte
}
type TopUpJournalState uint8

const (
	TopUpJournalEmpty TopUpJournalState = iota
	TopUpJournalPending
	TopUpJournalInstalled
	TopUpJournalAcked
	TopUpJournalTerminal
)

type TopUpRecovery struct {
	State                                                              TopUpJournalState
	BindingGeneration, NextSequence, RetiredSequence, ArtifactFrontier uint64
	Request                                                            protocolv4.TopUpRequestFacts
	Response                                                           protocolv4.TopUpResponseFacts
	Terminal                                                           TopUpServerSnapshot
	PermanentFenceGeneration                                           uint64
}

func SQLiteTopUpJournalCharge(l SQLiteLimits, c SQLiteTopUpConfig) (resourcev4.Vector, error) {
	base, err := SQLiteStoreCharge(l)
	if err != nil {
		return base, err
	}
	if !validBusinessIdentifier(c.Tenant) || c.Source == ([16]byte{}) || c.BindingGeneration == 0 || c.IdentityBytes == 0 || c.IdentityBytes > 65536 || c.KeyReferenceBytes == 0 || c.KeyReferenceBytes > 512 || c.PoolBytes == 0 || c.Clock == nil || c.Authority == nil || l.MaxRecords < 5 || uint64(l.MaxRecordBytes) < uint64(c.IdentityBytes)+uint64(c.KeyReferenceBytes)+65536+64 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	// Full pool bytes, one current batch's facts and the original identity must
	// all fit the fixed pager; no capacity check depends on future cleanup.
	if c.PoolBytes > uint64(l.MaxRecords-1)*uint64(l.MaxRecordBytes) || c.PoolBytes/4096+32 > uint64(l.MaxPages) {
		return resourcev4.Vector{}, ErrCapacity
	}
	return base.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(SQLiteTopUpJournal{})) + uint64(l.MaxRecordBytes) + 128, resourcev4.Items: 1})
}
func newSQLiteTopUpJournal(s *sqliteStore, c SQLiteTopUpConfig) *SQLiteTopUpJournal {
	c.Tenant = strings.Clone(c.Tenant)
	j := &SQLiteTopUpJournal{store: &SQLiteStore{s}, config: c, record: make([]byte, s.backing.limits.MaxRecordBytes)}
	w := admissionWriter{dst: j.configuration[:]}
	w.text(c.Tenant)
	w.bytes(c.Source[:])
	w.uint(uint64(c.IdentityBytes))
	w.uint(uint64(c.KeyReferenceBytes))
	w.uint(c.PoolBytes)
	j.configurationBytes = w.n
	return j
}
func CreateSQLiteTopUpJournal(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpConfig, reservation, environment resourcev4.Reference) (*SQLiteTopUpJournal, error) {
	return openSQLiteTopUpJournal(ctx, backing, identity, continuity, c, reservation, environment, true)
}
func OpenSQLiteTopUpJournal(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpConfig, reservation, environment resourcev4.Reference) (*SQLiteTopUpJournal, error) {
	return openSQLiteTopUpJournal(ctx, backing, identity, continuity, c, reservation, environment, false)
}
func openSQLiteTopUpJournal(ctx context.Context, backing *SQLiteBacking, identity SQLiteIdentity, continuity SQLiteContinuity, c SQLiteTopUpConfig, reservation, environment resourcev4.Reference, create bool) (*SQLiteTopUpJournal, error) {
	if c.Authority == nil {
		return nil, ErrConfiguration
	}
	if err := c.Authority.CheckTopUpOwner(identity, c.Tenant, c.Source, c.BindingGeneration); err != nil {
		return nil, err
	}
	s, err := openSQLitePurpose(ctx, backing, identity, continuity, reservation, environment, create, nil, nil, &c, nil, nil, nil)
	if s == nil {
		return nil, err
	}
	if s.topUps == nil {
		s.topUps = &SQLiteTopUpJournal{store: s}
	}
	return s.topUps, err
}
func (j *SQLiteTopUpJournal) check() error {
	return j.config.Authority.CheckTopUpOwner(j.store.identity, j.config.Tenant, j.config.Source, j.config.BindingGeneration)
}
func (j *SQLiteTopUpJournal) Close() {
	if j != nil && j.store != nil {
		j.store.Close()
	}
}
func (j *SQLiteTopUpJournal) WaitCleanup(ctx context.Context) error { return j.store.WaitCleanup(ctx) }
func (j *SQLiteTopUpJournal) Retire() error {
	if err := j.store.Retire(); err != nil {
		return err
	}
	clear(j.record)
	j.record = nil
	return nil
}

// Recover is read-only and does not parse material, recover keys, install or
// Acquire. The current authorized owner receives facts from the original source.
func (j *SQLiteTopUpJournal) Recover(ctx context.Context) (TopUpRecovery, error) {
	if err := j.store.begin(ctx); err != nil {
		return TopUpRecovery{}, err
	}
	defer j.store.end()
	if err := j.store.checkFence(); err != nil {
		return TopUpRecovery{}, err
	}
	if err := j.check(); err != nil {
		return TopUpRecovery{}, err
	}
	result, err := j.readRecovery()
	if err != nil {
		return TopUpRecovery{}, err
	}
	if err = j.check(); err != nil {
		return TopUpRecovery{}, err
	}
	return result, ctx.Err()
}

// Begin commits the exact pending intent before control I/O may send it. The
// caller has already verified the complete immutable identity and matching key
// provider handles; only their original certificate and opaque provider locator
// are persisted. Neither can be replaced during recovery of this intent.
func (j *SQLiteTopUpJournal) Begin(ctx context.Context, r protocolv4.TopUpRequestFacts, certificate, keyReference []byte) error {
	if r.Tenant != j.config.Tenant || r.Source != j.config.Source || r.Generation != j.config.BindingGeneration || r.Digest == ([32]byte{}) || r.DesiredCount < 1 || r.DesiredCount > 4 || r.MaxItemBytes < 1 || r.MaxItemBytes > 65536 || r.DeadlineMS == 0 || len(certificate) < 1 || uint64(len(certificate)) > uint64(j.config.IdentityBytes) || len(keyReference) < 1 || uint64(len(keyReference)) > uint64(j.config.KeyReferenceBytes) {
		return ErrConfiguration
	}
	requestDigest, err := protocolv4.ComputeTopUpRequestDigest(r)
	if err != nil || requestDigest != r.Digest {
		return ErrConfiguration
	}
	digest, err := protocolv4.TopUpIdentityDigest(certificate)
	if err != nil || digest != r.Identity {
		return ErrConfiguration
	}
	if err := j.store.begin(ctx); err != nil {
		return err
	}
	defer j.store.end()
	n, err := encodeTopUpRequest(j.pending[:], r)
	if err != nil {
		return err
	}
	defer clear(j.pending[:])
	guard := func() error {
		if err := j.check(); err != nil {
			return err
		}
		return j.config.Authority.CheckTopUpIdentity(r)
	}
	return j.store.writeTransaction(ctx, guard, func() error {
		old, err := j.readRecovery()
		if err != nil {
			return err
		}
		if old.BindingGeneration != j.config.BindingGeneration {
			return ErrFenced
		}
		if old.PermanentFenceGeneration != 0 || old.State == TopUpJournalTerminal && old.Terminal.Permanent {
			return ErrFenced
		}
		if old.State == TopUpJournalPending || old.State == TopUpJournalInstalled {
			if old.Request != r {
				return ErrConflict
			}
			return j.matchIdentity(certificate, keyReference)
		}
		if r.Sequence() != old.NextSequence || old.NextSequence == math.MaxUint64 || old.NextSequence != old.RetiredSequence+1 {
			return ErrConflict
		}
		now, err := j.config.Clock.Sample()
		if err != nil {
			return err
		}
		if !now.ValidBefore(r.DeadlineMS) {
			return timev4.ErrExpired
		}
		// readRecovery uses separate fixed scratch, preserving this original intent.
		n, err = encodeTopUpRequest(j.pending[:], r)
		if err != nil {
			return err
		}
		return j.store.exec("UPDATE manifest SET next_sequence=?1,state=1,pending=?2,applied=x'',terminal=x'',identity=?3,key_reference=?4 WHERE id=1", named(1, sqliteUint(old.NextSequence+1)), named(2, j.pending[:n]), named(3, certificate), named(4, keyReference))
	})
}

// Install requires the original source's already verified certificate/key owner
// and full credential checks. Its guard is checked by the source before entry;
// this storage boundary rechecks owner, time, exact intent and all batch facts.
// An already-Applied replay compares facts only, even if credentials now expire.
func (j *SQLiteTopUpJournal) Install(ctx context.Context, request protocolv4.TopUpRequestFacts, batch *protocolv4.TopUpBatch) error {
	if batch == nil || !batch.MatchesRequest(request) {
		return ErrConfiguration
	}
	if err := j.store.begin(ctx); err != nil {
		return err
	}
	defer j.store.end()
	defer clear(j.record)
	f, err := batch.Facts()
	if err != nil {
		return err
	}
	needsIdentity := false
	guard := func() error {
		if err := j.check(); err != nil {
			return err
		}
		if !needsIdentity {
			return nil
		}
		if err := j.config.Authority.CheckTopUpIdentity(request); err != nil {
			return err
		}
		now, err := j.config.Clock.Sample()
		if err != nil {
			return err
		}
		for _, item := range f.Entries[:f.Count] {
			if !now.ValidBefore(item.ExpiryMS) {
				return timev4.ErrExpired
			}
		}
		return nil
	}
	return j.store.writeTransaction(ctx, guard, func() error {
		old, err := j.readRecovery()
		if err != nil {
			return err
		}
		if old.Request != request || f.Source != request.Source || f.Operation != request.Operation || f.Tenant != request.Tenant || f.Count != request.DesiredCount {
			return ErrConflict
		}
		if old.State == TopUpJournalInstalled || old.State == TopUpJournalAcked {
			if old.Response != f {
				return ErrConflict
			}
			return nil
		}
		if old.State != TopUpJournalPending || old.BindingGeneration != j.config.BindingGeneration || f.Generation != request.Generation {
			return ErrFenced
		}
		needsIdentity = true
		if err = guard(); err != nil {
			return err
		}
		if err = protocolv4.CheckTopUpInstallSequence(f, old.ArtifactFrontier); err != nil {
			return err
		}
		var counts [2]driver.Value
		if err = j.store.one("SELECT pool_count,pool_bytes FROM manifest WHERE id=1", counts[:]); err != nil {
			return err
		}
		count, cok := counts[0].(int64)
		total, tok := counts[1].(int64)
		if !cok || !tok || count < 0 || total < 0 || count > int64(j.store.backing.limits.MaxRecords-1) || uint64(total) > j.config.PoolBytes {
			return ErrStorageFormat
		}
		if int64(f.Count) > int64(j.store.backing.limits.MaxRecords-1)-count {
			return ErrCapacity
		}
		for i := uint32(0); i < f.Count; i++ {
			item := f.Entries[i]
			now, err := j.config.Clock.Sample()
			if err != nil {
				return err
			}
			if !now.ValidBefore(item.ExpiryMS) {
				return timev4.ErrExpired
			}
			material, err := batch.Material(i)
			if err != nil {
				return err
			}
			if item.Identity != request.Identity || item.Generation != f.Generation {
				return ErrConflict
			}
			n, err := j.poolRecord(material, request.Identity)
			if err != nil {
				return err
			}
			if uint64(n) > j.config.PoolBytes-uint64(total) {
				return ErrCapacity
			}
			if err = j.store.exec("INSERT INTO pool VALUES (?1,?2,?3,?4,?5,?6)", named(1, sqliteUint(item.Sequence)), named(2, sqliteUint(item.Generation)), named(3, sqliteUint(item.ExpiryMS)), named(4, item.Material[:]), named(5, item.Identity[:]), named(6, j.record[:n])); err != nil {
				return err
			}
			total += int64(n)
		}
		n, err := encodeTopUpResponse(j.applied[:], f)
		if err != nil {
			return err
		}
		defer clear(j.applied[:])
		return j.store.exec("UPDATE manifest SET state=2,applied=?1,frontier=?2,pool_count=?3,pool_bytes=?4 WHERE id=1", named(1, j.applied[:n]), named(2, sqliteUint(f.Entries[f.Count-1].Sequence)), named(3, count+int64(f.Count)), named(4, total))
	})
}

// ConfirmAck may only be called after the control adapter authenticates a
// successful Ack for these exact facts and current owner. Local timeout or a
// source/call error must never enter this method. It releases only this TopUp
// sequence; Spend/Admission histories and installed pool items are unaffected.
func (j *SQLiteTopUpJournal) ConfirmAck(ctx context.Context, request protocolv4.TopUpRequestFacts, response protocolv4.TopUpResponseFacts) error {
	if err := j.store.begin(ctx); err != nil {
		return err
	}
	defer j.store.end()
	return j.store.writeTransaction(ctx, j.check, func() error {
		old, err := j.readRecovery()
		if err != nil {
			return err
		}
		if old.Request != request || old.Response != response || (old.State != TopUpJournalInstalled && old.State != TopUpJournalAcked) || old.BindingGeneration != j.config.BindingGeneration {
			return ErrConflict
		}
		return j.store.exec("UPDATE manifest SET state=3,retired_sequence=?1 WHERE id=1", named(1, sqliteUint(request.Sequence())))
	})
}

// ReadPendingIdentity retrieves the same persisted identity for unapplied
// recovery. The trusted provider must recover matching keys and revalidate the
// original certificate before installation. Applied recovery never calls this.
func (j *SQLiteTopUpJournal) ReadPendingIdentity(ctx context.Context, request protocolv4.TopUpRequestFacts, certificate, keyReference []byte) (certBytes, keyBytes int, err error) {
	if uint64(len(certificate)) < uint64(j.config.IdentityBytes) || uint64(len(keyReference)) < uint64(j.config.KeyReferenceBytes) {
		return 0, 0, ErrCapacity
	}
	if err = j.store.begin(ctx); err != nil {
		return 0, 0, err
	}
	defer j.store.end()
	defer func() {
		if err != nil {
			clear(certificate)
			clear(keyReference)
			certBytes, keyBytes = 0, 0
		}
	}()
	if err = j.store.checkFence(); err != nil {
		return 0, 0, err
	}
	if err = j.check(); err != nil {
		return 0, 0, err
	}
	state, err := j.readRecovery()
	if err != nil {
		return 0, 0, err
	}
	if state.State != TopUpJournalPending || state.Request != request {
		return 0, 0, ErrConflict
	}
	err = j.store.readOne("SELECT CASE WHEN length(identity)<=?1 THEN identity ELSE NULL END,CASE WHEN length(key_reference)<=?2 THEN key_reference ELSE NULL END FROM manifest WHERE id=1", 2, func(v []driver.Value) error {
		cert, cok := v[0].([]byte)
		key, kok := v[1].([]byte)
		if !cok || !kok || len(cert) == 0 || len(key) == 0 {
			return ErrStorageFormat
		}
		digest, err := protocolv4.TopUpIdentityDigest(cert)
		if err != nil || digest != request.Identity {
			return ErrStorageFormat
		}
		certBytes = copy(certificate, cert)
		keyBytes = copy(keyReference, key)
		return nil
	}, named(1, int64(j.config.IdentityBytes)), named(2, int64(j.config.KeyReferenceBytes)))
	if err != nil {
		return 0, 0, err
	}
	if err = j.check(); err != nil {
		return 0, 0, err
	}
	return certBytes, keyBytes, ctx.Err()
}
