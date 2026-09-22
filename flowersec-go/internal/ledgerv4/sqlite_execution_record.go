package ledgerv4

import (
	"context"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

const executionFactsBytes = 104

type storedExecution struct {
	SQLiteExecutionObservation
	request, contract [32]byte
	invocation        [32]byte
}

type executionGCRecord struct {
	key   [executionStorageKeyBytes]byte
	facts SQLiteExecutionObservation
}

// This fixed encoding belongs exclusively to the business store format. It is
// neither a peer protocol nor a transferable execution capability.
func encodeExecutionFacts(v SQLiteExecutionObservation) (b [executionFactsBytes]byte) {
	for i, n := range [...]uint64{v.Version, v.Epoch, v.RegistrationRevision} {
		binary.BigEndian.PutUint64(b[i*8:], n)
	}
	b[24], b[26] = v.State, v.Reason
	for i, flag := range [...]bool{v.Dispatched, v.WorkActive, v.CancelRequested, v.ResultFormed, v.ResultDeleted, v.StreamMetadataOnly} {
		if flag {
			b[25] |= 1 << i
		}
	}
	for i, n := range [...]uint64{v.DeadlineAtMS, v.HistoryNotBeforeGCMS, v.ResultNotAfterMS} {
		binary.BigEndian.PutUint64(b[28+i*8:], n)
	}
	for i, n := range [...]uint32{v.ResponseLimitBytes, v.ResultBytes, v.ApplicationErrorCode} {
		binary.BigEndian.PutUint32(b[52+i*4:], n)
	}
	copy(b[64:], v.ResultDigest[:])
	binary.BigEndian.PutUint64(b[96:], v.RunDeadlineAtMS)
	return
}

func decodeExecutionFacts(value driver.Value) (v SQLiteExecutionObservation, err error) {
	b, ok := value.([]byte)
	if !ok || len(b) != executionFactsBytes || b[25]&^byte(63) != 0 || b[27] != 0 {
		return v, ErrStorageFormat
	}
	v.Found = true
	v.StreamMetadataOnly = b[25]&32 != 0
	v.Version, v.Epoch, v.RegistrationRevision = binary.BigEndian.Uint64(b), binary.BigEndian.Uint64(b[8:]), binary.BigEndian.Uint64(b[16:])
	v.State, v.Reason = b[24], b[26]
	v.Dispatched, v.WorkActive, v.CancelRequested, v.ResultFormed, v.ResultDeleted = b[25]&1 != 0, b[25]&2 != 0, b[25]&4 != 0, b[25]&8 != 0, b[25]&16 != 0
	v.DeadlineAtMS, v.HistoryNotBeforeGCMS, v.ResultNotAfterMS = binary.BigEndian.Uint64(b[28:]), binary.BigEndian.Uint64(b[36:]), binary.BigEndian.Uint64(b[44:])
	v.ResponseLimitBytes, v.ResultBytes, v.ApplicationErrorCode = binary.BigEndian.Uint32(b[52:]), binary.BigEndian.Uint32(b[56:]), binary.BigEndian.Uint32(b[60:])
	copy(v.ResultDigest[:], b[64:])
	v.RunDeadlineAtMS = binary.BigEndian.Uint64(b[96:])
	if v.Dispatched != (v.RunDeadlineAtMS != 0) || v.RunDeadlineAtMS > v.DeadlineAtMS {
		return SQLiteExecutionObservation{}, ErrStorageFormat
	}
	if v.Version == 0 || v.Epoch == 0 || v.RegistrationRevision == 0 || v.State < SQLiteExecutionAccepted || v.State > SQLiteExecutionUnknown || v.Reason > SQLiteExecutionReasonNotDispatched || v.DeadlineAtMS == 0 || v.HistoryNotBeforeGCMS <= v.DeadlineAtMS || v.ResultBytes > v.ResponseLimitBytes || v.ResponseLimitBytes > 1048576 || v.State == SQLiteExecutionAccepted && (v.Dispatched || !v.WorkActive) || v.State == SQLiteExecutionExecuting && (!v.Dispatched || !v.WorkActive) || v.ResultFormed && (!v.Dispatched || v.State != SQLiteExecutionCompleted && v.State != SQLiteExecutionFailed) || !v.ResultFormed && (v.ResultBytes != 0 || v.ResultDigest != ([32]byte{}) || v.ResultNotAfterMS != 0 || v.ApplicationErrorCode != 0 && !v.StreamMetadataOnly) || v.ResultDeleted && !v.ResultFormed || v.StreamMetadataOnly && (v.ResultFormed || v.ResultDeleted || v.ResultBytes != 0 || v.ApplicationErrorCode != 0 && (!v.Dispatched || v.State != SQLiteExecutionFailed)) {
		return SQLiteExecutionObservation{}, ErrStorageFormat
	}
	return v, nil
}

func (e *SQLiteExecutions) readExecution(key []byte) (r storedExecution, err error) {
	s := e.store.sqliteStore
	rows, err := s.querier.QueryContext(context.Background(), "SELECT CASE WHEN length(request)=32 THEN request ELSE NULL END,CASE WHEN length(contract)=32 THEN contract ELSE NULL END,CASE WHEN length(facts)=104 THEN facts ELSE NULL END,active,length(payload),length(terms),CASE WHEN length(invocation)=32 THEN invocation ELSE NULL END FROM executions WHERE key=?1", []driver.NamedValue{named(1, key)})
	if err != nil {
		return r, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [7]driver.Value
	if err = rows.Next(values[:]); err == io.EOF {
		return r, nil
	} else if err != nil {
		return r, err
	}
	r.SQLiteExecutionObservation, err = decodeExecutionFacts(values[2])
	if err != nil {
		return r, err
	}
	request, rok := values[0].([]byte)
	contract, cok := values[1].([]byte)
	active, aok := values[3].(int64)
	n, nok := values[4].(int64)
	terms, tok := values[5].(int64)
	expected := int64(r.ResponseLimitBytes)
	if r.ResultDeleted || r.StreamMetadataOnly {
		expected = 0
	}
	if !rok || len(request) != 32 || !cok || len(contract) != 32 || !aok || active < 0 || active > 1 || (active == 1) != r.WorkActive || !nok || n != expected || n > int64(s.backing.limits.MaxRecordBytes) || !tok || terms < 1 || terms > int64(len(e.contract)) {
		return storedExecution{}, ErrStorageFormat
	}
	copy(r.request[:], request)
	copy(r.contract[:], contract)
	invocation, iok := values[6].([]byte)
	if !iok || len(invocation) != 32 {
		return storedExecution{}, ErrStorageFormat
	}
	copy(r.invocation[:], invocation)
	if r.request == ([32]byte{}) || r.contract == ([32]byte{}) || r.invocation == ([32]byte{}) {
		return storedExecution{}, ErrStorageFormat
	}
	if err = rows.Next(values[:]); err != io.EOF {
		return storedExecution{}, ErrStorageFormat
	}
	return r, nil
}

func (e *SQLiteExecutions) updateFacts(key []byte, v SQLiteExecutionObservation) error {
	if v.Version == math.MaxUint64 {
		return ErrCapacity
	}
	v.Version++
	facts := encodeExecutionFacts(v)
	active := int64(0)
	if v.WorkActive {
		active = 1
	}
	if err := e.store.exec("UPDATE executions SET facts=?1,active=?2 WHERE key=?3", named(1, facts[:]), named(2, active), named(3, key)); err != nil {
		return err
	}
	return e.store.changedOne()
}

// readBoundedBlob copies before stepping/finalizing the sole driver cursor.
// Queries must select length plus a CASE-limited blob, never an unbounded row.
func (e *SQLiteExecutions) readBoundedBlob(query string, dst []byte, args ...driver.NamedValue) (n int, err error) {
	rows, err := e.store.querier.QueryContext(context.Background(), query, args)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	var values [2]driver.Value
	if err = rows.Next(values[:]); err != nil {
		return 0, err
	}
	length, ok := values[0].(int64)
	body, bok := values[1].([]byte)
	if !ok || !bok || length < 0 || length != int64(len(body)) || length > int64(len(dst)) {
		return 0, ErrStorageFormat
	}
	n = copy(dst, body)
	if err = rows.Next(values[:]); err != io.EOF {
		return n, ErrStorageFormat
	}
	return n, nil
}

func (e *SQLiteExecutions) readTerms(key []byte) (int, error) {
	return e.readBoundedBlob("SELECT length(terms),CASE WHEN length(terms)<=8192 THEN terms ELSE NULL END FROM executions WHERE key=?1", e.contract[:], named(1, key))
}
