package protocolv4

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// Run the shared positive/negative corpus and maximum-body cases through both
// codec paths. The protected path must preserve exact semantics and source bytes.
func decodeSnapshotsBoth(t *testing.T, codec *ContractSnapshotCodec, request ContractQueryTargets, wire []byte, known []*ServiceContract, windows []uint64, outputs [][]byte) (ContractSnapshotSet, error) {
	t.Helper()
	expectedOutputs := make([][]byte, len(outputs))
	for i := range outputs {
		expectedOutputs[i] = bytes.Clone(outputs[i])
	}
	// Preserve original alias cases instead of disguising them with test copies.
	for i := range outputs {
		for j := 0; j < i; j++ {
			if queryBuffersOverlap(outputs[i], outputs[j]) {
				return codec.Decode(request, wire, known, windows, outputs)
			}
		}
	}
	expected, expectedErr := codec.Decode(request, wire, known, windows, expectedOutputs)
	reader, err := NewContractSnapshotReader()
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(wire)
	read, err := reader.Begin(request, wire, known, windows, outputs)
	var got ContractSnapshotSet
	if err == nil {
		defer read.Close()
		if _, err := read.Result(); !errors.Is(err, CBORFailure("decoder_incomplete")) {
			t.Fatal("premature result", err)
		}
		for step := 0; step < 30000; step++ {
			beforePhase, beforeIndex, beforeOffset := read.phase, read.index, read.offset
			done, e := read.Step()
			err = e
			if (beforePhase == 3 || beforePhase == 5) && beforeIndex == read.index && read.offset-beforeOffset > 4096 {
				t.Fatal("unbounded body work")
			}
			if done || err != nil {
				break
			}
			if step == 29999 {
				t.Fatal("fixed reader did not finish")
			}
		}
		got, err = read.Result()
		read.Close()
	}
	if !reflect.DeepEqual(got, expected) || !sameCBORFailure(err, expectedErr) {
		t.Fatalf("reader differs: result=%+v error=%v; synchronous=%+v error=%v", got, err, expected, expectedErr)
	}
	for i := range outputs {
		if !bytes.Equal(outputs[i], expectedOutputs[i]) {
			t.Fatalf("reader output differs at %d", i)
		}
	}
	if !bytes.Equal(wire, original) {
		t.Fatal("borrowed response was modified on release")
	}
	return got, err
}
func sameCBORFailure(a, b error) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Error() == b.Error()
}

// v4.go_contract_query.incremental_decode
func TestContractSnapshotReaderCancellationAndReuse(t *testing.T) {
	codec, err := NewContractQueryCodec()
	appOK(t, err)
	request, err := codec.DecodeTargets(queryRuntimeBytes(t, "contract_targets_plain"))
	appOK(t, err)
	wire := queryRuntimeBytes(t, "contract_snapshots_denied")
	reader, err := NewContractSnapshotReader()
	appOK(t, err)
	outputs := [][]byte{make([]byte, 8192)}
	read, err := reader.Begin(request, wire, []*ServiceContract{nil}, []uint64{1000}, outputs)
	appOK(t, err)
	for range 4 {
		_, err = read.Step()
		appOK(t, err)
	}
	if _, err = reader.Begin(request, wire, []*ServiceContract{nil}, []uint64{1000}, outputs); !errors.Is(err, CBORFailure("decoder_busy")) {
		t.Fatal(err)
	}
	original := bytes.Clone(wire)
	read.Close()
	next, err := reader.Begin(request, wire, []*ServiceContract{nil}, []uint64{1000}, outputs)
	appOK(t, err)
	defer next.Close()
	if _, err = read.Step(); !errors.Is(err, CBORFailure("document_released")) {
		t.Fatal(err)
	}
	if _, err = read.Result(); !errors.Is(err, CBORFailure("document_released")) {
		t.Fatal(err)
	}
	if !bytes.Equal(original, wire) {
		t.Fatal("Close cleared borrowed response")
	}
}
