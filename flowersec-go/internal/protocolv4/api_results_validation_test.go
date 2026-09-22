package protocolv4

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestV4ReadResultValidationMatrix(t *testing.T) {
	zero, maxBytes := uint64(0), uint64(16)
	open := V4ReadResult{WaitStatus: V4WaitStatusReady, StreamStatus: V4StreamStatusOpen, Progress: V4ReadProgress{Target: &zero}}
	if err := open.Validate(ReadResultContext{Method: "read_exactly", CursorKind: "exact", Target: &zero, StreamStatus: V4StreamStatusOpen}); err != nil {
		t.Fatal(err)
	}
	blocked := V4ReadResult{Progress: V4ReadProgress{Offset: 4}, WaitStatus: V4WaitStatusBlocked, StreamStatus: V4StreamStatusOpen}
	if err := blocked.Validate(ReadResultContext{Method: "read", StartOffset: 4, MaxBytes: &maxBytes, StreamStatus: V4StreamStatusOpen}); err != nil {
		t.Fatal(err)
	}
	eof := V4ReadResult{Data: []byte("tail"), Progress: V4ReadProgress{Offset: 8, Filled: 4}, WaitStatus: V4WaitStatusReady, StreamStatus: V4StreamStatusEof}
	context := ReadResultContext{Method: "read", StartOffset: 4, Transferred: 4, MaxBytes: &maxBytes, StreamStatus: V4StreamStatusEof}
	if err := eof.Validate(context); err != nil {
		t.Fatal(err)
	}
	cause := V4ReadCauseDelimiterNotFound
	bad := eof
	bad.Cause = &cause
	if err := bad.Validate(context); !errors.Is(err, ErrInvalidAPIResult) {
		t.Fatalf("terminal result with a cause accepted: %v", err)
	}
	bad = V4ReadResult{Data: []byte("x"), Progress: V4ReadProgress{Filled: 2}, WaitStatus: V4WaitStatusReady, StreamStatus: V4StreamStatusOpen}
	if err := bad.Validate(context); !errors.Is(err, ErrInvalidAPIResult) {
		t.Fatalf("filled/data mismatch accepted: %v", err)
	}
	bad = V4ReadResult{WaitStatus: V4WaitStatusWaitCanceled, StreamStatus: V4StreamStatusEof}
	if err := bad.Validate(ReadResultContext{Method: "read", MaxBytes: &maxBytes, StreamStatus: V4StreamStatusEof}); !errors.Is(err, ErrInvalidAPIResult) {
		t.Fatalf("wait cancellation changed stream status: %v", err)
	}
}

func TestV4WriteProgressValidation(t *testing.T) {
	valid := V4WriteProgress{RequestedBytes: 8, AcceptedBytes: 4, Phase: V4WritePhaseRunning, TerminalReason: V4WriteTerminalReasonNone, CleanupStatus: V4CleanupStatus{Status: V4CleanupStatePending, CoreCleanup: V4CoreCleanupPending}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.Phase = V4WritePhaseTerminal
	valid.TerminalReason = V4WriteTerminalReasonComplete
	if err := valid.Validate(); !errors.Is(err, ErrInvalidAPIResult) {
		t.Fatal("partial acceptance reported complete", err)
	}
	valid.AcceptedBytes = valid.RequestedBytes
	valid.CleanupStatus = V4CleanupStatus{Status: V4CleanupStateComplete, CoreCleanup: V4CoreCleanupComplete}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.AcceptedBytes = 9
	if err := valid.Validate(); !errors.Is(err, ErrInvalidAPIResult) {
		t.Fatalf("accepted bytes exceeded request: %v", err)
	}
}

// Decode only the corpus's native JSON tags. This is test transport, not a new
// public JSON representation. Unknown fields and unrepresentable uint64 values
// must fail before a Go native value is passed to its semantic validator.
func decodeAPIResultFixture(raw any, value reflect.Value) error {
	if value.Kind() == reflect.Pointer {
		value.Set(reflect.New(value.Type().Elem()))
		return decodeAPIResultFixture(raw, value.Elem())
	}
	switch value.Kind() {
	case reflect.Struct:
		object, ok := raw.(map[string]any)
		if !ok {
			return ErrInvalidAPIResult
		}
		seen := make(map[int]bool)
		for key, child := range object {
			index := -1
			for i := 0; i < value.NumField(); i++ {
				if strings.EqualFold(strings.ReplaceAll(key, "_", ""), value.Type().Field(i).Name) {
					index = i
					break
				}
			}
			if index < 0 || seen[index] {
				return ErrInvalidAPIResult
			}
			seen[index] = true
			if err := decodeAPIResultFixture(child, value.Field(index)); err != nil {
				return err
			}
		}
		for i := 0; i < value.NumField(); i++ {
			optional := value.Field(i).Kind() == reflect.Pointer
			if value.Type() == reflect.TypeFor[ReadResultContext]() {
				name := value.Type().Field(i).Name
				optional = optional || name == "CursorKind" || name == "Delimiter"
			}
			if !seen[i] && !optional {
				return ErrInvalidAPIResult
			}
		}
	case reflect.Uint64:
		object, ok := raw.(map[string]any)
		if !ok || len(object) != 1 {
			return ErrInvalidAPIResult
		}
		text, ok := object["$bigint"].(string)
		if !ok {
			return ErrInvalidAPIResult
		}
		n, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return err
		}
		value.SetUint(n)
	case reflect.Slice:
		object, ok := raw.(map[string]any)
		if !ok || len(object) != 1 {
			return ErrInvalidAPIResult
		}
		text, ok := object["$bytes"].(string)
		if !ok {
			return ErrInvalidAPIResult
		}
		data, err := hex.DecodeString(text)
		if err != nil {
			return err
		}
		value.SetBytes(data)
	case reflect.String:
		text, ok := raw.(string)
		if !ok {
			return ErrInvalidAPIResult
		}
		value.SetString(text)
	case reflect.Bool:
		b, ok := raw.(bool)
		if !ok {
			return ErrInvalidAPIResult
		}
		value.SetBool(b)
	default:
		return fmt.Errorf("unhandled corpus type %s", value.Type())
	}
	return nil
}

func TestNativeReadWriteAPIResultsCorpus(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/api_results.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID, Type       string
			Input, Context any
			Accept         bool
		}
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	tested := 0
	for _, vector := range corpus.Vectors {
		var result any
		switch vector.Type {
		case "ReadResult":
			result = new(V4ReadResult)
		case "ReadProgress":
			result = new(V4ReadProgress)
		case "ReadMethodFailure":
			result = new(V4ReadMethodFailure)
		case "ReaderCursorSnapshot":
			result = new(V4ReaderCursorSnapshot)
		case "WriteProgress":
			result = new(V4WriteProgress)
		case "TransferProgress":
			result = new(V4TransferProgress)
		case "CloseResult":
			result = new(V4CloseResult)
		case "CleanupStatus":
			result = new(V4CleanupStatus)
		case "TypedError":
			result = new(V4TypedError)
		default:
			continue
		}
		tested++
		t.Run(vector.ID, func(t *testing.T) {
			err := decodeAPIResultFixture(vector.Input, reflect.ValueOf(result).Elem())
			if err == nil {
				if read, ok := result.(*V4ReadResult); ok {
					var context ReadResultContext
					err = decodeAPIResultFixture(vector.Context, reflect.ValueOf(&context).Elem())
					if err == nil {
						err = read.Validate(context)
					}
				} else if failure, ok := result.(*V4ReadMethodFailure); ok {
					var context ReadMethodFailureContext
					err = decodeAPIResultFixture(vector.Context, reflect.ValueOf(&context).Elem())
					if err == nil {
						err = failure.Validate(context)
					}
				} else if transfer, ok := result.(*V4TransferProgress); ok {
					var context TransferContext
					err = decodeAPIResultFixture(vector.Context, reflect.ValueOf(&context).Elem())
					if err == nil {
						err = transfer.Validate(context)
					}
				} else {
					err = result.(interface{ Validate() error }).Validate()
				}
			}
			if (err == nil) != vector.Accept {
				t.Fatalf("accept=%v, validation=%v", vector.Accept, err)
			}
		})
	}
	if tested < 35 {
		t.Fatalf("incomplete native read/write corpus: %d cases", tested)
	}
}

// Every currently allocated non-normal error must survive its exact registry
// projection. A wrong scope cannot become valid merely by using a known code.
func TestV4TypedErrorRegistryProjection(t *testing.T) {
	var registry struct {
		Metadata map[string]struct{ Scope, Retry string } `json:"error_code_metadata"`
	}
	if err := json.Unmarshal([]byte(ErrorCodeRegistryJSON), &registry); err != nil {
		t.Fatal(err)
	}
	for name, meta := range registry.Metadata {
		if name == "normal" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			err := V4TypedError{Code: V4ErrorCode(name), Scope: V4ErrorScope(meta.Scope), RetryDisposition: V4RetryDisposition(meta.Retry)}
			if err.Validate() != nil {
				t.Fatal("registered projection rejected", err)
			}
			if err.Scope == V4ErrorScopeSession {
				err.Scope = V4ErrorScopeStream
			} else {
				err.Scope = V4ErrorScopeSession
			}
			if err.Validate() == nil {
				t.Fatal("wrong error scope accepted", err)
			}
		})
	}
	failure := V4TypedError{Code: V4ErrorCodeStreamDataInvalid, Scope: V4ErrorScopeStream, RetryDisposition: V4RetryDispositionPreserveFacts}
	maxBytes := uint64(4)
	read := V4ReadResult{Data: []byte("x"), Progress: V4ReadProgress{Offset: 1, Filled: 1}, WaitStatus: V4WaitStatusReady, StreamStatus: V4StreamStatusError, Error: &failure}
	if err := read.Validate(ReadResultContext{Method: "read", Transferred: 1, MaxBytes: &maxBytes, StreamStatus: V4StreamStatusError, StreamError: &failure}); err != nil {
		t.Fatal("error-bearing successful handoff rejected", err)
	}
}
