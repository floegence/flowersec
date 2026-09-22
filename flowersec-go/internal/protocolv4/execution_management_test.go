package protocolv4

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

// v4.go_management.canonical
func TestExecutionManagementCanonicalCorpus(t *testing.T) {
	c, err := NewManagementCodec()
	if err != nil {
		t.Fatal(err)
	}
	var out [1024]byte
	for _, v := range cborRefVectors(t) {
		if !strings.HasPrefix(v.ID, "management_") {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			var n int
			switch v.Schema {
			case "ExecutionManagementTarget":
				var target ManagementTarget
				target, err = c.DecodeTarget(wire)
				if err == nil {
					n, err = c.EncodeTarget(out[:], target)
				}
			case "QueryOperationResponse", "RequestCancelResponse":
				var result ManagementResult
				cancel := v.Schema == "RequestCancelResponse"
				result, err = c.DecodeResult(wire, cancel)
				if err == nil {
					n, err = c.EncodeResult(out[:], result, cancel)
				}
			default:
				return
			}
			if v.ExpectedError != "" {
				if err == nil {
					t.Fatal("accepted malformed payload")
				}
				return
			}
			if err != nil || !bytes.Equal(out[:n], wire) {
				t.Fatal("canonical round trip", err)
			}
		})
	}
}
func TestExecutionManagementParserSplitBoundaries(t *testing.T) {
	headers, err := NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	var wire [600]byte
	n, _, err := headers.Encode(wire[2:514], "query_operation_request", ApplicationHeaderFields{Type: 7, PayloadBytes: 3, DeadlineAtMS: 1000, ServiceContractDigest: [32]byte{9}, ControlSerial: 1})
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(wire[:2], uint16(n))
	copy(wire[n+2:], []byte{1, 2, 3})
	wireBytes := wire[:n+5]
	all := append(bytes.Clone(wireBytes), wireBytes...)
	for split := 1; split <= len(all); split++ {
		p, err := NewManagementParser()
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for start := 0; start < len(all); {
			limit := min(len(all), start+split)
			for start < limit {
				n, got, err := p.Next(all[start:limit])
				if err != nil || n == 0 {
					t.Fatal(split, start, n, err)
				}
				start += n
				if got != nil {
					count++
					if !bytes.Equal(got, wireBytes) || cap(got) != len(got) {
						t.Fatal("borrowed envelope changed")
					}
				}
			}
		}
		if count != 2 || p.End() != nil {
			t.Fatal("message boundary", split, count, p.End())
		}
	}
	for length := 1; length < len(wireBytes); length++ {
		p, _ := NewManagementParser()
		_, _, err = p.Next(wireBytes[:length])
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(p.End(), io.ErrUnexpectedEOF) {
			t.Fatal("partial EOF accepted", length)
		}
		if _, _, err = p.Next(wireBytes[length:]); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal("partial EOF not sticky")
		}
	}
}

// v4.go_management.expired_result
func TestExecutionManagementExpiredResultRequiresRetainedFacts(t *testing.T) {
	c, err := NewManagementCodec()
	if err != nil {
		t.Fatal(err)
	}
	result := ManagementResult{Status: "result_expired", Observation: ManagementObservation{Found: true, State: 3, Dispatched: true, ResultDeleted: true, ResultBytes: 4, ResultDigest: [32]byte{9}}}
	var wire [512]byte
	n, err := c.EncodeResult(wire[:], result, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.DecodeResult(wire[:n], false); err != nil || got != result {
		t.Fatal(got, err)
	}
	for _, change := range []func(*ManagementResult){
		func(v *ManagementResult) { v.Observation = ManagementObservation{Reason: "history_unknown"} },
		func(v *ManagementResult) { v.Observation.ResultDeleted = false },
		func(v *ManagementResult) { v.Observation.ResultAvailable = true },
		func(v *ManagementResult) { v.Status = "ok" },
	} {
		invalid := result
		change(&invalid)
		if _, err := c.EncodeResult(wire[:], invalid, false); err == nil {
			t.Fatal("contradictory expired result encoded", invalid)
		}
	}
	if _, err := c.EncodeResult(wire[:], result, true); err == nil {
		t.Fatal("query result substituted for cancellation result")
	}
}

// v4.go_management.absence_variant
func TestExecutionManagementAbsenceIsAClosedQueryVariant(t *testing.T) {
	c, err := NewManagementCodec()
	if err != nil {
		t.Fatal(err)
	}
	var wire [512]byte
	for _, status := range []string{"not_found", "history_unknown"} {
		reason := "not_registered"
		if status == "history_unknown" {
			reason = "history_unknown"
		}
		result := ManagementResult{Status: status, Observation: ManagementObservation{Reason: reason}}
		n, err := c.EncodeResult(wire[:], result, false)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.DecodeResult(wire[:n], false); err != nil || got != result {
			t.Fatal(got, err)
		}
		if _, err := c.EncodeResult(wire[:], result, true); err == nil {
			t.Fatal("absence query substituted for cancellation")
		}
		for _, change := range []func(*ManagementResult){
			func(v *ManagementResult) { v.Status = "ok" },
			func(v *ManagementResult) {
				v.Observation = ManagementObservation{Found: true, State: 3, Dispatched: true}
			},
			func(v *ManagementResult) {
				if reason == "not_registered" {
					v.Observation.Reason = "history_unknown"
				} else {
					v.Observation.Reason = "not_registered"
				}
			},
		} {
			invalid := result
			change(&invalid)
			if _, err := c.EncodeResult(wire[:], invalid, false); err == nil {
				t.Fatal("ambiguous absence query accepted", invalid)
			}
		}
	}
}
