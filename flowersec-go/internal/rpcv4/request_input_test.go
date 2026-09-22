package rpcv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func decodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The original shared domain transcript supplies every immutable execution
// option. Only its last lp-payload is varied; this is independent of the runtime
// incremental verifier and also exercises the same shared cross-SDK oracle.
func inputFixture(t testing.TB, execution bool, payload []byte) (protocolv4.ApplicationHeader, *protocolv4.ServiceContract, []byte) {
	return inputFixtureWithLimit(t, execution, payload, 1024)
}

func inputFixtureWithLimit(t testing.TB, execution bool, payload []byte, limit uint32) (protocolv4.ApplicationHeader, *protocolv4.ServiceContract, []byte) {
	return inputFixtureWithContractLimit(t, execution, payload, limit, false)
}

func inputFixtureWithContractLimit(t testing.TB, execution bool, payload []byte, limit uint32, smallContract bool) (protocolv4.ApplicationHeader, *protocolv4.ServiceContract, []byte) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/transport_v4/domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var domains struct {
		Vectors []struct {
			ID     string
			Inputs struct{ Contract map[string]string }
			Result struct {
				Input  string `json:"input_hex"`
				Output string `json:"output_hex"`
			}
		}
	}
	if err := json.Unmarshal(data, &domains); err != nil {
		t.Fatal(err)
	}
	var contractWire, originalInput []byte
	for _, v := range domains.Vectors {
		if v.ID == "domain_execution_unary_request" {
			contractWire = decodeHex(t, v.Inputs.Contract["$bytes"])
			originalInput = decodeHex(t, v.Result.Input)
		}
	}
	if len(originalInput) == 0 {
		t.Fatal("missing shared digest transcript")
	}
	kind := "execution_unary_request"
	if !execution {
		kind = "transient_unary_request"
		data, err = os.ReadFile("../../../testdata/transport_v4/corpus.json")
		if err != nil {
			t.Fatal(err)
		}
		var corpus struct{ Vectors []struct{ ID, Hex string } }
		if err := json.Unmarshal(data, &corpus); err != nil {
			t.Fatal(err)
		}
		for _, v := range corpus.Vectors {
			if v.ID == "service_unary_transient" {
				contractWire = decodeHex(t, v.Hex)
			}
		}
	}
	if smallContract {
		// Independently rewrite the fixed corpus contract's canonical maximum
		// from 1 MiB to 1024, and its full LP body in the digest transcript.
		originalContract := contractWire
		marker := []byte{0x0a, 0x1a, 0, 0x10, 0, 0}
		if bytes.Count(contractWire, marker) != 1 {
			t.Fatal("contract maximum fixture changed")
		}
		contractWire = bytes.Replace(contractWire, marker, []byte{0x0a, 0x19, 4, 0}, 1)
		at := bytes.Index(originalInput, originalContract)
		if !execution || at < 4 {
			t.Fatal("missing original contract transcript")
		}
		rewritten := append([]byte(nil), originalInput[:at-4]...)
		rewritten = binary.BigEndian.AppendUint32(rewritten, uint32(len(contractWire)))
		rewritten = append(rewritten, contractWire...)
		originalInput = append(rewritten, originalInput[at+len(originalContract):]...)
	}
	codec, err := protocolv4.NewServiceContractCodec(2048)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(contractWire)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fields := []protocolv4.Field{
		{Name: "message_kind", Number: uint64(header(t, kind).Fields().Kind)},
		{Name: "type_id", Number: 1}, {Name: "payload_length", Number: uint64(len(payload))},
		{Name: "deadline_at_ms", Number: 50000}, {Name: "service_contract_digest", Kind: protocolv4.ByteString, Bytes: digest[:]},
		{Name: "admission_mode", Number: 0}, {Name: "response_limit_bytes", Number: uint64(limit)},
	}
	if execution {
		if !bytes.Equal(originalInput[len(originalInput)-3:], []byte("abc")) {
			t.Fatal("shared transcript changed")
		}
		input := append([]byte(nil), originalInput[:len(originalInput)-7]...)
		binary.BigEndian.PutUint32(input[len(input)-4:], limit)
		input = binary.BigEndian.AppendUint32(input, uint32(len(payload)))
		input = append(input, payload...)
		digest := sha256.Sum256(input)
		fields = append(fields, protocolv4.Field{Name: "operation_id", Kind: protocolv4.ByteString, Bytes: bytes.Repeat([]byte{1}, 32)}, protocolv4.Field{Name: "request_digest", Kind: protocolv4.ByteString, Bytes: digest[:]})
	}
	var storage [512]byte
	wire, err := protocolv4.EncodeMap(storage[:], "ApplicationHeader", fields)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := protocolv4.NewApplicationHeaderCodec()
	if err != nil {
		t.Fatal(err)
	}
	h, err := hc.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := contract.CheckRequest(h); err != nil && (!smallContract || limit <= 1024) {
		t.Fatal(err)
	}
	return h, contract, bytes.Clone(wire)
}

func inputReservation(t *testing.T, h protocolv4.ApplicationHeader, c InputConfig) (*resourcev4.Root, resourcev4.Reference) {
	t.Helper()
	charge, err := RequestInputCharge(h, c)
	if err != nil {
		t.Fatal(err)
	}
	config := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 4, ReservationSlots: 4, ReferenceSlots: 8, Limit: charge}
	backing, err := resourcev4.BackingBytes(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Limit[resourcev4.SDKBytes] += backing
	r, err := resourcev4.NewRoot(config)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := r.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ref.Release()
		r.Close()
		if !r.Snapshot().CleanupComplete {
			t.Error("input backing leaked", r.Snapshot())
		}
	})
	return r, ref
}

// v4.go_rpc_input.original_fragments
func TestRequestInputOriginalFragmentsAndOneTimeHandoff(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(map[bool]string{false: "transient", true: "execution"}[execution], func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x7c}, 1<<20)
			h, contract, headerWire := inputFixture(t, execution, payload)
			defer contract.Release()
			c := InputConfig{Capture: true, RuntimeBytes: 4096, HashRuntimeBytes: 512}
			root, ref := inputReservation(t, h, c)
			p, err := NewRequestInput(h, contract, c, ref)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			contract.Release() // No contract/decoder alias is needed during input.
			if _, err := p.Take(); err == nil {
				t.Fatal("partial input escaped")
			}
			parser, err := protocolv4.NewRPCFragmentParser()
			if err != nil {
				t.Fatal(err)
			}
			defer parser.Close()
			feed := func(wire []byte) {
				for len(wire) > 0 {
					chunk := wire[:min(len(wire), 257)]
					wire = wire[len(chunk):]
					for len(chunk) > 0 {
						n, part, err := parser.Next(chunk)
						if err != nil {
							t.Fatal(err)
						}
						chunk = chunk[n:]
						if n == 0 {
							t.Fatal("parser did not consume")
						}
						if part.Fragment.Serial == 0 || part.Fragment.Kind == protocolv4.RPCBegin {
							continue
						}
						if err := p.WriteAt(part.Fragment.Offset+part.ChunkOffset, part.Fragment.Payload); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			var wire [16384]byte
			n, err := protocolv4.EncodeRPCFragment(wire[:], protocolv4.RPCFragment{Kind: protocolv4.RPCBegin, Serial: 1, Header: headerWire})
			if err != nil {
				t.Fatal(err)
			}
			feed(wire[:n])
			for offset := 0; offset < len(payload); {
				end := min(offset+16367, len(payload))
				n, err := protocolv4.EncodeRPCFragment(wire[:], protocolv4.RPCFragment{Kind: protocolv4.RPCData, Serial: 1, Offset: uint32(offset), Payload: payload[offset:end]})
				if err != nil {
					t.Fatal(err)
				}
				feed(wire[:n])
				clear(wire[:])
				offset = end
			}
			if err := parser.End(); err != nil {
				t.Fatal(err)
			}
			if err := p.Finish(); err != nil {
				t.Fatal(err)
			}
			if err := p.Finish(); err == nil {
				t.Fatal("second complete gate")
			}
			verified, err := p.Take()
			if err != nil {
				t.Fatal(err)
			}
			defer verified.Close()
			if _, err := p.Take(); err == nil {
				t.Fatal("double input transfer")
			}
			p.Close()
			ref.Release()
			borrow, err := verified.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer borrow.Release()
			if _, err := verified.Borrow(); err == nil {
				t.Fatal("unbounded parallel borrow")
			}
			got, original, err := borrow.Bytes()
			if err != nil || original != h || !bytes.Equal(got, payload) {
				t.Fatal("original payload lost", err)
			}
			verified.Close()
			if verified.CleanupComplete() || root.Snapshot().Reservations != 1 {
				t.Fatal("live codec borrow refunded")
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("logical close erased live input")
			}
			borrow.Release()
			if !verified.CleanupComplete() || root.Snapshot().Reservations != 0 {
				t.Fatal("real input exit retained charge")
			}
			if _, _, err := borrow.Bytes(); err == nil {
				t.Fatal("released borrow reused")
			}
		})
	}
}

// v4.go_rpc_input.discard_digest
func TestRequestInputDiscardStillVerifiesOriginalDigest(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "tampered"}[wrong], func(t *testing.T) {
			payload := []byte("abc")
			h, contract, _ := inputFixture(t, true, payload)
			defer contract.Release()
			c := InputConfig{RuntimeBytes: 1024, HashRuntimeBytes: 512}
			_, ref := inputReservation(t, h, c)
			p, err := NewRequestInput(h, contract, c, ref)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if p.payload != nil {
				t.Fatal("discard allocated payload")
			}
			if wrong {
				payload[1] ^= 1
			}
			for i := range payload {
				if err := p.WriteAt(uint32(i), payload[i:i+1]); err != nil {
					t.Fatal(err)
				}
			}
			err = p.Finish()
			if wrong && err != protocolv4.CBORFailure("application_request_digest") || !wrong && err != nil {
				t.Fatal("digest result", err)
			}
			if _, err := p.Take(); err == nil {
				t.Fatal("discard exposed input")
			}
		})
	}
}

func TestRequestInputAbortTruncationAndEmptyBoundary(t *testing.T) {
	for _, mode := range []string{"abort", "wrong_abort", "truncated", "overlap", "overrun", "empty_data", "empty_payload"} {
		t.Run(mode, func(t *testing.T) {
			payload := []byte("abc")
			if mode == "empty_payload" {
				payload = nil
			}
			h, contract, _ := inputFixture(t, true, payload)
			defer contract.Release()
			c := InputConfig{Capture: true, RuntimeBytes: 1024, HashRuntimeBytes: 512}
			_, ref := inputReservation(t, h, c)
			p, err := NewRequestInput(h, contract, c, ref)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if mode == "empty_payload" {
				if err := p.Finish(); err != nil {
					t.Fatal(err)
				}
				if err := p.Abort(0); err == nil {
					t.Fatal("empty input aborted")
				}
				v, err := p.Take()
				if err != nil {
					t.Fatal(err)
				}
				v.Close()
				return
			}
			if err := p.WriteAt(0, payload[:1]); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "abort":
				if err := p.Abort(1); err != nil {
					t.Fatal(err)
				}
			case "wrong_abort":
				err = p.Abort(0)
			case "truncated":
				err = p.Finish()
			case "overlap":
				err = p.WriteAt(0, payload[:1])
			case "overrun":
				err = p.WriteAt(1, payload)
			case "empty_data":
				err = p.WriteAt(1, nil)
			}
			if mode != "abort" && err == nil {
				t.Fatal("invalid input accepted")
			}
			if err := p.WriteAt(1, payload[1:]); err == nil {
				t.Fatal("sealed input reopened")
			}
			if _, err := p.Take(); err == nil {
				t.Fatal("incomplete input delivered")
			}
		})
	}
}

func TestVerifiedInputStaleBorrowAndActualCallbackExit(t *testing.T) {
	h, contract, _ := inputFixture(t, false, []byte("abc"))
	defer contract.Release()
	c := InputConfig{Capture: true, RuntimeBytes: 1024}
	root, ref := inputReservation(t, h, c)
	p, err := NewRequestInput(h, contract, c, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.WriteAt(0, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := p.Finish(); err != nil {
		t.Fatal(err)
	}
	v, err := p.Take()
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	first, err := v.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	second, err := v.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	entered, exit, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		defer second.Release()
		b, _, err := second.Bytes()
		if err != nil {
			t.Error(err)
		}
		close(entered)
		<-exit
		if !bytes.Equal(b, []byte("abc")) {
			t.Error("close cleared active callback bytes")
		}
	}()
	<-entered
	v.Close()
	first.Release()
	if v.CleanupComplete() || root.Snapshot().Reservations != 1 {
		t.Error("stale borrower retired current alias")
	}
	close(exit)
	<-done
	if !v.CleanupComplete() {
		t.Fatal("callback did not release original backing")
	}
}

func TestRequestInputAdmissionFailureAndChargeOverflow(t *testing.T) {
	h, contract, _ := inputFixture(t, true, []byte("abc"))
	defer contract.Release()
	c := InputConfig{Capture: true, RuntimeBytes: 1024, HashRuntimeBytes: 512}
	_, ref := inputReservation(t, h, c)
	if _, err := NewRequestInput(header(t, "transient_unary_request"), contract, c, ref); err == nil {
		t.Fatal("wrong contract accepted")
	}
	if err := ref.Check(); err != nil {
		t.Fatal("pre-admission failure consumed owner", err)
	}
	p, err := NewRequestInput(h, contract, c, ref)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	for _, cfg := range []InputConfig{{Capture: true, RuntimeBytes: math.MaxUint64, HashRuntimeBytes: 512}, {Capture: true, RuntimeBytes: 1, HashRuntimeBytes: math.MaxUint64}, {Capture: true, RuntimeBytes: 1, HashRuntimeBytes: math.MaxUint64 - 512}} {
		if _, err := RequestInputCharge(h, cfg); err == nil {
			t.Fatal("charge overflow admitted")
		}
	}
}
