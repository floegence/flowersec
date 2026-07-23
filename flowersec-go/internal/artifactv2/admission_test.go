package artifactv2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFSB2RoundTripAndBinding(t *testing.T) {
	for _, kind := range []PathKind{PathDirect, PathTunnel} {
		t.Run(string(kind), func(t *testing.T) {
			request, err := BuildRequest(validArtifact(t, kind), "q1")
			if err != nil {
				t.Fatal(err)
			}
			raw, err := MarshalRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := ParseRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Request.PathKind != kind || decoded.Request.ChosenCandidateID != "q1" {
				t.Fatalf("unexpected decoded request: %+v", decoded.Request)
			}
			if !bytes.Equal(decoded.Raw, raw) || decoded.LocalAdmissionBinding != AdmissionBinding(raw) {
				t.Fatal("FSB2 raw bytes or local admission binding drifted")
			}
		})
	}
}

func TestFSB2RejectsDuplicateUnknownAndWrongVariantFields(t *testing.T) {
	request, err := BuildRequest(validArtifact(t, PathDirect), "w1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	payload := raw[FSB2HeaderSize:]
	tests := []struct {
		name    string
		payload []byte
		kind    PathKind
	}{
		{name: "duplicate", payload: bytes.Replace(payload, []byte(`"profile":"flowersec/2"`), []byte(`"profile":"flowersec/2","profile":"flowersec/2"`), 1), kind: PathDirect},
		{name: "unknown", payload: replaceJSONField(t, payload, "future", true), kind: PathDirect},
		{name: "business", payload: replaceJSONField(t, payload, "tenant_id", "tenant-1"), kind: PathDirect},
		{name: "tunnel field on direct", payload: replaceJSONField(t, payload, "attach_token", "attach"), kind: PathDirect},
		{name: "direct field on tunnel", payload: replaceJSONField(t, payload, "routing_token", "route"), kind: PathTunnel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := rawFSB2Frame(tt.kind, tt.payload)
			if _, err := ReadRequest(bytes.NewReader(frame)); err == nil {
				t.Fatalf("ReadRequest accepted %s", frame)
			}
		})
	}

	bad := append([]byte(nil), raw...)
	bad[6] = 1
	if _, err := ReadRequest(bytes.NewReader(bad)); err == nil {
		t.Fatal("ReadRequest accepted unknown flags")
	}
}

func TestFSB2PayloadBoundaryAndPreallocationGuard(t *testing.T) {
	request, err := BuildRequest(validArtifact(t, PathDirect), "w1")
	if err != nil {
		t.Fatal(err)
	}
	base, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	basePayload := len(base) - FSB2HeaderSize
	wantEncodedTokenBytes := len(request.RoutingToken) + (MaxCanonicalFSB2Payload - basePayload)
	controls := wantEncodedTokenBytes / 6
	plain := wantEncodedTokenBytes % 6
	request.RoutingToken = strings.Repeat("\x01", controls) + strings.Repeat("a", plain)
	exact, err := MarshalRequest(request)
	if err != nil {
		t.Fatalf("marshal exact boundary: %v", err)
	}
	if got := len(exact) - FSB2HeaderSize; got != MaxCanonicalFSB2Payload {
		t.Fatalf("payload length = %d, want %d", got, MaxCanonicalFSB2Payload)
	}
	if _, err := ReadRequest(bytes.NewReader(exact)); err != nil {
		t.Fatalf("read exact boundary: %v", err)
	}

	var oversized [FSB2HeaderSize]byte
	copy(oversized[0:4], "FSB2")
	oversized[4] = 2
	oversized[5] = byte(pathKindCode(PathDirect))
	binary.BigEndian.PutUint32(oversized[8:12], MaxCanonicalFSB2Payload+1)
	reader := &countingReader{data: oversized[:]}
	_, err = ReadRequest(reader)
	if !errors.Is(err, ErrFSB2PayloadTooLarge) {
		t.Fatalf("oversized error = %v, want ErrFSB2PayloadTooLarge", err)
	}
	if reader.bytesRead != FSB2HeaderSize {
		t.Fatalf("oversized reader consumed %d bytes, want header-only %d", reader.bytesRead, FSB2HeaderSize)
	}
}

func TestFSA2StrictStatusAndReasonRegistry(t *testing.T) {
	reasons := ReasonRegistry{"capacity": {}, "invalid_token": {}}
	tests := []AdmissionResponse{
		{Status: AdmissionSuccess},
		{Status: AdmissionReject, Reason: "invalid_token"},
		{Status: AdmissionRetryable, Reason: "capacity"},
	}
	for _, response := range tests {
		raw, err := MarshalResponse(response, reasons)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadResponse(bytes.NewReader(raw), reasons)
		if err != nil {
			t.Fatal(err)
		}
		if got != response {
			t.Fatalf("response = %+v, want %+v", got, response)
		}
	}

	invalid := []AdmissionResponse{
		{Status: AdmissionSuccess, Reason: "invalid_token"},
		{Status: AdmissionReject},
		{Status: AdmissionRetryable, Reason: "unknown"},
		{Status: AdmissionStatus(9), Reason: "invalid_token"},
	}
	for _, response := range invalid {
		if _, err := MarshalResponse(response, reasons); err == nil {
			t.Fatalf("MarshalResponse accepted %+v", response)
		}
	}

	unknown := rawFSA2Frame(AdmissionReject, "unknown")
	if _, err := ParseResponse(unknown, reasons); err == nil {
		t.Fatal("ReadResponse accepted an unregistered reason")
	}
	for _, raw := range [][]byte{
		rawFSA2Frame(AdmissionSuccess, "invalid_token"),
		rawFSA2Frame(AdmissionReject, ""),
		rawFSA2Frame(AdmissionStatus(9), "invalid_token"),
	} {
		if _, err := ParseResponse(raw, reasons); err == nil {
			t.Fatalf("ReadResponse accepted malformed response %x", raw)
		}
	}
	valid, err := MarshalResponse(AdmissionResponse{Status: AdmissionSuccess}, reasons)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse(append(valid, 0), reasons); err == nil {
		t.Fatal("ParseResponse accepted bytes after declared reason")
	}
}

func rawFSB2Frame(kind PathKind, payload []byte) []byte {
	out := make([]byte, FSB2HeaderSize+len(payload))
	copy(out[0:4], "FSB2")
	out[4] = 2
	out[5] = byte(pathKindCode(kind))
	binary.BigEndian.PutUint32(out[8:12], uint32(len(payload)))
	copy(out[12:], payload)
	return out
}

func rawFSA2Frame(status AdmissionStatus, reason string) []byte {
	out := make([]byte, FSA2HeaderSize+len(reason))
	copy(out[0:4], "FSA2")
	out[4] = 2
	out[5] = byte(status)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(reason)))
	copy(out[8:], reason)
	return out
}

type countingReader struct {
	data      []byte
	bytesRead int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.bytesRead += n
	return n, nil
}
