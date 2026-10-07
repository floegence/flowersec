package flowersec

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

func publicResumeVector(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		if v.ID == id {
			wire, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			return wire
		}
	}
	t.Fatal("missing vector", id)
	return nil
}

func TestResumeCodecCapturesCanonicalValues(t *testing.T) {
	f := newPublicReferenceFixture(t)
	charge, err := ResumeCodecCharge()
	codec, err := NewResumeCodec(f.reserve(t, charge, err))
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	for _, tc := range []struct {
		name       string
		protection uint8
	}{{"resume_signed_token_fields", ResumeSignedToken}, {"resume_mac_token_fields", ResumeMACToken}} {
		wire := publicResumeVector(t, tc.name)
		original := append([]byte(nil), wire...)
		token, err := codec.ImportToken(wire, tc.protection)
		if err != nil || token.EncodedBytes() != len(wire) {
			t.Fatal(token, err)
		}
		clear(wire)
		out := make([]byte, token.EncodedBytes())
		if _, err := token.CopyEncoded(out); err != nil || !bytes.Equal(out, original) {
			t.Fatal("token retained mutable input", err)
		}
		if _, err := codec.ImportToken(original, 1-tc.protection); err == nil {
			t.Fatal("accepted wrong token protection")
		}
		if _, err := codec.ImportToken(append(original, 0), tc.protection); err == nil {
			t.Fatal("accepted trailing token bytes")
		}
	}
	for _, tc := range []struct {
		name   string
		status uint8
	}{{"resume_result_accepted", ResumeAccepted}, {"resume_result_rejected", ResumeRejected}, {"resume_result_unknown", ResumeUnknown}} {
		result, err := codec.DecodeResult(publicResumeVector(t, tc.name))
		if err != nil || result.Status != tc.status || result.HasProgress != (tc.status == ResumeAccepted) {
			t.Fatal(result, err)
		}
	}
	codec.Close()
	if _, err := codec.ImportToken(nil, 0); !errors.Is(err, ErrOperationClosed) {
		t.Fatal(err)
	}
	if _, err := codec.DecodeResult(nil); !errors.Is(err, ErrOperationClosed) {
		t.Fatal(err)
	}
}

func TestPrepareResumeProjectsOriginalOperation(t *testing.T) {
	ctx := context.Background()
	owner, operation := &sessionv4.StreamOwnership{}, &sessionv4.UnaryOperation{}
	method := ResumeMethod{Kind: "example/resume", Contract: [32]byte{1}, DefaultResponseLimitBytes: 1024}
	codec, _ := protocolv4.NewResumeCodec()
	token, err := codec.DecodeToken(publicResumeVector(t, "resume_signed_token_fields"), 0)
	if err != nil {
		t.Fatal(err)
	}
	options := OperationOptions{DeadlineAtMS: 1<<53 + 33, AdmissionMode: 1, ExplicitAdmissionMode: true}
	calls := 0
	session := &Session{prepareResume: func(gotCtx context.Context, gotMethod sessionv4.ResumeMethodDefinition, gotTarget *sessionv4.StreamOwnership, gotToken protocolv4.ResumeToken, gotOptions rpcv4.UnaryPreparation) (*sessionv4.UnaryOperation, error) {
		calls++
		if gotCtx != ctx || gotMethod != method || gotTarget != owner || gotToken != token || gotOptions.DeadlineAtMS != options.DeadlineAtMS || gotOptions.AdmissionMode != 1 {
			t.Error("resume substituted original arguments")
		}
		return operation, nil
	}}
	handle, err := session.PrepareResume(ctx, method, &v4Stream{owner: owner}, token, options)
	if err != nil || handle.inner != operation || calls != 1 {
		t.Fatal(handle, calls, err)
	}
	if _, err := session.PrepareResume(ctx, method, nil, token, options); err == nil || calls != 1 {
		t.Fatal("missing target entered preparation", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.PrepareResume(ctx, method, &v4Stream{owner: owner}, token, options); !errors.Is(err, ErrOperationClosed) || calls != 1 {
		t.Fatal(err, calls)
	}
}
