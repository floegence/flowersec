package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func assertOnceInitialSigningRetained(t *testing.T, codec *protocolv4.SignedMapCodec, signed *protocolv4.SignedMap, byteCap, nodeCap int) {
	t.Helper()
	// Observe backing lengths without exporting a diagnostic API or borrowing
	// private arrays. The real peer verification and Noise use the live map.
	state := reflect.ValueOf(codec).Elem()
	decoder := state.FieldByName("decoder").Elem()
	if !state.FieldByName("sealed").Bool() || state.FieldByName("message").Len() != 0 || state.FieldByName("encoded").Len() != byteCap || decoder.FieldByName("byteLimit").Int() != int64(byteCap) || decoder.FieldByName("nodeLimit").Int() != int64(nodeCap) {
		t.Fatal("original signing flight retained its full signing input or changed declared capacities")
	}
	if wire, err := signed.Bytes(); err != nil || len(wire) == 0 {
		t.Fatal("compaction discarded the original signed admission map", err)
	}
}

type initialOnceSigningProvider struct {
	original         protocolv4.MapSigner
	failure          error
	entered, release chan struct{}
	calls            atomic.Uint32
	message          []byte
}

func (p *initialOnceSigningProvider) PublicKey() []byte { return p.original.PublicKey() }
func (p *initialOnceSigningProvider) Sign(message []byte) ([]byte, error) {
	p.calls.Add(1)
	if p.entered != nil {
		p.message = message
		close(p.entered)
		<-p.release
	}
	if p.failure != nil {
		return nil, p.failure
	}
	return p.original.Sign(message)
}

func TestAcceptedAdmissionOnceSigningFailureFencesOriginalFlight(t *testing.T) {
	for _, failure := range []string{"binding", "signer"} {
		t.Run(failure, func(t *testing.T) {
			f, e, _, a, _ := acceptedAdmissionFixture(t)
			server, response := admitAcceptedSQLite(t, f, a)
			originalResponse := response
			codec, err := protocolv4.NewOnceSigningMapCodec("FSA4", 16384, 4096)
			if err != nil {
				t.Fatal(err)
			}
			provider := &initialOnceSigningProvider{original: f.trust.signers[1]}
			var want error = protocolv4.CBORFailure("admission_response_binding")
			wantCalls := uint32(0)
			if failure == "binding" {
				response.AdmissionBinding[0] ^= 1
			} else {
				want = errors.New("original signing provider failure")
				provider.failure = want
				wantCalls = 1
			}
			signed, result, err := server.SendAdmissionResponse(codec, f.trust.certificates[1], response, provider, func() error { return e.guard.checkAdmitted() })
			if signed != nil || !result.Started || result.Submitted || !errors.Is(err, want) || provider.calls.Load() != wantCalls {
				t.Fatal("failed original FSA changed signing/publication facts", result, err, provider.calls.Load())
			}
			response = originalResponse
			provider.failure = nil
			if signed, repeated, err := server.SendAdmissionResponse(codec, f.trust.certificates[1], response, provider, func() error { return e.guard.checkAdmitted() }); signed != nil || repeated.Started || !errors.Is(err, want) || provider.calls.Load() != wantCalls {
				t.Fatal("failed original flight admitted a repeated signer", repeated, err, provider.calls.Load())
			}
			state := reflect.ValueOf(codec).Elem()
			if state.FieldByName("sealed").Bool() || state.FieldByName("message").Len() == 0 || state.FieldByName("encoded").Len() != 16384 {
				t.Fatal("failed signing retired original independent-job capacities")
			}
		})
	}
}

func TestAcceptedAdmissionOnceSigningCloseKeepsLateProviderAndCharge(t *testing.T) {
	f, e, _, a, _ := acceptedAdmissionFixture(t)
	server, response := admitAcceptedSQLite(t, f, a)
	codec, err := protocolv4.NewOnceSigningMapCodec("FSA4", 16384, 4096)
	if err != nil {
		t.Fatal(err)
	}
	provider := &initialOnceSigningProvider{original: f.trust.signers[1], entered: make(chan struct{}), release: make(chan struct{})}
	type outcome struct {
		signed *protocolv4.SignedMap
		write  InitialWriteResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		signed, result, err := server.SendAdmissionResponse(codec, f.trust.certificates[1], response, provider, func() error { return e.guard.checkAdmitted() })
		done <- outcome{signed, result, err}
	}()
	select {
	case <-provider.entered:
	case <-time.After(time.Second):
		close(provider.release)
		<-done
		t.Fatal("original FSA did not enter the signing provider")
	}
	original := bytes.Clone(provider.message)
	charged := f.root.Snapshot().Charged
	a.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = a.WaitCleanup(cleanup)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || f.root.Snapshot().Charged[resourcev4.Sessions] != charged[resourcev4.Sessions] || server.config.Reservation.CheckRetained() != nil || !bytes.Equal(provider.message, original) {
		close(provider.release)
		<-done
		t.Fatal("Close erased or refunded the original FSA before signing returned", err)
	}
	close(provider.release)
	got := <-done
	if got.signed != nil || got.write.Submitted || got.err == nil || provider.calls.Load() != 1 || !bytes.Equal(provider.message, make([]byte, len(provider.message))) {
		if got.signed != nil {
			got.signed.Release()
		}
		t.Fatal("late provider published or retained the canceled original FSA", got.write, got.err)
	}
	if signed, repeated, err := server.SendAdmissionResponse(codec, f.trust.certificates[1], response, provider, func() error { return nil }); signed != nil || repeated.Started || err == nil || provider.calls.Load() != 1 {
		t.Fatal("late provider completion revived the original flight", repeated, err)
	}
}
