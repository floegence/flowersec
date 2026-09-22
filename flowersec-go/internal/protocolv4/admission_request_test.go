package protocolv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
)

type admissionTestSigner struct {
	key              ed25519.PrivateKey
	calls            atomic.Int32
	entered, release chan struct{}
	bad              bool
}

func (s *admissionTestSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }
func (s *admissionTestSigner) Sign(input []byte) ([]byte, error) {
	s.calls.Add(1)
	if s.entered != nil {
		close(s.entered)
		<-s.release
	}
	signature := ed25519.Sign(s.key, input)
	if s.bad {
		signature[0] ^= 1
	}
	return signature, nil
}

func runtimeAdmissionRequest(t *testing.T, f *runtimeAdmissionFixture, signer *admissionTestSigner, guard func() error) *AdmissionRequest {
	t.Helper()
	codec, err := NewSignedMapCodec("FSB4", 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewAdmissionRequest(f.hello, f.binding, f.proof, f.certificate, codec, signer, guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestRuntimeAdmissionRequestSignsOriginalBindingOnce(t *testing.T) {
	for _, source := range []string{"live_authority", "preauthorized_pool"} {
		t.Run(source, func(t *testing.T) {
			f := newRuntimeAdmissionFixture(t, source, 5)
			seed := [32]byte{71, 23, 4}
			signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
			r := runtimeAdmissionRequest(t, f, signer, func() error { return nil })
			request, err := r.Build()
			if err != nil {
				t.Fatal(err)
			}
			defer request.Release()
			if _, err = f.hello.MatchFSB(f.binding, request, f.certificate); err != nil {
				t.Fatal(err)
			}
			nonce, _ := request.Field("admission_nonce").ByteString()
			if [32]byte(nonce) == ([32]byte{}) || [32]byte(nonce) != r.nonce {
				t.Fatal("original generated nonce missing")
			}
			wire, _ := request.Bytes()
			original := bytes.Clone(wire)
			if _, err = r.Build(); err != CBORFailure("admission_used") || signer.calls.Load() != 1 {
				t.Fatal("request resigned", err)
			}
			if !bytes.Equal(wire, original) {
				t.Fatal("original signed request changed")
			}
			other := runtimeAdmissionRequest(t, f, signer, func() error { return nil })
			second, err := other.Build()
			if err != nil {
				t.Fatal(err)
			}
			defer second.Release()
			otherNonce, _ := second.Field("admission_nonce").ByteString()
			if bytes.Equal(nonce, otherNonce) {
				t.Fatal("separate local owner reused nonce")
			}
			// This checks random generation only. A second invocation is not an
			// authorized retry; the durable/private connection guards prohibit it.
		})
	}
}

func TestRuntimeAdmissionRequestRetainsOriginalMaterial(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	seed := [32]byte{71, 23, 4}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
	r := runtimeAdmissionRequest(t, f, signer, func() error { return nil })
	proof, _ := f.proof.Bytes()
	certificate, _ := f.certificate.Bytes()
	proof, certificate = bytes.Clone(proof), bytes.Clone(certificate)
	f.proof.Release()
	f.certificate.Release()
	request, err := r.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Release()
	p, _ := request.Field("activation_authorization").ByteString()
	c, _ := request.Field("client_certificate").ByteString()
	if !bytes.Equal(p, proof) || !bytes.Equal(c, certificate) {
		t.Fatal("released verifier changed original input")
	}
}

func TestRuntimeAdmissionRequestFailureNeverRegenerates(t *testing.T) {
	for _, fault := range []string{"cancelled", "key", "signature", "closed"} {
		t.Run(fault, func(t *testing.T) {
			f := newRuntimeAdmissionFixture(t, "live_authority", 5)
			seed := [32]byte{71, 23, 4}
			signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
			live := true
			r := runtimeAdmissionRequest(t, f, signer, func() error {
				if !live {
					return context.Canceled
				}
				return nil
			})
			switch fault {
			case "cancelled":
				live = false
			case "key":
				seed[0]++
				signer.key = ed25519.NewKeyFromSeed(seed[:])
			case "signature":
				signer.bad = true
			case "closed":
				r.Close()
			}
			if m, err := r.Build(); err == nil || m != nil {
				t.Fatal("failed owner signed", err)
			}
			calls := signer.calls.Load()
			live = true
			signer.bad = false
			if m, err := r.Build(); err == nil || m != nil || signer.calls.Load() != calls {
				t.Fatal("failed signature regenerated", err)
			}
		})
	}
}

func TestRuntimeAdmissionRequestLateSignerCannotPublish(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	seed := [32]byte{71, 23, 4}
	signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:]), entered: make(chan struct{}), release: make(chan struct{})}
	r := runtimeAdmissionRequest(t, f, signer, func() error { return nil })
	result := make(chan error, 1)
	go func() {
		m, err := r.Build()
		if m != nil {
			m.Release()
			err = errors.New("late signature published")
		}
		result <- err
	}()
	<-signer.entered
	if _, err := r.Build(); err != CBORFailure("admission_busy") {
		t.Fatal("second signer queued", err)
	}
	r.Close()
	close(signer.release)
	if err := <-result; err != CBORFailure("admission_owner") {
		t.Fatal(err)
	}
	if signer.calls.Load() != 1 {
		t.Fatal("duplicate signing call")
	}
	if len(r.proof) != 0 || len(r.certificate) != 0 || r.nonce != ([32]byte{}) {
		t.Fatal("exited signing owner retained scratch")
	}
}
