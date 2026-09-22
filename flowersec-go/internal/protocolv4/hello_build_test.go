package protocolv4

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestRuntimeHelloBuildersAndAdmissionSignatures(t *testing.T) {
	for _, source := range []string{"live_authority", "preauthorized_pool"} {
		t.Run(source, func(t *testing.T) {
			f := newRuntimeAdmissionFixture(t, source, 5)
			w, err := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			client, err := w.BuildClientHello(make([]byte, 16384), f.artifact, 5, f.binding.attempt, 3|(uint64(1)<<63), 2, []byte("client hint"))
			if err != nil {
				t.Fatal(err)
			}
			server, h, err := w.BuildServerHello(make([]byte, 16384), f.artifact, 5, f.binding.attempt, client, 3, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}, []byte("server hint"))
			if err != nil {
				t.Fatal(err)
			}
			clientBinding, err := w.Bind(f.artifact, 5, f.binding.attempt, client, server, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1})
			if err != nil || clientBinding.transcript != h.transcript || clientBinding.transport != h.transport {
				t.Fatal("different endpoint contexts", err)
			}
			if h.features != 1 {
				t.Fatal("disabled resume or unknown optional offer selected")
			}
			d, _ := NewDecoder(16384, 4096)
			c, err := d.DecodeMap(client, "ClientHello", DecodeContext{})
			if err != nil {
				t.Fatal(err)
			}
			nonce, _ := c.Root().Named("ClientHello", "client_nonce").ByteString()
			if !bytes.Equal(nonce, f.binding.sessionNonce[:]) {
				t.Fatal("client nonce regenerated")
			}
			c.Release()
			seed := [32]byte{71, 23, 4}
			signer := &admissionTestSigner{key: ed25519.NewKeyFromSeed(seed[:])}
			codec, _ := NewSignedMapCodec("FSB4", 65536, 4096)
			request, err := NewAdmissionRequest(clientBinding, f.binding, f.proof, f.certificate, codec, signer, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer request.Close()
			fsb, err := request.Build()
			if err != nil {
				t.Fatal(err)
			}
			defer fsb.Release()
			admission, err := h.MatchFSB(f.binding, fsb, f.certificate)
			if err != nil {
				t.Fatal(err)
			}
			for _, admitted := range []bool{true, false} {
				response := AdmissionResponse{Code: 1}
				if admitted {
					response = AdmissionResponse{Admitted: true, ServerEpoch: 7, ReservationKey: [32]byte{4}, AdmissionBinding: admission, ServerIdentityDigest: h.serverIdentity}
				}
				rc, _ := NewSignedMapCodec("FSA4", 16384, 4096)
				fsa, err := h.BuildResponse(rc, f.serverCertificate, response, signer, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				defer fsa.Release()
				var result AdmissionResponse
				if admitted {
					result, err = clientBinding.MatchFSA(fsa, f.serverCertificate, f.binding, fsb, f.certificate)
				} else {
					result, err = clientBinding.MatchFSA(fsa, f.serverCertificate, nil, nil, nil)
				}
				if err != nil || result != response {
					t.Fatal("original generated response mismatch", admitted, result, response, err)
				}
			}
		})
	}
}

func TestRuntimeHelloBuilderRejectsDifferentOriginalBeforeResponse(t *testing.T) {
	f := newRuntimeAdmissionFixture(t, "live_authority", 5)
	w, _ := NewHelloWorkspace(HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
	client, err := w.BuildClientHello(make([]byte, 16384), f.artifact, 5, f.binding.attempt, 3, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	attempt := f.binding.attempt
	attempt[0] ^= 1
	if wire, _, err := w.BuildServerHello(make([]byte, 16384), f.artifact, 5, attempt, client, 3, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}, nil); err == nil || wire != nil {
		t.Fatal("other attempt echoed", err)
	}
	if wire, _, err := w.BuildServerHello(make([]byte, 16384), f.artifact, 6, f.binding.attempt, client, 3, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}, nil); err == nil || wire != nil {
		t.Fatal("other candidate echoed", err)
	}
	if wire, _, err := w.BuildServerHello(make([]byte, 16384), f.artifact, 5, f.binding.attempt, client, 3, HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 0, Exporter: make([]byte, 32)}, nil); err == nil || wire != nil {
		t.Fatal("unsupported mode selected", err)
	}
}
