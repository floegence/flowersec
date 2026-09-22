package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// Test material is signed from the shared canonical templates, with real
// matching endpoint DH/signature keys. These local test keys are not an issuer
// trust store, time/revocation source or durable deployment qualification.
func initialSignTemplate(t *testing.T, schema string, wire []byte, changes map[string]protocolv4.Field, seed [32]byte, sources ...string) *protocolv4.SignedMap {
	t.Helper()
	d, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	source := "live_authority"
	if len(sources) > 0 {
		source = sources[0]
	}
	context := protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": source}}
	doc, err := d.DecodeShape(wire, schema, context)
	if err != nil {
		t.Fatal(schema, err)
	}
	defer doc.Release()
	var registry struct {
		Maps map[string]struct {
			Signature int `json:"signature_field"`
			Fields    map[string]struct{ Name, Type string }
		} `json:"frame_maps"`
	}
	if err = json.Unmarshal([]byte(protocolv4.CBORSyntaxRegistryJSON), &registry); err != nil {
		t.Fatal(err)
	}
	var fields []protocolv4.Field
	for _, spec := range registry.Maps[schema].Fields {
		if spec.Name == "signature" || spec.Name == "client_signature" || spec.Name == "server_signature" {
			continue
		}
		if replacement, ok := changes[spec.Name]; ok {
			replacement.Name = spec.Name
			fields = append(fields, replacement)
			continue
		}
		v := doc.Root().Named(schema, spec.Name)
		if v.Encoded() == nil {
			continue
		}
		f := protocolv4.Field{Name: spec.Name}
		switch spec.Type {
		case "bytes":
			f.Kind = protocolv4.ByteString
			f.Bytes, _ = v.ByteString()
		case "text":
			f.Kind = protocolv4.TextString
			f.Text, _ = v.Text()
		case "map":
			f.Kind = protocolv4.EncodedMap
			f.Bytes = v.Encoded()
		case "array":
			f.Kind = protocolv4.EncodedArray
			f.Bytes = v.Encoded()
		case "bool":
			f.Kind = protocolv4.Boolean
			b, _ := v.Bool()
			if b {
				f.Number = 1
			}
		default:
			if b, ok := v.ByteString(); ok {
				f.Kind = protocolv4.ByteString
				f.Bytes = b
			} else if encoded := v.Encoded(); len(encoded) > 0 && encoded[0]>>5 == 5 {
				f.Kind, f.Bytes = protocolv4.EncodedMap, encoded
			} else {
				f.Number, _ = v.Uint()
			}
		}
		fields = append(fields, f)
	}
	codec, err := protocolv4.NewSignedMapCodec(schema, 65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Sign(fields, seed, context)
	if err != nil {
		t.Fatal(schema, err)
	}
	t.Cleanup(signed.Release)
	return signed
}

func initialChild(t *testing.T, wire []byte, schema, field string) []byte {
	t.Helper()
	d, _ := protocolv4.NewDecoder(65536, 4096)
	doc, err := d.DecodeShape(wire, schema, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Release()
	b, ok := doc.Root().Named(schema, field).ByteString()
	if !ok {
		t.Fatal("missing embedded map", field)
	}
	return bytes.Clone(b)
}

func TestInitialNegotiationBuildsSignedAdmissionAndReady(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			baseFSB := initialFixture(t, "fsb_fields")
			certificateTemplate := initialChild(t, baseFSB, "FSB4", "client_certificate")
			var certificates [2]*protocolv4.SignedMap
			var signers [2]bootstrapSigner
			var keys [2]*cryptov4.DHKey
			var identities [2][32]byte
			for role := range 2 {
				var err error
				keys[role], err = cryptov4.GenerateDHKey(profile)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(keys[role].Close)
				seed := [32]byte{byte(73 + role), 29, 8}
				signers[role] = bootstrapSigner{ed25519.NewKeyFromSeed(seed[:])}
				spec, _ := protocolv4.Profile(profile)
				dh, err := protocolv4.EncodeMap(make([]byte, 128), "NoiseStaticPublicKey", []protocolv4.Field{{Name: "algorithm", Number: uint64(spec.DHAlgorithm)}, {Name: "public_key_bytes", Kind: protocolv4.ByteString, Bytes: keys[role].PublicKey()}})
				if err != nil {
					t.Fatal(err)
				}
				certificates[role] = initialSignTemplate(t, "IdentityCertificate", certificateTemplate, map[string]protocolv4.Field{
					"expires_at_ms": {Number: 1000000},
					"role":          {Number: uint64(role)}, "crypto_profile_id": {Kind: protocolv4.TextString, Text: profile}, "noise_static_public_key": {Kind: protocolv4.EncodedMap, Bytes: dh},
					"ed25519_public_key": {Kind: protocolv4.ByteString, Bytes: signers[role].PublicKey()},
				}, [32]byte{1})
				identities[role], err = certificates[role].Digest("certificate_digest")
				if err != nil {
					t.Fatal(err)
				}
			}
			artifact := initialSignTemplate(t, "Artifact", initialFixture(t, "artifact_pool_sixteen_fields"), map[string]protocolv4.Field{
				"initiation_not_after_ms": {Number: 800000}, "session_not_after_ms": {Number: 900000},
				"crypto_profile_id": {Kind: protocolv4.TextString, Text: profile}, "client_identity_digest": {Kind: protocolv4.ByteString, Bytes: identities[0][:]}, "server_identity_digest": {Kind: protocolv4.ByteString, Bytes: identities[1][:]},
			}, [32]byte{1})
			artifactDigest, err := artifact.Digest("artifact_digest")
			if err != nil {
				t.Fatal(err)
			}
			_, routeDigest, err := artifact.CopyCandidateRoute(5, make([]byte, 16384))
			if err != nil {
				t.Fatal(err)
			}
			candidate := artifact.Field("candidates").Index(5)
			candidateID, _ := candidate.Named("Candidate", "candidate_id").ByteString()
			changes := map[string]protocolv4.Field{"artifact_digest": {Kind: protocolv4.ByteString, Bytes: artifactDigest[:]}, "candidate_selection": {Kind: protocolv4.ByteString, Bytes: candidateID}, "route_selection": {Kind: protocolv4.ByteString, Bytes: routeDigest[:]}}
			changes["activation_not_after_ms"] = protocolv4.Field{Number: 800000}
			changes["session_not_after_ms"] = protocolv4.Field{Number: 900000}
			for _, pair := range [][2]string{{"tenant_id", "tenant_id"}, {"issuer_key_id", "artifact_issuer_key_id"}, {"lease_id", "lease_id"}, {"audience", "audience"}, {"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}} {
				v := artifact.Field(pair[0])
				field := protocolv4.Field{}
				if b, ok := v.ByteString(); ok {
					field.Kind, field.Bytes = protocolv4.ByteString, b
				} else {
					field.Kind = protocolv4.TextString
					field.Text, _ = v.Text()
				}
				changes[pair[1]] = field
			}
			proof := initialSignTemplate(t, "ActivationAuthorization", initialChild(t, baseFSB, "FSB4", "activation_authorization"), changes, [32]byte{2})
			pw, _ := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
			activation, err := pw.BindActivation(artifact, proof, "live_authority", 5)
			if err != nil {
				t.Fatal(err)
			}
			attemptBytes, _ := proof.Field("attempt_id").ByteString()
			attempt := [16]byte(attemptBytes)
			clock := sessionTestClock(t)
			now, err := clock.Sample()
			if err != nil {
				t.Fatal(err)
			}
			var exchanges [2]*InitialExchange
			var hellos [2]*protocolv4.HelloBinding
			var configs [2]InitialConfig
			left, right := net.Pipe()
			streams := [2]net.Conn{left, right}
			t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
			negotiated := [2]chan error{make(chan error, 1), make(chan error, 1)}
			for role := range 2 {
				configs[role] = initialTestConfig(t, protocolv4.Direction(role), profile)
				configs[role].Deadline, err = timev4.NewAgeAt(clock, now, 60000, now.LowerMS+3600000)
				if err != nil {
					t.Fatal(err)
				}
				exchanges[role], err = NewInitialStream(context.Background(), configs[role], streams[role])
				if err != nil {
					t.Fatal(err)
				}
				cleanupInitial(t, exchanges[role])
				w, err := protocolv4.NewHelloWorkspace(protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024})
				if err != nil {
					t.Fatal(err)
				}
				hello := InitialHello{Artifact: artifact, Index: 5, Attempt: attempt, Workspace: w, Policy: protocolv4.HelloPolicy{RouteAllowedFeatures: 3, BindingMode: 1}, Offered: 3, BindingModes: 2}
				go func() {
					var err error
					if role == 0 {
						hellos[role], err = exchanges[role].NegotiateClient(hello)
					} else {
						hellos[role], err = exchanges[role].NegotiateServer(hello)
					}
					negotiated[role] <- err
				}()
			}
			for role := range 2 {
				if err := <-negotiated[role]; err != nil {
					t.Fatal("hello", role, err)
				}
			}
			var fsb, fsa, receivedFSB, receivedFSA *protocolv4.SignedMap
			var admission [32]byte
			received := make(chan error, 1)
			vc, _ := protocolv4.NewSignedMapCodec("FSB4", 65536, 4096)
			go func() {
				received <- exchanges[1].Receive(protocolv4.FrameAdmission, func(wire []byte) error {
					var err error
					receivedFSB, err = vc.Verify(wire, [32]byte(signers[0].PublicKey()), protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
					if err != nil {
						return err
					}
					admission, err = hellos[1].MatchFSB(activation, receivedFSB, certificates[0])
					return err
				})
			}()
			codec, _ := protocolv4.NewSignedMapCodec("FSB4", 65536, 4096)
			fsb, _, err = exchanges[0].SendAdmission(activation, proof, certificates[0], codec, signers[0], func() error { return nil })
			if err != nil {
				t.Fatal("FSB send", err)
			}
			defer fsb.Release()
			if err := <-received; err != nil {
				t.Fatal("FSB receive", err)
			}
			defer receivedFSB.Release()
			var admitted protocolv4.AdmissionResponse
			rc, _ := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
			go func() {
				received <- exchanges[0].Receive(protocolv4.FrameAdmissionResult, func(wire []byte) error {
					var err error
					receivedFSA, err = rc.Verify(wire, [32]byte(signers[1].PublicKey()), protocolv4.DecodeContext{})
					if err != nil {
						return err
					}
					admitted, err = hellos[0].MatchFSA(receivedFSA, certificates[1], activation, fsb, certificates[0])
					return err
				})
			}()
			response := protocolv4.AdmissionResponse{Admitted: true, ServerEpoch: 1, ReservationKey: [32]byte{4}, AdmissionBinding: admission, ServerIdentityDigest: identities[1]}
			sc, _ := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
			fsa, _, err = exchanges[1].SendAdmissionResponse(sc, certificates[1], response, signers[1], func() error { return nil })
			if err != nil {
				t.Fatal("FSA send", err)
			}
			defer fsa.Release()
			if err := <-received; err != nil {
				t.Fatal("FSA receive", err)
			}
			defer receivedFSA.Release()
			if admitted != response {
				t.Fatal("response facts changed")
			}
			material, err := hellos[0].BindHandshakeMaterial(artifact, activation, certificates[0], certificates[1], fsb, fsa)
			if err != nil {
				t.Fatal("handshake credential projection", err)
			}
			defer material.Close()
			for role := range 2 {
				fsbBytes, fsaBytes := make([]byte, 65536), make([]byte, 16384)
				config, err := cryptov4.AdmissionHandshakeConfig(material, cryptov4.AdmissionKeyConfig{Authorization: configs[role].Authorization, Role: protocolv4.Direction(role), LocalDH: keys[role], Signer: signers[role], Clock: clock, Deadline: configs[role].Deadline, SessionDeadlineMS: now.LowerMS + 3600000}, fsbBytes, fsaBytes)
				if err != nil {
					t.Fatal("handshake config", err)
				}
				if config.SessionDeadlineMS != 900000 {
					t.Fatal("original deadline widened", config.SessionDeadlineMS)
				}
				wrong := config
				wrong.Signer = signers[1-role]
				if h, err := cryptov4.NewHandshake(wrong); err == nil || h != nil {
					t.Fatal("another certificate signer accepted")
				}
				clear(wrong.PSK[:])
				wrong = config
				wrong.LocalDH = keys[1-role]
				if h, err := cryptov4.NewHandshake(wrong); err == nil || h != nil {
					t.Fatal("another certificate static key accepted")
				}
				clear(wrong.PSK[:])
				go func() {
					defer clear(config.PSK[:])
					defer clear(fsbBytes)
					defer clear(fsaBytes)
					records := initialRecordLimits()
					records.MaxFrame = config.Session.Contract.Limits().MaxFrame
					records.MaxScopes = config.Session.Contract.Limits().MaxStreams
					engine, err := exchanges[role].Authenticate(config, records, func(*cryptov4.Engine) error { return nil })
					if engine != nil {
						engine.Close()
					}
					negotiated[role] <- err
				}()
			}
			for role := range 2 {
				if err := <-negotiated[role]; err != nil {
					t.Fatal("Noise/READY", role, err)
				}
			}
		})
	}
}
