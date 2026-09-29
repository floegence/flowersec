package assemblyv4

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/tlspolicy"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type quicAssemblyFixture struct {
	factory  *QUICCarrierFactory
	server   *QUICServer
	request  sessionv4.CarrierPreparationRequest
	entrance sessionv4.AcceptedEntranceConfig
	root     *resourcev4.Root
	owner    resourcev4.OwnerKey
	accounts []resourcev4.Account
}

func quicAssemblyTest(t *testing.T, pin bool) *quicAssemblyFixture {
	t.Helper()
	return quicAssemblyTestClock(t, pin, sessionTestClock(t))
}

func quicAssemblyTestClock(t *testing.T, pin bool, clock *timev4.Clock) *quicAssemblyFixture {
	t.Helper()
	f := new(quicAssemblyFixture)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.UnixMilli(1000), NotAfter: time.UnixMilli(200000),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().(*net.UDPAddr).AddrPort()
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	encode := func(schema string, fields ...protocolv4.Field) []byte {
		t.Helper()
		wire, err := protocolv4.EncodeMap(make([]byte, 16384), schema, fields)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	policyFields := []protocolv4.Field{{Name: "mode", Number: 0}, {Name: "require_consumer_tls13_verification", Kind: protocolv4.Boolean, Number: 1}}
	if pin {
		digest := sha256.Sum256(der)
		entry := encode("TLSPin", protocolv4.Field{Name: "leaf_der_sha256", Kind: protocolv4.ByteString, Bytes: digest[:]},
			protocolv4.Field{Name: "not_before_ms", Number: 2000}, protocolv4.Field{Name: "not_after_ms", Number: 190000},
			protocolv4.Field{Name: "certificate_profile", Kind: protocolv4.TextString, Text: tlspolicy.CertificateProfile})
		policyFields[0].Number = 1
		policyFields = append(policyFields, protocolv4.Field{Name: "pin_kind"}, protocolv4.Field{Name: "pins", Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81}, entry...)})
		roots = nil
	}
	policy := encode("TLSPolicy", policyFields...)
	leg := encode("Leg", protocolv4.Field{Name: "access_class"}, protocolv4.Field{Name: "leg_id", Kind: protocolv4.ByteString, Bytes: make([]byte, 16)},
		protocolv4.Field{Name: "endpoint_role", Number: 1}, protocolv4.Field{Name: "dialer_role"}, protocolv4.Field{Name: "listener_role", Number: 1},
		protocolv4.Field{Name: "carrier"}, protocolv4.Field{Name: "host", Kind: protocolv4.TextString, Text: "127.0.0.1"},
		protocolv4.Field{Name: "port", Number: uint64(address.Port())}, protocolv4.Field{Name: "alpn", Kind: protocolv4.TextString, Text: rawquic.ALPNDirect},
		protocolv4.Field{Name: "path", Kind: protocolv4.TextString}, protocolv4.Field{Name: "subprotocol", Kind: protocolv4.TextString},
		protocolv4.Field{Name: "tls_policy", Kind: protocolv4.EncodedMap, Bytes: policy})
	candidateID := [16]byte{77}
	route := encode("Route", protocolv4.Field{Name: "path_kind"}, protocolv4.Field{Name: "candidate_id", Kind: protocolv4.ByteString, Bytes: candidateID[:]},
		protocolv4.Field{Name: "direct_leg", Kind: protocolv4.EncodedMap, Bytes: leg})
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 30
	}
	f.root, err = resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 128})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.root.Close()
		if snapshot := f.root.Snapshot(); !snapshot.CleanupComplete {
			t.Error("QUIC assembly retained original resources", snapshot)
		}
	})
	f.owner = resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{1}, Backing: [16]byte{1}, Kind: 1}
	reserve := func(owner resourcev4.OwnerKey, charge resourcev4.Vector, accounts ...resourcev4.Account) resourcev4.Reference {
		t.Helper()
		ref, err := f.root.Reserve(owner, charge, accounts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	environment := reserve(f.owner, resourcev4.Vector{resourcev4.SDKBytes: 1})
	scope := corePlanTestScope(t, f.root, limit, 1)
	f.accounts = []resourcev4.Account{scope.Tenant}
	limits := quicbase.DefaultLimits()
	limits.MaxInboundStreams = 8
	options := rawquic.OwnedOptions{Limits: limits, StreamSlots: 8, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	sc := QUICServerConfig{Root: f.root, Owner: admissionResourceKey(f.owner, 600), Clock: clock, Accounts: f.accounts, Address: address,
		Route: route, Certificate: certificate, Roots: roots, Connection: options, Connections: 2, RuntimeBytes: 65536,
		ListenerRuntimeBytes: 65536, ListenerProviderBytes: 1 << 20, ListenerProviderTasks: 4}
	charge, err := QUICServerCharge(sc)
	if err != nil {
		t.Fatal(err)
	}
	f.server, err = NewQUICServer(sc, reserve(sc.Owner, charge, f.accounts...), environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = f.server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.server.WaitCleanup(ctx); err != nil {
			t.Error("QUIC server retained native owner", err)
		}
	})
	fc := QUICFactoryConfig{Root: f.root, Owner: admissionResourceKey(f.owner, 2), Clock: clock, Route: route, RemoteAddress: address,
		Roots: roots, Options: options, Connections: 1, RuntimeBytes: 65536}
	charge, err = QUICCarrierFactoryCharge(fc)
	if err != nil {
		t.Fatal(err)
	}
	f.factory, err = NewQUICCarrierFactory(fc, reserve(fc.Owner, charge), environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.factory.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.factory.WaitCleanup(ctx); err != nil {
			t.Error("QUIC factory retained native owner", err)
		}
	})
	charge, err = sessionv4.PreparedCarrierCharge(8192)
	if err != nil {
		t.Fatal(err)
	}
	preparedRef := reserve(admissionResourceKey(f.owner, 3), charge, scope.Tenant, scope.Session)
	deadline, err := timev4.NewAge(clock, 10000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte("flowersec/v4/route\x00"))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(route)))
	hash.Write(size[:])
	hash.Write(route)
	member := protocolv4.PoolMember{CandidateID: candidateID}
	copy(member.RouteDigest[:], hash.Sum(nil))
	f.request = sessionv4.CarrierPreparationRequest{Config: sessionv4.PreparedCarrierConfig{Candidate: member, Attempt: [16]byte{44},
		Session: testSessionContract(t, protocolv4.DHProfileX25519, "transport", 4096, 4, 0, ^uint64(0)),
		Role:    protocolv4.ClientToServer, Deadline: deadline, Reservation: preparedRef, Environment: environment, RuntimeBytes: 8192},
		Scope: scope, Route: route, Budget: sessionv4.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}}
	f.entrance = sessionv4.AcceptedEntranceConfig{RuntimeBytes: 8192, InitialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192,
		Initial: sessionv4.InitialConfig{Role: protocolv4.ServerToClient, Profile: protocolv4.DHProfileX25519, ActivationSourceProfile: "preauthorized_pool",
			Deadline: deadline, Limits: sessionv4.InitialLimits{MaxFrame: 4096, Nodes: 4096}}}
	return f
}

func (f *quicAssemblyFixture) accept(t *testing.T, ctx context.Context) *QUICIngress {
	t.Helper()
	ingress, err := f.server.Accept(ctx, f.entrance)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ingress.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := ingress.WaitCleanup(cleanup); err != nil {
			t.Error("QUIC ingress retained native owner", err)
		}
	})
	return ingress
}

func TestQUICFactoryServerPreparationPreservesOriginalOwnership(t *testing.T) {
	for _, pin := range []bool{false, true} {
		t.Run(map[bool]string{false: "ca", true: "pin"}[pin], func(t *testing.T) {
			f := quicAssemblyTest(t, pin)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			prepared, err := f.factory.PrepareCarrier(ctx, f.request)
			if err != nil {
				t.Fatal(err)
			}
			cleanupPreparedTest(t, prepared)
			ingress := f.accept(t, ctx)
			if f.server.Address() != f.factory.c.RemoteAddress || !prepared.AdmissionBinding().Native || prepared.AdmissionBinding().MessageCarrier {
				t.Fatal("native binding did not preserve original provider")
			}
			endpoint, err := ingress.provider.connection.AcceptedEndpoint()
			if err != nil || endpoint.Local != f.server.Address() || endpoint.ServerName != "" || !endpoint.TLS13 || endpoint.ALPN != rawquic.ALPNDirect {
				t.Fatal("native accepted endpoint differs from signed route", endpoint, err)
			}
			if f.root.Snapshot().Charged[resourcev4.Connections] != 2 {
				t.Fatal("client or pre-TLS server connection was not admitted")
			}
			f.factory.Close()
			pending, stop := context.WithTimeout(ctx, 10*time.Millisecond)
			if err := f.factory.WaitCleanup(pending); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("factory refunded a returned provider", err)
			}
			stop()
			if err := prepared.Check(); err != nil {
				t.Fatal("factory closure changed original carrier ownership", err)
			}
			if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); err != nil {
				t.Fatal(err)
			}
			// Opening a local QUIC stream does not publish it. The server must
			// wait for the first credential-bearing flight from activation.
			pending, stop = context.WithTimeout(ctx, 25*time.Millisecond)
			defer stop()
			entrance, err := ingress.PrepareAccepted(pending, f.request.Config.Deadline)
			if entrance != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("preparation published Flowersec bytes or lost cancellation", entrance, err)
			}
			if err := ingress.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := prepared.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := prepared.Retire(); err != nil {
				t.Fatal(err)
			}
			if err := f.factory.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQUICIngressClaimKeepsOriginalScopeAndDeadline(t *testing.T) {
	f := quicAssemblyTest(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prepared, err := f.factory.PrepareCarrier(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPreparedTest(t, prepared)
	ingress := f.accept(t, ctx)
	if result, err := ingress.PrepareAccepted(ctx, f.request.Config.Deadline); result != nil || !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("unclaimed physical ingress entered Environment preparation", err)
	}
	before := f.root.Snapshot().Charged
	if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, nil, f.entrance); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("preauth account omitted", err)
	}
	if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, []resourcev4.Account{f.request.Scope.Session}, f.entrance); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("preauth account substituted", err)
	}
	other := f.entrance
	other.Initial.Deadline, err = timev4.NewAge(f.factory.c.Clock, 10000, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, other); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("deadline substituted", err)
	}
	other = f.entrance
	other.Initial.Limits.MaxFrame++
	if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, other); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("entrance limits substituted", err)
	}
	if f.root.Snapshot().Charged != before {
		t.Fatal("local invalid claims changed native ownership")
	}
	if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); err != nil {
		t.Fatal(err)
	}
	if err := ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("same ingress claimed twice", err)
	}
	_ = ingress.Close()
	if err := ingress.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func quicTestClientHello(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		if vector.ID == "client_hello_fields" {
			wire, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			return wire
		}
	}
	t.Fatal("missing ClientHello vector")
	return nil
}

func TestQUICServerAcceptedEntranceReadsOnlyOriginalMaintenance(t *testing.T) {
	f := quicAssemblyTest(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	charge, err := rawquic.OwnedCharge(f.factory.c.Options)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(admissionResourceKey(f.owner, 900), charge, f.request.Scope.Tenant, f.request.Scope.Session)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Release()
	client, err := rawquic.DialOwned(ctx, f.server.Address(), &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect},
		RootCAs: f.factory.c.Roots, Time: func() time.Time { return time.UnixMilli(100000) }}, f.factory.c.Options, 131072, 128, ref, f.request.Config.Environment)
	if err != nil {
		t.Fatal(err)
	}
	var maintenance *rawquic.OwnedStream
	t.Cleanup(func() {
		_ = client.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if maintenance != nil {
			_ = maintenance.Close()
			if err := maintenance.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if err := maintenance.Retire(); err != nil {
				t.Error(err)
			}
		}
		if err := client.WaitCleanup(cleanup); err != nil {
			t.Error(err)
		}
		if err := client.Retire(); err != nil {
			t.Error(err)
		}
	})
	ingress := f.accept(t, ctx)
	if err = ingress.ClaimAdmission(f.root, f.owner, f.request.Config.Environment, f.accounts, f.entrance); err != nil {
		t.Fatal(err)
	}
	maintenance, err = client.OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := quicTestClientHello(t)
	wire, err := (protocolv4.Envelope{FrameType: protocolv4.FrameNegotiate, Payload: hello}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := maintenance.Write(wire); err != nil || n != len(wire) {
		t.Fatal("native first flight", n, err)
	}
	entrance, err := ingress.PrepareAccepted(ctx, f.request.Config.Deadline)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		entrance.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := entrance.WaitCleanup(cleanup); err != nil {
			t.Error(err)
		}
		if err := entrance.Retire(); err != nil {
			t.Error(err)
		}
	})
	got := make([]byte, 4096)
	n, err := entrance.ReadClientHello(got)
	if err != nil || !bytes.Equal(got[:n], hello) {
		t.Fatal("accepted entrance lost original maintenance bytes", n, err)
	}
	_ = ingress.Close()
	if ingress.provider.connection.CheckEnvironment(f.request.Config.Environment) != nil {
		t.Fatal("ingress close revoked transferred entrance")
	}
	_ = f.server.Close()
	pending, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	if err := f.server.WaitCleanup(pending); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("server released unretired entrance", err)
	}
	stop()
	entrance.Close()
	if err := entrance.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := entrance.Retire(); err != nil {
		t.Fatal(err)
	}
	if err := f.server.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestQUICFactoryRejectsChangedBindingBeforeNetwork(t *testing.T) {
	f := quicAssemblyTest(t, false)
	for _, failure := range []string{"route", "candidate", "scope", "address attempt", "contract"} {
		t.Run(failure, func(t *testing.T) {
			request := f.request
			switch failure {
			case "route":
				request.Route = bytes.Clone(request.Route)
				request.Route[len(request.Route)-1] ^= 1
			case "candidate":
				request.Config.Candidate.RouteDigest[0] ^= 1
			case "scope":
				request.Scope = sessionv4.SessionResourceScope{}
			case "address attempt":
				request.AddressAttempt = 1
			case "contract":
				request.Config.Session.Contract = protocolv4.SessionContract{}
			}
			before := f.root.Snapshot().Charged
			if prepared, err := f.factory.PrepareCarrier(context.Background(), request); prepared != nil || err == nil {
				t.Fatal("invalid binding reached native preparation", err)
			} else if failure == "address attempt" && err != native.ErrAddressesExhausted {
				t.Fatal("numeric inventory changed failure classification", err)
			}
			if f.root.Snapshot().Charged != before || f.request.Config.Reservation.Check() != nil {
				t.Fatal("rejection consumed caller ownership")
			}
		})
	}
}

func TestQUICServerCloseJoinsPendingAccept(t *testing.T) {
	f := quicAssemblyTest(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{})
	ended := make(chan error, 1)
	go func() {
		close(entered)
		_, err := f.server.Accept(ctx, f.entrance)
		ended <- err
	}()
	<-entered
	_ = f.server.Close()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("closed listener published ingress")
		}
	case <-ctx.Done():
		t.Fatal("native Accept did not return", ctx.Err())
	}
	if err := f.server.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}
