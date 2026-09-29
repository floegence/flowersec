package sessionv4

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrier/quicbase"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/rawquic"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func nativeTransportCorePair(t *testing.T, profile string, application ...string) ([2]*SessionCore, context.Context) {
	return nativeTransportCorePairConfigured(t, profile, nil, application...)
}

func nativeTransportCorePairConfigured(t *testing.T, profile string, configure func(int, *executorFixture, *SessionPlan, *RPCServicesConfig), application ...string) ([2]*SessionCore, context.Context) {
	return nativeTransportCorePairPrepared(t, profile, nil, nil, configure, application...)
}

func nativeTransportCorePairPrepared(t *testing.T, profile string, clock *timev4.Clock, preparePlan func(int, *executorFixture, *SessionPlanConfig), configure func(int, *executorFixture, *SessionPlan, *RPCServicesConfig), application ...string) ([2]*SessionCore, context.Context) {
	t.Helper()
	app := "transport"
	if len(application) != 0 {
		app = application[0]
	}
	capacity := len(application) > 1 && application[1] == "capacity"
	datagrams := len(application) > 1 && application[1] == "datagrams"
	var fixtures [2]initialCoreFixture
	prepare := initialCorePrepareWithResources(t, &fixtures, false, func(c *SessionCoreConfig) {
		c.Native = true
		c.NativeAuthWorkers = 1
		c.SendWorkers = [3]uint32{2}
		c.NativeIngress = MaintenanceIngressPolicy{10000, 1000, 8}
		c.Streams = factoryStreamConfig()
		if datagrams {
			c.Datagrams = true
			c.WorkSlots = 6
		}
		if app != "transport" {
			// Account for credit updates from all admitted internal channels.
			// The transport-only fixture's eight-frame burst does not cover RPC.
			c.NativeIngress = MaintenanceIngressPolicy{10000, 1, 256}
			c.applicationServices = true
			c.Handlers = SessionStreamHandlerConfig{internal: true, RuntimeBytes: 4096}
			c.MaxScopes, c.WorkSlots = 16, 16
			c.Open.Active, c.Open.Terminal = 12, 32
			c.Open.PerClass = [3]uint32{2, 10}
			c.Open.PerOpener = [2][3]uint32{{2, 5}, {2, 5}}
			c.Open.Protected = [2][3]uint32{{0, 5}, {0, 5}}
			c.Open.Lifetime = [2][3]uint64{{1024, 1024}, {1024, 1024}}
			c.SendWorkers = [3]uint32{2, 10}
			c.Streams = SessionStreamConfig{ReceivePoolBytes: 1 << 20, ReceiveBytes: 32768, InitialReceiveLimit: 16384, SendBytes: 1024, QueueBytes: 16384, RuntimeBytes: 4096, WriteWaiters: 2, MaxPlaintext: 1152, Chunk: 1024}
			if app == "execution" {
				c.Open.Active = 13
				c.Open.PerClass[ManagementStream] = 1
				c.Open.PerOpener[0][ManagementStream], c.Open.Protected[0][ManagementStream] = 1, 1
				c.Open.Lifetime[0][ManagementStream], c.SendWorkers[ManagementStream] = 16, 1
			}
		}
		if capacity {
			c.MaxScopes = 1035
			c.Open.Active += 1022
			c.Open.PerClass[BusinessStream] = 1024
			c.Open.PerOpener[0][BusinessStream], c.Open.PerOpener[1][BusinessStream] = 1024, 1024
			c.Open.Terminal = 2048
			c.SendWorkers[BusinessStream] = 1024
			c.WorkSlots, c.NativeAuthWorkers = 4, 1
			c.NativeIngress = MaintenanceIngressPolicy{10000, 1, 256}
			c.Streams.ReceivePoolBytes = 1 << 20
		}
	}, func(c *resourcev4.Config) {
		c.Limit[resourcev4.Connections] = 4
		c.Limit[resourcev4.NativeHandles] = 64
		c.Limit[resourcev4.TLSHandshakes] = 4
		c.Limit[resourcev4.Tasks], c.Limit[resourcev4.WorkSlots] = 512, 512
		if capacity {
			c.ReservationSlots, c.ReferenceSlots = 16384, 32768
			c.Limit[resourcev4.SDKBytes] = 128 << 20
			c.Limit[resourcev4.Items] = 1 << 20
			c.Limit[resourcev4.Tasks], c.Limit[resourcev4.WorkSlots] = 1<<16, 1<<16
			c.Limit[resourcev4.Timers], c.Limit[resourcev4.NativeHandles] = 1<<16, 4096
		}
	})
	pair, configs := initialTestPairPrepared(t, profile, "stream", 0, func(h *cryptov4.HandshakeConfig, initial *InitialConfig) {
		if clock != nil {
			h.Clock = clock
			var err error
			h.Deadline, err = timev4.NewAge(clock, 60000, h.SessionDeadlineMS)
			if err != nil {
				t.Fatal(err)
			}
			initial.Deadline = h.Deadline
		}

		if app != "transport" {
			h.Session = testSessionContract(t, profile, app, 65536, 16, 0, h.Session.SessionNotAfterMS, 1<<20)
			initial.Limits.MaxFrame = 65536
		}
		if capacity {
			h.Session = testSessionContract(t, profile, app, 65536, 1035, 0, h.Session.SessionNotAfterMS, 1<<20)
			initial.Limits.MaxFrame = 65536
		}
		prepare(h, initial)
		if app != "transport" {
			if configure == nil {
				nativeTestRPCServices(t, &fixtures[h.Role])
			} else {
				nativeTestRPCServicesPlan(t, &fixtures[h.Role], nil, func(f *executorFixture, plan *SessionPlanConfig) {
					if preparePlan != nil {
						preparePlan(int(h.Role), f, plan)
					}
				}, func(f *executorFixture, p *SessionPlan, c *RPCServicesConfig) {
					configure(int(h.Role), f, p, c)
				})
			}
		}
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	limits := quicbase.DefaultLimits()
	limits.MaxInboundStreams = 24
	options := rawquic.OwnedOptions{Limits: limits, StreamSlots: 24, RuntimeBytes: 65536, ProviderBytes: 32 << 20, ProviderTasks: 16}
	if capacity {
		limits.MaxInboundStreams = 1164
		options.Limits, options.StreamSlots = limits, 1164
	}
	listener, err := rawquic.Listen("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{rawquic.ALPNDirect}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	allowance := 10 * time.Second
	if capacity {
		allowance = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), allowance)
	t.Cleanup(cancel)
	charge, err := rawquic.OwnedCharge(options)
	if err != nil {
		t.Fatal(err)
	}
	var connections [2]*rawquic.OwnedConnection
	connections[0], err = rawquic.DialOwned(ctx, netip.MustParseAddrPort(listener.Addr().String()), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, NextProtos: []string{rawquic.ALPNDirect}}, options, 262144, 128, fixtures[0].reserve(t, charge), fixtures[0].environment)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	connections[1], err = rawquic.AcceptOwned(accepted, options, fixtures[1].reserve(t, charge), fixtures[1].environment)
	if err != nil {
		t.Fatal(err)
	}
	var maintenance [2]*rawquic.OwnedStream
	cleanupConnections := func() {
		for _, c := range connections {
			_ = c.Close()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for i, c := range connections {
			if err := c.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
			if maintenance[i] != nil {
				_ = maintenance[i].Close()
				if err := maintenance[i].Retire(); err != nil {
					t.Error(err)
				}
				maintenance[i] = nil
			}
			if err := c.Retire(); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(cleanupConnections)
	maintenance[0], err = connections[0].OpenMaintenance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = pair[0].stream.Close()
	pair[0].stream = maintenance[0]
	if err = fixtures[0].plan.BindNativeConnection(connections[0]); err != nil {
		t.Fatal(err)
	}
	hello := initialHelloProfile(t, initialFixture(t, "client_hello_fields"), "ClientHello", profile)
	helloFrame, _ := initialFlight(0)
	first := make(chan error, 1)
	go func() {
		stream, e := connections[1].AcceptMaintenance(ctx)
		if e != nil {
			first <- e
			return
		}
		maintenance[1] = stream
		_ = pair[1].stream.Close()
		pair[1].stream = stream
		if e = fixtures[1].plan.BindNativeConnection(connections[1]); e == nil {
			e = pair[1].Receive(helloFrame, initialExact(hello))
		}
		first <- e
	}()
	if _, err = pair[0].Send(helloFrame, initialCopy(hello)); err != nil {
		t.Fatal(err)
	}
	if err = <-first; err != nil {
		t.Fatal(err)
	}
	wires := [][]byte{initialHelloProfile(t, initialFixture(t, "server_hello_fields"), "ServerHello", profile), configs[0].FSB, configs[0].FSA}
	for index, wire := range wires {
		frame, sender := initialFlight(uint8(index + 1))
		done := make(chan error, 1)
		go func() { done <- pair[1-sender].Receive(frame, initialExact(wire)) }()
		if _, err = pair[sender].Send(frame, initialCopy(wire)); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
	results := startInitialCorePair(pair, configs, &fixtures)
	var cores [2]*SessionCore
	for role := range 2 {
		result := waitInitialCoreOutcome(t, results[role])
		if result.err != nil {
			t.Fatal(result.err)
		}
		cores[role] = result.core
	}
	ended := make(chan error, 2)
	for _, core := range cores {
		go func() { ended <- core.Runtime().Run(ctx) }()
	}
	t.Cleanup(func() {
		for _, core := range cores {
			core.Close()
		}
		for range 2 {
			_ = waitRuntime(t, ended)
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for role := range 2 {
			if rpc := fixtures[role].plan.rpc; rpc != nil {
				rpc.Close()
				if err := rpc.waitChannel(cleanup); err != nil {
					t.Error(err)
				}
			}
			if err := fixtures[role].plan.Abort(cleanup); err != nil {
				t.Error(err)
			}
			if err := pair[role].WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
		}
		cleanupConnections()
		for role := range 2 {
			if got := fixtures[role].root.Snapshot().Reservations; app == "transport" && got != 1 {
				t.Error("native provider or Session retained resources", role, got)
			}
		}
	})
	return cores, ctx
}

func nativeTestRPCServices(t *testing.T, fixture *initialCoreFixture, configure ...func(*executorFixture, *SessionPlan, *RPCServicesConfig)) {
	nativeTestRPCServicesHistory(t, fixture, nil, configure...)
}

func nativeTestRPCServicesHistory(t *testing.T, fixture *initialCoreFixture, history []string, configure ...func(*executorFixture, *SessionPlan, *RPCServicesConfig)) {
	nativeTestRPCServicesPlan(t, fixture, history, nil, configure...)
}
func nativeTestRPCServicesPlan(t *testing.T, fixture *initialCoreFixture, history []string, preparePlan func(*executorFixture, *SessionPlanConfig), configure ...func(*executorFixture, *SessionPlan, *RPCServicesConfig)) {
	t.Helper()
	f := &executorFixture{root: fixture.root, serial: 100, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 4, ResidentReady: 2, CompletionRunning: 1, CompletionReserved: 2, QueryOwners: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	// Configured service fixtures need completion owners for their actual
	// outgoing result/item consumers in addition to the two Session floors.
	if len(configure) != 0 {
		f.config.CompletionReserved = 16
	}
	charge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitApplicationTask(t, f.executor.Done()) })
	accounts := []resourcev4.Account{fixture.scope.Tenant, fixture.scope.Session}
	planConfig := SessionPlanConfig{Services: true, ContractQueries: true, ExecutionHistoryNamespaces: history, RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		return AuthorizeApplicationResult{}, ErrApplicationAuthorization
	}}
	if preparePlan != nil {
		preparePlan(f, &planConfig)
	}
	p := applicationTestPlan(t, f, planConfig, accounts...)
	c := fixture.plan.config
	rpcConfig := RPCServicesConfig{Native: true, NotifyReceivePending: 16, NotifyPublishPending: 16, NotificationWaitMS: 10000, NotificationCleanupMS: 10000, CompletionGraceMS: 5000,
		ShortRequestBytes: 8192, ShortResponseBytes: 8192, ShortTaskCharge: f.executor.TaskCharge(), ShortCompletionCharge: f.executor.CompletionFloorCharge(), CryptoProfile: c.Session.Profile,
		Bootstrap: c.Streams, MaxDataPayloadBytes: 1024, Root: fixture.root, Owner: fixture.plan.resourceOwner, Accounts: accounts,
		Session: c.Session.Contract, Clock: c.Clock, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}},
		Routes: rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 4096, Clock: c.Clock}, Slots: 4, ResidentSlots: 2, MaxCaptureBytes: 1048576, RuntimeBytes: 4096, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, InvocationRuntimeBytes: 4096}
	for _, fn := range configure {
		fn(f, p, &rpcConfig)
	}
	rpc, err := p.InstallRPCServices(rpcConfig)
	if err != nil {
		t.Fatal(err)
	}
	fixture.plan.rpc = rpc
}

func nativeTransfer(t *testing.T, ctx context.Context, source, destination *StreamOwnership, body string) {
	t.Helper()
	if n, err := source.WriteAll(ctx, []byte(body)); n != len(body) || err != nil {
		t.Fatal("write", n, err)
	}
	var dst [64]byte
	result, err := destination.ReadInto(ctx, dst[:len(body)])
	if err != nil || string(dst[:result.Progress.Filled]) != body {
		t.Fatal("read", result, err, string(dst[:result.Progress.Filled]))
	}
}

func TestNativeTransportCoreRealQUICDuplex(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			cores, ctx := nativeTransportCorePair(t, profile)
			streams := factoryOpenPair(t, cores, ctx)
			nativeTransfer(t, ctx, streams[0], streams[1], "native original")
			if err := streams[0].CloseWrite(ctx); err != nil {
				t.Fatal(err)
			}
			var end [1]byte
			if result, err := streams[1].ReadInto(ctx, end[:]); err != nil || result.ReadTerminal != protocolv4.V4ReadTerminalEof {
				t.Fatal("native FIN", result, err)
			}
			nativeTransfer(t, ctx, streams[1], streams[0], "reverse survives FIN")
			if err := streams[1].CloseWrite(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := cores[0].ProbeLiveness(ctx, 1000); err != nil {
				t.Fatal("maintenance", err)
			}
		})
	}
}

// Corrupt one accepted native direction. Authentication failure resets that
// entire Stream, while independent associations and maintenance remain live.
type nativeCorruptWriter struct{ destination io.Writer }

func (w nativeCorruptWriter) Write(p []byte) (int, error) {
	copyOf := append([]byte(nil), p...)
	copyOf[len(copyOf)-1] ^= 1
	return w.destination.Write(copyOf)
}

func TestNativeTransportBadDirectionResetsStreamAndPreservesHealthyStream(t *testing.T) {
	cores, ctx := nativeTransportCorePair(t, protocolv4.DHProfileX25519)
	bad := factoryOpenPair(t, cores, ctx)
	healthy := factoryOpenPair(t, cores, ctx)
	bad[0].flow.send.writer.writer = nativeCorruptWriter{bad[0].flow.send.writer.writer}
	if _, err := bad[0].WriteAll(ctx, []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	var dst [16]byte
	if _, err := bad[1].ReadInto(ctx, dst[:]); err == nil {
		t.Fatal("invalid tag delivered as data")
	}
	if _, err := bad[1].WriteAll(ctx, []byte("reverse revoked")); err == nil {
		t.Fatal("authentication failure retained the reset Stream's reverse capability")
	}
	nativeTransfer(t, ctx, healthy[0], healthy[1], "independent healthy")
	nativeTransfer(t, ctx, healthy[1], healthy[0], "independent reverse")
	for {
		_, err := cores[1].ProbeLiveness(ctx, 1000)
		if err == nil {
			break
		}
		if !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestNativeTransportPartialInputDoesNotBlockHealthyStream(t *testing.T) {
	cores, ctx := nativeTransportCorePair(t, protocolv4.DHProfileX25519)
	paused := factoryOpenPair(t, cores, ctx)
	healthy := factoryOpenPair(t, cores, ctx)
	// A real native direction stops after the envelope prefix. It owns its
	// original partial-frame storage while B uses its complete positive credit.
	var prefix [protocolv4.EnvelopePrefixSize]byte
	binary.BigEndian.PutUint32(prefix[:4], 128)
	prefix[4] = byte(protocolv4.FrameStreamData)
	if _, err := paused[0].flow.send.writer.writer.Write(prefix[:]); err != nil {
		t.Fatal(err)
	}
	for {
		assembly := paused[1].flow.nativeReceive
		assembly.pool.mu.Lock()
		partial := assembly.phase == nativeDataReading && assembly.length != 0
		assembly.pool.mu.Unlock()
		if partial {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	nativeTransfer(t, ctx, healthy[0], healthy[1], strings.Repeat("x", 64))
	nativeTransfer(t, ctx, healthy[1], healthy[0], "independent reverse")
	assembly := paused[1].flow.nativeReceive
	assembly.pool.mu.Lock()
	stillPartial := assembly.phase == nativeDataReading && assembly.length != 0
	assembly.pool.mu.Unlock()
	if !stillPartial {
		t.Fatal("healthy progress waited for paused input cleanup")
	}
}

func TestNativeTransportRPCBootstrapAndIndependentChannels(t *testing.T) {
	for _, application := range []string{"services", "execution"} {
		for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
			t.Run(application+"/"+profile, func(t *testing.T) {
				cores, ctx := nativeTransportCorePair(t, profile, application)
				var first [2]*RPCChannel
				var assemblies [2]*NativeDataAssembly
				t.Cleanup(func() {
					if !t.Failed() {
						return
					}
					for role := range cores {
						a := cores[role].Admission()
						a.mu.Lock()
						t.Log("admission cause", role, a.failure)
						a.mu.Unlock()
						runtime := cores[role].Runtime()
						runtime.mu.Lock()
						t.Log("runtime cause", role, runtime.result)
						runtime.mu.Unlock()
						if x := assemblies[role]; x != nil {
							x.pool.mu.Lock()
							t.Log("original native cause", role, x.cause)
							x.pool.mu.Unlock()
						}
						if ch := first[role]; ch != nil {
							ch.mu.Lock()
							t.Log("original channel cause", role, ch.failure)
							ch.mu.Unlock()
						}
					}
				})
				for role, core := range cores {
					r := core.plan.rpc
					for {
						r.mu.Lock()
						first[role] = r.channel
						r.mu.Unlock()
						if first[role] != nil {
							break
						}
						select {
						case <-ctx.Done():
							t.Fatal("native bootstrap did not materialize", ctx.Err())
						case <-time.After(time.Millisecond):
						}
					}
					a := core.Admission()
					a.mu.Lock()
					s, err := a.slot(r.bootstrap.handle)
					bound := err == nil && s.carrier != nil && s.carrier.native != nil && s.carrier.shared == nil && s.flow.nativeReceive != nil && r.bootstrap.reader == nil
					if bound {
						assemblies[role] = s.flow.nativeReceive
					}
					a.mu.Unlock()
					if !bound {
						t.Fatal("scope one did not retain original native ownership")
					}
				}
				for role, core := range cores {
					r := core.plan.rpc
					f := &executorFixture{root: r.root, serial: 180}
					assertRPCChannelRefusal(t, ctx, r, f, first[role], first[role].Association().Channel)
					channel, err := r.OpenChannel(ctx, RPCBulk, streamTestDeadline(t, core.Engine()))
					if err != nil {
						t.Fatal("native dynamic RPC", err)
					}
					assertRPCChannelRefusal(t, ctx, r, f, channel, channel.Association().Channel)
					if _, err := r.OpenNotifyChannel(ctx, streamTestDeadline(t, core.Engine())); err != nil {
						t.Fatal("native notification channel", err)
					}
				}
				if application == "execution" {
					for _, core := range cores {
						r := core.plan.rpc
						for {
							r.mu.Lock()
							bound := r.management != nil && r.management.channel != nil
							r.mu.Unlock()
							if bound {
								break
							}
							select {
							case <-ctx.Done():
								t.Fatal("native management channel", ctx.Err())
							case <-time.After(time.Millisecond):
							}
						}
					}
				}
			})
		}
	}
}

// This original publication tail deliberately retains its input even after
// native Close. A finite cleanup observer cannot release its Session charge.
type nativeDelayedWriter struct {
	destination io.Writer
	entered     chan struct{}
	returned    chan struct{}
	once        sync.Once
}

func (w *nativeDelayedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.returned
	return w.destination.Write(p)
}

func TestNativeTransportCloseRetainsOriginalPublicationTail(t *testing.T) {
	cores, ctx := nativeTransportCorePair(t, protocolv4.DHProfileX25519)
	streams := factoryOpenPair(t, cores, ctx)
	w := &nativeDelayedWriter{destination: streams[0].flow.send.writer.writer, entered: make(chan struct{}), returned: make(chan struct{})}
	streams[0].flow.send.writer.writer = w
	write := make(chan error, 1)
	go func() { _, err := streams[0].WriteAll(ctx, []byte("held")); write <- err }()
	select {
	case <-w.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer close(w.returned)
	before := cores[0].plan.root.Snapshot()
	cores[0].Close()
	observer, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := cores[0].WaitCleanup(observer); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup forgot original publication", err)
	}
	if cores[0].plan.root.Snapshot().Charged[resourcev4.Sessions] != before.Charged[resourcev4.Sessions] {
		t.Fatal("close refunded live Session publication tail")
	}
}
