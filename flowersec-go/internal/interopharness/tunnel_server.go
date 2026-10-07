package interopharness

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/assemblyv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/runtimehost"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// TunnelServer owns one original server material, admitted native preparation,
// server allow recipient and public Acceptor. The application control delivery
// uses its independently configured fixed mTLS identity and actual Handler.
// Successful delivery alone is neither an e2e admission nor a READY receipt.
type TunnelServer struct {
	Client                                            *Client
	Registration                                      *fs.TunnelServerRegistration
	Acceptor                                          *fs.ServeHandle
	mu                                                sync.Mutex
	delivered, allowed, allowing, accepting, accepted bool
	allowRequest                                      fs.TunnelServerAllowRequest
	grant                                             []byte
	address                                           string
	httpClient                                        *http.Client
	transport                                         *http.Transport
	options                                           fs.TunnelAcceptOptions
	localPoolClient                                   *RegisteredPoolClientInstallation
	serveDone                                         <-chan struct{}
	serveClose                                        func()
}

type TunnelServerOptions struct {
	LiveDeployment                      *RegisteredLiveServerDeployment
	SocketScope                         assemblyv4.NativeDialScope
	TLSCertificatePEM, TLSPrivateKeyPEM string
}

// CloseOwners starts shutdown for every concrete server owner that can retain
// a physical position after a reporter's bounded cleanup attempt.
func (s *TunnelServer) CloseOwners() {
	if s == nil {
		return
	}
	if s.Registration != nil {
		s.Registration.Close()
	}
	if s.Acceptor != nil {
		s.Acceptor.Close()
	}
	if s.serveClose != nil {
		s.serveClose()
	}
	if s.Client != nil {
		s.Client.CloseOwners()
	}
}

func (s *TunnelServer) WaitOwners(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var result error
	if s.Registration != nil {
		result = errors.Join(result, s.Registration.WaitCleanup(ctx))
	}
	if s.Acceptor != nil {
		result = errors.Join(result, s.Acceptor.WaitCleanup(ctx))
	}
	if s.serveDone != nil {
		select {
		case <-s.serveDone:
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	if s.Client != nil {
		result = errors.Join(result, s.Client.WaitOwners(ctx))
	}
	return result
}

func NewTunnelServer(ctx context.Context, reporter *Reporter, materialJSON, trustPEM, origin string, handlers HandlerConfig, nativeOptions ...TunnelServerOptions) (*TunnelServer, error) {
	return construct(reporter, func() *TunnelServer {
		if len(nativeOptions) > 1 {
			reporter.Fatal("one independently installed native TLS manifest is required")
		}
		var original Material
		reporter.Cleanup(func() { releaseOwnedMaterial(&original) })
		var liveInstallation *RegisteredLiveClientInstallation
		if len(nativeOptions) == 1 && nativeOptions[0].LiveDeployment != nil {
			var err error
			original, liveInstallation, err = nativeOptions[0].LiveDeployment.ServerMaterial(materialJSON, trustPEM, origin)
			if err != nil {
				reporter.Fatal(err)
			}
			materialJSON, err = original.JSON()
			if err != nil {
				reporter.Fatal(err)
			}
			if nativeOptions[0].TLSCertificatePEM != nativeOptions[0].LiveDeployment.CertificatePEM || nativeOptions[0].TLSPrivateKeyPEM != nativeOptions[0].LiveDeployment.PrivateKeyPEM {
				reporter.Fatal("native live B TLS options differ from its independent installation")
			}
		} else {
			if err := json.Unmarshal([]byte(materialJSON), &original); err != nil {
				reporter.Fatal(err)
			}
		}
		if original.Source == "live_authority" && liveInstallation == nil {
			reporter.Fatal("live B requires its independent installation before relay publication")
		}
		if original.Role != 1 {
			reporter.Fatal("server requires original endpoint B material")
		}
		routeDecoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			reporter.Fatal(err)
		}
		originalRoute, err := routeDecoder.DecodeMap(original.Route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		listenerRole, listenerOK := originalRoute.Root().Named("Route", "server_leg").Named("Leg", "listener_role").Uint()
		originalRoute.Release()
		if !listenerOK || listenerRole != 1 && listenerRole != 2 {
			reporter.Fatal("original endpoint B listener role is invalid")
		}
		var socketScope assemblyv4.NativeDialScope
		if len(nativeOptions) == 1 {
			socketScope = nativeOptions[0].SocketScope
		}
		clientOption := ClientOptions{LiveDeployment: liveInstallation, DeferCarrier: listenerRole == 1, DialScope: socketScope}
		if original.Source == "preauthorized_pool" && len(nativeOptions) == 1 {
			clientOption.PoolDeployment = nativeOptions[0].LiveDeployment
		}
		clientOptions := []ClientOptions{clientOption}
		client, err := NewClient(ctx, reporter, materialJSON, trustPEM, origin, handlers, clientOptions...)
		if err != nil {
			reporter.Fatal(err)
		}
		if client.Material.Role != 1 || (client.PoolPublication == nil && len(client.Material.Tunnels) != 2) {
			reporter.Fatal("server requires original paired tunnel material")
		}
		r, h := client.Runtime, client.Runtime.Authority
		if listenerRole == 1 {
			if len(nativeOptions) != 1 || nativeOptions[0].TLSCertificatePEM == "" || nativeOptions[0].TLSPrivateKeyPEM == "" {
				reporter.Fatal("endpoint B listener requires independent native TLS certificate and key")
			}
			certificate, err := tls.X509KeyPair([]byte(nativeOptions[0].TLSCertificatePEM), []byte(nativeOptions[0].TLSPrivateKeyPEM))
			if err != nil {
				reporter.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(trustPEM)) {
				reporter.Fatal("native listener CA trust is missing")
			}
			address, kind, _, err := materialRoute(client.Material.Route, 1)
			if err != nil {
				reporter.Fatal(err)
			}
			config := runtimehost.NativeTunnelListenerConfig{Root: h.Root, Owner: h.Owner(), Accounts: []resourcev4.Account{h.Scope[1].Tenant}, Environment: h.Environment, Clock: h.Clock, Route: h.Route, Deployment: client.Material.RelayDeployment, Side: protocolv4.ServerToClient, Session: h.Admission[1].Core.Session, RuntimeBytes: 65536, Leg: reporter.nativeScopedLeg(kind, address, certificate, roots, socketScope)}
			cost, err := runtimehost.NativeTunnelListenerCharge(config)
			if err != nil {
				reporter.Fatal(err)
			}
			native, err := runtimehost.NewNativeTunnelListener(config, h.Reserve(cost, config.Accounts...), h.Environment)
			if err != nil {
				reporter.Fatal(err)
			}
			reporter.Cleanup(func() {
				native.Close()
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				reporter.ErrorIf(native.WaitCleanup(cleanup))
			})
			reporter.Owner(native.Close, native.WaitCleanup)
			client.Carrier = native
		}
		factory, ok := client.Carrier.(sessionv4.AdmittingConsumerCarrierFactory)
		if !ok {
			reporter.Fatal("native factory must admit original carrier preparation")
		}
		var grantWire []byte
		for _, entry := range client.Material.Tunnels {
			if entry.CandidateIndex == 0 && entry.Role == 1 {
				if grantWire != nil {
					reporter.Fatal("duplicate original server Grant")
				}
				grantWire = entry.Grant
			}
		}
		if client.PoolPublication != nil {
			grantWire = client.PoolPublication.serverGrant
		}
		var attempt [16]byte
		var end uint64
		if original.Source == "live_authority" {
			codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
			if err != nil {
				reporter.Fatal(err)
			}
			parent, err := codec.VerifyCredential(original.Artifact, h.Lease.Trust[0])
			if err != nil {
				reporter.Fatal(err)
			}
			var valid bool
			end, valid = parent.Field("initiation_not_after_ms").Uint()
			parent.Release()
			if !valid || end == 0 {
				reporter.Fatal("installed live B registry has no initiation deadline")
			}
			for _, entry := range original.Tunnels {
				if entry.Role == 1 {
					expiry, err := canonicalMaterialUint(entry.LiveGrant.MaxNotAfterMS, true)
					if err != nil {
						reporter.Fatal(err)
					}
					end = min(end, expiry)
				}
			}
		} else {
			if grantWire == nil {
				reporter.Fatal("original server Grant is missing")
			}
			codec, err := protocolv4.NewSignedMapCodec("Grant", 65536, 4096)
			if err != nil {
				reporter.Fatal(err)
			}
			grant, err := codec.VerifyCredential(grantWire, h.Lease.Trust[0])
			if err != nil {
				reporter.Fatal(err)
			}
			defer grant.Release()
			wire, ok := grant.Field("attempt_id").ByteString()
			if !ok || len(wire) != 16 {
				reporter.Fatal("original Grant has no attempt")
			}
			copy(attempt[:], wire)
			end, ok = grant.Field("not_after_ms").Uint()
			if !ok || end == 0 {
				reporter.Fatal("original Grant has no deadline")
			}
		}
		decoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			reporter.Fatal(err)
		}
		route, err := decoder.DecodeMap(h.Route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			reporter.Fatal(err)
		}
		defer route.Release()
		id, ok := route.Root().Named("Route", "candidate_id").ByteString()
		if !ok || len(id) != 16 {
			reporter.Fatal("original candidate is missing")
		}
		candidate := protocolv4.PoolMember{Index: 0, CandidateID: [16]byte(id), RouteDigest: h.BrowserRouteDigest}
		var recipient [16]byte
		if _, err = rand.Read(recipient[:]); err != nil || recipient == ([16]byte{}) {
			reporter.Fatal("original server recipient entropy unavailable")
		}
		var certificate, controlClient tls.Certificate
		var serverRoots, clientRoots *x509.CertPool
		var clientCertificateDER []byte
		allowAddress := "127.0.0.1:0"
		allowWorkMS := reporter.operationMS(15000)
		if original.Source == "preauthorized_pool" {
			allowWorkMS = 2000
		}
		if client.PoolPublication != nil {
			installed := nativeOptions[0].LiveDeployment.ServerAllow
			if installed == nil {
				reporter.Fatal("pool B lacks its independent A Allow transport installation")
			}
			address, _, err := installedPoolAllowAddress(*installed)
			if err != nil {
				reporter.Fatal(err)
			}
			allowAddress = address.String()
			allowWorkMS, err = canonicalMaterialUint(installed.WorkMS, true)
			if err != nil {
				reporter.Fatal(err)
			}
			certificate, err = tls.X509KeyPair([]byte(installed.TLS.CertificatePEM), []byte(installed.TLS.PrivateKeyPEM))
			if err != nil {
				reporter.Fatal(err)
			}
			clientRoots = x509.NewCertPool()
			if !clientRoots.AppendCertsFromPEM([]byte(installed.TLS.TrustPEM)) {
				reporter.Fatal("pool Allow installed A trust is empty")
			}
			clientCertificateDER = installed.ClientCertificateDER
			if len(clientCertificateDER) == 0 {
				reporter.Fatal("pool Allow requires the exact independently installed A certificate")
			}
		} else {
			certificate, serverRoots, _, _, err = TLSMaterial("127.0.0.1")
			if err != nil {
				reporter.Fatal(err)
			}
			controlClient, clientRoots, err = engineeringControlClientTLS()
			if err != nil {
				reporter.Fatal(err)
			}
			clientCertificateDER = controlClient.Certificate[0]
		}
		// The original host allowance covers the bounded TLS listener and HTTP
		// provider before either opens; SDK registration/carrier owners are charged
		// separately by the public constructors below.
		hostRef := h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 1048576, resourcev4.ProviderBytes: 8 << 20, resourcev4.Tasks: 8, resourcev4.WorkSlots: 2, resourcev4.Timers: 8, resourcev4.Items: 8})
		reporter.Cleanup(hostRef.Release)
		entrance := fs.AcceptedEntranceConfig{Initial: h.Admission[1].Initial, RuntimeBytes: 65536, InitialRuntimeBytes: 65536, CarrierRuntimeBytes: 65536}
		entrance.Initial.Deadline = nil
		registrationAccounts := []fs.ResourceAccount{h.Scope[1].Tenant, h.Scope[1].Session}
		options := fs.TunnelServerRegistrationOptions{Material: r.Materials[1], Root: h.Root, Owner: h.Owner(), Accounts: registrationAccounts, Environment: h.Environment, Dependencies: h.Environment, RuntimeBytes: 65536, Entrance: entrance,
			Registration: fs.TunnelServerAllowRegistrationConfig{Runtime: ctx, Clock: h.Clock, Factory: factory, Recipient: recipient, Candidate: candidate, Attempt: attempt, Scope: h.Scope[1], Budget: fs.CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, NotAfterMS: end, WorkMS: reporter.operationMS(10000), RuntimeBytes: 65536, RecipientRuntimeBytes: 65536, SubscriptionRuntimeBytes: 65536, CarrierRuntimeBytes: 65536},
			Allow:        fs.TunnelServerAllowHTTPSServiceConfig{Clock: h.Clock, ClientCertificateDER: clientCertificateDER, RequestsPerMinute: 60, Burst: 1, WorkMS: allowWorkMS, RuntimeBytes: 65536}}
		registrationCost, err := fs.TunnelServerRegistrationCharge(options)
		if err != nil {
			reporter.Fatal(err)
		}
		options.Reservation = h.Reserve(registrationCost, registrationAccounts...)
		registration, err := fs.NewTunnelServerRegistration(options)
		options.Reservation.Release()
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(func() {
			registration.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reporter.ErrorIf(registration.WaitCleanup(cleanup))
		})
		reporter.Owner(registration.Close, registration.WaitCleanup)
		binding, err := registration.Binding()
		if err != nil {
			reporter.Fatal(err)
		}
		binding.NotAfterMS = min(binding.NotAfterMS, end)
		if original.Source == "live_authority" {
			control, registeredRecipient, err := newRegisteredLiveControl(ctx, reporter, h, client.Material, liveInstallation, binding)
			if err != nil {
				reporter.Fatal(err)
			}
			client.LiveControl = control.Provider.(*controlv4.RegisteredControlTransport)
			client.LiveRecipient = registeredRecipient
		}
		serveConfig := fs.ServeConfig{Positions: 1, RuntimeBytes: 16384, DrainTimeoutMS: 1000, Clock: h.Clock}
		acceptor, err := fs.NewAcceptor(ctx, fs.AcceptorOptions{Environment: r.Environment, ServeOptions: fs.ServeOptions{Config: serveConfig, Reservation: r.reserve(fs.ServeCharge(serveConfig))}})
		if err != nil {
			reporter.Fatal(err)
		}
		reporter.Cleanup(func() {
			acceptor.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			reporter.ErrorIf(acceptor.WaitCleanup(cleanup))
		})
		reporter.Owner(acceptor.Close, acceptor.WaitCleanup)
		var listener net.Listener
		err = assemblyv4.RunNativeDial(ctx, socketScope, func() error { var err error; listener, err = net.Listen("tcp", allowAddress); return err })
		if err != nil {
			if listener != nil {
				_ = listener.Close()
			}
			reporter.Fatal(err)
		}
		bounded := newLimitedListener(listener, 1)
		server := &http.Server{Handler: registration.Handler(), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{certificate}, ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert, SessionTicketsDisabled: true}, MaxHeaderBytes: 8192, ReadHeaderTimeout: reporter.operationDuration(5 * time.Second), ReadTimeout: reporter.operationDuration(15 * time.Second), WriteTimeout: reporter.operationDuration(15 * time.Second), IdleTimeout: time.Second}
		done := make(chan struct{})
		var serveErr error
		go func() { defer close(done); serveErr = server.Serve(tls.NewListener(bounded, server.TLSConfig)) }()
		serveClose := func() {
			// Owner closure only initiates physical retirement. Do not perform an
			// unbounded graceful Shutdown here: the caller's cleanup deadline is
			// enforced by WaitOwners below.
			_ = server.Close()
			_ = bounded.Close()
			bounded.CloseConnections()
		}
		reporter.Owner(serveClose, func(ctx context.Context) error {
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		var transport *http.Transport
		var httpClient *http.Client
		if original.Source == "live_authority" {
			transport = &http.Transport{Proxy: nil, DialContext: scopedControlDial(socketScope), TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{controlClient}, RootCAs: serverRoots, ServerName: "127.0.0.1"}, TLSHandshakeTimeout: reporter.operationDuration(5 * time.Second), DisableKeepAlives: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ResponseHeaderTimeout: reporter.operationDuration(15 * time.Second), MaxResponseHeaderBytes: 8192}
			httpClient = &http.Client{Transport: transport, Timeout: reporter.operationDuration(15 * time.Second), CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control redirects are forbidden") }}
		}
		reporter.Cleanup(func() {
			if transport != nil {
				transport.CloseIdleConnections()
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(cleanup)
			_ = server.Close()
			_ = bounded.Close()
			bounded.CloseConnections()
			select {
			case <-done:
				if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
					reporter.ErrorIf(serveErr)
				}
			case <-cleanup.Done():
				reporter.ErrorIf(cleanup.Err())
			}
		})
		input := fs.AcceptedSessionInput{Config: h.Admission[1], Root: h.Root, ResourceOwner: h.Owner(), Environment: h.Environment, Preauth: h.Preauth, Scope: h.Scope[1], Store: h.Store, Authority: h.Authority}
		input.Config.Initial.Deadline = nil
		recordBytes := uint32(4096)
		if original.Source == "live_authority" {
			// Match the original registered admission store's bounded record workspace.
			recordBytes = 524288
		}
		result := &TunnelServer{Client: client, Registration: registration, Acceptor: acceptor, allowRequest: binding, grant: append([]byte(nil), grantWire...), address: "https://" + listener.Addr().String() + "/tunnel/server-allow", transport: transport, httpClient: httpClient, serveDone: done, serveClose: serveClose,
			options: fs.TunnelAcceptOptions{Input: input, Source: acceptedMaterial{r.Materials[1], h.Hello}, Limits: h.Limits, Entrance: entrance, Dependencies: h.Environment, Accounts: registrationAccounts, LocalCapabilities: h.Hello.Offered, IngressRuntimeBytes: 65536, IntakeRuntimeBytes: 65536, MaxAdmissionRecordBytes: recordBytes}}
		if original.Source == "preauthorized_pool" && client.PoolPublication == nil {
			// Same-process engineering setup provisions the sender independently
			// of the signed material. Only A's original Connect uses this identity.
			result.localPoolClient = &RegisteredPoolClientInstallation{WireRevision: WireRevision, Tenant: binding.Tenant, Audience: binding.Audience, ServerAllow: RegisteredPoolAllowInstallation{Endpoint: result.address, TLS: ownedLiveTLSInstallation(reporter, controlClient, engineeringTrustPEM(certificate)), WorkMS: "2000"}}
		}
		reporter.Cleanup(func() {
			clear(result.grant)
			result.grant = nil
			if result.localPoolClient != nil {
				*result.localPoolClient = RegisteredPoolClientInstallation{}
				result.localPoolClient = nil
			}
		})
		if client.PoolPublication != nil {
			// This is only an installation ACK. Native Prepare, Allow and HOP
			// wait for A's original Connect publication after confirmed TxA-P.
			if err = client.PoolPublication.acknowledge(ctx, result.liveGuard(ctx)); err != nil {
				reporter.Fatal(err)
			}
		}
		if client.LiveControl != nil {
			if listenerRole == 1 {
				if err = client.LiveControl.AnnounceOriginalRelayReady(ctx, result.liveGuard(ctx)); err != nil {
					reporter.Fatal(err)
				}
			}
			if err = client.LiveControl.RegisterLiveServer(ctx, recipient, result.liveGuard(ctx)); err != nil {
				reporter.Fatal(err)
			}
		}
		return result
	})
}

// DeliverOriginalAllow relays only the original live authority publication.
// Pool publications belong exclusively to A's original Connect.
// The live request serializes the same original binding and verified Grant
// into one bounded authenticated request to this exact registration. Its
// acknowledgement is read from the real server service after native prepare.
func (s *TunnelServer) DeliverOriginalAllow(ctx context.Context) (err error) {
	if s == nil || ctx == nil {
		return errors.New("invalid original tunnel server")
	}
	if s.Client.Material.Source == "preauthorized_pool" {
		return errors.New("pool server Allow belongs to the original client Connect")
	}
	s.mu.Lock()
	if s.delivered {
		s.mu.Unlock()
		return errors.New("original server allow already dispatched")
	}
	s.delivered, s.allowing = true, true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.allowing = false; s.allowed = err == nil; s.mu.Unlock() }()
	var activationDigest, grantDigest [32]byte
	if s.Client.LiveControl != nil {
		publication, err := s.Client.LiveControl.ReceiveOriginalLivePublication(ctx, s.liveGuard(ctx), s.Registration.ReserveOriginalLivePublication)
		if err != nil {
			return err
		}
		defer clear(publication.Activation)
		defer clear(publication.Grant)
		binding, proofDigest, originalGrantDigest, err := s.verifyOriginalLivePublication(publication)
		if err != nil {
			return err
		}
		s.allowRequest = binding
		s.grant = append(s.grant[:0], publication.Grant...)
		activationDigest, grantDigest = proofDigest, originalGrantDigest
		hello := s.Client.Runtime.Authority.Hello
		hello.Attempt = publication.Attempt
		s.options.Source = acceptedMaterial{s.Client.Runtime.Materials[1], hello}
	}
	limit, err := protocolv4.SchemaByteLimit("Grant")
	if err != nil {
		return err
	}
	wire := make([]byte, limit+1024)
	defer clear(wire)
	n, err := controlv4.EncodeTunnelServerAllow(wire, s.allowRequest, s.grant)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.address, bytes.NewReader(wire[:n:n]))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/cbor")
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/cbor" || response.ContentLength != 1 {
		return errors.New("actual original server allow was rejected")
	}
	var acknowledgement [2]byte
	n, err = io.ReadFull(response.Body, acknowledgement[:1])
	if err != nil || n != 1 || acknowledgement[0] != 0xf5 {
		return errors.New("invalid original server allow acknowledgement")
	}
	n, err = response.Body.Read(acknowledgement[1:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("original server allow has trailing bytes")
	}
	if s.Client.LiveControl != nil {
		if err = s.Client.LiveControl.AcknowledgeOriginalLiveAllow(ctx, s.allowRequest.Attempt, activationDigest, grantDigest, s.liveGuard(ctx)); err != nil {
			return err
		}
	}
	return nil
}

func (s *TunnelServer) Accept(ctx context.Context) (*fs.Session, error) {
	if s == nil || ctx == nil {
		return nil, errors.New("invalid original tunnel server")
	}
	s.mu.Lock()
	if (s.Client.Material.Source != "preauthorized_pool" && !s.allowed) || s.allowing || s.accepting || s.accepted {
		s.mu.Unlock()
		return nil, errors.New("original accepted position unavailable")
	}
	s.accepting = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.accepting = false; s.mu.Unlock() }()
	session, err := s.Registration.Accept(ctx, s.Acceptor, s.options)
	if err != nil {
		return nil, err
	}
	if err = s.Client.Runtime.retainSession(1, session); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.accepted = true
	s.mu.Unlock()
	return session, nil
}
