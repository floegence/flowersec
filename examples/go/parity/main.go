// The two application endpoints share a process for this single-invitation
// example. They exchange RPC only through the public SDK over TLS WebSocket.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v7"
	cp "github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

const origin = "https://parity.example"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "capacity-worker" {
		if err := capacityWorker(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "issue-pair" || os.Args[1] == "authorize" || os.Args[1] == "endpoint") {
		var err error
		switch os.Args[1] {
		case "issue-pair":
			err = issuePair(os.Args[2:])
		case "authorize":
			err = serveAuthorizer(os.Args[2:])
		case "endpoint":
			err = runEndpoint(os.Args[2:])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	mode := flag.String("mode", "first", "first, contracts, or large")
	fixture := flag.String("contracts", "parity-contracts.json", "shared canonical parity declarations")
	state := flag.String("state", "", "existing private state directory for durable spend and admission markers")
	flag.Parse()
	if err := run(*mode, *fixture, *state); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

const markerContents = "flowersec/5\n"

// A successful marker survives application restarts on this filesystem. The
// example does not assume it can detect rollback of the filesystem itself.
func mark(dir, name string) error {
	return publish(dir, name, []byte(markerContents))
}

func publish(dir, name string, data []byte) error {
	return publicationSync((*os.File).Sync).publish(dir, name, data)
}

type publicationSync func(*os.File) error

func (flush publicationSync) publish(dir, name string, data []byte) error {
	if err := flush.link(dir, name, data); err != nil {
		return err
	}
	return flush.directory(dir)
}

func linkPublication(dir, name string, data []byte) error {
	return publicationSync((*os.File).Sync).link(dir, name, data)
}

func (flush publicationSync) link(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, flush(f), f.Close())
	if err != nil {
		return err
	}
	return os.Link(f.Name(), filepath.Join(dir, name))
}

func syncPublicationDirectory(dir string) error {
	return publicationSync((*os.File).Sync).directory(dir)
}

func (flush publicationSync) directory(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(flush(d), d.Close())
}

func cert() (*tls.Config, *x509.CertPool, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "parity.local"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, t, t, pub, key)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(crt)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, roots, nil
}

func run(mode, fixture, state string) error {
	if mode != "first" && mode != "contracts" && mode != "large" {
		return errors.New("unknown mode")
	}
	if state == "" {
		return errors.New("-state must name a private state directory")
	}
	info, err := os.Stat(state)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private")
	}
	want, err := readContracts(fixture)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	expires := time.Now().Add(2 * time.Minute)
	var limits fs.RPCFrameLimits
	if mode == "large" {
		limits = fs.RPCFrameLimits{ReadBytes: 64 << 20, WriteBytes: 64 << 20}
	}
	sh, err := fs.NewSessionHandlers(fs.SessionHandlerOptions{})
	if err != nil {
		return err
	}
	serverApp, err := install(sh, want, expires, mode == "large")
	if err != nil {
		return err
	}
	ch := fs.NewRPCHandlers()
	clientApp, err := install(ch, want, expires, mode == "large")
	if err != nil {
		return err
	}
	var record atomic.Pointer[cp.AuthorizationRecord]
	var resolutions atomic.Int32
	var releases atomic.Int32
	released := make(chan string, 1)
	take := make(chan struct{})
	accepted := make(chan fs.Session)
	a, err := fs.NewAcceptor(fs.AcceptorOptions{
		AllowedOrigins: []string{origin}, RPCFrameLimits: limits,
		Authorize: func(ctx context.Context, r cp.RuntimeAuthorizationRequest) (cp.AuthorizationResponse, error) {
			p := record.Load()
			if ctx.Err() != nil || p == nil || p.LookupKey() != r.LookupKey() {
				return cp.AuthorizationResponse{}, errors.New("no active invitation")
			}
			id := r.LookupKey()
			resp, err := cp.AuthorizeRuntime(r, *p, id)
			if err != nil {
				return cp.AuthorizationResponse{}, err
			}
			var decision struct {
				Decision string `json:"decision"`
			}
			if err = json.Unmarshal(resp.JSON(), &decision); err != nil {
				return cp.AuthorizationResponse{}, err
			}
			if decision.Decision != "allow" {
				return resp, nil
			}
			if err = mark(state, "accepted-"+id); err != nil {
				return cp.AuthorizationResponse{}, err
			}
			return resp, nil
		},
		ResolveHandlers: func(ctx context.Context, r cp.RuntimeAuthorizationRequest) (*fs.SessionHandlers, error) {
			p := record.Load()
			if ctx.Err() != nil || p == nil || p.LookupKey() != r.LookupKey() {
				return nil, errors.New("authorization record unavailable")
			}
			resolutions.Add(1)
			return sh, nil
		},
		Release: func(_ context.Context, id string) {
			if releases.Add(1) == 1 {
				released <- id
			}
		},
		OnSession: func(callback context.Context, s fs.Session, id string) error {
			if id != "first-public-v5" {
				return errors.New("unexpected accepted channel")
			}
			select {
			case <-take:
			case <-callback.Done():
				return callback.Err()
			case <-ctx.Done():
				return ctx.Err()
			}
			serverApp.bind(s)
			select {
			case accepted <- s:
			case <-callback.Done():
				return callback.Err()
			case <-ctx.Done():
				return ctx.Err()
			}
			<-callback.Done()
			return callback.Err()
		},
	})
	if err != nil {
		return err
	}
	tlsConfig, roots, err := cert()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	server, err := fs.NewWebSocketHTTPServer(fs.WebSocketHTTPServerOptions{Handler: a.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second})
	if err != nil {
		_ = listener.Close()
		return err
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	defer server.Close()
	endpoints, err := cp.NewEndpointSet(cp.EndpointConfig{ID: "wss", URL: "wss://" + listener.Addr().String() + fs.WebSocketDirectPath, TLS: cp.CAPolicy()})
	if err != nil {
		return err
	}
	issued, err := cp.NewIssuer().IssueDirect(cp.DirectIssueOptions{Session: cp.SessionOptions{ChannelID: "first-public-v5", ExpiresAt: expires}, Endpoints: endpoints, RendezvousGroupID: "direct", ListenerAudience: "parity", UpstreamAddress: listener.Addr().String()})
	if err != nil {
		return err
	}
	r := issued.AuthorizationRecord()
	record.Store(&r)
	artifact, err := fs.ParseArtifact(issued.ArtifactJSON())
	if err != nil {
		return err
	}
	lease, err := fs.NewArtifactLease(artifact, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return mark(state, "spent-"+r.LookupKey())
	})
	if err != nil {
		return err
	}
	client, err := fs.Connect(ctx, lease, fs.ConnectorOptions{Origin: origin, TrustRoots: roots, RPCHandlers: ch, RPCFrameLimits: limits})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()
	clientApp.bind(client)
	if mode == "large" {
		if err = verifyLargeEcho(ctx, client); err != nil {
			return err
		}
	} else {
		payload := value{Value: "ping"}
		var echo value
		if err = client.RPC().Call(ctx, 7001, payload, &echo); err != nil {
			return fmt.Errorf("first echo: %w", err)
		}
		if echo != payload {
			return errors.New("incorrect first echo")
		}
	}
	if resolutions.Load() != 1 {
		return errors.New("incorrect handler resolution count")
	}
	close(take)
	var peer fs.Session
	select {
	case peer = <-accepted:
	case <-ctx.Done():
		return ctx.Err()
	}
	if mode == "contracts" {
		results := make(chan error, 2)
		for _, s := range []fs.Session{client, peer} {
			go func() { results <- verifyContracts(ctx, s, want) }()
		}
		for range 2 {
			if err := <-results; err != nil {
				return fmt.Errorf("contracts: %w", err)
			}
		}
		// Changing a live grant must affect both discovery and the actual call.
		serverApp.mu.Lock()
		delete(serverApp.grant, 7005)
		serverApp.mu.Unlock()
		for _, negative := range []struct {
			id uint32
			q  any
		}{{queryID, query{namespace, []uint32{7005}}}, {queryID, query{namespace, []uint32{7890}}}, {7005, value{"datagram-ready"}}} {
			var remote *fs.RPCError
			err := client.RPC().Call(ctx, negative.id, negative.q, nil)
			if !errors.As(err, &remote) || remote.Code != 403 {
				return fmt.Errorf("expected application rejection for %d: %v", negative.id, err)
			}
		}
	}
	if err = client.Close(); err != nil {
		return fmt.Errorf("client close: %w", err)
	}
	for _, s := range []fs.Session{client, peer} {
		term, err := s.WaitTermination(ctx)
		if err != nil {
			return err
		}
		if term.Error.Code() != fs.SessionClosed {
			return fmt.Errorf("unexpected terminal state %s", term.Error.Code())
		}
	}
	select {
	case got := <-released:
		if got != r.LookupKey() || releases.Load() != 1 {
			return errors.New("incorrect lease release")
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	if err = server.Close(); err != nil {
		return err
	}
	if err = <-serveResult; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listener exit: %w", err)
	}
	fmt.Printf("mode=%s protocol=flowersec/5 carrier=direct-wss invitations=1 echo_before_application_take=true lease_releases=1\n", mode)
	if mode == "contracts" {
		fmt.Println("query_type=7004 contracts_verified_per_endpoint=4 denied_or_unknown_queries=2 denied_calls=1")
	}
	return nil
}

func verifyLargeEcho(ctx context.Context, s fs.Session) error {
	payload := make([]byte, largeEchoBytes)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	var out largeEchoPayload
	if err := s.RPC().Call(ctx, largeEchoID, payload, &out); err != nil {
		return fmt.Errorf("32 MiB echo: %w", err)
	}
	if !bytes.Equal(payload, out) {
		return errors.New("32 MiB echo differs")
	}
	fmt.Printf("payload_bytes=%d sha256=%x\n", len(out), sha256.Sum256(out))
	return nil
}
