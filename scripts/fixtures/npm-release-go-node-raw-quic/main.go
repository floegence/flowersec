package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v5"
	"github.com/floegence/flowersec/flowersec-go/v5/controlplane"
)

const (
	testID     = "release/npm-consumer/go-node-raw-quic/direct-session"
	rpcTypeID  = uint32(7001)
	streamKind = "release.consumer.echo"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tlsConfig, trustPEM, err := serverTLS()
	if err != nil {
		return fmt.Errorf("tls fixture: %w", err)
	}
	listener, err := flowersec.NewRawQUICDirectListener(flowersec.RawQUICListenerOptions{
		Address: "127.0.0.1:0", TLSConfig: tlsConfig, MaxInboundStreams: 8,
	})
	if err != nil {
		return fmt.Errorf("raw QUIC listener: %w", err)
	}
	defer listener.Close()

	endpoints, err := controlplane.NewEndpointSet(controlplane.EndpointConfig{
		ID:  "raw-quic",
		URL: "quic://" + listener.Address(),
		TLS: controlplane.CAPolicy(),
	})
	if err != nil {
		return fmt.Errorf("endpoint set: %w", err)
	}
	issued, err := controlplane.NewIssuer().IssueDirect(controlplane.DirectIssueOptions{
		Session: controlplane.SessionOptions{
			ChannelID: "release-consumer", ExpiresAt: time.Now().Add(time.Minute), MaxInboundStreams: 8,
		},
		Endpoints: endpoints, RendezvousGroupID: "release-consumer", ListenerAudience: "registry-readback",
		UpstreamAddress: "127.0.0.1:1",
	})
	if err != nil {
		return fmt.Errorf("issue artifact: %w", err)
	}
	record := issued.AuthorizationRecord()

	var rpcObserved atomic.Bool
	var streamObserved atomic.Bool
	released := make(chan struct{}, 1)
	sessionDone := make(chan error, 1)
	handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
	if err != nil {
		return err
	}
	if err := handlers.HandleRPC(rpcTypeID, func(_ context.Context, request json.RawMessage) (any, *flowersec.RPCError) {
		var payload struct {
			Value string `json:"value"`
		}
		if json.Unmarshal(request, &payload) != nil || payload.Value != "ping" {
			return nil, &flowersec.RPCError{Code: 400, Message: "invalid request"}
		}
		rpcObserved.Store(true)
		return map[string]string{"server": "go-release-consumer"}, nil
	}); err != nil {
		return err
	}
	if err := handlers.HandleStream(streamKind, func(_ context.Context, incoming flowersec.IncomingStream) error {
		payload, readErr := io.ReadAll(incoming.Stream)
		if readErr != nil || string(payload) != "hello-node" {
			return errors.New("invalid consumer stream payload")
		}
		if _, writeErr := incoming.Stream.Write(append([]byte("go:"), payload...)); writeErr != nil {
			return writeErr
		}
		streamObserved.Store(true)
		return nil
	}); err != nil {
		return err
	}

	acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
		Listeners: []flowersec.DirectListener{listener},
		Authorize: func(_ context.Context, request controlplane.RuntimeAuthorizationRequest) (controlplane.AuthorizationResponse, error) {
			return controlplane.AuthorizeRuntime(request, record, "release-consumer-lease")
		},
		Release: func(context.Context, string) {
			select {
			case released <- struct{}{}:
			default:
			}
		},
		ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
			return handlers, nil
		},
		OnSession: func(sessionCtx context.Context, session flowersec.Session, _ string) error {
			termination, waitErr := session.WaitTermination(sessionCtx)
			if waitErr != nil {
				sessionDone <- waitErr
				return waitErr
			}
			if termination.Error.Code() != flowersec.SessionClosed {
				waitErr = fmt.Errorf("session termination = %s", termination.Error.Code())
			}
			sessionDone <- waitErr
			return waitErr
		},
	})
	if err != nil {
		return fmt.Errorf("acceptor: %w", err)
	}

	serveCtx, stopServe := context.WithCancel(ctx)
	serveDone := make(chan error, 1)
	go func() { serveDone <- acceptor.Serve(serveCtx) }()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"type": "ready", "test_id": testID, "artifact_json": string(issued.ArtifactJSON()),
		"trust_pem": string(trustPEM), "origin": "https://consumer.example",
	}); err != nil {
		stopServe()
		return err
	}

	select {
	case err = <-sessionDone:
	case <-ctx.Done():
		err = fmt.Errorf("session completion: %w", ctx.Err())
	}
	stopServe()
	select {
	case serveErr := <-serveDone:
		if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
			err = errors.Join(err, serveErr)
		}
	case <-time.After(3 * time.Second):
		err = errors.Join(err, errors.New("acceptor cleanup timed out"))
	}
	if err != nil {
		return err
	}
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		return errors.New("accepted lease was not released")
	}
	if !rpcObserved.Load() || !streamObserved.Load() {
		return fmt.Errorf("application wire incomplete: rpc=%t stream=%t", rpcObserved.Load(), streamObserved.Load())
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"type": "result", "test_id": testID,
		"cases": []string{"handshake", "rpc", "stream", "stream-fin", "close", "cleanup"},
	})
}

func serverTLS() (*tls.Config, []byte, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "Flowersec release consumer root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}},
	}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), nil
}
