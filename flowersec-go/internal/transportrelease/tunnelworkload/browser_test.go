package tunnelworkload

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	carrierwt "github.com/floegence/flowersec/flowersec-go/v2/internal/carrier/webtransport"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
	flowersession "github.com/floegence/flowersec/flowersec-go/v2/internal/session"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/transportrelease"
)

func TestBrowserTunnelTopologiesUseProductionWebTransportBrokerPath(t *testing.T) {
	for _, topology := range BrowserTopologies() {
		t.Run(string(topology), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			endpoint, err := OpenBrowserEndpointAt(ctx, topology, "127.0.0.1", "https://127.0.0.1:9000")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				if err := endpoint.Close(cleanupCtx); err != nil {
					t.Error(err)
				}
			}()

			issued, err := endpoint.IssueBrowserArtifact()
			if err != nil {
				t.Fatal(err)
			}
			issued.Start()
			artifact, err := artifactv2.DecodeArtifactJSON(strings.NewReader(issued.ArtifactJSON()))
			if err != nil {
				t.Fatal(err)
			}
			browserSession := connectBrowserWebTransport(t, ctx, endpoint, *artifact)
			serverSession, err := issued.AwaitServer(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer browserSession.Close()
			defer serverSession.Close()

			payload := json.RawMessage(`"browser-tunnel-rpc"`)
			var response json.RawMessage
			if err := browserSession.RPC().Call(ctx, 1, payload, &response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, payload) {
				t.Fatalf("RPC response = %s", response)
			}

			serverDone := make(chan error, 1)
			go func() { serverDone <- transportrelease.ServeBrowserBulk(ctx, serverSession, []int64{4096}) }()
			if err := runBrowserBulkClient(ctx, browserSession, 4096); err != nil {
				t.Fatal(err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func connectBrowserWebTransport(t *testing.T, ctx context.Context, endpoint *BrowserEndpoint, artifact artifactv2.Artifact) flowersession.SessionV2 {
	t.Helper()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: endpoint.roots, ServerName: "127.0.0.1"}
	dial, err := connectv2.NewWebTransportCarrierDial(connectv2.WebTransportDialConfig{
		TLSConfig: tlsConfig, Limits: carrierwt.DefaultLimits(), Origin: "https://127.0.0.1:9000",
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebTransport: dial,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	connector := connectv2.NewConnector(connectv2.ArtifactLease{
		Artifact: artifact, CommitSpend: func(context.Context) error { return nil },
	}, flowersession.GoCapabilities(), connectv2.RequireQUICFamily, factory)
	result, err := connector.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidate.ID != "browser-leg" || result.Candidate.Carrier != artifactv2.CarrierWebTransport {
		t.Fatalf("browser selected %+v", result.Candidate)
	}
	return result.Session
}

func runBrowserBulkClient(ctx context.Context, session flowersession.SessionV2, byteCount int64) error {
	outgoing, err := session.OpenStream(ctx, "release-bulk", flowersession.Metadata{"direction": "client-to-server"})
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = outgoing.Reset()
		}
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := io.CopyN(outgoing, bytes.NewReader(bytes.Repeat([]byte{0xa5}, int(byteCount))), byteCount)
		writeDone <- errors.Join(writeErr, outgoing.CloseWrite())
	}()
	response, readErr := io.ReadAll(outgoing)
	if err := errors.Join(readErr, <-writeDone); err != nil {
		return err
	}
	if int64(len(response)) != byteCount || !bytes.Equal(response, bytes.Repeat([]byte{0x5a}, int(byteCount))) {
		return errors.New("browser bulk response mismatch")
	}
	completed = true
	return nil
}

func TestBrowserTunnelEndpointRejectsInvalidTopologyAndUsesP256Pin(t *testing.T) {
	if _, err := OpenBrowserEndpointAt(context.Background(), BrowserTopology("browser_tunnel_wt_wt"), "127.0.0.1", "http://127.0.0.1"); err == nil {
		t.Fatal("accepted browser topology outside the frozen matrix")
	}
	endpoint, err := OpenBrowserEndpointAt(context.Background(), BrowserTunnelWTWSS, "127.0.0.1", "http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close(context.Background())
	encoded, err := endpoint.CertificateHashBase64URL()
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := base64.RawURLEncoding.DecodeString(encoded); err != nil || len(digest) != 32 {
		t.Fatalf("certificate hash = %q: %v", encoded, err)
	}
	certificate, err := x509.ParseCertificate(endpoint.certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Fatal("browser tunnel certificate is not ECDSA P-256")
	}
}
