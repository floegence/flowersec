package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/interopharness"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/transporttest"
)

type endpoint struct {
	WireRevision             int    `json:"wire_revision"`
	Profile                  string `json:"profile"`
	Source                   string `json:"source"`
	TrustPEM                 string `json:"trust_pem"`
	Origin                   string `json:"origin"`
	URL                      string `json:"url"`
	CertificateHash          string `json:"certificate_hash"`
	CertificateNotAfterUnixS int64  `json:"certificate_not_after_unix_s,omitempty"`
	ArtifactJSON             string `json:"artifact_json"`
}

func main() {
	productDirect := flag.Bool("product-direct", false, "serve one production current transport direct WebTransport session")
	publicCA := flag.Bool("public-ca", false, "use deployment-provided public-CA TLS material")
	wrongPin := flag.Bool("wrong-pin", false, "issue an independently signed mismatched pin without CA fallback")
	exchangeDatagram := flag.Bool("datagram", false, "exchange one encrypted current transport datagram")
	origin := flag.String("origin", "", "exact browser Origin")
	flag.Parse()
	if !*productDirect || flag.NArg() != 0 {
		fail(errors.New("usage: browser-webtransport-peer --product-direct --origin <origin> [--public-ca] [--wrong-pin] [--datagram]"))
	}
	fail(runProductDirect(*origin, *publicCA, *wrongPin, *exchangeDatagram))
}

func runProductDirect(origin string, publicCA, wrongPin, exchangeDatagram bool) error {
	if origin == "" {
		return errors.New("product-direct mode requires an exact browser Origin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var (
		server              *transporttest.ProductDirectEndpoint
		err                 error
		certificateNotAfter int64
	)
	if publicCA {
		serverTLS, notAfter, tlsErr := publicCATLSConfig(
			os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_CERT"),
			os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_KEY"),
		)
		if tlsErr != nil {
			return tlsErr
		}
		server, err = transporttest.OpenProductDirectBrowserEndpointAtWithTLS(
			ctx,
			"127.0.0.1",
			os.Getenv("FLOWERSEC_BROWSER_PUBLIC_CA_HOST"),
			origin,
			serverTLS,
		)
		certificateNotAfter = notAfter
	} else {
		server, err = transporttest.OpenProductDirectBrowserEndpointAt(ctx, "127.0.0.1", origin)
	}
	if err != nil {
		return err
	}
	defer server.Close()
	var issued *transporttest.ProductDirectBrowserArtifact
	if wrongPin {
		issued, err = server.IssueBrowserWrongPinArtifact()
	} else if publicCA {
		issued, err = server.IssueBrowserCAArtifact()
	} else {
		issued, err = server.IssueBrowserArtifact()
	}
	if err != nil {
		return err
	}
	defer issued.Cancel()
	certificateHash, err := server.CertificateHashBase64URL()
	if err != nil {
		return err
	}
	var original interopharness.Material
	if err = json.Unmarshal([]byte(issued.ArtifactJSON()), &original); err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(endpoint{
		WireRevision: original.WireRevision, Profile: original.Profile, Source: original.Source, TrustPEM: server.TrustPEM(), Origin: origin,
		URL: server.CandidateURL(), CertificateHash: certificateHash,
		CertificateNotAfterUnixS: certificateNotAfter, ArtifactJSON: issued.ArtifactJSON(),
	}); err != nil {
		return err
	}
	established, err := issued.AwaitServer(ctx)
	if err != nil {
		return err
	}
	if exchangeDatagram {
		if err := exchangeOneDatagram(ctx, established); err != nil {
			return err
		}
	}
	closeErr := established.Close()
	return errors.Join(closeErr, established.WaitCleanup(ctx))
}

func exchangeOneDatagram(ctx context.Context, session *flowersec.Session) error {
	channel, err := session.UnreliableMessages()
	if err != nil {
		return err
	}
	request, err := channel.Receive(ctx)
	if err != nil {
		return err
	}
	if string(request) != "browser-webtransport-datagram-request" {
		return errors.New("unexpected browser WebTransport datagram request")
	}
	status, err := channel.Send(
		ctx,
		[]byte("browser-webtransport-datagram-response"),
		flowersec.UnreliableSendOptions{ExpiresAt: time.Now().Add(5 * time.Second)},
	)
	if err != nil {
		return fmt.Errorf("send browser WebTransport datagram response: %w", err)
	}
	if status != flowersec.UnreliableAccepted {
		return fmt.Errorf("send browser WebTransport datagram response status = %s", status)
	}
	return nil
}

func publicCATLSConfig(certificatePath, privateKeyPath string) (*tls.Config, int64, error) {
	if certificatePath == "" || privateKeyPath == "" {
		return nil, 0, errors.New("public-CA mode requires certificate and private-key paths")
	}
	pair, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, 0, errors.New("public-CA TLS material is invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, 0, errors.New("public-CA leaf certificate is invalid")
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	now := time.Now()
	if !ok || publicKey.Curve != elliptic.P256() || now.Before(leaf.NotBefore) ||
		!now.Before(leaf.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) > 14*24*time.Hour {
		return nil, 0, errors.New("public-CA leaf does not satisfy the browser certificate profile")
	}
	pair.Leaf = leaf
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		SessionTicketsDisabled: true, Certificates: []tls.Certificate{pair},
	}, leaf.NotAfter.Unix(), nil
}

func fail(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
