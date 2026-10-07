package parityclient

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

// fixtureManifest is an explicitly trusted application deployment supplied by
// the local acceptance runner. It is not an untrusted connection invitation:
// it intentionally contains local identity seeds and independent namespace pins.
// Production callers supply those separate authorities through Configuration.
type fixtureManifest struct {
	WireRevision int    `json:"wire_revision"`
	Profile      string `json:"profile"`
	Source       string `json:"source"`
	Generation   struct {
		Source     []byte `json:"source"`
		Generation uint64 `json:"generation"`
	} `json:"generation"`
	Role                   uint8  `json:"role"`
	Artifact               []byte `json:"artifact"`
	Activation             []byte `json:"activation"`
	ClientCertificate      []byte `json:"client_certificate"`
	ServerCertificate      []byte `json:"server_certificate"`
	Route                  []byte `json:"route"`
	RouteDigest            []byte `json:"route_digest"`
	ActivationSigningKeyID string `json:"activation_signing_key_id"`
	IdentitySeed           []byte `json:"identity_seed"`
	DHSeed                 []byte `json:"dh_seed"`
	Namespaces             []struct {
		Tenant        string `json:"tenant"`
		Authority     string `json:"authority"`
		Generation    uint64 `json:"generation"`
		RootKeyID     []byte `json:"root_key_id"`
		RootPublicKey []byte `json:"root_public_key"`
		BootstrapURL  string `json:"bootstrap_url"`
		StateURL      string `json:"state_url"`
	} `json:"namespaces"`
	Tunnels            []json.RawMessage `json:"tunnels"`
	RelayDeployment    json.RawMessage   `json:"relay_deployment"`
	LiveControlBaseURL string            `json:"live_control_base_url,omitempty"`
}

type fixtureSigner struct{ key ed25519.PrivateKey }

func (s fixtureSigner) PublicKey() []byte                   { return s.key.Public().(ed25519.PublicKey) }
func (s fixtureSigner) Sign(message []byte) ([]byte, error) { return ed25519.Sign(s.key, message), nil }

type fixtureDH struct{ key *ecdh.PrivateKey }

func (d fixtureDH) PublicKey() []byte { return d.key.PublicKey().Bytes() }
func (d fixtureDH) SharedSecret(wire []byte) ([]byte, error) {
	peer, err := d.key.Curve().NewPublicKey(wire)
	if err != nil {
		return nil, err
	}
	return d.key.ECDH(peer)
}

// OpenAcceptanceFixture preserves the repository runner's material-file input.
// Call it only for a manifest provisioned by that trusted local runner. It
// builds every transport, trust, resource and durable owner via published APIs.
// A non-nil Client must be closed even when an error is returned.
func OpenAcceptanceFixture(ctx context.Context, materialPath, trustPath, receiptPath, origin string) (*Client, error) {
	if materialPath == "" || trustPath == "" || receiptPath == "" || origin == "" {
		return nil, errors.New("acceptance fixture paths and origin are required")
	}
	if _, err := os.Lstat(receiptPath); err == nil {
		return nil, errors.New("invitation observation receipt already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	wire, err := readBoundedFile(materialPath, 262144)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	var material fixtureManifest
	defer func() { clear(material.IdentitySeed); clear(material.DHSeed); clear(material.Artifact) }()
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&material); err != nil {
		return nil, err
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("fixture manifest has trailing data")
	}
	if material.WireRevision != 4 || material.Source != "preauthorized_pool" || material.Role != 0 ||
		len(material.Namespaces) != 1 || len(material.Tunnels) != 0 || material.LiveControlBaseURL != "" ||
		len(material.IdentitySeed) != 32 || len(material.DHSeed) != 32 || len(material.Generation.Source) != 16 || material.Generation.Generation == 0 {
		return nil, errors.New("fixture is outside the direct WSS pool-client cookbook")
	}
	for _, value := range [][]byte{material.Artifact, material.Activation, material.ClientCertificate, material.ServerCertificate} {
		if len(value) == 0 || len(value) > 65536 {
			return nil, errors.New("fixture signed material exceeds its declared bound")
		}
	}
	namespace := material.Namespaces[0]
	if len(namespace.RootKeyID) != 16 || len(namespace.RootPublicKey) != 32 || namespace.Generation == 0 {
		return nil, errors.New("fixture namespace pins are incomplete")
	}
	root := fs.NamespaceTrustRoot{Tenant: namespace.Tenant, Authority: namespace.Authority,
		KeyID: [16]byte(namespace.RootKeyID), PublicKey: [32]byte(namespace.RootPublicKey), MaxLifetimeMS: 30000000}
	trustPEM, err := readBoundedFile(trustPath, 65536)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trustPEM) {
		return nil, errors.New("fixture TLS roots are invalid")
	}
	curve := ecdh.X25519()
	switch material.Profile {
	case "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1":
	case "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1":
		curve = ecdh.P256()
	default:
		return nil, errors.New("fixture identity profile is unsupported")
	}
	private, err := curve.NewPrivateKey(material.DHSeed)
	if err != nil {
		return nil, err
	}
	signer := fixtureSigner{ed25519.NewKeyFromSeed(material.IdentitySeed)}
	clock, err := acceptanceClock()
	if err != nil {
		clear(signer.key)
		return nil, err
	}
	historyDirectory, err := filepath.Abs(receiptPath + ".history")
	if err != nil {
		clock.Close()
		clear(signer.key)
		return nil, err
	}
	identity := fs.SQLiteIdentity{Authority: "parity.consumer", Generation: 1}
	if _, err = rand.Read(identity.StoreID[:]); err != nil {
		clock.Close()
		clear(signer.key)
		return nil, err
	}
	client, err := New(ctx, Configuration{
		Material: Material{Artifact: material.Artifact, Activation: material.Activation,
			ClientCertificate: material.ClientCertificate, ServerCertificate: material.ServerCertificate,
			ActivationSigningKeyID: material.ActivationSigningKeyID,
			Generation:             fs.MaterialGeneration{Source: [16]byte(material.Generation.Source), Generation: material.Generation.Generation}},
		Namespace: root, BootstrapURL: namespace.BootstrapURL, TLSRoots: roots, Clock: clock,
		Signer: signer, StaticDH: fixtureDH{private}, Origin: origin,
		HistoryDirectory: historyDirectory, HistoryIdentity: identity,
	})
	if client == nil {
		clock.Close()
		clear(signer.key)
		return nil, err
	}
	client.ownedHostCleanup = func() { clock.Close(); clear(signer.key) }
	return client, err
}

func readBoundedFile(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(maximum) {
		return nil, errors.New("example input must be a bounded regular file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maximum {
		clear(wire)
		return nil, errors.New("example input grew beyond its admitted bound")
	}
	return wire, nil
}

// The local acceptance runner explicitly trusts its host clock for this short
// invocation. A deployment supplies its own qualified Clock to New instead.
func acceptanceClock() (*fs.Clock, error) {
	started := time.Now()
	if started.UnixMilli() < 2 {
		return nil, errors.New("local acceptance clock is unavailable")
	}
	var incarnation [16]byte
	if _, err := rand.Read(incarnation[:]); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var last uint64
	clock, err := fs.NewClock(fs.ClockProfile{Rate: fs.ClockRate{Denominator: 1},
		MaxWidthMS: 2000, MaxAgeMS: 60000, MaxRoundTripMS: 1000}, func() (fs.ClockTick, error) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		elapsed := now.Sub(started)
		wall := now.UnixMilli() - started.UnixMilli()
		if elapsed < 0 || elapsed > time.Minute || wall < 0 || wall-int64(elapsed/time.Millisecond) > 250 || int64(elapsed/time.Millisecond)-wall > 250 {
			return fs.ClockTick{}, errors.New("acceptance host clock continuity was lost")
		}
		milliseconds := uint64(elapsed / time.Millisecond)
		if milliseconds < last {
			return fs.ClockTick{}, errors.New("acceptance monotonic clock regressed")
		}
		last = milliseconds
		return fs.ClockTick{Milliseconds: milliseconds, Incarnation: incarnation}, nil
	})
	if err != nil {
		return nil, err
	}
	mark, err := clock.Monotonic()
	if err == nil {
		anchor := uint64(started.UnixMilli()) + mark.Milliseconds
		err = clock.InstallTrusted(mark, fs.TimeInterval{LowerMS: anchor - 2, UpperMS: anchor + 2})
	}
	if err != nil {
		clock.Close()
		return nil, err
	}
	return clock, nil
}
