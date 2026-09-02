package sessionv3

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv3"
)

type versionIsolationDatagramCarrier struct {
	wire       []byte
	terminated chan struct{}
	closeOnce  sync.Once
	mu         sync.Mutex
	closeError carrier.ApplicationError
}

func newVersionIsolationDatagramCarrier(wire []byte) *versionIsolationDatagramCarrier {
	return &versionIsolationDatagramCarrier{wire: wire, terminated: make(chan struct{})}
}

func (*versionIsolationDatagramCarrier) Kind() carrier.Kind         { return carrier.KindRawQUIC }
func (*versionIsolationDatagramCarrier) Path() carrier.Path         { return carrier.PathDirect }
func (*versionIsolationDatagramCarrier) MaxIncomingStreams() uint16 { return 3 }
func (*versionIsolationDatagramCarrier) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, io.ErrClosedPipe
}
func (*versionIsolationDatagramCarrier) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, io.ErrClosedPipe
}
func (value *versionIsolationDatagramCarrier) Termination() <-chan struct{} { return value.terminated }
func (value *versionIsolationDatagramCarrier) CloseWithErrorContext(_ context.Context, applicationError carrier.ApplicationError) error {
	value.mu.Lock()
	value.closeError = applicationError
	value.mu.Unlock()
	value.closeOnce.Do(func() { close(value.terminated) })
	return nil
}
func (value *versionIsolationDatagramCarrier) CloseWithError(applicationError carrier.ApplicationError) error {
	return value.CloseWithErrorContext(context.Background(), applicationError)
}
func (value *versionIsolationDatagramCarrier) Abort(applicationError carrier.ApplicationError) error {
	return value.CloseWithError(applicationError)
}
func (value *versionIsolationDatagramCarrier) Close() error {
	return value.CloseWithError(carrier.ApplicationError{})
}
func (*versionIsolationDatagramCarrier) UnreliableAvailable() bool   { return true }
func (*versionIsolationDatagramCarrier) SendUnreliable([]byte) error { return nil }
func (value *versionIsolationDatagramCarrier) ReceiveUnreliable(context.Context) ([]byte, error) {
	return append([]byte(nil), value.wire...), nil
}

func TestPreviousVersionUnreliableDatagramsAreRecognized(t *testing.T) {
	previousMagic := []byte{'F', 'S', 'D', '2', 3}
	previousVersion := []byte{'F', 'S', 'D', '3', 2}
	current := []byte{'F', 'S', 'D', '3', 3}
	ordinaryInvalid := []byte{'n', 'o', 'i', 's', 'e'}

	for name, wire := range map[string][]byte{
		"previous magic":   previousMagic,
		"previous version": previousVersion,
	} {
		if !isPreviousVersionUnreliableDatagram(wire) {
			t.Fatalf("%s was not recognized", name)
		}
	}
	for name, wire := range map[string][]byte{
		"current": current,
		"noise":   ordinaryInvalid,
	} {
		if isPreviousVersionUnreliableDatagram(wire) {
			t.Fatalf("%s was incorrectly recognized", name)
		}
	}
}

func TestPreviousVersionUnreliableDatagramsFailTheLiveSession(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v3/version_isolation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Frames []struct {
			ID        string `json:"id"`
			V2Magic   string `json:"v2_magic_hex"`
			V2Version string `json:"v2_version_hex"`
		} `json:"frames"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var datagram struct {
		V2Magic   string
		V2Version string
	}
	for _, frame := range fixture.Frames {
		if frame.ID == "fsd3" {
			datagram.V2Magic, datagram.V2Version = frame.V2Magic, frame.V2Version
		}
	}
	if datagram.V2Magic == "" || datagram.V2Version == "" {
		t.Fatal("shared FSD3 version-isolation vector is missing")
	}
	for name, encoded := range map[string]string{
		"v2 magic":   datagram.V2Magic,
		"v2 version": datagram.V2Version,
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			transport := newVersionIsolationDatagramCarrier(wire)
			session, err := newEngineSession(transport, nil, Config{
				Role: RoleClient, Path: PathDirect, Suite: protocolv3.SuiteChaCha20Poly1305,
				MaxInboundStreams: 1, EstablishTimeout: time.Second,
				RekeyPrepareTimeout: time.Second, RekeyCompletionTimeout: time.Second,
			}, handshakeMaterial{selectedFeatures: protocolv3.FeatureUnreliableMessages})
			if err != nil {
				t.Fatal(err)
			}
			_, receiveErr := session.unreliable.Receive(context.Background())
			if !errors.Is(receiveErr, ErrSessionProtocol) {
				t.Fatalf("receive error = %v, want session protocol failure", receiveErr)
			}
			transport.mu.Lock()
			closeError := transport.closeError
			transport.mu.Unlock()
			if closeError.Code != 6 || closeError.Reason != "session protocol failure" {
				t.Fatalf("carrier close = %+v, want protocol failure", closeError)
			}
		})
	}
}
