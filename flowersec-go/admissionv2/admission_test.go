package admissionv2_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
)

var reasons = artifactv2.ReasonRegistry{"capacity": {}, "invalid_credential": {}}

func TestClientAndServerAdmissionSuccess(t *testing.T) {
	clientStream, serverStream := streamPair()
	raw := validFSB2(t)
	serverResult := make(chan *artifactv2.DecodedRequest, 1)
	serverErr := make(chan error, 1)
	go func() {
		decoded, err := admissionv2.Serve(context.Background(), serverStream, reasons, func(_ context.Context, request *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			serverResult <- request
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		if err != nil {
			serverErr <- err
			return
		}
		if decoded == nil {
			serverErr <- errors.New("missing decoded request")
		}
	}()
	response, err := admissionv2.Commit(context.Background(), clientStream, raw, reasons)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if response.Status != artifactv2.AdmissionSuccess {
		t.Fatalf("response = %+v", response)
	}
	select {
	case decoded := <-serverResult:
		if decoded.LocalAdmissionBinding != artifactv2.AdmissionBinding(raw) {
			t.Fatal("admission binding mismatch")
		}
	case err := <-serverErr:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("server did not authorize request")
	}
}

func TestCommitReturnsStableRejectAndRetryableErrors(t *testing.T) {
	for _, response := range []artifactv2.AdmissionResponse{
		{Status: artifactv2.AdmissionReject, Reason: "invalid_credential"},
		{Status: artifactv2.AdmissionRetryable, Reason: "capacity"},
	} {
		clientStream, serverStream := streamPair()
		go func() {
			_, _ = admissionv2.Serve(context.Background(), serverStream, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
				return response, nil
			})
		}()
		got, err := admissionv2.Commit(context.Background(), clientStream, validFSB2(t), reasons)
		var admissionErr *admissionv2.ResponseError
		if !errors.As(err, &admissionErr) {
			t.Fatalf("Commit(%+v) error = %v", response, err)
		}
		if got != response || admissionErr.Status != response.Status || admissionErr.Reason != response.Reason {
			t.Fatalf("response/error = %+v/%+v", got, admissionErr)
		}
	}
}

func TestServeReturnsStableRejectAndRetryableErrors(t *testing.T) {
	for _, testCase := range []struct {
		response artifactv2.AdmissionResponse
		want     error
	}{
		{response: artifactv2.AdmissionResponse{Status: artifactv2.AdmissionReject, Reason: "invalid_credential"}, want: admissionv2.ErrAdmissionRejected},
		{response: artifactv2.AdmissionResponse{Status: artifactv2.AdmissionRetryable, Reason: "capacity"}, want: admissionv2.ErrAdmissionRetryable},
	} {
		t.Run(testCase.response.Reason, func(t *testing.T) {
			clientStream, serverStream := streamPair()
			type serverResult struct {
				decoded *artifactv2.DecodedRequest
				err     error
			}
			serverDone := make(chan serverResult, 1)
			go func() {
				decoded, err := admissionv2.Serve(context.Background(), serverStream, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
					return testCase.response, nil
				})
				serverDone <- serverResult{decoded: decoded, err: err}
			}()

			got, err := admissionv2.Commit(context.Background(), clientStream, validFSB2(t), reasons)
			var clientAdmissionErr *admissionv2.ResponseError
			if !errors.As(err, &clientAdmissionErr) || got != testCase.response {
				t.Fatalf("Commit response/error = %+v/%v", got, err)
			}

			select {
			case result := <-serverDone:
				var serverAdmissionErr *admissionv2.ResponseError
				if !errors.As(result.err, &serverAdmissionErr) {
					t.Fatalf("Serve error = %v, want ResponseError", result.err)
				}
				if !errors.Is(result.err, testCase.want) {
					t.Fatalf("Serve error = %v, want %v", result.err, testCase.want)
				}
				if result.decoded == nil || serverAdmissionErr.Status != testCase.response.Status || serverAdmissionErr.Reason != testCase.response.Reason {
					t.Fatalf("Serve decoded/error = %+v/%+v", result.decoded, serverAdmissionErr)
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not return after sending rejection")
			}
		})
	}
}

func TestServerRejectsTrailingCredentialBytesBeforeAuthorization(t *testing.T) {
	clientStream, serverStream := streamPair()
	raw := append(validFSB2(t), 0)
	var authorized atomic.Bool
	serverErr := make(chan error, 1)
	go func() {
		_, err := admissionv2.Serve(context.Background(), serverStream, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized.Store(true)
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		serverErr <- err
	}()
	if _, err := clientStream.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := clientStream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; !errors.Is(err, admissionv2.ErrTrailingBytes) {
		t.Fatalf("Serve error = %v", err)
	}
	if authorized.Load() {
		t.Fatal("authorizer ran before exact FSB2 boundary validation")
	}
}

func TestClientRejectsTrailingResponseBytes(t *testing.T) {
	clientStream, serverStream := streamPair()
	rawResponse, err := artifactv2.MarshalResponse(artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, reasons)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = io.Copy(io.Discard, serverStream)
		_, _ = serverStream.Write(append(rawResponse, 0))
		_ = serverStream.CloseWrite()
	}()
	if _, err := admissionv2.Commit(context.Background(), clientStream, validFSB2(t), reasons); !errors.Is(err, admissionv2.ErrTrailingBytes) {
		t.Fatalf("Commit error = %v", err)
	}
}

func TestContextCancellationInterruptsBlockedAdmission(t *testing.T) {
	clientStream, _ := streamPair()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := admissionv2.Commit(ctx, clientStream, validFSB2(t), reasons); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Commit canceled error = %v", err)
	}
}

func TestReceiveAndRespondAllowTunnelToDelaySuccess(t *testing.T) {
	clientStream, serverStream := streamPair()
	raw := validFSB2(t)
	received := make(chan *artifactv2.DecodedRequest, 1)
	serverErr := make(chan error, 1)
	release := make(chan struct{})
	go func() {
		decoded, err := admissionv2.Receive(context.Background(), serverStream)
		if err != nil {
			serverErr <- err
			return
		}
		received <- decoded
		<-release
		serverErr <- admissionv2.Respond(context.Background(), serverStream, artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, reasons)
	}()
	clientDone := make(chan error, 1)
	go func() {
		_, err := admissionv2.Commit(context.Background(), clientStream, raw, reasons)
		clientDone <- err
	}()
	select {
	case decoded := <-received:
		if decoded.LocalAdmissionBinding != artifactv2.AdmissionBinding(raw) {
			t.Fatal("admission binding mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("Receive did not complete")
	}
	select {
	case err := <-clientDone:
		t.Fatalf("Commit completed before delayed response: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-serverErr; err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

type memoryStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once
}

func streamPair() (*memoryStream, *memoryStream) {
	abReader, abWriter := io.Pipe()
	baReader, baWriter := io.Pipe()
	leftCtx, leftCancel := context.WithCancelCause(context.Background())
	rightCtx, rightCancel := context.WithCancelCause(context.Background())
	left := &memoryStream{reader: baReader, writer: abWriter, ctx: leftCtx, cancel: leftCancel}
	right := &memoryStream{reader: abReader, writer: baWriter, ctx: rightCtx, cancel: rightCancel}
	return left, right
}

func (stream *memoryStream) Read(payload []byte) (int, error)  { return stream.reader.Read(payload) }
func (stream *memoryStream) Write(payload []byte) (int, error) { return stream.writer.Write(payload) }
func (stream *memoryStream) Context() context.Context          { return stream.ctx }
func (stream *memoryStream) CloseWrite() error                 { return stream.writer.Close() }
func (stream *memoryStream) Reset() error                      { return stream.Close() }
func (stream *memoryStream) Close() error {
	stream.once.Do(func() {
		stream.cancel(carrier.ErrStreamReset)
		_ = stream.reader.CloseWithError(carrier.ErrStreamReset)
		_ = stream.writer.CloseWithError(carrier.ErrStreamReset)
	})
	return nil
}

func validFSB2(t *testing.T) []byte {
	t.Helper()
	session := artifactv2.SessionContract{
		ChannelID: "channel-1", InitExpireAtUnixSeconds: time.Now().Add(time.Hour).Unix(), IdleTimeoutSeconds: 60,
		EstablishTimeoutSeconds: 30, RekeyPrepareTimeoutSeconds: 10, RekeyCompletionTimeoutSeconds: 30,
		MaxInboundStreams: 32, AllowedSuites: []uint16{1, 2}, DefaultSuite: 1,
	}
	for index := range session.E2EEPSK {
		session.E2EEPSK[index] = byte(index + 1)
	}
	hash, _, err := artifactv2.ComputeSessionContractHash(session)
	if err != nil {
		t.Fatal(err)
	}
	session.ContractHash = hash
	artifact := artifactv2.Artifact{
		Version: 2, Profile: artifactv2.Profile, Session: session,
		Path: artifactv2.ArtifactPath{
			Kind: artifactv2.PathDirect, RendezvousGroupID: "group-1", ListenerAudience: "listener-1", RoutingToken: "opaque",
			Candidates: []artifactv2.Candidate{{ID: "q1", Carrier: artifactv2.CarrierRawQUIC, URL: "quic://example.test:443", WireProfile: "flowersec-direct/2"}},
		},
		Scoped: []artifactv2.ScopeMetadata{}, Correlation: artifactv2.CorrelationContext{Version: 2, Tags: []artifactv2.CorrelationTag{}},
	}
	request, err := artifactv2.BuildRequest(artifact, "q1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var _ carrier.Stream = (*memoryStream)(nil)
