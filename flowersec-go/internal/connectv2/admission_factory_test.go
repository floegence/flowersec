package connectv2_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
)

func TestAdmissionFactoryKeepsCredentialBytesBehindPreparedCommit(t *testing.T) {
	artifact := validArtifact(t)
	candidate := artifact.Path.Candidates[1]
	clientStream, serverStream := admissionStreamPair()
	authorized := make(chan struct{}, 1)
	reasons := artifactv2.ReasonRegistry{"capacity": {}}
	serverErr := make(chan error, 1)
	go func() {
		_, err := admissionv2.Serve(context.Background(), serverStream, reasons, func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error) {
			authorized <- struct{}{}
			return artifactv2.AdmissionResponse{Status: artifactv2.AdmissionSuccess}, nil
		})
		serverErr <- err
	}()
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierRawQUIC: func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			return &streamAdmissionHandle{session: fakeSession{kind: carrier.KindQUIC}, stream: clientStream, reasons: reasons}, nil
		},
	}, reasons)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-authorized:
		t.Fatal("carrier ready wrote credential bytes before Commit")
	default:
	}
	request, err := artifactv2.BuildRequest(artifact, candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	fsb2, err := artifactv2.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	session, err := prepared.Commit(context.Background(), fsb2)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if session.Kind() != carrier.KindQUIC {
		t.Fatalf("session kind = %s", session.Kind())
	}
	select {
	case <-authorized:
	case <-time.After(time.Second):
		t.Fatal("server did not receive committed FSB2")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionFactoryAbortClosesLocallyWithoutCommit(t *testing.T) {
	artifact := validArtifact(t)
	candidate := artifact.Path.Candidates[1]
	clientStream, _ := admissionStreamPair()
	session := &closingFakeSession{kind: carrier.KindQUIC}
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierRawQUIC: func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			return &streamAdmissionHandle{session: session, stream: clientStream}, nil
		},
	}, artifactv2.ReasonRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attempt.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := attempt.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !session.closed {
		t.Fatal("Abort left the carrier session writable")
	}
}

func TestAdmissionFactoryAbortWaitsForLateHandleAndUsesLiveCleanupContext(t *testing.T) {
	artifact := validArtifact(t)
	candidate := artifact.Path.Candidates[1]
	handle := &cancelRejectingAdmissionHandle{}
	dialStarted := make(chan struct{})
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierRawQUIC: func(ctx context.Context, _ artifactv2.Candidate, _ artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			close(dialStarted)
			<-ctx.Done()
			return handle, nil
		},
	}, artifactv2.ReasonRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	readyDone := make(chan error, 1)
	go func() {
		_, readyErr := attempt.Ready(context.Background())
		readyDone <- readyErr
	}()
	<-dialStarted

	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), time.Second)
	defer cancelCleanup()
	if err := attempt.Abort(cleanupCtx); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := <-readyDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Ready error = %v, want canceled", err)
	}
	if !handle.locallyClosed.Load() {
		t.Fatal("Abort returned before the late admission handle became locally unwritable")
	}
	if handle.canceledCloseCalls.Load() != 0 {
		t.Fatalf("late handle received %d canceled cleanup calls", handle.canceledCloseCalls.Load())
	}
}

func TestAdmissionFactoryPassesExactSessionContractToCarrierDial(t *testing.T) {
	artifact := validArtifact(t)
	candidate := artifact.Path.Candidates[1]
	var received artifactv2.SessionContract
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierRawQUIC: func(_ context.Context, _ artifactv2.Candidate, contract artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			received = contract
			return &streamAdmissionHandle{session: fakeSession{kind: carrier.KindQUIC}, stream: newDiscardAdmissionStream()}, nil
		},
	}, artifactv2.ReasonRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := factory.NewAttempt(candidate, artifact.Session)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := attempt.Ready(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close(context.Background())
	if received.MaxInboundStreams != artifact.Session.MaxInboundStreams || received.ContractHash != artifact.Session.ContractHash {
		t.Fatalf("carrier dial contract = %+v, want artifact session contract", received)
	}
}

func TestConnectorDeadlineIncludesAdmissionHandleCleanup(t *testing.T) {
	artifact := validArtifact(t)
	handle := &deadlineAdmissionHandle{}
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebSocket: func(context.Context, artifactv2.Candidate, artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			return handle, nil
		},
	}, artifactv2.ReasonRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	connector := connectv2.NewConnector(
		inMemoryLease(artifact),
		allCapabilities(),
		connectv2.RequireWebSocket,
		factory,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err = connector.Connect(ctx)
	elapsed := time.Since(started)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("admission handle cleanup exceeded the total establishment deadline: %v", elapsed)
	}
	if !handle.locallyClosed.Load() {
		t.Fatal("admission handle remained locally writable")
	}
}

func TestConnectorDeadlineClosesLateAdmissionHandleWithLiveCleanupContext(t *testing.T) {
	artifact := validArtifact(t)
	handle := &cancelRejectingAdmissionHandle{}
	dialStarted := make(chan struct{})
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebSocket: func(ctx context.Context, _ artifactv2.Candidate, _ artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			close(dialStarted)
			<-ctx.Done()
			return handle, nil
		},
	}, artifactv2.ReasonRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	connector := connectv2.NewConnector(
		inMemoryLease(artifact),
		allCapabilities(),
		connectv2.RequireWebSocket,
		factory,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err = connector.Connect(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect error = %v, want deadline exceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("late admission cleanup exceeded the bounded deadline: %v", elapsed)
	}
	select {
	case <-dialStarted:
	default:
		t.Fatal("carrier dial did not start")
	}
	deadline := time.Now().Add(time.Second)
	for !handle.locallyClosed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !handle.locallyClosed.Load() {
		t.Fatal("late admission handle remained locally writable")
	}
	if handle.canceledCloseCalls.Load() != 0 {
		t.Fatalf("late handle received %d canceled cleanup calls", handle.canceledCloseCalls.Load())
	}
}

func TestConnectorDeadlineClosesHandleReturnedAfterCleanupGrace(t *testing.T) {
	artifact := validArtifact(t)
	handle := &cancelRejectingAdmissionHandle{}
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	factory, err := connectv2.NewAdmissionFactory(map[artifactv2.Carrier]connectv2.CarrierDial{
		artifactv2.CarrierWebSocket: func(ctx context.Context, _ artifactv2.Candidate, _ artifactv2.SessionContract) (connectv2.AdmissionHandle, error) {
			close(dialStarted)
			<-ctx.Done()
			<-releaseDial
			return handle, nil
		},
	}, artifactv2.ReasonRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	connector := connectv2.NewConnector(
		inMemoryLease(artifact),
		allCapabilities(),
		connectv2.RequireWebSocket,
		factory,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	connectDone := make(chan error, 1)
	go func() {
		_, connectErr := connector.Connect(ctx)
		connectDone <- connectErr
	}()
	<-dialStarted
	select {
	case connectErr := <-connectDone:
		if !errors.Is(connectErr, context.DeadlineExceeded) {
			t.Fatalf("Connect error = %v, want deadline exceeded", connectErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Connect did not stop after the bounded cleanup grace")
	}

	close(releaseDial)
	deadline := time.Now().Add(time.Second)
	for !handle.locallyClosed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !handle.locallyClosed.Load() {
		t.Fatal("handle returned after cleanup grace remained locally writable")
	}
	if handle.canceledCloseCalls.Load() != 0 {
		t.Fatalf("late handle received %d canceled cleanup calls", handle.canceledCloseCalls.Load())
	}
}

type deadlineAdmissionHandle struct {
	locallyClosed atomic.Bool
}

type cancelRejectingAdmissionHandle struct {
	locallyClosed      atomic.Bool
	canceledCloseCalls atomic.Int32
}

func (*cancelRejectingAdmissionHandle) CommitAdmission(context.Context, []byte, artifactv2.ReasonRegistry) (carrier.Session, error) {
	return nil, errors.New("unexpected admission commit")
}

func (handle *cancelRejectingAdmissionHandle) Close(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		handle.canceledCloseCalls.Add(1)
		return err
	}
	handle.locallyClosed.Store(true)
	return nil
}

func (*deadlineAdmissionHandle) CommitAdmission(ctx context.Context, _ []byte, _ artifactv2.ReasonRegistry) (carrier.Session, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (handle *deadlineAdmissionHandle) Close(ctx context.Context) error {
	handle.locallyClosed.Store(true)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return nil
	}
}

type closingFakeSession struct {
	kind   carrier.Kind
	closed bool
}

func (session *closingFakeSession) Kind() carrier.Kind { return session.kind }
func (*closingFakeSession) Path() carrier.Path         { return carrier.PathDirect }
func (*closingFakeSession) MaxIncomingStreams() uint16 { return 34 }
func (*closingFakeSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, io.ErrClosedPipe
}
func (*closingFakeSession) AcceptStream(context.Context) (carrier.Stream, error) {
	return nil, io.ErrClosedPipe
}
func (session *closingFakeSession) CloseWithError(carrier.ApplicationError) error {
	session.closed = true
	return nil
}
func (session *closingFakeSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	session.closed = true
	return nil
}
func (session *closingFakeSession) Close() error { session.closed = true; return nil }

type streamAdmissionHandle struct {
	session carrier.Session
	stream  carrier.Stream
	reasons artifactv2.ReasonRegistry
}

func (handle *streamAdmissionHandle) CommitAdmission(ctx context.Context, fsb2 []byte, _ artifactv2.ReasonRegistry) (carrier.Session, error) {
	if _, err := admissionv2.Commit(ctx, handle.stream, fsb2, handle.reasons); err != nil {
		_ = handle.session.Close()
		return nil, err
	}
	return handle.session, nil
}

func (handle *streamAdmissionHandle) Close(context.Context) error {
	return errors.Join(handle.stream.Reset(), handle.session.Close())
}

type admissionMemoryStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once
}

func newDiscardAdmissionStream() *admissionMemoryStream {
	reader, peerWriter := io.Pipe()
	peerReader, writer := io.Pipe()
	ctx, cancel := context.WithCancelCause(context.Background())
	go func() {
		_, _ = io.Copy(io.Discard, peerReader)
		_ = peerWriter.Close()
	}()
	return &admissionMemoryStream{reader: reader, writer: writer, ctx: ctx, cancel: cancel}
}

func admissionStreamPair() (*admissionMemoryStream, *admissionMemoryStream) {
	abReader, abWriter := io.Pipe()
	baReader, baWriter := io.Pipe()
	leftContext, leftCancel := context.WithCancelCause(context.Background())
	rightContext, rightCancel := context.WithCancelCause(context.Background())
	return &admissionMemoryStream{reader: baReader, writer: abWriter, ctx: leftContext, cancel: leftCancel},
		&admissionMemoryStream{reader: abReader, writer: baWriter, ctx: rightContext, cancel: rightCancel}
}

func (stream *admissionMemoryStream) Read(payload []byte) (int, error) {
	return stream.reader.Read(payload)
}
func (stream *admissionMemoryStream) Write(payload []byte) (int, error) {
	return stream.writer.Write(payload)
}
func (stream *admissionMemoryStream) Context() context.Context { return stream.ctx }
func (stream *admissionMemoryStream) CloseWrite() error        { return stream.writer.Close() }
func (stream *admissionMemoryStream) Reset() error             { return stream.Close() }
func (stream *admissionMemoryStream) Close() error {
	stream.once.Do(func() {
		stream.cancel(carrier.ErrStreamReset)
		_ = stream.reader.CloseWithError(carrier.ErrStreamReset)
		_ = stream.writer.CloseWithError(carrier.ErrStreamReset)
	})
	return nil
}

var _ carrier.Stream = (*admissionMemoryStream)(nil)
