package tunnelv3

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/admissionv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
)

var (
	ErrInvalidNativeLeg = errors.New("invalid flowersec v5 native-stream tunnel leg")
	ErrAdmissionState   = errors.New("invalid flowersec v5 tunnel admission state")
)

// NativeStreamLeg admits a raw QUIC or WebTransport session on its dedicated
// stream. It rejects additional streams while waiting for the peer leg.
type NativeStreamLeg struct {
	session       carrier.Session
	activated     carrier.Session
	admission     carrier.Stream
	openAdmission func(context.Context) (carrier.Stream, error)

	mu        sync.Mutex
	received  bool
	responded bool
	pending   carrier.Stream
}

// NewNativeStreamLeg binds a dedicated admission stream to a native session.
func NewNativeStreamLeg(session carrier.Session, admission carrier.Stream) (*NativeStreamLeg, error) {
	if !nativeTunnelSession(session) || admission == nil {
		return nil, ErrInvalidNativeLeg
	}
	return &NativeStreamLeg{session: session, activated: session, admission: admission}, nil
}

// NewPendingNativeLeg opens the stream only after the coordinator admits work.
func NewPendingNativeLeg(session carrier.Session, open func(context.Context) (carrier.Stream, error)) (*NativeStreamLeg, error) {
	if !nativeTunnelSession(session) || open == nil {
		return nil, ErrInvalidNativeLeg
	}
	return &NativeStreamLeg{session: session, activated: session, openAdmission: open}, nil
}

func nativeTunnelSession(session carrier.Session) bool {
	return session != nil && session.Path() == carrier.PathTunnel &&
		(session.Kind() == carrier.KindRawQUIC || session.Kind() == carrier.KindWebTransport)
}

func (leg *NativeStreamLeg) CarrierKind() carrier.Kind { return leg.session.Kind() }

func (leg *NativeStreamLeg) ReceiveAdmission(ctx context.Context) (*artifactv3.DecodedRequest, error) {
	leg.mu.Lock()
	if leg.received {
		leg.mu.Unlock()
		return nil, ErrAdmissionState
	}
	leg.received = true
	open := leg.openAdmission
	leg.openAdmission = nil
	stream := leg.admission
	leg.mu.Unlock()
	if open != nil {
		var err error
		stream, err = open(ctx)
		if err != nil {
			return nil, err
		}
		leg.mu.Lock()
		leg.admission = stream
		leg.mu.Unlock()
	}
	decoded, err := admissionv3.Receive(ctx, stream)
	if err != nil {
		return nil, err
	}
	if decoded.Request.PathKind != artifactv3.PathTunnel {
		_ = stream.Reset()
		return nil, ErrInvalidNativeLeg
	}
	return decoded, nil
}

func (leg *NativeStreamLeg) SendAdmission(ctx context.Context, response artifactv3.AdmissionResponse, reasons artifactv3.ReasonRegistry) error {
	leg.mu.Lock()
	if !leg.received || leg.admission == nil || leg.responded {
		leg.mu.Unlock()
		return ErrAdmissionState
	}
	leg.responded = true
	leg.mu.Unlock()
	return admissionv3.Respond(ctx, leg.admission, response, reasons)
}

func (leg *NativeStreamLeg) Activate(_ context.Context, role uint8) (carrier.Session, error) {
	leg.mu.Lock()
	ready := leg.received && leg.responded && (role == 1 || role == 2)
	if !ready {
		leg.mu.Unlock()
		return nil, ErrAdmissionState
	}
	pending := leg.pending
	leg.pending = nil
	leg.mu.Unlock()
	if pending != nil {
		handoff := &nativeStreamHandoffSession{Session: leg.activated, first: pending}
		if datagrams, ok := leg.activated.(carrier.UnreliableTransport); ok {
			return &struct {
				*nativeStreamHandoffSession
				carrier.UnreliableTransport
			}{handoff, datagrams}, nil
		}
		return handoff, nil
	}
	return leg.activated, nil
}

func (leg *NativeStreamLeg) RejectWaitingStreams(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		stream, err := leg.session.AcceptStream(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return err
		}
		if ctx.Err() != nil {
			leg.mu.Lock()
			if leg.pending == nil {
				leg.pending = stream
			} else {
				_ = stream.Reset()
			}
			leg.mu.Unlock()
			return ctx.Err()
		}
		_ = stream.Reset()
	}
}

type nativeStreamHandoffSession struct {
	carrier.Session
	mu    sync.Mutex
	first carrier.Stream
}

func (session *nativeStreamHandoffSession) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	session.mu.Lock()
	first := session.first
	session.first = nil
	session.mu.Unlock()
	if first != nil {
		return first, nil
	}
	return session.Session.AcceptStream(ctx)
}

func (leg *NativeStreamLeg) CloseWithError(ctx context.Context, applicationError carrier.ApplicationError) error {
	if leg == nil {
		return io.ErrClosedPipe
	}
	return leg.activated.CloseWithErrorContext(ctx, applicationError)
}

var _ PendingLeg = (*NativeStreamLeg)(nil)
var _ WaitingStreamRejector = (*NativeStreamLeg)(nil)
