package tunnelv2

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v2/admissionv2"
	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
)

var (
	ErrInvalidNativeLeg = errors.New("invalid Flowersec v2 native-stream tunnel leg")
	ErrAdmissionState   = errors.New("invalid Flowersec v2 tunnel admission state")
)

// NativeStreamLeg adapts a raw QUIC or WebTransport session whose dedicated
// admission stream has already been accepted. It rejects every additional
// stream while the coordinator is waiting for the peer leg.
type NativeStreamLeg struct {
	session   carrier.Session
	admission carrier.Stream

	mu        sync.Mutex
	received  bool
	responded bool
}

// NewNativeStreamLeg binds a dedicated admission stream to a native session.
func NewNativeStreamLeg(session carrier.Session, admission carrier.Stream) (*NativeStreamLeg, error) {
	if session == nil || admission == nil ||
		(session.Kind() != carrier.KindQUIC && session.Kind() != carrier.KindWebTransport) ||
		session.Path() != carrier.PathTunnel {
		return nil, ErrInvalidNativeLeg
	}
	return &NativeStreamLeg{session: session, admission: admission}, nil
}

func (leg *NativeStreamLeg) CarrierKind() carrier.Kind { return leg.session.Kind() }

func (leg *NativeStreamLeg) ReceiveAdmission(ctx context.Context) (*artifactv2.DecodedRequest, error) {
	leg.mu.Lock()
	if leg.received {
		leg.mu.Unlock()
		return nil, ErrAdmissionState
	}
	leg.received = true
	leg.mu.Unlock()
	decoded, err := admissionv2.Receive(ctx, leg.admission)
	if err != nil {
		return nil, err
	}
	if decoded.Request.PathKind != artifactv2.PathTunnel {
		_ = leg.admission.Reset()
		return nil, ErrInvalidNativeLeg
	}
	return decoded, nil
}

func (leg *NativeStreamLeg) SendAdmission(ctx context.Context, response artifactv2.AdmissionResponse, reasons artifactv2.ReasonRegistry) error {
	leg.mu.Lock()
	if !leg.received || leg.responded {
		leg.mu.Unlock()
		return ErrAdmissionState
	}
	leg.responded = true
	leg.mu.Unlock()
	return admissionv2.Respond(ctx, leg.admission, response, reasons)
}

func (leg *NativeStreamLeg) Activate(context.Context) (carrier.Session, error) {
	leg.mu.Lock()
	ready := leg.received && leg.responded
	leg.mu.Unlock()
	if !ready {
		return nil, ErrAdmissionState
	}
	return leg.session, nil
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
		_ = stream.Reset()
	}
}

func (leg *NativeStreamLeg) CloseWithError(ctx context.Context, applicationError carrier.ApplicationError) error {
	if leg == nil {
		return io.ErrClosedPipe
	}
	return leg.session.CloseWithErrorContext(ctx, applicationError)
}

var _ PendingLeg = (*NativeStreamLeg)(nil)
var _ WaitingStreamRejector = (*NativeStreamLeg)(nil)
