// Package admissionv3 runs the transport-neutral FSB3/FSA3 admission exchange
// on one bounded carrier stream.
package admissionv3

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
)

var (
	ErrTrailingBytes      = errors.New("trailing bytes on Flowersec v3 admission stream")
	ErrAdmissionRejected  = errors.New("Flowersec v3 admission rejected")
	ErrAdmissionRetryable = errors.New("Flowersec v3 admission retryable with a fresh artifact")
	ErrInvalidAuthorizer  = errors.New("invalid Flowersec v3 admission authorizer")
)

type ResponseError struct {
	Status artifactv3.AdmissionStatus
	Reason string
}

func (err *ResponseError) Error() string {
	return fmt.Sprintf("Flowersec v3 admission status=%d reason=%q", err.Status, err.Reason)
}

func (err *ResponseError) Unwrap() error {
	if err.Status == artifactv3.AdmissionRetryable {
		return ErrAdmissionRetryable
	}
	return ErrAdmissionRejected
}

type Authorize func(context.Context, *artifactv3.DecodedRequest) (artifactv3.AdmissionResponse, error)

// ClientExchange owns the Flowersec admission protocol over a credential-free
// runtime transport. Runtime adapters expose this boundary but never parse or
// emit FSB3/FSA3 themselves.
type ClientExchange interface {
	Commit(context.Context, []byte) error
}

type streamClientExchange struct {
	stream carrier.Stream
	path   artifactv3.PathKind
}

// NewStreamClientExchange binds the admission protocol to one native stream.
func NewStreamClientExchange(stream carrier.Stream, path artifactv3.PathKind) ClientExchange {
	return &streamClientExchange{stream: stream, path: path}
}

func (exchange *streamClientExchange) Commit(ctx context.Context, rawFSB3 []byte) error {
	if exchange == nil || exchange.stream == nil {
		return io.ErrClosedPipe
	}
	decoded, err := artifactv3.ParseRequest(rawFSB3)
	if err != nil {
		return err
	}
	if decoded.Request.PathKind != exchange.path {
		return fmt.Errorf("admission path %q does not match carrier path %q", decoded.Request.PathKind, exchange.path)
	}
	_, err = CommitClient(ctx, exchange.stream, rawFSB3)
	return err
}

// CommitClient writes the one-shot credential and accepts any syntactically
// valid bounded rejection reason without making it runtime configuration.
func CommitClient(ctx context.Context, stream carrier.Stream, rawFSB3 []byte) (response artifactv3.AdmissionResponse, err error) {
	return commit(ctx, stream, rawFSB3, artifactv3.ReadClientResponse)
}

// Commit writes the one-shot credential frame and reads an exact FSA3 response.
// Callers must mark the artifact spent before invoking this function.
func Commit(ctx context.Context, stream carrier.Stream, rawFSB3 []byte, reasons artifactv3.ReasonRegistry) (response artifactv3.AdmissionResponse, err error) {
	return commit(ctx, stream, rawFSB3, func(reader io.Reader) (artifactv3.AdmissionResponse, error) {
		return artifactv3.ReadResponse(reader, reasons)
	})
}

func commit(ctx context.Context, stream carrier.Stream, rawFSB3 []byte, readResponse func(io.Reader) (artifactv3.AdmissionResponse, error)) (response artifactv3.AdmissionResponse, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return response, io.ErrClosedPipe
	}
	if _, err := artifactv3.ParseRequest(rawFSB3); err != nil {
		return response, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = stream.Reset()
		}
	}()
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	if err := writeFull(stream, rawFSB3); err != nil {
		return response, preferContextError(ctx, err)
	}
	if err := stream.CloseWrite(); err != nil {
		return response, preferContextError(ctx, err)
	}
	response, err = readResponse(stream)
	if err != nil {
		return response, preferContextError(ctx, err)
	}
	if err := requireCleanEOF(stream); err != nil {
		return response, preferContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	succeeded = true
	if response.Status != artifactv3.AdmissionSuccess {
		return response, &ResponseError{Status: response.Status, Reason: response.Reason}
	}
	return response, nil
}

// Serve validates the exact request boundary before invoking the generic
// authorizer. The callback owns token interpretation; this package does not.
func Serve(ctx context.Context, stream carrier.Stream, reasons artifactv3.ReasonRegistry, authorize Authorize) (decoded *artifactv3.DecodedRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return nil, io.ErrClosedPipe
	}
	if authorize == nil {
		_ = stream.Reset()
		return nil, ErrInvalidAuthorizer
	}
	decoded, err = Receive(ctx, stream)
	if err != nil {
		return nil, err
	}
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	response, err := authorize(ctx, decoded)
	if err != nil {
		_ = stream.Reset()
		return nil, err
	}
	if err := Respond(ctx, stream, response, reasons); err != nil {
		return nil, err
	}
	if response.Status != artifactv3.AdmissionSuccess {
		return decoded, &ResponseError{Status: response.Status, Reason: response.Reason}
	}
	return decoded, nil
}

// Receive consumes exactly one FSB3 request and its peer FIN without sending a
// response. Tunnel pairing uses this split phase to hold SUCCESS until both
// independently authorized legs are ready.
func Receive(ctx context.Context, stream carrier.Stream) (decoded *artifactv3.DecodedRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return nil, io.ErrClosedPipe
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = stream.Reset()
		}
	}()
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	decoded, err = artifactv3.ReadRequest(stream)
	if err != nil {
		return nil, preferContextError(ctx, err)
	}
	if err := requireCleanEOF(stream); err != nil {
		return nil, preferContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	succeeded = true
	return decoded, nil
}

// Respond writes exactly one FSA3 response and closes the response direction.
func Respond(ctx context.Context, stream carrier.Stream, response artifactv3.AdmissionResponse, reasons artifactv3.ReasonRegistry) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return io.ErrClosedPipe
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = stream.Reset()
		}
	}()
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	rawResponse, err := artifactv3.MarshalResponse(response, reasons)
	if err != nil {
		return err
	}
	if err := writeFull(stream, rawResponse); err != nil {
		return preferContextError(ctx, err)
	}
	if err := stream.CloseWrite(); err != nil {
		return preferContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written < 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func requireCleanEOF(reader io.Reader) error {
	var one [1]byte
	read, err := reader.Read(one[:])
	if read != 0 || err == nil {
		return ErrTrailingBytes
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func interruptOnCancellation(ctx context.Context, stream carrier.Stream) func() {
	stop := context.AfterFunc(ctx, func() { _ = stream.Reset() })
	return func() { _ = stop() }
}

func preferContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}
